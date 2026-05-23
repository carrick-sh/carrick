//! Thread + futex coordination shared across a guest process's host threads.
//! No HVF, no syscalls — pure data structures behind their own locks so they
//! can be held across vCPU runs without entangling the dispatcher lock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use parking_lot::Mutex as ParkingMutex;
use parking_lot_core::{FilterOp, ParkResult, ParkToken, UnparkToken};

pub type ThreadId = i32;

struct ThreadEntry {
    /// Guest address to zero + FUTEX_WAKE on thread exit (CLONE_CHILD_CLEARTID).
    clear_child_tid: u64,
    /// Mach port of the host thread backing this guest tid, recorded once when
    /// the vCPU thread starts. `/proc/<tid>/stat`'s state char is read from the
    /// KERNEL via `thread_info` on this port (no hand-tracked "sleeping" flag —
    /// the kernel already knows whether the thread is WAITING, and it covers
    /// every blocking path). 0 = not yet recorded.
    mach_port: crate::host_proc::ThreadPort,
}

pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: Mutex<HashMap<ThreadId, ThreadEntry>>,
}

/// Process-global handle to THIS process's live thread registry, so the
/// `/proc/<tid>/stat` and `/proc/<pid>/task/` synthesis (which runs on the
/// fs/open path, where the per-syscall registry isn't threaded through) can
/// read this process's thread tids + states. Set when the vCPU loop creates
/// its registry and re-set in a forked child (which builds a fresh one).
static CURRENT_REGISTRY: std::sync::Mutex<Option<std::sync::Arc<ThreadRegistry>>> =
    std::sync::Mutex::new(None);

/// Publish `registry` as this process's current registry. Called by the run
/// loop at startup and after fork (the child has its own registry).
pub fn set_current_registry(registry: std::sync::Arc<ThreadRegistry>) {
    if let Ok(mut g) = CURRENT_REGISTRY.lock() {
        *g = Some(registry);
    }
}

/// This process's live `(tid, state_char)` threads, or empty if unset.
pub fn current_thread_states() -> Vec<(ThreadId, char)> {
    CURRENT_REGISTRY
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|r| r.thread_states()))
        .unwrap_or_default()
}

impl ThreadRegistry {
    pub fn new(main_tid: ThreadId) -> Self {
        let mut map = HashMap::new();
        map.insert(
            main_tid,
            ThreadEntry {
                clear_child_tid: 0,
                mach_port: 0,
            },
        );
        Self {
            next_tid: AtomicI32::new(main_tid + 1),
            inner: Mutex::new(map),
        }
    }

    pub fn register_child(&self, clear_child_tid: u64) -> ThreadId {
        let tid = self.next_tid.fetch_add(1, Ordering::Relaxed);
        // INVARIANT: a poisoned mutex means another thread panicked while holding
        // it — the registry is in an unknown state and recovery is impossible.
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("thread registry mutex poisoned")
            .insert(
                tid,
                ThreadEntry {
                    clear_child_tid,
                    mach_port: 0,
                },
            );
        tid
    }

    pub fn clear_child_tid(&self, tid: ThreadId) -> Option<u64> {
        // INVARIANT: mutex poisoning is unrecoverable; panic propagation is correct.
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("thread registry mutex poisoned")
            .get(&tid)
            .map(|e| e.clear_child_tid)
    }

    pub fn set_clear_child_tid(&self, tid: ThreadId, addr: u64) {
        // INVARIANT: mutex poisoning is unrecoverable; panic propagation is correct.
        #[allow(clippy::expect_used)]
        if let Some(e) = self
            .inner
            .lock()
            .expect("thread registry mutex poisoned")
            .get_mut(&tid)
        {
            e.clear_child_tid = addr;
        }
    }

    /// Returns true if this was the last live thread (process should exit).
    pub fn exit(&self, tid: ThreadId) -> bool {
        // INVARIANT: mutex poisoning is unrecoverable; panic propagation is correct.
        #[allow(clippy::expect_used)]
        let mut map = self.inner.lock().expect("thread registry mutex poisoned");
        map.remove(&tid);
        map.is_empty()
    }

    pub fn live_count(&self) -> usize {
        // INVARIANT: mutex poisoning is unrecoverable; panic propagation is correct.
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("thread registry mutex poisoned")
            .len()
    }

    /// Is `tid` a live thread of this process? Used to route a guest
    /// `tgkill`/`tkill` to a sibling vs. reporting ESRCH.
    pub fn is_live(&self, tid: ThreadId) -> bool {
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("thread registry mutex poisoned")
            .contains_key(&tid)
    }

    /// Record the mach port of the host thread backing `tid`. Called ONCE by
    /// the vCPU thread itself when it starts (it knows its own pthread). This
    /// is the only per-thread state we keep for `/proc` — the run/sleep state
    /// is read live from the kernel, not tracked here.
    pub fn record_thread_port(&self, tid: ThreadId, port: crate::host_proc::ThreadPort) {
        #[allow(clippy::expect_used)]
        if let Some(e) = self
            .inner
            .lock()
            .expect("thread registry mutex poisoned")
            .get_mut(&tid)
        {
            e.mach_port = port;
        }
    }

    /// Live `(tid, state_char)` for every thread of this process — the data
    /// behind `/proc/<pid>/task/` and `/proc/<tid>/stat`. The state char is
    /// read from the kernel via `thread_info` on each thread's recorded mach
    /// port (`'S'` = WAITING, `'R'` = RUNNING, …); a thread whose port isn't
    /// recorded yet reports `'R'`.
    pub fn thread_states(&self) -> Vec<(ThreadId, char)> {
        #[allow(clippy::expect_used)]
        let ports: Vec<(ThreadId, crate::host_proc::ThreadPort)> = self
            .inner
            .lock()
            .expect("thread registry mutex poisoned")
            .iter()
            .map(|(&tid, e)| (tid, e.mach_port))
            .collect();
        // Query the kernel OUTSIDE the lock (thread_info is a syscall).
        ports
            .into_iter()
            .map(|(tid, port)| {
                let state = if port != 0 {
                    crate::host_proc::thread_run_state_char(port)
                } else {
                    'R'
                };
                (tid, state)
            })
            .collect()
    }
}

/// How a `FUTEX_WAIT` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexWaitOutcome {
    /// A `FUTEX_WAKE` advanced this address's generation. Linux returns 0.
    Woken,
    /// The guest-supplied timeout elapsed. Linux returns -ETIMEDOUT.
    TimedOut,
    /// A signal is pending for the process, so the wait was interrupted to let
    /// the trap loop deliver it. Linux returns -EINTR (the caller re-loops).
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct FutexWait {
    pub addr: u64,
    generation: u64,
}

struct FutexBucket {
    generation: AtomicU64,
    waiters: AtomicUsize,
}

impl FutexBucket {
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
        }
    }
}

const FUTEX_WAKE_TOKEN: usize = 1;
const FUTEX_SIGNAL_TOKEN: usize = 2;

/// Address-keyed futex wait queues. Each guest futex word is identified by a
/// stable Carrick-owned bucket key derived from an `Arc<FutexBucket>`, not by
/// feeding raw guest addresses to `parking_lot_core`.
pub struct FutexTable {
    buckets: ParkingMutex<HashMap<u64, Arc<FutexBucket>>>,
}

impl FutexTable {
    pub fn new() -> Self {
        Self {
            buckets: ParkingMutex::new(HashMap::new()),
        }
    }

    fn bucket(&self, addr: u64) -> Arc<FutexBucket> {
        let mut buckets = self.buckets.lock();
        Arc::clone(
            buckets
                .entry(addr)
                .or_insert_with(|| Arc::new(FutexBucket::new())),
        )
    }

    fn bucket_key(bucket: &Arc<FutexBucket>) -> usize {
        Arc::as_ptr(bucket) as usize
    }

    /// Capture the futex generation immediately after the dispatcher has
    /// verified the guest word. The runtime later parks against this token
    /// with syscall locks released; a wake that races in between advances the
    /// generation and the waiter returns without sleeping.
    pub fn prepare_wait(&self, addr: u64) -> FutexWait {
        let bucket = self.bucket(addr);
        FutexWait {
            addr,
            generation: bucket.generation.load(Ordering::Acquire),
        }
    }

    pub fn wait(
        &self,
        addr: u64,
        timeout: Option<std::time::Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexWaitOutcome {
        let wait = self.prepare_wait(addr);
        self.wait_prepared(wait, timeout, interrupted)
    }

    /// Wait until the generation captured by `prepare_wait` advances,
    /// `timeout` elapses, or `interrupted()` reports a pending signal. The
    /// caller must have already checked `*uaddr == expected` before creating
    /// the wait token.
    pub fn wait_prepared(
        &self,
        wait: FutexWait,
        timeout: Option<std::time::Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexWaitOutcome {
        self.wait_prepared_with_token(wait, timeout, ParkToken(0), interrupted)
    }

    pub fn wait_prepared_for_thread(
        &self,
        wait: FutexWait,
        timeout: Option<std::time::Duration>,
        tid: ThreadId,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexWaitOutcome {
        let token = usize::try_from(tid).unwrap_or(0);
        self.wait_prepared_with_token(wait, timeout, ParkToken(token), interrupted)
    }

    fn wait_prepared_with_token(
        &self,
        wait: FutexWait,
        timeout: Option<std::time::Duration>,
        park_token: ParkToken,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexWaitOutcome {
        use std::cell::Cell;
        use std::time::Instant;

        let bucket = self.bucket(wait.addr);
        let key = Self::bucket_key(&bucket);
        let deadline = timeout.map(|duration| Instant::now() + duration);

        loop {
            if bucket.generation.load(Ordering::Acquire) != wait.generation {
                return FutexWaitOutcome::Woken;
            }
            if interrupted() {
                return FutexWaitOutcome::Interrupted;
            }

            if let Some(deadline) = deadline
                && Instant::now() >= deadline
            {
                return FutexWaitOutcome::TimedOut;
            }

            let registered = Cell::new(false);
            let park_result = unsafe {
                parking_lot_core::park(
                    key,
                    || {
                        if bucket.generation.load(Ordering::Acquire) != wait.generation {
                            return false;
                        }
                        registered.set(true);
                        bucket.waiters.fetch_add(1, Ordering::AcqRel);
                        true
                    },
                    || {},
                    |_, _| {
                        bucket.waiters.fetch_sub(1, Ordering::AcqRel);
                    },
                    park_token,
                    deadline,
                )
            };

            match park_result {
                ParkResult::Unparked(token) => {
                    if registered.get() {
                        bucket.waiters.fetch_sub(1, Ordering::AcqRel);
                    }
                    match token.0 {
                        FUTEX_WAKE_TOKEN => return FutexWaitOutcome::Woken,
                        FUTEX_SIGNAL_TOKEN if interrupted() => {
                            return FutexWaitOutcome::Interrupted;
                        }
                        _ => {}
                    }
                }
                ParkResult::Invalid => {
                    if bucket.generation.load(Ordering::Acquire) != wait.generation {
                        return FutexWaitOutcome::Woken;
                    }
                }
                ParkResult::TimedOut => return FutexWaitOutcome::TimedOut,
            }
        }
    }

    /// Wake all futex waiters for a process-directed signal. Any guest thread may
    /// deliver that signal, so every parked thread must re-evaluate its
    /// `interrupted()` predicate now rather than waiting for a timeout deadline.
    pub fn notify_signal_pending(&self) {
        let buckets = self.buckets.lock().values().cloned().collect::<Vec<_>>();
        for bucket in buckets {
            let key = Self::bucket_key(&bucket);
            unsafe {
                parking_lot_core::unpark_filter(
                    key,
                    |_| FilterOp::Unpark,
                    |_| UnparkToken(FUTEX_SIGNAL_TOKEN),
                );
            }
        }
    }

    /// Wake only futex waiters parked by `tid`, used for thread-directed
    /// `tgkill`/`tkill` delivery. Waiters for other tids stay parked until a real
    /// `FUTEX_WAKE`, timeout, or process-directed signal reaches them.
    pub fn notify_signal_pending_for(&self, tid: ThreadId) {
        let Ok(token) = usize::try_from(tid) else {
            return;
        };
        let buckets = self.buckets.lock().values().cloned().collect::<Vec<_>>();
        for bucket in buckets {
            let key = Self::bucket_key(&bucket);
            unsafe {
                parking_lot_core::unpark_filter(
                    key,
                    |parked| {
                        if parked.0 == token {
                            FilterOp::Unpark
                        } else {
                            FilterOp::Skip
                        }
                    },
                    |_| UnparkToken(FUTEX_SIGNAL_TOKEN),
                );
            }
        }
    }

    /// Wake up to `n` waiters on `addr`. Returns the number of waiters that
    /// `parking_lot_core` actually removed from this bucket.
    pub fn wake(&self, addr: u64, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let bucket = self.bucket(addr);
        bucket.generation.fetch_add(1, Ordering::AcqRel);
        let key = Self::bucket_key(&bucket);
        let mut remaining = n as usize;
        let result = unsafe {
            parking_lot_core::unpark_filter(
                key,
                |_| {
                    if remaining == 0 {
                        FilterOp::Stop
                    } else {
                        remaining -= 1;
                        FilterOp::Unpark
                    }
                },
                |_| UnparkToken(FUTEX_WAKE_TOKEN),
            )
        };
        result.unparked_threads as u32
    }

    #[cfg(test)]
    pub fn waiter_count(&self, addr: u64) -> usize {
        self.bucket(addr).waiters.load(Ordering::Acquire)
    }
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn allocates_monotonic_tids_above_base() {
        let reg = ThreadRegistry::new(/*main_tid=*/ 1000);
        assert_eq!(reg.live_count(), 1);
        let t = reg.register_child(/*clear_child_tid=*/ 0x4000);
        assert!(t > 1000);
        assert_eq!(reg.live_count(), 2);
        assert_eq!(reg.clear_child_tid(t), Some(0x4000));
    }

    #[test]
    fn exit_removes_thread_and_reports_last() {
        let reg = ThreadRegistry::new(1000);
        let t = reg.register_child(0);
        assert!(!reg.exit(t)); // not last
        assert!(reg.exit(1000)); // last live thread -> true
    }

    #[test]
    fn futex_wake_with_no_waiters_returns_zero() {
        let table = FutexTable::new();
        assert_eq!(table.wake(0x8000, 1), 0);
    }

    #[test]
    fn futex_wake_returns_actual_waiter_count() {
        let table = Arc::new(FutexTable::new());
        let table2 = Arc::clone(&table);
        let addr = 0x8000_u64;

        let waiter = std::thread::spawn(move || table2.wait(addr, None, &|| false));
        while table.waiter_count(addr) == 0 {
            std::thread::yield_now();
        }

        assert_eq!(table.wake(addr, 2), 1);
        match waiter.join() {
            Ok(outcome) => assert_eq!(outcome, FutexWaitOutcome::Woken),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn futex_wait_woken_by_wake_across_threads() {
        let table = Arc::new(FutexTable::new());
        let table2 = Arc::clone(&table);
        let addr = 0xdead_beef_u64;

        // Spawn a thread that sleeps briefly, then wakes the waiter.
        let waker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            table2.wake(addr, 1);
        });

        // Main thread waits indefinitely — should be woken by the spawned thread.
        let outcome = table.wait(addr, None, &|| false);
        assert_eq!(
            outcome,
            FutexWaitOutcome::Woken,
            "expected to be woken by wake()"
        );

        waker.join().unwrap();
    }

    #[test]
    fn futex_wait_times_out_with_no_waker() {
        let table = FutexTable::new();
        let addr = 0xcafe_babe_u64;
        // No one will wake this — should time out (guest deadline elapses).
        let outcome = table.wait(addr, Some(Duration::from_millis(20)), &|| false);
        assert_eq!(outcome, FutexWaitOutcome::TimedOut);
    }

    #[test]
    fn futex_wait_interrupted_by_pending_signal() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let table = Arc::new(FutexTable::new());
        let addr = 0xfeed_face_u64;
        let pending = Arc::new(AtomicBool::new(false));
        let pending2 = Arc::clone(&pending);
        let table2 = Arc::clone(&table);

        // Raise the "signal pending" flag shortly after the wait begins.
        let raiser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            pending2.store(true, Ordering::SeqCst);
            table2.notify_signal_pending();
        });

        // Indefinite wait with no waker, but the predicate eventually fires —
        // the signal notification wakes the parked thread immediately.
        let outcome = table.wait(addr, None, &|| pending.load(Ordering::SeqCst));
        assert_eq!(outcome, FutexWaitOutcome::Interrupted);

        raiser.join().unwrap();
    }

    #[test]
    fn signal_wake_targets_only_matching_waiter_tid() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let table = Arc::new(FutexTable::new());
        let addr = 0x5151_0000_u64;
        let target_tid = 10;
        let sibling_tid = 11;
        let target_pending = Arc::new(AtomicBool::new(false));
        let sibling_pending = Arc::new(AtomicBool::new(false));

        let target_wait = table.prepare_wait(addr);
        let target_table = Arc::clone(&table);
        let target_pending2 = Arc::clone(&target_pending);
        let target = std::thread::spawn(move || {
            target_table.wait_prepared_for_thread(target_wait, None, target_tid, &|| {
                target_pending2.load(Ordering::SeqCst)
            })
        });

        let sibling_wait = table.prepare_wait(addr);
        let sibling_table = Arc::clone(&table);
        let sibling_pending2 = Arc::clone(&sibling_pending);
        let sibling = std::thread::spawn(move || {
            sibling_table.wait_prepared_for_thread(sibling_wait, None, sibling_tid, &|| {
                sibling_pending2.load(Ordering::SeqCst)
            })
        });

        while table.waiter_count(addr) < 2 {
            std::thread::yield_now();
        }

        target_pending.store(true, Ordering::SeqCst);
        table.notify_signal_pending_for(target_tid);

        match target.join() {
            Ok(outcome) => assert_eq!(outcome, FutexWaitOutcome::Interrupted),
            Err(payload) => std::panic::resume_unwind(payload),
        }
        assert_eq!(table.waiter_count(addr), 1);

        assert_eq!(table.wake(addr, 1), 1);
        match sibling.join() {
            Ok(outcome) => assert_eq!(outcome, FutexWaitOutcome::Woken),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
