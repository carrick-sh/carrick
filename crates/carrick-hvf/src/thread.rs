//! Thread + futex coordination shared across a guest process's host threads.
//!
//! THEORY OF OPERATION
//!
//! Carrick runs each guest thread as a real macOS thread driving its own HVF
//! vCPU; there is no guest Linux kernel to arbitrate between them. The two data
//! structures here are what stands in for the kernel's per-process thread table
//! and its futex hash bucket array. They are pure host-memory structures behind
//! their own `parking_lot` locks — deliberately NO HVF calls and NO syscalls —
//! so a lock here can be held across a vCPU run without entangling the
//! dispatcher lock (which, post-BKL-retirement, must never be the single point
//! that serializes every guest thread).
//!
//! [`ThreadRegistry`] is the per-process thread table. It allocates monotonic
//! guest tids, tracks `CLONE_CHILD_CLEARTID` addresses (zeroed + woken on thread
//! exit), per-thread `prctl`/`pthread_setname_np` names, and — crucially — it
//! does NOT track run/sleep state itself. The `/proc/<tid>/stat` state char is
//! read LIVE from the host kernel via `thread_info` on each thread's recorded
//! mach port (see [`ThreadRegistry::thread_states`]); the kernel already knows
//! whether a thread is WAITING in any blocking path, so a hand-maintained
//! "sleeping" flag would only be a second source of truth to keep wrong. A
//! process-global handle ([`set_current_registry`]) lets the fs/open `/proc`
//! synthesis reach this process's registry without threading it through every
//! syscall; a forked child re-publishes a fresh one.
//!
//! [`FutexTable`] is the futex implementation. The key design decision is that
//! a PRIVATE futex (`FUTEX_PRIVATE_FLAG`) never touches `__ulock` or a real
//! shared address at all: it parks on a Carrick-owned `parking_lot_core` key
//! derived from an `Arc<FutexBucket>`, keyed by the guest address, with a
//! per-bucket GENERATION counter. `FUTEX_WAKE` bumps the generation and unparks;
//! a waiter that re-checks the generation and finds it advanced returns `Woken`
//! without sleeping, which closes the classic lost-wake race between the
//! dispatcher's `*uaddr == expected` check and the actual park (see
//! [`FutexTable::prepare_wait`] — the generation is captured under the
//! dispatcher's verification, then the park happens with syscall locks
//! released). SHARED futexes (cross-process, on the shared aperture) are handled
//! elsewhere via Darwin `os_sync_wait_on_address`/`__ulock`; this table owns the
//! private case, which is the overwhelming majority.
//!
//! Three properties are non-obvious and load-bearing:
//!
//!   * SHARDING. The address→bucket lookup runs on EVERY futex syscall, wait and
//!     wake. A single global map lock serialized all guest threads' futex ops
//!     and throttled high-concurrency runtimes (Go with `GOMAXPROCS = ncpu`
//!     spins up that many M's, each parking/waking on its own word). The address
//!     map is sharded `FUTEX_SHARDS` (64) ways by a Fibonacci hash of the
//!     address so aligned words — which share low bits — spread across shards.
//!
//!   * SIGNAL INTERRUPTIBILITY. A guest futex wait must abort with `-EINTR` when
//!     a signal becomes pending so the trap loop can deliver it. The park's wake
//!     predicate ORs in `interrupted()`, and the signal pump calls
//!     [`FutexTable::notify_signal_pending`] (process-directed) or
//!     [`FutexTable::notify_signal_pending_for`] (thread-directed `tgkill`) to
//!     unpark waiters with a distinguishing token so only the right threads
//!     re-evaluate their predicate rather than waiting out a timeout.
//!
//!   * REQUEUE. `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` is the one primitive Darwin's
//!     `__ulock` lacks; `parking_lot_core::unpark_requeue` provides it by
//!     atomically relinking parked records from one key to another. A requeued
//!     thread stays blocked inside its original `park()` and only wakes on an
//!     unpark of the destination key — see [`FutexTable::requeue`] for why this
//!     composes with the generation model (token unparks bypass the per-bucket
//!     generation check).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

use parking_lot::Mutex as ParkingMutex;
use parking_lot_core::{FilterOp, ParkResult, ParkToken, RequeueOp, UnparkResult, UnparkToken};

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
    /// Per-thread name (prctl PR_SET_NAME / pthread_setname_np), exposed via
    /// `/proc/<pid>/task/<tid>/comm`. `None` until the thread names itself; the
    /// /proc handler then falls back to the executable basename. TASK_COMM_LEN
    /// is 16 (15 chars + NUL).
    name: Option<[u8; 16]>,
}

pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: ParkingMutex<HashMap<ThreadId, ThreadEntry>>,
}

/// Process-global handle to THIS process's live thread registry, so the
/// `/proc/<tid>/stat` and `/proc/<pid>/task/` synthesis (which runs on the
/// fs/open path, where the per-syscall registry isn't threaded through) can
/// read this process's thread tids + states. Set when the vCPU loop creates
/// its registry and re-set in a forked child (which builds a fresh one).
static CURRENT_REGISTRY: ParkingMutex<Option<Arc<ThreadRegistry>>> = ParkingMutex::new(None);

/// Publish `registry` as this process's current registry. Called by the run
/// loop at startup and after fork (the child has its own registry).
pub fn set_current_registry(registry: Arc<ThreadRegistry>) {
    *CURRENT_REGISTRY.lock() = Some(registry);
}

/// This process's live `(tid, state_char)` threads, or empty if unset.
pub fn current_thread_states() -> Vec<(ThreadId, char)> {
    CURRENT_REGISTRY
        .lock()
        .as_ref()
        .map(|r| r.thread_states())
        .unwrap_or_default()
}

/// `tid`'s prctl/pthread-set name from the current process's registry, if set.
/// Used by the `/proc/<pid>/task/<tid>/comm` handler (which has no direct
/// registry handle) to report per-thread names.
pub fn current_thread_name(tid: ThreadId) -> Option<[u8; 16]> {
    CURRENT_REGISTRY
        .lock()
        .as_ref()
        .and_then(|r| r.thread_name(tid))
}

impl ThreadRegistry {
    pub fn new(main_tid: ThreadId) -> Self {
        let mut map = HashMap::new();
        map.insert(
            main_tid,
            ThreadEntry {
                clear_child_tid: 0,
                mach_port: 0,
                name: None,
            },
        );
        Self {
            next_tid: AtomicI32::new(main_tid + 1),
            inner: ParkingMutex::new(map),
        }
    }

    pub fn register_child(&self, clear_child_tid: u64) -> ThreadId {
        let tid = self.next_tid.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().insert(
            tid,
            ThreadEntry {
                clear_child_tid,
                mach_port: 0,
                name: None,
            },
        );
        tid
    }

    pub fn clear_child_tid(&self, tid: ThreadId) -> Option<u64> {
        self.inner.lock().get(&tid).map(|e| e.clear_child_tid)
    }

    pub fn set_clear_child_tid(&self, tid: ThreadId, addr: u64) {
        if let Some(e) = self.inner.lock().get_mut(&tid) {
            e.clear_child_tid = addr;
        }
    }

    /// Returns true if this was the last live thread (process should exit).
    pub fn exit(&self, tid: ThreadId) -> bool {
        let mut map = self.inner.lock();
        map.remove(&tid);
        map.is_empty()
    }

    pub fn live_count(&self) -> usize {
        self.inner.lock().len()
    }

    /// Is `tid` a live thread of this process? Used to route a guest
    /// `tgkill`/`tkill` to a sibling vs. reporting ESRCH.
    pub fn is_live(&self, tid: ThreadId) -> bool {
        self.inner.lock().contains_key(&tid)
    }

    /// Every live thread id of this process. Unlike `thread_states`, this does
    /// NOT query the kernel for run state — it's the cheap enumeration used to
    /// route a process-directed signal (`kill(getpid(), sig)`) to a thread that
    /// doesn't block `sig`.
    pub fn live_tids(&self) -> Vec<ThreadId> {
        self.inner.lock().keys().copied().collect()
    }

    /// Set `tid`'s name (prctl PR_SET_NAME / pthread_setname_np). `name` is the
    /// raw bytes; truncated to 15 + a NUL terminator (TASK_COMM_LEN = 16).
    pub fn set_thread_name(&self, tid: ThreadId, name: &[u8]) {
        let mut buf = [0u8; 16];
        let n = name.iter().take_while(|&&b| b != 0).count().min(15);
        buf[..n].copy_from_slice(&name[..n]);
        if let Some(e) = self.inner.lock().get_mut(&tid) {
            e.name = Some(buf);
        }
    }

    /// `tid`'s name, if it has named itself; `None` falls back to the exe
    /// basename at the /proc/comm layer.
    pub fn thread_name(&self, tid: ThreadId) -> Option<[u8; 16]> {
        self.inner.lock().get(&tid).and_then(|e| e.name)
    }

    /// Record the mach port of the host thread backing `tid`. Called ONCE by
    /// the vCPU thread itself when it starts (it knows its own pthread). This
    /// is the only per-thread state we keep for `/proc` — the run/sleep state
    /// is read live from the kernel, not tracked here.
    pub fn record_thread_port(&self, tid: ThreadId, port: crate::host_proc::ThreadPort) {
        if let Some(e) = self.inner.lock().get_mut(&tid) {
            e.mach_port = port;
        }
    }

    /// Live `(tid, state_char)` for every thread of this process — the data
    /// behind `/proc/<pid>/task/` and `/proc/<tid>/stat`. The state char is
    /// read from the kernel via `thread_info` on each thread's recorded mach
    /// port (`'S'` = WAITING, `'R'` = RUNNING, …); a thread whose port isn't
    /// recorded yet reports `'R'`.
    pub fn thread_states(&self) -> Vec<(ThreadId, char)> {
        let ports: Vec<(ThreadId, crate::host_proc::ThreadPort)> = self
            .inner
            .lock()
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

/// Number of independently-locked shards of the futex address map. `bucket()`
/// runs on EVERY futex syscall (wait and wake); a single global lock here
/// serialized all guest threads' futex ops, which throttled high-concurrency
/// runtimes (Go with GOMAXPROCS = ncpu spins up that many M's, each parking and
/// waking on its own futex word). Sharding by address spreads that contention.
/// 64 shards keeps per-shard contention low for any realistic thread count.
const FUTEX_SHARDS: usize = 64;

/// Address-keyed futex wait queues. Each guest futex word is identified by a
/// stable Carrick-owned bucket key derived from an `Arc<FutexBucket>`, not by
/// feeding raw guest addresses to `parking_lot_core`. The address→bucket map is
/// sharded so the lookup lock is not a global serialization point.
pub struct FutexTable {
    #[allow(clippy::type_complexity)]
    shards: Box<[ParkingMutex<HashMap<u64, Arc<FutexBucket>>>; FUTEX_SHARDS]>,
}

impl FutexTable {
    pub fn new() -> Self {
        Self {
            shards: Box::new(std::array::from_fn(|_| ParkingMutex::new(HashMap::new()))),
        }
    }

    /// Pick the shard for `addr`. A multiplicative (Fibonacci) hash spreads
    /// aligned futex addresses (which share low bits) across shards.
    fn shard(&self, addr: u64) -> &ParkingMutex<HashMap<u64, Arc<FutexBucket>>> {
        let h = addr.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58;
        &self.shards[h as usize % FUTEX_SHARDS]
    }

    fn bucket(&self, addr: u64) -> Arc<FutexBucket> {
        let mut shard = self.shard(addr).lock();
        Arc::clone(
            shard
                .entry(addr)
                .or_insert_with(|| Arc::new(FutexBucket::new())),
        )
    }

    /// Snapshot every live bucket across all shards (for process-/thread-directed
    /// signal wakeups, which must reach waiters regardless of address).
    fn all_buckets(&self) -> Vec<Arc<FutexBucket>> {
        let mut all = Vec::new();
        for shard in self.shards.iter() {
            all.extend(shard.lock().values().cloned());
        }
        all
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
        let buckets = self.all_buckets();
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
        let buckets = self.all_buckets();
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

    /// `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` core: wake up to `nr_wake` waiters
    /// on `from`, then move up to `nr_requeue` of the REMAINING waiters to
    /// `to`'s queue (where a later `FUTEX_WAKE(to)` will reach them). Returns
    /// `(woken, requeued)`.
    ///
    /// This is the primitive Darwin's `__ulock` lacks but `parking_lot_core`
    /// provides via `unpark_requeue`: it atomically relinks parked thread
    /// records from one parking-lot key to another. A requeued guest thread
    /// stays blocked inside its original `park()` call — it does NOT return to
    /// the wait loop and re-park on the old key — so the move is durable; the
    /// thread only wakes when someone unparks `to`'s key, at which point it
    /// returns `Woken` via the `FUTEX_WAKE_TOKEN` match (the per-bucket
    /// generation check is bypassed for a token unpark, which is exactly why
    /// requeue composes with the generation model).
    ///
    /// A large `nr_requeue` (glibc/musl pass `INT_MAX` for "requeue everyone")
    /// takes the O(queue) `RequeueAll`/`UnparkOneRequeueRest` fast path; a
    /// bounded `nr_requeue` loops `RequeueOne` so the count is exact. The
    /// caller is responsible for rejecting a negative `nr_requeue` (the kernel
    /// returns EINVAL) before calling this.
    pub fn requeue(&self, from: u64, to: u64, nr_wake: u32, nr_requeue: u32) -> (u32, u32) {
        // glibc/musl request "all" via INT_MAX; anything at/above this cap is
        // treated as unbounded so it takes the single-pass fast path rather
        // than an INT_MAX-iteration RequeueOne loop.
        const REQUEUE_ALL: u32 = i32::MAX as u32;
        let from_bucket = self.bucket(from);
        let to_bucket = self.bucket(to);
        let key_from = Self::bucket_key(&from_bucket);
        let key_to = Self::bucket_key(&to_bucket);

        // Waking advances the source generation so the woken threads observe a
        // change; requeued threads are reached by a token unpark on `to`.
        if nr_wake > 0 {
            from_bucket.generation.fetch_add(1, Ordering::AcqRel);
        }

        let mut woken: u32 = 0;
        let mut requeued: u32 = 0;

        // Fast path: requeue-all (nr_requeue saturated). One unpark_requeue
        // call wakes ≤1 and moves the rest. For nr_wake >= 2 we first wake the
        // extra (nr_wake - 1) via the normal filter, since unpark_requeue only
        // wakes one.
        if nr_requeue >= REQUEUE_ALL {
            if nr_wake >= 2 {
                woken += self.wake_no_genbump(&from_bucket, nr_wake - 1);
            }
            let op = if nr_wake >= 1 {
                RequeueOp::UnparkOneRequeueRest
            } else {
                RequeueOp::RequeueAll
            };
            let res: UnparkResult = unsafe {
                parking_lot_core::unpark_requeue(
                    key_from,
                    key_to,
                    || op,
                    |_op, _res| UnparkToken(FUTEX_WAKE_TOKEN),
                )
            };
            woken += res.unparked_threads as u32;
            requeued += res.requeued_threads as u32;
            return (woken, requeued);
        }

        // Bounded path: wake nr_wake, then requeue exactly up to nr_requeue.
        if nr_wake > 0 {
            woken += self.wake_no_genbump(&from_bucket, nr_wake);
        }
        while requeued < nr_requeue {
            let res: UnparkResult = unsafe {
                parking_lot_core::unpark_requeue(
                    key_from,
                    key_to,
                    || RequeueOp::RequeueOne,
                    |_op, _res| UnparkToken(FUTEX_WAKE_TOKEN),
                )
            };
            if res.requeued_threads == 0 {
                break; // source queue drained
            }
            requeued += res.requeued_threads as u32;
            if !res.have_more_threads {
                break;
            }
        }
        (woken, requeued)
    }

    /// Unpark up to `n` waiters on an already-resolved bucket WITHOUT bumping
    /// its generation (the caller bumped it once up front). Used by `requeue`
    /// to wake the `nr_wake` portion.
    fn wake_no_genbump(&self, bucket: &Arc<FutexBucket>, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let key = Self::bucket_key(bucket);
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
    fn requeue_moves_waiters_from_one_addr_to_another() {
        // N threads park on `from`; requeue(nr_wake=1, nr_requeue=ALL) wakes 1
        // and moves the rest to `to`; a wake(to) then frees them, while a
        // wake(from) afterwards finds nobody.
        let table = Arc::new(FutexTable::new());
        let from = 0x1111_0000_u64;
        let to = 0x2222_0000_u64;
        const N: usize = 4;

        let parked = Arc::new(AtomicUsize::new(0));
        let returned = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..N {
            let t = Arc::clone(&table);
            let parked = Arc::clone(&parked);
            let returned = Arc::clone(&returned);
            handles.push(std::thread::spawn(move || {
                parked.fetch_add(1, Ordering::SeqCst);
                // Park on `from`; a requeue relinks us to `to` transparently.
                let _ = t.wait(from, Some(Duration::from_secs(5)), &|| false);
                returned.fetch_add(1, Ordering::SeqCst);
            }));
        }
        // Wait for all parked, plus a beat to enter park().
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while parked.load(Ordering::SeqCst) < N && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(50));

        let (woken, requeued) = table.requeue(from, to, 1, u32::MAX);
        assert_eq!(woken, 1, "exactly one waiter woken");
        assert_eq!(requeued, (N - 1) as u32, "the rest requeued to `to`");

        // `from` is now empty.
        assert_eq!(table.wake(from, u32::MAX), 0, "no waiters left on `from`");
        // `to` holds the N-1 requeued; wake them.
        assert_eq!(
            table.wake(to, u32::MAX),
            (N - 1) as u32,
            "the requeued waiters are reachable on `to`"
        );

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(returned.load(Ordering::SeqCst), N, "all waiters completed");
    }

    #[test]
    fn requeue_bounded_count_is_exact() {
        // requeue with a BOUNDED nr_requeue moves exactly that many, leaving
        // the rest on `from`.
        let table = Arc::new(FutexTable::new());
        let from = 0x3333_0000_u64;
        let to = 0x4444_0000_u64;
        const N: usize = 5;

        let parked = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..N {
            let t = Arc::clone(&table);
            let parked = Arc::clone(&parked);
            handles.push(std::thread::spawn(move || {
                parked.fetch_add(1, Ordering::SeqCst);
                let _ = t.wait(from, Some(Duration::from_secs(5)), &|| false);
            }));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while parked.load(Ordering::SeqCst) < N && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(50));

        // Wake 0, requeue exactly 2 of the 5.
        let (woken, requeued) = table.requeue(from, to, 0, 2);
        assert_eq!(woken, 0);
        assert_eq!(requeued, 2, "exactly 2 requeued");
        // `to` has 2; `from` still has 3.
        assert_eq!(table.wake(to, u32::MAX), 2, "2 reachable on `to`");
        assert_eq!(table.wake(from, u32::MAX), 3, "3 remain on `from`");

        for h in handles {
            h.join().unwrap();
        }
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
