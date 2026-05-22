//! Thread + futex coordination shared across a guest process's host threads.
//! No HVF, no syscalls — pure data structures behind their own locks so they
//! can be held across vCPU runs without entangling the big kernel lock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Condvar, Mutex};

pub type ThreadId = i32;

struct ThreadEntry {
    /// Guest address to zero + FUTEX_WAKE on thread exit (CLONE_CHILD_CLEARTID).
    clear_child_tid: u64,
}

pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: Mutex<HashMap<ThreadId, ThreadEntry>>,
}

impl ThreadRegistry {
    pub fn new(main_tid: ThreadId) -> Self {
        let mut map = HashMap::new();
        map.insert(main_tid, ThreadEntry { clear_child_tid: 0 });
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
            .insert(tid, ThreadEntry { clear_child_tid });
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

/// Address-keyed futex wait queues. Each guest futex word is identified by its
/// guest address (private futexes only for v1 — apt/glibc use FUTEX_PRIVATE).
pub struct FutexTable {
    inner: Mutex<HashMap<u64, u64>>, // addr -> generation counter
    cv: Condvar,
}

impl FutexTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cv: Condvar::new(),
        }
    }

    /// Wait until the generation for `addr` advances, `timeout` elapses, or
    /// `interrupted()` reports a pending signal. The caller must have ALREADY
    /// checked `*uaddr == expected` under the (separate) kernel lock and
    /// released it.
    ///
    /// Even an indefinite wait (`timeout == None`) is polled on a bounded cap
    /// so a process whose threads are ALL parked in futex still notices a
    /// pending signal within `POLL_CAP`. A spurious wake from the cap that
    /// neither advances the generation nor finds a signal just re-parks; futex
    /// callers always re-check their word, so this is semantically safe.
    pub fn wait(
        &self,
        addr: u64,
        timeout: Option<std::time::Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexWaitOutcome {
        use std::time::{Duration, Instant};
        const POLL_CAP: Duration = Duration::from_millis(50);
        // INVARIANT: mutex/condvar poisoning means another thread panicked while
        // holding the lock — unrecoverable, panic propagation is correct.
        #[allow(clippy::expect_used)]
        let mut map = self.inner.lock().expect("futex table mutex poisoned");
        let start_gen = *map.get(&addr).unwrap_or(&0);
        let deadline = timeout.map(|d| Instant::now() + d);
        loop {
            if *map.get(&addr).unwrap_or(&0) != start_gen {
                return FutexWaitOutcome::Woken;
            }
            if interrupted() {
                return FutexWaitOutcome::Interrupted;
            }
            let slice = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return FutexWaitOutcome::TimedOut;
                    }
                    (dl - now).min(POLL_CAP)
                }
                None => POLL_CAP,
            };
            #[allow(clippy::expect_used)]
            let (m, _res) = self
                .cv
                .wait_timeout(map, slice)
                .expect("futex condvar poisoned");
            map = m;
            // Loop: re-check generation / interrupt / deadline. `_res.timed_out()`
            // only tells us the slice elapsed, which may be the POLL_CAP rather
            // than the guest deadline — the deadline branch above is authoritative.
        }
    }

    /// Wake up to `n` waiters on `addr`. Returns `n` (best-effort upper bound;
    /// glibc only relies on >=1 progress, and waiters re-check `*uaddr`).
    pub fn wake(&self, addr: u64, n: u32) -> u32 {
        {
            // INVARIANT: mutex poisoning is unrecoverable; panic propagation is correct.
            #[allow(clippy::expect_used)]
            let mut map = self.inner.lock().expect("futex table mutex poisoned");
            let g = map.entry(addr).or_insert(0);
            *g = g.wrapping_add(1);
        }
        self.cv.notify_all(); // coarse: all waiters re-check their addr
        n
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
    fn futex_wake_with_no_waiters_returns_requested_count() {
        let table = FutexTable::new();
        // Implementation returns n (requested count) as best-effort upper bound.
        assert_eq!(table.wake(0x8000, 1), 1);
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

        // Raise the "signal pending" flag shortly after the wait begins.
        let raiser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            pending2.store(true, Ordering::SeqCst);
        });

        // Indefinite wait with no waker, but the predicate eventually fires —
        // the poll cap (50ms) guarantees we observe it.
        let outcome = table.wait(addr, None, &|| pending.load(Ordering::SeqCst));
        assert_eq!(outcome, FutexWaitOutcome::Interrupted);

        raiser.join().unwrap();
    }
}
