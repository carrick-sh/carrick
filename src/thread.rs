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

    /// Wait until the generation for `addr` advances or `timeout` elapses.
    /// The caller must have ALREADY checked `*uaddr == expected` under the
    /// (separate) kernel lock and released it. Returns true if woken, false on
    /// timeout.
    pub fn wait(&self, addr: u64, timeout: Option<std::time::Duration>) -> bool {
        // INVARIANT: mutex/condvar poisoning means another thread panicked while
        // holding the lock — unrecoverable, panic propagation is correct.
        #[allow(clippy::expect_used)]
        let mut map = self.inner.lock().expect("futex table mutex poisoned");
        let start_gen = *map.get(&addr).unwrap_or(&0);
        loop {
            let cur = *map.get(&addr).unwrap_or(&0);
            if cur != start_gen {
                return true;
            }
            match timeout {
                None => {
                    #[allow(clippy::expect_used)]
                    {
                        map = self.cv.wait(map).expect("futex condvar poisoned");
                    }
                }
                Some(d) => {
                    #[allow(clippy::expect_used)]
                    let (m, res) = self
                        .cv
                        .wait_timeout(map, d)
                        .expect("futex condvar poisoned");
                    map = m;
                    if res.timed_out() {
                        return false;
                    }
                }
            }
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
        let woken = table.wait(addr, None);
        assert!(woken, "expected to be woken by wake(), got timeout");

        waker.join().unwrap();
    }

    #[test]
    fn futex_wait_times_out_with_no_waker() {
        let table = FutexTable::new();
        let addr = 0xcafe_babe_u64;
        // No one will wake this — should time out and return false.
        let result = table.wait(addr, Some(Duration::from_millis(20)));
        assert!(!result, "expected timeout (false), but got woken");
    }
}
