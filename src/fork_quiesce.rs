//! Stop-the-world barrier for forking a multithreaded guest. The forking
//! thread quiesces every other guest vCPU thread at the lock-safe run-loop top
//! before `libc::fork`, so the child inherits no carrick lock held by a thread
//! that won't exist in the child. See
//! docs/superpowers/specs/2026-05-24-multithreaded-fork-design.md.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct QuiesceBarrier {
    quiescing: AtomicBool,
    paused: Mutex<usize>,
    cv: Condvar,
}

impl QuiesceBarrier {
    pub(crate) fn new() -> Self {
        Self {
            quiescing: AtomicBool::new(false),
            paused: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// Step 1 (forking thread): raise the quiesce flag. The caller then wakes
    /// the other threads (kick in-guest vCPUs + notify blocked waiters) and
    /// calls `wait_quiesced`. Split from the wait so the wakes happen between —
    /// a thread woken by the kick/notify must observe `is_quiescing()==true` at
    /// the run-loop top, so the flag MUST be raised before the wakes.
    pub(crate) fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// Step 2 (forking thread): wait until `others` threads have parked at the
    /// barrier, or `timeout`. Returns false on timeout (caller aborts the fork
    /// with EAGAIN and calls `end_quiesce`).
    pub(crate) fn wait_quiesced(&self, others: usize, timeout: Duration) -> bool {
        if others == 0 {
            return true;
        }
        let deadline = Instant::now() + timeout;
        let mut paused = self.paused.lock().unwrap();
        while *paused < others {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (g, res) = self.cv.wait_timeout(paused, deadline - now).unwrap();
            paused = g;
            if res.timed_out() && *paused < others {
                return false;
            }
        }
        true
    }

    /// Is a quiesce in progress? Cheap; checked at the run-loop top.
    pub(crate) fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Called by every OTHER thread at the lock-safe run-loop top. If a quiesce
    /// is in progress, register as paused and block until it ends.
    pub(crate) fn park_if_quiescing(&self) {
        if !self.is_quiescing() {
            return;
        }
        let mut paused = self.paused.lock().unwrap();
        *paused += 1;
        self.cv.notify_all(); // wake the forking thread's count-wait
        while self.quiescing.load(Ordering::SeqCst) {
            paused = self.cv.wait(paused).unwrap();
        }
        *paused -= 1;
    }

    /// Called by the forking thread (parent path, child path, or timeout abort)
    /// to lower the flag and release the parked threads.
    pub(crate) fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
        let _g = self.paused.lock().unwrap();
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn quiesce_waits_for_all_others_then_releases() {
        let barrier = Arc::new(QuiesceBarrier::new());
        let resumed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let n = 3;
        let mut handles = Vec::new();
        for _ in 0..n {
            let b = Arc::clone(&barrier);
            let r = Arc::clone(&resumed);
            let s = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    b.park_if_quiescing();
                    std::thread::yield_now();
                }
                r.fetch_add(1, Ordering::SeqCst);
            }));
        }
        std::thread::sleep(Duration::from_millis(20));
        barrier.set_quiescing();
        assert!(
            barrier.wait_quiesced(n, Duration::from_secs(5)),
            "all others should quiesce"
        );
        barrier.end_quiesce();
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(resumed.load(Ordering::SeqCst), n);
    }

    #[test]
    fn wait_quiesced_times_out_when_a_thread_never_parks() {
        let barrier = QuiesceBarrier::new();
        barrier.set_quiescing();
        assert!(!barrier.wait_quiesced(1, Duration::from_millis(100)));
        barrier.end_quiesce();
    }
}
