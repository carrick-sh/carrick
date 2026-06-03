//! Stop-the-world barriers for mutating shared guest/VM state while sibling
//! vCPU threads run.
//!
//! THEORY OF OPERATION
//!
//! `fork(2)` and guest page-table edits share one hard problem: a single host
//! thread must mutate state that every other guest vCPU thread can observe, and
//! POSIX `fork` only carries the calling thread into the child. This module
//! provides two distinct Pause-Modify-Resume barriers for the two cases. The
//! shared mechanic: the acting thread raises a `quiescing` flag, every OTHER
//! thread checks it at a LOCK-SAFE point at the top of its run loop and parks,
//! the acting thread waits until the others have parked (or left guest), does
//! its mutation, then lowers the flag and releases them. Blocking waits
//! ([`crate::thread`] futex, [`crate::io_wait`]) OR [`is_quiescing`] into their
//! wake predicate so a parked thread returns (a spurious EINTR) and reaches the
//! run-loop-top barrier rather than re-parking and missing the quiesce.
//!
//! The two barriers differ in WHAT they do to siblings:
//!
//!   * [`QuiesceBarrier`] (fork): the child must inherit NO carrick lock held by
//!     a thread that won't exist in it, and NO HVF VM topology mid-mutation. So
//!     siblings fully quiesce (release their vCPUs) before `libc::fork`, and the
//!     VM is torn down and rebuilt around the fork. The count it waits on comes
//!     from the [`crate::vcpu_kick`] kicker's LIVE-vCPU count, NOT the thread
//!     registry: a thread that has a tid but hasn't built its vCPU yet must not
//!     be awaited (it would never reach the barrier). `try_begin_fork`
//!     serializes forks via a CAS flag (not a held guard) so the flag survives
//!     `libc::fork` cleanly and the child clears it. [`topology_lock`] separately
//!     serializes a sibling building its vCPU against a fork destroying the VM,
//!     so a vCPU is never created in the `hv_vm_destroy` window (which would be
//!     HV_BUSY) — and a being-born thread holding it is NOT yet kicker-registered,
//!     so the fork's quiesce never waits on it: no deadlock.
//!
//!   * [`PtQuiesce`] (page-table edits): carrick edits the guest's stage-1 tables
//!     from the HOST while sibling vCPUs run (`mprotect`/`PROT_NONE`/`munmap`); a
//!     sibling walking a block mid-structural-change can fault. Here siblings
//!     KEEP their vCPUs and merely park out-of-guest. The editor waits until no
//!     sibling is in-guest — tracked by the kicker's per-vCPU `in_guest` flags,
//!     not a count — then edits, then resumes. [`PtQuiesce::pause_guard`] mints an
//!     RAII guard so the resume fires on every exit path of the editing syscall,
//!     including `?`-propagated errors.
//!
//! See docs/archive/superpowers/specs/2026-05-24-multithreaded-fork-design.md.
// INVARIANT: every `.unwrap()` in this module is on a std::sync Mutex/Condvar
// guard. `lock()`/`wait()` only return `Err` on poisoning — a thread panicking
// while holding the guard — which cannot occur in this no-panic codebase. The
// allow is module-scoped because every lock site shares the identical
// invariant; a per-line allow would be pure noise.
#![allow(clippy::unwrap_used)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Process-wide barrier (one HVF VM per process). Reachable from the run loop,
/// `handle_fork`, AND the blocking-wait predicates (futex / io_wait) so a parked
/// thread returns to its run-loop top when a quiesce begins.
pub fn barrier() -> &'static QuiesceBarrier {
    static B: OnceLock<QuiesceBarrier> = OnceLock::new();
    B.get_or_init(QuiesceBarrier::new)
}

/// True while a fork quiesce is in progress. Blocking waits OR this into their
/// wake predicate so they return (spurious EINTR) and reach the run-loop-top
/// barrier instead of re-parking.
pub fn is_quiescing() -> bool {
    barrier().is_quiescing()
}

/// Serializes HVF VM-topology mutations: a sibling thread building its vCPU vs.
/// a fork tearing the VM down and rebuilding it. Both hold this for the
/// duration of their critical section, so a vCPU can never be created in the
/// window where the forker calls `hv_vm_destroy` (which would be HV_BUSY), and
/// a thread born during a fork waits and then builds in the *rebuilt* VM. A
/// being-born thread holding this lock is NOT yet in the vCPU kicker, so the
/// fork's quiesce (which waits only on kicker-registered vCPUs) never waits on
/// it — no deadlock.
pub fn topology_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

#[derive(Debug)]
pub struct QuiesceBarrier {
    quiescing: AtomicBool,
    forking: AtomicBool,
    paused: Mutex<usize>,
    cv: Condvar,
}

impl Default for QuiesceBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl QuiesceBarrier {
    pub fn new() -> Self {
        Self {
            quiescing: AtomicBool::new(false),
            forking: AtomicBool::new(false),
            paused: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// Serialize forks: at most one quiesce/fork at a time. Returns false if
    /// another fork is in progress (caller returns EAGAIN; the guest retries,
    /// and meanwhile this thread parks at the barrier the other fork raised).
    /// CAS-based (not a held guard) so the flag survives `libc::fork` cleanly —
    /// the child clears it via `end_fork`.
    pub fn try_begin_fork(&self) -> bool {
        self.forking
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the fork serialization (every handle_fork exit path).
    pub fn end_fork(&self) {
        self.forking.store(false, Ordering::SeqCst);
    }

    /// Step 1 (forking thread): raise the quiesce flag. The caller then wakes
    /// the other threads (kick in-guest vCPUs + notify blocked waiters) and
    /// calls `wait_quiesced`. Split from the wait so the wakes happen between —
    /// a thread woken by the kick/notify must observe `is_quiescing()==true` at
    /// the run-loop top, so the flag MUST be raised before the wakes.
    pub fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// Step 2 (forking thread): wait until `others` threads have parked at the
    /// barrier, or `timeout`. Returns false on timeout (caller aborts the fork
    /// with EAGAIN and calls `end_quiesce`).
    pub fn wait_quiesced(&self, others: usize, timeout: Duration) -> bool {
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
    pub fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Number of threads currently parked at the barrier (diagnostic).
    pub fn paused_count(&self) -> usize {
        *self.paused.lock().unwrap()
    }

    /// Called by every OTHER thread at the lock-safe run-loop top. If a quiesce
    /// is in progress, register as paused and block until it ends.
    pub fn park_if_quiescing(&self) {
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
    pub fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
        let _g = self.paused.lock().unwrap();
        self.cv.notify_all();
    }
}

/// Process-wide Pause-Modify-Resume barrier for runtime guest stage-1
/// page-table edits (mprotect / PROT_NONE / munmap). Carrick (the VMM) edits
/// the guest's stage-1 tables from the HOST while sibling vCPUs run; a sibling
/// walking a block mid-structural-change can fault. The editing thread becomes
/// the sole coordinator, raises `quiescing` so every OTHER vCPU parks (KEEPING
/// its vCPU) at its run-loop top before re-entering guest, waits until no
/// sibling is in-guest (via the kicker's in_guest flags — not a count), edits,
/// then resumes. Distinct from fork's quiesce (which tears vCPUs down).
pub fn pt_barrier() -> &'static PtQuiesce {
    static B: OnceLock<PtQuiesce> = OnceLock::new();
    B.get_or_init(PtQuiesce::new)
}

#[derive(Debug)]
pub struct PtQuiesce {
    coordinator: AtomicBool,
    quiescing: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Default for PtQuiesce {
    fn default() -> Self {
        Self::new()
    }
}

impl PtQuiesce {
    pub fn new() -> Self {
        Self {
            coordinator: AtomicBool::new(false),
            quiescing: AtomicBool::new(false),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    pub fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Try to become the sole pausing editor (loser parks + retries).
    pub fn try_become_coordinator(&self) -> bool {
        self.coordinator
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// OTHER thread (or a coordinator-CAS loser) parks here until the pause
    /// ends, keeping its vCPU. Called at the lock-safe run-loop top.
    pub fn park(&self) {
        let mut g = self.lock.lock().unwrap();
        while self.quiescing.load(Ordering::SeqCst) {
            g = self.cv.wait(g).unwrap();
        }
    }

    /// Coordinator: end the pause, wake parked threads, drop coordinator.
    pub fn end(&self) {
        let _g = self.lock.lock().unwrap();
        self.quiescing.store(false, Ordering::SeqCst);
        self.coordinator.store(false, Ordering::SeqCst);
        self.cv.notify_all();
    }

    /// Mint the RAII resume-guard. The caller MUST already be the coordinator
    /// (won `try_become_coordinator`), have raised `set_quiescing`, and waited
    /// for siblings to leave guest. Dropping the guard calls `end`, so the pause
    /// is released on EVERY exit path of the editing syscall (incl. `?`-errors).
    /// `tid` is the editor, recorded so the drop can fire `pt-pause-end`.
    pub fn pause_guard(&'static self, tid: i32) -> PtPauseGuard {
        PtPauseGuard { barrier: self, tid }
    }
}

/// RAII handle that ends a page-table-edit pause (resuming sibling vCPUs) when
/// dropped. Held for the duration of the table-editing syscall.
pub struct PtPauseGuard {
    barrier: &'static PtQuiesce,
    tid: i32,
}

impl Drop for PtPauseGuard {
    fn drop(&mut self) {
        self.barrier.end();
        crate::probes::pt_pause_end(self.tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
