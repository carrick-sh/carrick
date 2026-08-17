//! Who can execute guest code: the population a stop-the-world barrier must
//! account for.
//!
//! Carrick raises a process-wide barrier before mutating shared guest state —
//! the stage-1 page-table Pause-Modify-Resume, and the fork transaction that
//! rewrites process topology. The question that decision rests on is
//!
//! > is any OTHER thread able to run guest instructions before my mutation
//! > completes?
//!
//! and that is a MEMBERSHIP question about vCPU loops. It is emphatically not
//! [`carrick_hal::VcpuRegistry::count`], which counts live vCPU LEASES. The two
//! populations diverge for exactly the threads that matter: a sibling parked in
//! a futex, an `epoll_wait`, or a blocking fd wait has already released its
//! lease and unregistered, so a two-thread process reads a lease count of 1 —
//! yet a host fd readying, an `EVFILT_TIMER`, a cross-process shared-futex wake
//! or the signal pump returns that sibling to guest without asking the mutator
//! for permission. Keying the RAISE decision on the lease count therefore left
//! the barrier down for precisely the thread that would go on to walk the
//! half-edited structure.
//!
//! The lease count remains the right question for the DRAIN that follows —
//! "has everyone stopped yet?" — and the drains keep using it. Only the raise
//! decision moves here.
//!
//! Membership is maintained by [`GuestExecutorParticipation`], an RAII guard
//! held for exactly the lifetime of one vCPU loop, in the same spirit as the
//! crash-capture quorum's participant flag: a thread published into the task
//! graph whose host loop was cancelled before it started, and a loop that has
//! already returned, are both outside the population. The guard carries the
//! crash-safe-point facet too, so the two cannot drift — they are one fact
//! ("this thread's vCPU loop is live") read by two subsystems.
//!
//! Residual window, stated plainly: participation begins when the vCPU loop
//! starts, not when `clone` publishes the thread into the task graph. A thread
//! between publication and loop start is not yet counted. It also cannot yet
//! execute guest code, and the fork lane separately closes clone admission
//! (`close_for_fork`) before it quiesces, but the page-table lane has no such
//! closure. That window is unchanged from the lease-count predicate this
//! replaces and is not addressed here.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::objects::ThreadRef;

/// Live vCPU loops for one Linux process — the threads that can execute guest
/// code on its behalf.
///
/// Scope is one Linux process because that is the scope of the vCPU registry it
/// replaces: an HVPatch fork child receives a fresh kicker
/// (`ThreadedEngine::fresh_fork_kicker`) alongside its own `KernelState`, and a
/// legacy `libc::fork` child gets both by copying the parent's process. Threads
/// of one thread group share both.
#[derive(Debug, Default)]
pub struct GuestExecutorCensus {
    live: AtomicUsize,
}

impl GuestExecutorCensus {
    /// Join the population for as long as the returned guard lives. Call this
    /// once at the top of a vCPU loop, before the thread registers a vCPU.
    ///
    /// `thread` is the same thread's Kernel object when the lane has one
    /// (HVPatch); passing it makes this guard carry the crash-safe-point facet
    /// as well, so a loop can never be a member of one population and not the
    /// other.
    pub(crate) fn enter(self: &Arc<Self>, thread: Option<ThreadRef>) -> GuestExecutorParticipation {
        self.live.fetch_add(1, Ordering::SeqCst);
        if let Some(thread) = thread.as_ref() {
            thread.enter_crash_safe_point_participation();
        }
        GuestExecutorParticipation {
            census: Arc::clone(self),
            thread,
        }
    }

    /// How many vCPU loops are live for this Linux process.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Must a stop-the-world barrier be raised before mutating shared guest
    /// state?
    ///
    /// Call ONLY from a thread that itself holds a
    /// [`GuestExecutorParticipation`] — every vCPU loop does — since the
    /// caller counts itself.
    pub fn has_peer_executor(&self) -> bool {
        self.live() > 1
    }

    /// `libc::fork` CHILD-side reset. The parent's other vCPU loops do not
    /// exist in the child (only the calling thread is replicated) and nothing
    /// in the child would ever decrement them, so an inherited count would keep
    /// the child raising barriers for threads that cannot run — and, worse,
    /// hand its drains a population they can never satisfy. Call from the child
    /// arm beside the futex/kicker/barrier resets.
    pub(crate) fn reset_for_forked_child(&self) {
        self.live.store(1, Ordering::SeqCst);
    }
}

/// Membership in a [`GuestExecutorCensus`], held for exactly one vCPU loop.
///
/// Released on every exit path — normal return, error, unwind — because that is
/// the whole point: an abandoned membership makes a mutator raise a barrier
/// forever for a thread that will never park, and makes a crash quorum wait out
/// its deadline on a thread that can never answer.
pub struct GuestExecutorParticipation {
    census: Arc<GuestExecutorCensus>,
    thread: Option<ThreadRef>,
}

impl Drop for GuestExecutorParticipation {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.as_ref() {
            thread.leave_crash_safe_point_participation();
        }
        self.census.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sole_executor_needs_no_barrier() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _only = census.enter(None);
        assert_eq!(census.live(), 1);
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn a_peer_that_released_its_vcpu_lease_still_counts() {
        // The whole defect: the peer here is the parked sibling. It holds no
        // vCPU lease and is absent from the kicker, but its loop is live and it
        // can be woken back into guest at any moment.
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None);
        let parked_sibling = census.enter(None);
        assert_eq!(census.live(), 2);
        assert!(census.has_peer_executor());
        drop(parked_sibling);
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn membership_ends_on_unwind() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None);
        let result = std::panic::catch_unwind({
            let census = Arc::clone(&census);
            move || {
                let _doomed = census.enter(None);
                assert!(census.has_peer_executor());
                panic!("vCPU loop unwound");
            }
        });
        assert!(result.is_err());
        assert!(
            !census.has_peer_executor(),
            "an unwound loop must leave the population"
        );
    }

    #[test]
    fn a_forked_child_starts_from_its_own_thread_alone() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _forker = census.enter(None);
        let _sibling = census.enter(None);
        // Post-fork, the child's copy still reads the parent's siblings.
        assert_eq!(census.live(), 2);
        census.reset_for_forked_child();
        assert_eq!(census.live(), 1);
        assert!(!census.has_peer_executor());
    }
}
