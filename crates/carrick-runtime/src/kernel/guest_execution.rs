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
//! and that is a MEMBERSHIP question about active guest execution.
//!
//! [`GuestExecutorCensus`] tracks live guest executor participation for one
//! Linux process. When a thread suspends (for example on a futex, `epoll_wait`,
//! or host blocking wait), suspension drops its [`GuestExecutorParticipation`]
//! via `leave_executor`. Blocked logical loops do not remain in the census while
//! suspended.
//!
//! Upon waking and seeking initial admission or re-admission to execute guest
//! code, a thread enters [`GuestExecutorCensus`] before attempting vCPU
//! registration (`enter_guest_executor_then_register`). If a barrier or lease
//! drain freeze is active, registration admission is denied, and the thread
//! suspends again (dropping its participation). This ordering guarantees that
//! any peer thread attempting to enter guest execution is visible in the census
//! before its registration can be published.
//!
//! Stop-the-world barriers use [`GuestExecutorCensus::has_peer_executor`] to
//! decide whether to raise the barrier, while drain convergence uses
//! identity-aware vCPU lease drain polling and `any_other_in_guest`.
//!
//! Membership is maintained by [`GuestExecutorParticipation`], an RAII guard
//! held for the lifetime of active guest execution participation, in the same
//! spirit as the crash-capture quorum's participant flag: a thread published
//! into the task graph whose host loop was cancelled before it started, and a
//! thread that has suspended or returned, are both outside the population. The
//! guard carries the crash-safe-point facet too, so the two cannot drift — they
//! are one fact ("this thread actively participates in guest execution") read by
//! two subsystems.
//!
//! Residual window, stated plainly: participation begins when the vCPU loop
//! enters execution, not when `clone` publishes the thread into the task graph.
//! A thread between publication and loop start is not yet counted. It also cannot
//! yet execute guest code, and the fork lane separately closes clone admission
//! (`close_for_fork`) before it quiesces, but the page-table lane has no such
//! closure.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::objects::ThreadRef;

/// Live guest executors for one Linux process — the threads actively
/// participating in guest execution on its behalf.
///
/// Scope is one Linux process because that is the scope of the vCPU registry:
/// an HVPatch fork child receives a fresh kicker
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
    fn a_peer_that_releases_participation_leaves_the_census() {
        // When a peer suspends, it drops its participation and leaves the census.
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
}
