//! Who can execute guest code: the population a stage-1 page-table pause must
//! account for.
//!
//! Carrick coordinates mutations of shared guest state through distinct
//! authorities:
//! - Stage-1 page-table Pause-Modify-Resume uses [`GuestExecutorCensus`]
//!   (`has_peer_executor`) to decide whether to pause sibling execution.
//! - Process fork and crash snapshot raise their quiesce barriers from durable
//!   `Task::threads()` membership (`Task::threads().len().saturating_sub(1)`),
//!   not this census.
//!
//! A raised quiesce barrier parks admitted executors at the run-loop safe point,
//! but does not itself deny vCPU registration. Registration admission is
//! governed by the identity-aware vCPU registry lease freeze: only a non-owner
//! lease drain freeze denies registration; the exact freeze owner may
//! re-register through its own raised fork barrier.
//!
//! [`GuestExecutorCensus`] tracks live guest executor participation for one
//! Linux process. When a thread suspends (for example on a futex, `epoll_wait`,
//! or host blocking wait), suspension drops its [`GuestExecutorParticipation`]
//! via `leave_executor`. Blocked logical loops do not remain in the census while
//! suspended.
//!
//! Upon waking and seeking initial admission or re-admission to execute guest
//! code, a thread enters [`GuestExecutorCensus`] before attempting vCPU
//! registration (`enter_guest_executor_then_register`). If a lease drain freeze
//! is held by another owner, registration admission returns `Waiting`, and the
//! thread suspends again (dropping its participation). This ordering guarantees
//! that any peer thread attempting to enter guest execution is visible in the
//! census before its registration can be published.
//!
//! Membership is maintained by [`GuestExecutorParticipation`], an RAII guard
//! held for the lifetime of an admitted guest executor quantum, in the same
//! spirit as the crash-capture quorum's participant flag: a thread published
//! into the task graph whose host loop was cancelled before it started, and a
//! thread that has suspended or returned, are both outside the population. The
//! guard carries the crash-safe-point facet too, so the two cannot drift — they
//! are one fact ("this thread actively participates in guest execution") read by
//! two subsystems.
//!
//! Residual window, stated plainly: participation begins when an admitted
//! executor enters its execution quantum, not when `clone` publishes the thread
//! into the task graph. A thread between publication and execution entry is not
//! yet counted. It also cannot yet execute guest code, and the fork lane
//! separately closes clone admission (`close_for_fork`) before it quiesces, but
//! the page-table lane has no such closure.

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
    /// upon entering an admitted guest execution quantum, before the thread
    /// registers a vCPU.
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

    /// How many admitted guest executors are actively participating for this
    /// Linux process.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Must a stop-the-world page-table pause be raised before mutating shared
    /// stage-1 descriptors?
    ///
    /// Call ONLY from a thread that itself holds a
    /// [`GuestExecutorParticipation`] — every admitted guest executor does —
    /// since the caller counts itself.
    pub fn has_peer_executor(&self) -> bool {
        self.live() > 1
    }
}

/// Membership in a [`GuestExecutorCensus`], held for the duration of an
/// admitted guest executor quantum.
///
/// Released on every exit path — suspension, normal return, error, unwind —
/// because that is the whole point: an abandoned membership makes a page-table
/// mutator pause forever for a thread that will never park, and makes a crash
/// quorum wait out its deadline on a thread that can never answer.
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
                panic!("admitted executor quantum unwound");
            }
        });
        assert!(result.is_err());
        assert!(
            !census.has_peer_executor(),
            "an unwound executor must leave the population"
        );
    }
}
