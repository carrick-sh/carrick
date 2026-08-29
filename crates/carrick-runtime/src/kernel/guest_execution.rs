//! Who can execute guest code: the population a stage-1 page-table pause must
//! account for.
//!
//! Carrick coordinates mutations of shared guest state through distinct
//! authorities:
//! - Stage-1 page-table Pause-Modify-Resume uses [`GuestExecutorCensus`]
//!   (`has_peer_executor`) to decide whether to pause sibling execution.
//! - Process fork and crash snapshot raise their quiesce barriers from their
//!   distinct Task-minted durable-membership witnesses, not this census.
//!
//! A raised quiesce barrier parks admitted executors at the run-loop safe point,
//! but does not itself deny vCPU registration. Registration admission is
//! governed by the identity-aware vCPU registry lease freeze: only a non-owner
//! lease drain freeze denies registration; the exact freeze owner may
//! re-register through its own raised fork barrier.
//!
//! [`GuestExecutorCensus`] tracks live guest executor participation for one
//! exact dispatch MM. Distinct CLONE_VM dispatchers share the census through
//! their shared MM authority. When a thread suspends (for example on a futex,
//! `epoll_wait`, or host blocking wait), suspension drops its
//! [`GuestExecutorParticipation`] via `leave_executor`. Blocked logical loops do
//! not remain in the census while suspended.
//!
//! Upon waking and seeking initial admission or re-admission to execute guest
//! code, a thread enters [`GuestExecutorCensus`] before attempting vCPU
//! registration (`enter_mm_executor_then_register`). If a lease drain freeze is
//! held by another owner, registration admission returns `Waiting`, and the
//! thread suspends again (dropping its participation). This ordering guarantees
//! that any peer thread attempting to enter guest execution is visible in the
//! exact-MM census before its registration can be published.
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

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::Arc;

use parking_lot::{Mutex, MutexGuard};

use super::objects::{
    CrashSafePointParticipation, CrashSafePointParticipationError, ThreadKey, ThreadRef,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GuestExecutorIdentity {
    Thread(ThreadKey),
    Anonymous(NonZeroU64),
}

#[derive(Debug)]
struct GuestExecutorCensusState {
    participants: BTreeSet<GuestExecutorIdentity>,
    next_anonymous: u64,
}

impl Default for GuestExecutorCensusState {
    fn default() -> Self {
        Self {
            participants: BTreeSet::new(),
            next_anonymous: 1,
        }
    }
}

fn saturating_participant_count_for_probe(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestExecutorCensusError {
    #[error("thread {thread:?} is already admitted as a guest executor")]
    DuplicateThread { thread: ThreadKey },
    #[error("anonymous guest-executor identities are exhausted")]
    AnonymousIdentityExhausted,
    #[error("thread {thread:?} already owns crash safe-point participation")]
    CrashParticipationAlreadyActive { thread: ThreadKey },
    #[error("thread {thread:?} exhausted crash safe-point participation identities")]
    CrashParticipationIdentityExhausted { thread: ThreadKey },
}

/// Live guest executors for one exact dispatch MM.
///
/// The owning `DispatchMmAuthority` is shared by CLONE_VM dispatchers, so a
/// process boundary cannot conceal a peer that may walk the same stage-1
/// descriptors. Copied forks and exec replacements receive fresh authorities
/// and therefore fresh censuses.
#[derive(Debug, Default)]
pub struct GuestExecutorCensus {
    state: Mutex<GuestExecutorCensusState>,
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
    pub(crate) fn enter(
        self: &Arc<Self>,
        thread: Option<ThreadRef>,
    ) -> Result<GuestExecutorParticipation, GuestExecutorCensusError> {
        let mut state = self.state.lock();
        let identity = match thread.as_ref() {
            Some(thread) => GuestExecutorIdentity::Thread(thread.key()),
            None => {
                let id = NonZeroU64::new(state.next_anonymous)
                    .ok_or(GuestExecutorCensusError::AnonymousIdentityExhausted)?;
                state.next_anonymous = state.next_anonymous.checked_add(1).unwrap_or(0);
                GuestExecutorIdentity::Anonymous(id)
            }
        };
        if !state.participants.insert(identity) {
            return Err(match identity {
                GuestExecutorIdentity::Thread(thread) => {
                    GuestExecutorCensusError::DuplicateThread { thread }
                }
                GuestExecutorIdentity::Anonymous(_) => {
                    GuestExecutorCensusError::AnonymousIdentityExhausted
                }
            });
        }
        let crash_participation = match thread.as_ref() {
            Some(thread) => match thread.enter_crash_safe_point_participation() {
                Ok(participation) => Some(participation),
                Err(error) => {
                    let removed = state.participants.remove(&identity);
                    debug_assert!(removed);
                    return Err(match error {
                        CrashSafePointParticipationError::AlreadyActive { thread } => {
                            GuestExecutorCensusError::CrashParticipationAlreadyActive { thread }
                        }
                        CrashSafePointParticipationError::IdentityExhausted { thread } => {
                            GuestExecutorCensusError::CrashParticipationIdentityExhausted { thread }
                        }
                    });
                }
            },
            None => None,
        };
        drop(state);
        Ok(GuestExecutorParticipation {
            census: Arc::clone(self),
            identity,
            crash_participation,
        })
    }

    /// Must a stop-the-world page-table pause be raised before mutating shared
    /// stage-1 descriptors?
    ///
    /// Call ONLY from a thread that itself holds a
    /// [`GuestExecutorParticipation`] — every admitted guest executor does —
    /// since the caller counts itself.
    pub fn has_peer_executor(&self) -> bool {
        self.state.lock().participants.iter().nth(1).is_some()
    }

    /// Numeric projection solely for the fixed-width probe ABI.
    pub(crate) fn participant_count_for_probe(&self) -> i32 {
        saturating_participant_count_for_probe(self.state.lock().participants.len())
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
    identity: GuestExecutorIdentity,
    crash_participation: Option<CrashSafePointParticipation>,
}

/// Proof that one exact census contains only the borrowing participant.
///
/// The census mutex remains held for the proof's lifetime, so another executor
/// cannot enter after the sole-executor decision and race the protected work.
pub(crate) struct SoleGuestExecutor<'participant> {
    _state: MutexGuard<'participant, GuestExecutorCensusState>,
    _participant: std::marker::PhantomData<&'participant GuestExecutorParticipation>,
}

impl GuestExecutorParticipation {
    pub(crate) fn claim_sole(&self) -> Option<SoleGuestExecutor<'_>> {
        let state = self.census.state.lock();
        if state.participants.len() != 1 || !state.participants.contains(&self.identity) {
            return None;
        }
        Some(SoleGuestExecutor {
            _state: state,
            _participant: std::marker::PhantomData,
        })
    }
}

impl Drop for GuestExecutorParticipation {
    fn drop(&mut self) {
        drop(self.crash_participation.take());
        if !self.census.state.lock().participants.remove(&self.identity) {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::{Kernel, KernelContext, RootBootstrap};

    fn bootstrap_thread(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn duplicate_exact_thread_admission_is_rejected() {
        let (_kernel, context) = bootstrap_thread(19_500);
        let census = Arc::new(GuestExecutorCensus::default());
        let _first = census
            .enter(Some(context.thread().clone()))
            .expect("first exact participant");
        assert!(matches!(
            census.enter(Some(context.thread().clone())),
            Err(GuestExecutorCensusError::DuplicateThread { .. })
        ));
    }

    #[test]
    fn failed_crash_participation_unwinds_exact_census_identity() {
        let (_kernel, context) = bootstrap_thread(19_501);
        let thread = context.thread().clone();
        let _outside = thread
            .enter_crash_safe_point_participation()
            .expect("outside participation");
        let census = Arc::new(GuestExecutorCensus::default());

        assert!(matches!(
            census.enter(Some(thread.clone())),
            Err(GuestExecutorCensusError::CrashParticipationAlreadyActive {
                thread: rejected
            }) if rejected == thread.key()
        ));
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    fn dropping_one_exact_participant_preserves_the_other() {
        let census = Arc::new(GuestExecutorCensus::default());
        let first = census.enter(None).expect("first token");
        let second = census.enter(None).expect("second token");
        assert!(census.has_peer_executor());
        drop(second);
        assert!(!census.has_peer_executor());
        drop(first);
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    fn probe_participant_count_saturates_at_i32_max() {
        let max = usize::try_from(i32::MAX).expect("i32 max fits usize");
        assert_eq!(saturating_participant_count_for_probe(max), i32::MAX);
        assert_eq!(
            saturating_participant_count_for_probe(max.saturating_add(1)),
            i32::MAX
        );
    }

    #[test]
    fn anonymous_identity_exhaustion_never_reuses_the_final_token() {
        let census = Arc::new(GuestExecutorCensus::default());
        census.state.lock().next_anonymous = u64::MAX;

        let final_token = census.enter(None).expect("final nonzero token");
        assert!(matches!(
            census.enter(None),
            Err(GuestExecutorCensusError::AnonymousIdentityExhausted)
        ));
        drop(final_token);
        assert_eq!(census.participant_count_for_probe(), 0);
        assert!(matches!(
            census.enter(None),
            Err(GuestExecutorCensusError::AnonymousIdentityExhausted)
        ));
    }

    #[test]
    fn a_sole_executor_needs_no_barrier() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _only = census.enter(None).expect("sole token");
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn a_peer_that_releases_participation_leaves_the_census() {
        // When a peer suspends, it drops its participation and leaves the census.
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None).expect("mutator token");
        let parked_sibling = census.enter(None).expect("sibling token");
        assert!(census.has_peer_executor());
        drop(parked_sibling);
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn membership_ends_on_unwind() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None).expect("mutator token");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let census = Arc::clone(&census);
            move || {
                let _doomed = census.enter(None).expect("doomed token");
                assert!(census.has_peer_executor());
                panic!("admitted executor quantum unwound");
            }
        }));
        assert!(result.is_err());
        assert!(
            !census.has_peer_executor(),
            "an unwound executor must leave the population"
        );
    }
}
