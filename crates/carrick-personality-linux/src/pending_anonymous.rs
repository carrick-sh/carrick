//! Anonymous-family entry ordering; order 7 retains the native MM operation hooks.
use crate::abi::entry::{LinuxTaskState, SyscallResult};
use crate::dispatch::{AnonymousCall, FamilyCompletion};

pub enum DelegatedStep {
    NotDelegated,
    PreparedConflict,
    Served(SyscallResult),
    Forward,
    /// No effect occurred; a sibling edit held the MM's root or editor.
    /// `Some` is the caller's owner wait, sampled before the attempt, for a
    /// thread with no host venue; `None` forwards like [`Self::Forward`].
    Contended(Option<carrick_core_abi::PortalOwnerWait>),
}
/// How a contended native edit continued.
pub enum ContendedPark {
    /// The thread waits for its cause and then runs the same call again.
    Parked(FamilyCompletion),
    /// The cause already moved since the sample: attempt the call again.
    Retry,
    /// A signal or exit cancelled the wait: leave through the lifecycle
    /// checkpoint with this completion, never by retrying in the kernel.
    Interrupted(FamilyCompletion),
    /// This venue cannot wait: the call forwards.
    Unsupported,
}
pub enum PermissionStep {
    Forward,
    Return(SyscallResult),
    CommitOwed,
}
pub enum RetirementStep {
    Forward,
    Return(SyscallResult),
    Retired,
}

pub trait PendingAnonymousVenue {
    fn original_argument0(&self) -> u64;
    fn task_state(&self) -> Option<&LinuxTaskState>;
    fn delegated(&mut self) -> DelegatedStep;
    fn park_prepared(&mut self) -> Option<FamilyCompletion>;
    /// Wait on `wait` and replay the unchanged call (native members only).
    fn park_contended(&mut self, _wait: carrick_core_abi::PortalOwnerWait) -> ContendedPark {
        ContendedPark::Unsupported
    }
    /// Return the unchanged call to user mode to run again after the
    /// user-return checkpoint (signals, exit). Only a venue that parks
    /// contended calls ever reaches this.
    fn replay_at_checkpoint(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
    fn permission(&mut self) -> PermissionStep;
    fn retirement(&mut self) -> RetirementStep;
    fn install_result(&mut self, result: SyscallResult);
}

/// Delegated ownership wins; only its explicit NotDelegated allows the legacy
/// permission/retirement hooks. A raced prepared edit enrolls once and hands off.
pub fn serve(
    call: AnonymousCall,
    venue: &mut (impl PendingAnonymousVenue + ?Sized),
) -> FamilyCompletion {
    let original = venue.original_argument0();
    // One reselect per producer revision: a retry follows only a sibling
    // edit completed after the previous sample, so the loop is bounded by
    // completed edits; an unchanged revision parks or leaves.
    let mut previous: Option<carrick_core_abi::PortalOwnerWait> = None;
    loop {
        match venue.delegated() {
            DelegatedStep::PreparedConflict => {
                return venue.park_prepared().unwrap_or(FamilyCompletion::Handback);
            }
            DelegatedStep::Served(result) => {
                record_original(venue, original);
                return FamilyCompletion::Complete(result.raw());
            }
            DelegatedStep::Contended(Some(wait)) => {
                if previous.is_some_and(|last| {
                    last.cause() == wait.cause() && last.revision() >= wait.revision()
                }) {
                    // No producer moved since the last attempt: a retry
                    // would spin. Return through the checkpoint instead.
                    return venue.replay_at_checkpoint();
                }
                previous = Some(wait);
                match venue.park_contended(wait) {
                    ContendedPark::Parked(completion) | ContendedPark::Interrupted(completion) => {
                        return completion;
                    }
                    ContendedPark::Retry => continue,
                    ContendedPark::Unsupported => return FamilyCompletion::Forward,
                }
            }
            DelegatedStep::Forward | DelegatedStep::Contended(None) => {
                return FamilyCompletion::Forward;
            }
            DelegatedStep::NotDelegated => break,
        }
    }
    match call {
        AnonymousCall::Mprotect => match venue.permission() {
            PermissionStep::Forward => {}
            PermissionStep::Return(result) => {
                venue.install_result(result);
                return FamilyCompletion::Complete(result.raw());
            }
            PermissionStep::CommitOwed => {
                venue.install_result(SyscallResult::new(0));
                if record_original(venue, original) {
                    return FamilyCompletion::CommitOwed(0);
                }
                return FamilyCompletion::Complete(0);
            }
        },
        AnonymousCall::Munmap => match venue.retirement() {
            RetirementStep::Forward => {}
            RetirementStep::Return(result) => {
                venue.install_result(result);
                return FamilyCompletion::Complete(result.raw());
            }
            RetirementStep::Retired => {
                venue.install_result(SyscallResult::new(0));
                if record_original(venue, original) {
                    return FamilyCompletion::CommitOwed(0);
                }
            }
        },
        _ => {}
    }
    FamilyCompletion::Forward
}
fn record_original(venue: &(impl PendingAnonymousVenue + ?Sized), original: u64) -> bool {
    let Some(task) = venue.task_state() else {
        return false;
    };
    task.orig_arg0
        .store(original, core::sync::atomic::Ordering::Relaxed);
    true
}

#[cfg(test)]
mod tests {
    //! #856: the contended-edit loop is bounded by producer revisions and
    //! leaves through the checkpoint when cancelled.
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use carrick_core_abi::{El1MmHandle, PortalOwnerWait, PortalWaitCause, ReservationMm};
    use core::num::NonZeroU64;

    fn wait(revision: u64) -> PortalOwnerWait {
        // SAFETY: a fixture handle; no owner state is touched.
        unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    ReservationMm::new(4).unwrap(),
                    NonZeroU64::MIN,
                ),
                PortalWaitCause::Reservations,
                revision,
            )
        }
    }

    struct Venue {
        revisions: &'static [u64],
        park: fn(u64) -> ContendedPark,
        attempts: usize,
        replays: usize,
    }
    impl PendingAnonymousVenue for Venue {
        fn original_argument0(&self) -> u64 {
            0
        }
        fn task_state(&self) -> Option<&LinuxTaskState> {
            None
        }
        fn delegated(&mut self) -> DelegatedStep {
            let revision = self.revisions[self.attempts.min(self.revisions.len() - 1)];
            self.attempts += 1;
            assert!(self.attempts < 16, "the contended loop must not spin");
            DelegatedStep::Contended(Some(wait(revision)))
        }
        fn park_prepared(&mut self) -> Option<FamilyCompletion> {
            None
        }
        fn park_contended(&mut self, wait: PortalOwnerWait) -> ContendedPark {
            (self.park)(wait.revision())
        }
        fn replay_at_checkpoint(&mut self) -> FamilyCompletion {
            self.replays += 1;
            FamilyCompletion::FrameRestored
        }
        fn permission(&mut self) -> PermissionStep {
            PermissionStep::Forward
        }
        fn retirement(&mut self) -> RetirementStep {
            RetirementStep::Forward
        }
        fn install_result(&mut self, _: SyscallResult) {}
    }

    #[test]
    fn unchanged_revision_does_not_retry() {
        let mut venue = Venue {
            revisions: &[7],
            park: |_| ContendedPark::Retry,
            attempts: 0,
            replays: 0,
        };
        assert!(matches!(
            serve(AnonymousCall::Mprotect, &mut venue),
            FamilyCompletion::FrameRestored
        ));
        assert_eq!((venue.attempts, venue.replays), (2, 1));
    }

    #[test]
    fn moved_revisions_reselect_then_park() {
        let mut venue = Venue {
            revisions: &[7, 8, 9],
            park: |revision| {
                if revision < 9 {
                    ContendedPark::Retry
                } else {
                    ContendedPark::Parked(FamilyCompletion::Suspended)
                }
            },
            attempts: 0,
            replays: 0,
        };
        assert!(matches!(
            serve(AnonymousCall::Mmap, &mut venue),
            FamilyCompletion::Suspended
        ));
        assert_eq!((venue.attempts, venue.replays), (3, 0));
    }

    #[test]
    fn cancellation_leaves_through_the_checkpoint() {
        let mut venue = Venue {
            revisions: &[7],
            park: |_| ContendedPark::Interrupted(FamilyCompletion::FrameRestored),
            attempts: 0,
            replays: 0,
        };
        assert!(matches!(
            serve(AnonymousCall::Munmap, &mut venue),
            FamilyCompletion::FrameRestored
        ));
        assert_eq!(venue.attempts, 1);
    }
}
