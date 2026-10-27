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
    // Each retry follows a sibling edit that completed after the sample.
    loop {
        match venue.delegated() {
            DelegatedStep::PreparedConflict => {
                return venue.park_prepared().unwrap_or(FamilyCompletion::Handback);
            }
            DelegatedStep::Served(result) => {
                record_original(venue, original);
                return FamilyCompletion::Complete(result.raw());
            }
            DelegatedStep::Contended(Some(wait)) => match venue.park_contended(wait) {
                ContendedPark::Parked(completion) => return completion,
                ContendedPark::Retry => continue,
                ContendedPark::Unsupported => return FamilyCompletion::Forward,
            },
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
