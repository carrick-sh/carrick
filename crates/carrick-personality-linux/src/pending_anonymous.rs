//! Anonymous-family entry ordering; order 7 retains the native MM operation hooks.
use crate::abi::entry::{LinuxTaskState, SyscallResult};
use crate::dispatch::{AnonymousCall, FamilyCompletion};
use carrick_sched_core::spaces::notification::SpaceWaitCause;

pub enum DelegatedStep {
    NotDelegated,
    Contended(SpaceWaitCause),
    Served(SyscallResult),
    Forward,
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
    fn park_contended(&mut self, cause: SpaceWaitCause) -> Option<FamilyCompletion> {
        if cause == SpaceWaitCause::PreparedOverlap {
            self.park_prepared()
        } else {
            None
        }
    }
    fn permission(&mut self) -> PermissionStep;
    fn retirement(&mut self) -> RetirementStep;
    fn install_result(&mut self, result: SyscallResult);
    fn take_x86_handoff_receipt(
        &mut self,
    ) -> Option<carrick_core_abi::EntryHandoffReceipt<carrick_sched_core::ParkedContextWords>> {
        None
    }
}

/// Delegated ownership wins; only its explicit NotDelegated allows the legacy
/// permission/retirement hooks. A raced prepared edit enrolls once and hands off.
pub fn serve(
    call: AnonymousCall,
    venue: &mut (impl PendingAnonymousVenue + ?Sized),
) -> FamilyCompletion {
    let original = venue.original_argument0();
    match venue.delegated() {
        DelegatedStep::Contended(cause) => {
            return venue
                .park_contended(cause)
                .unwrap_or(FamilyCompletion::Handback);
        }
        DelegatedStep::Served(result) => {
            record_original(venue, original);
            return FamilyCompletion::Complete(result.raw());
        }
        DelegatedStep::Forward => return FamilyCompletion::Forward,
        DelegatedStep::NotDelegated => {}
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
