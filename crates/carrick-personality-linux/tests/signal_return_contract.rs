//! signal.return.no-result: sigreturn(2) restores context without a syscall result.
#![allow(clippy::unwrap_used)]
use carrick_guest_arch::UserVa;
use carrick_personality_linux::{lifecycle::UserCopy, signal::*};
use carrick_signal_core::{SignalSet, policy::SigBlockMask};

struct Native {
    accumulator: u64,
    invalid: bool,
    forced: bool,
    blocked: SigBlockMask,
}
impl UserCopy for Native {
    fn copy_in(&mut self, _: &mut [u8], _: UserVa) -> bool {
        false
    }
    fn copy_out(&mut self, _: UserVa, _: &[u8]) -> bool {
        false
    }
}
impl<'a> SignalNative<'a> for Native {
    fn arguments(&self) -> [u64; 6] {
        [0; 6]
    }
    fn process_signals(&mut self) -> Option<&mut dyn ProcessSignals> {
        None
    }
    fn current_blocked(&self) -> SigBlockMask {
        self.blocked
    }
    fn set_current_blocked(&mut self, mask: SigBlockMask) {
        self.blocked = mask;
    }
    fn current_pid(&self) -> u32 {
        1
    }
    fn current_tid(&self) -> u32 {
        1
    }
    fn force_sigsegv(&mut self) -> bool {
        self.forced = true;
        true
    }
    fn restore_signal_frame(
        &mut self,
    ) -> Result<carrick_signal_core::policy::SigBlockMask, carrick_syscall_abi::LinuxErrno> {
        if self.invalid {
            return Err(carrick_syscall_abi::LinuxErrno::new(14));
        }
        self.accumulator = 0x1234_5678;
        Ok(SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(1 << 9),
        ))
    }
}
#[test]
fn restored_context_has_no_syscall_result() {
    let mut native = Native {
        accumulator: 139,
        invalid: false,
        forced: false,
        blocked: SigBlockMask::blocking_all_of(SignalSet::default()),
    };
    let outcome = invoke(SignalCall::RtSigreturn, &mut native).unwrap();
    assert!(!matches!(outcome, SignalOutcome::Returned { .. }));
    assert_eq!(native.accumulator, 0x1234_5678);
    assert_eq!(native.blocked.signals().bits(), 1 << 9);
}

#[test]
fn restored_context_finishes_same_entry_and_retains_return_work() {
    use carrick_personality_linux::dispatch::{
        CompletionRoute, FamilyCompletion, completion_route,
    };
    assert_eq!(
        signal_effect(&SignalOutcome::Restored),
        FamilyCompletion::FrameRestored
    );
    assert_eq!(
        completion_route(FamilyCompletion::FrameRestored, false),
        CompletionRoute::Served
    );
    assert_eq!(
        completion_route(FamilyCompletion::FrameRestored, true),
        CompletionRoute::WithWork
    );
}

#[test]
fn invalid_signal_frame_is_not_an_errno_return() {
    let mut native = Native {
        accumulator: 139,
        invalid: true,
        forced: false,
        blocked: SigBlockMask::NONE,
    };
    let outcome = invoke(SignalCall::RtSigreturn, &mut native);
    assert_eq!(outcome, Some(SignalOutcome::Restored));
    assert!(native.forced);
}

#[test]
fn pidfd_send_signal_retains_host_owner() {
    let mut native = Native {
        accumulator: 434,
        invalid: false,
        forced: false,
        blocked: SigBlockMask::NONE,
    };
    assert_eq!(invoke(SignalCall::PidfdSendSignal, &mut native), None);
}

#[test]
fn signal_delivery_waits_for_the_owned_completion_ledger() {
    // Production WORK_PORT remains a dependency of the x86 in-zone fd-table
    // executor lane. This contract proves ledger ordering, not that carrier
    // handler's runtime implementation. See docs/design/in-ring-signals-status.md.
    use carrick_personality_linux::{
        abi::entry::{LinuxTaskState, ServedBoundary},
        dispatch::CompletionRoute,
    };
    let state = LinuxTaskState::new();
    assert!(signal_delivery_before_work(CompletionRoute::Served, &state));
    state.mark_pending_host_work();
    state.record_completed_with_work();
    assert!(!signal_delivery_before_work(
        CompletionRoute::WithWork,
        &state
    ));
    // Consuming the completed outcome does not complete its owed work.
    assert_eq!(
        state.take_served_boundary(),
        Some(ServedBoundary::Completed)
    );
    assert!(!signal_delivery_before_work(
        CompletionRoute::Served,
        &state
    ));
    state.clear_pending_host_work();
    assert!(signal_delivery_before_work(CompletionRoute::Served, &state));
    assert!(!signal_delivery_before_work(
        CompletionRoute::Forward,
        &state
    ));
}

#[test]
fn frame_masks_cross_as_blocked_domains() {
    fn frame_mask(params: carrick_guest_arch::SignalFrameParams) -> SigBlockMask {
        params.mask
    }
    fn restored_mask(native: &mut Native) -> Result<SigBlockMask, carrick_syscall_abi::LinuxErrno> {
        native.restore_signal_frame()
    }
    let mask = SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(1 << 9));
    let params = carrick_guest_arch::SignalFrameParams {
        stack: carrick_syscall_abi::LinuxSignalStack::empty(),
        signal: carrick_signal_core::policy::Signal::from_number(10).unwrap(),
        sigcode: 0,
        fault_addr: 0,
        sp: carrick_guest_arch::UserVa::new(0x4000),
        handler: carrick_guest_arch::UserVa::new(0x5000),
        restorer: Some(carrick_guest_arch::UserVa::new(0x6000)),
        mask,
    };
    let mut native = Native {
        accumulator: 15,
        invalid: false,
        forced: false,
        blocked: SigBlockMask::NONE,
    };
    assert_eq!(frame_mask(params), restored_mask(&mut native).unwrap());
}
