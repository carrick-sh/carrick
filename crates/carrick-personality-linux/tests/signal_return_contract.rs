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
    altstack: carrick_personality_linux::abi::thread::AltStack,
    arm_frame: Option<arm::RtSigframe>,
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
    fn set_current_altstack(&mut self, stack: carrick_personality_linux::abi::thread::AltStack) {
        self.altstack = stack;
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
    ) -> Result<RestoredSignalFrame, carrick_syscall_abi::LinuxErrno> {
        if let Some(frame) = &self.arm_frame {
            use zerocopy::IntoBytes;
            let resume = arm::decode(frame.as_bytes(), UserVa::new(0x40000), true)
                .map_err(|_| carrick_syscall_abi::LinuxErrno::new(14))?;
            self.accumulator = resume.regs[0];
            let stack = restored_altstack(resume.stack, carrick_guest_arch::GuestIsa::Aarch64)
                .ok_or(carrick_syscall_abi::LinuxErrno::new(14))?;
            return Ok(RestoredSignalFrame {
                mask: resume.mask,
                stack,
            });
        }
        if self.invalid {
            return Err(carrick_syscall_abi::LinuxErrno::new(14));
        }
        self.accumulator = 0x1234_5678;
        Ok(RestoredSignalFrame {
            mask: SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(1 << 9)),
            stack: self.altstack,
        })
    }
}
#[test]
fn restored_context_has_no_syscall_result() {
    let mut native = Native {
        accumulator: 139,
        invalid: false,
        forced: false,
        blocked: SigBlockMask::blocking_all_of(SignalSet::default()),
        altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
        arm_frame: None,
    };
    let outcome = invoke(SignalCall::RtSigreturn, &mut native).unwrap();
    assert!(!matches!(outcome, SignalOutcome::Returned { .. }));
    assert_eq!(native.accumulator, 0x1234_5678);
    assert_eq!(native.blocked.signals().bits(), 1 << 9);
}

#[test]
fn sigreturn_restores_saved_autodisarm_stack_after_handler() {
    use carrick_syscall_abi::{
        LinuxFpsimdContext, LinuxSiginfo, LinuxSignalContext, LinuxSignalStack,
    };
    let mut context = LinuxSignalContext::empty();
    context.pc = 0x10000;
    context.sp = 0x20000;
    let stack = LinuxSignalStack {
        ss_sp: 0x10_0000,
        ss_flags: carrick_syscall_abi::LINUX_SS_AUTODISARM as i32,
        _pad0: 0,
        ss_size: 8192,
    };
    let mut frame = arm::SignalFrame {
        rt: arm::RtSigframe {
            siginfo: LinuxSiginfo::empty(),
            ucontext: carrick_syscall_abi::LinuxUcontext {
                uc_mcontext: context,
                uc_stack: stack,
                uc_sigmask: SigBlockMask::NONE.signals().bits(),
                ..carrick_syscall_abi::LinuxUcontext::empty()
            },
        },
        frame_record: [0; 2],
    };
    arm::encode(&mut frame, Some(&LinuxFpsimdContext::empty()), None).unwrap();
    let frame = frame.rt;
    let mut native = Native {
        accumulator: 139,
        invalid: false,
        forced: false,
        blocked: SigBlockMask::NONE,
        altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
        arm_frame: Some(frame),
    };
    assert_eq!(
        invoke(SignalCall::RtSigreturn, &mut native),
        Some(SignalOutcome::Restored)
    );
    let expected_sp = stack.ss_sp;
    let expected_size = stack.ss_size;
    assert_eq!(native.altstack.sp, expected_sp);
    assert_eq!(native.altstack.size, expected_size);
    assert_eq!(
        native.altstack.flags,
        carrick_syscall_abi::LINUX_SS_AUTODISARM as u32
    );
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
        altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
        arm_frame: None,
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
        altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
        arm_frame: None,
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
    if let Some(doorbell) = state.take_host_work_doorbell() {
        doorbell.settled();
    }
    assert!(signal_delivery_before_work(CompletionRoute::Served, &state));
    assert!(!signal_delivery_before_work(
        CompletionRoute::Forward,
        &state
    ));
}

#[test]
fn frame_masks_cross_as_blocked_domains() {
    fn frame_mask(params: carrick_personality_linux::signal::SignalFrameParams) -> SigBlockMask {
        params.mask
    }
    fn restored_mask(native: &mut Native) -> Result<SigBlockMask, carrick_syscall_abi::LinuxErrno> {
        Ok(native.restore_signal_frame()?.mask)
    }
    let mask = SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(1 << 9));
    let params = carrick_personality_linux::signal::SignalFrameParams {
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
        altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
        arm_frame: None,
    };
    assert_eq!(frame_mask(params), restored_mask(&mut native).unwrap());
}

#[test]
fn public_arm_frame_preserves_same_entry_completion() {
    use carrick_personality_linux::dispatch::{
        CompletionRoute, FamilyCompletion, completion_route,
    };
    use carrick_syscall_abi::{
        LinuxFpsimdContext, LinuxSiginfo, LinuxSignalContext, LinuxSignalStack,
    };
    let mut context = LinuxSignalContext::empty();
    context.regs[0] = 0x1234_5678;
    context.pc = 0x10000;
    context.sp = 0x20000;
    let mask = SigBlockMask::blocking_all_of(SignalSet::from_bits(1 << 9));
    let mut frame = arm::SignalFrame {
        rt: arm::RtSigframe {
            siginfo: LinuxSiginfo::empty(),
            ucontext: carrick_syscall_abi::LinuxUcontext {
                uc_mcontext: context,
                uc_stack: LinuxSignalStack::empty(),
                uc_sigmask: mask.signals().bits(),
                ..carrick_syscall_abi::LinuxUcontext::empty()
            },
        },
        frame_record: [0; 2],
    };
    arm::encode(&mut frame, Some(&LinuxFpsimdContext::empty()), None).unwrap();
    let frame = frame.rt;
    for malformed in [false, true] {
        let mut public = frame;
        if malformed {
            public
                .ucontext
                .uc_mcontext
                .__reserved
                .copy_within(0..528, 528);
        }
        let mut native = Native {
            accumulator: 139,
            invalid: false,
            forced: false,
            blocked: SigBlockMask::NONE,
            altstack: carrick_personality_linux::abi::thread::AltStack::DISABLED,
            arm_frame: Some(public),
        };
        let outcome = invoke(SignalCall::RtSigreturn, &mut native).unwrap();
        assert_eq!(outcome, SignalOutcome::Restored);
        assert_eq!(native.forced, malformed);
        assert_eq!(
            native.accumulator,
            if malformed { 139 } else { 0x1234_5678 }
        );
        assert_eq!(
            native.blocked,
            if malformed { SigBlockMask::NONE } else { mask }
        );
        assert_eq!(signal_effect(&outcome), FamilyCompletion::FrameRestored);
        assert_eq!(
            completion_route(signal_effect(&outcome), true),
            CompletionRoute::WithWork
        );
    }
}
