//! sigaction(2): queries of uncatchable signals, negative errno, atomic exchange.
use carrick_guest_arch::UserVa;
use carrick_personality_linux::{lifecycle::UserCopy, signal::*};
use carrick_signal_core::{
    SignalSet,
    policy::{Action, SigBlockMask},
};

struct Native {
    args: [u64; 6],
    calls: usize,
    fail: bool,
}
impl UserCopy for Native {
    fn copy_in(&mut self, bytes: &mut [u8], _: UserVa) -> bool {
        bytes.fill(0);
        if bytes.len() == core::mem::size_of::<carrick_syscall_abi::LinuxSiginfo>() {
            let info = carrick_syscall_abi::LinuxSiginfo::kill(10, -1, 1, 0);
            bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&info));
        }
        true
    }
    fn copy_out(&mut self, _: UserVa, _: &[u8]) -> bool {
        true
    }
}
impl<'a> SignalNative<'a> for Native {
    fn arguments(&self) -> [u64; 6] {
        self.args
    }
    fn process_signals(&mut self) -> Option<&mut dyn ProcessSignals> {
        Some(self)
    }
    fn current_blocked(&self) -> SigBlockMask {
        SigBlockMask::NONE
    }
    fn set_current_blocked(&mut self, _: SigBlockMask) {}
    fn current_pid(&self) -> u32 {
        1
    }
    fn current_tid(&self) -> u32 {
        1
    }
    fn restore_signal_frame(
        &mut self,
    ) -> Result<carrick_signal_core::policy::SigBlockMask, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(14))
    }
}
impl ProcessSignals for Native {
    fn take_deliverable(
        &mut self,
        blocked: SigBlockMask,
    ) -> Option<(
        carrick_signal_core::policy::Signal,
        Option<carrick_personality_linux::abi::signal::LinuxSiginfo>,
        Action,
    )> {
        self.calls += 1;
        let signal = carrick_signal_core::policy::Signal::from_number(10)?;
        (!blocked.signals().contains(signal)).then_some((signal, None, Action::default()))
    }
    fn force_sigsegv(&mut self, _: SigBlockMask) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
    fn rt_sigaction(
        &mut self,
        _: carrick_signal_core::policy::Signal,
        _: Option<Action>,
    ) -> Result<Action, carrick_syscall_abi::LinuxErrno> {
        self.calls += 1;
        if self.fail {
            Err(carrick_syscall_abi::LinuxErrno::new(13))
        } else {
            Ok(Action::default())
        }
    }
    fn rt_sigpending(&self, _: SigBlockMask) -> u64 {
        0
    }
    fn kill(
        &mut self,
        _: SignalProcessSelector,
        _: SignalRequest,
        _: SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
    fn tkill(
        &mut self,
        _: SignalThreadSelector,
        _: SignalRequest,
        _: SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
    fn tgkill(
        &mut self,
        _: SignalThreadSelector,
        _: SignalThreadSelector,
        _: SignalRequest,
        _: SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
    fn rt_sigtimedwait(
        &mut self,
        _: SignalSet,
        _: Option<u64>,
        _: UserVa,
    ) -> Result<SignalWaitOutcome, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
    fn rt_sigsuspend(
        &mut self,
        _: SigBlockMask,
        _: SigBlockMask,
    ) -> Result<bool, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(22))
    }
}
fn result(outcome: Option<SignalOutcome>) -> Option<i64> {
    match outcome {
        Some(SignalOutcome::Returned { result, .. }) => Some(result.raw()),
        _ => None,
    }
}
#[test]
fn querying_kill_and_stop_succeeds() {
    for sig in [9, 19] {
        let mut native = Native {
            args: [sig, 0, 1, 8, 0, 0],
            calls: 0,
            fail: false,
        };
        assert_eq!(
            result(invoke(SignalCall::RtSigaction, &mut native)),
            Some(0)
        );
        assert_eq!(native.calls, 1);
    }
}
#[test]
fn old_and_new_action_use_one_owner_exchange() {
    let mut native = Native {
        args: [10, 1, 2, 8, 0, 0],
        calls: 0,
        fail: false,
    };
    assert_eq!(
        result(invoke(SignalCall::RtSigaction, &mut native)),
        Some(0)
    );
    assert_eq!(native.calls, 1);
}
#[test]
fn owner_errno_is_negative() {
    let mut native = Native {
        args: [10, 1, 2, 8, 0, 0],
        calls: 0,
        fail: true,
    };
    assert_eq!(
        result(invoke(SignalCall::RtSigaction, &mut native)),
        Some(-13)
    );
}

#[test]
fn signal_owner_errno_has_positive_typed_domain() {
    let mut native = Native {
        args: [0; 6],
        calls: 0,
        fail: true,
    };
    let result: Result<Action, carrick_syscall_abi::LinuxErrno> = native.rt_sigaction(
        carrick_signal_core::policy::Signal::from_number(10).unwrap(),
        None,
    );
    assert_eq!(result.unwrap_err().guest_retval(), -13);
}

#[test]
fn signal_owner_admits_validated_requests_and_selectors() {
    use carrick_personality_linux::signal::{SignalProcessSelector, SignalRequest};
    let mut native = Native {
        args: [0; 6],
        calls: 0,
        fail: false,
    };
    let result = native.kill(
        SignalProcessSelector::from_abi(1),
        SignalRequest::Probe,
        SignalInfo::Generated(None),
    );
    assert_eq!(result.unwrap_err().get(), 22);
    let restored: Result<
        carrick_signal_core::policy::SigBlockMask,
        carrick_syscall_abi::LinuxErrno,
    > = native.restore_signal_frame();
    assert_eq!(restored.unwrap_err().get(), 14);
}

#[test]
fn queued_siginfo_carries_the_admitted_signal_number() {
    let signal = carrick_signal_core::policy::Signal::from_number(10).unwrap();
    let payload = SignalInfo::Queued(carrick_syscall_abi::LinuxSiginfo::kill(64, -1, 1, 0))
        .payload(signal)
        .unwrap();
    let number = payload.si_signo;
    assert_eq!(number, 10);
}

#[test]
fn suspend_restore_rechecks_delivery_at_the_same_user_return() {
    let mut native = Native {
        args: [0; 6],
        calls: 0,
        fail: false,
    };
    let usr1 = carrick_signal_core::policy::Signal::from_number(10).unwrap();
    let temporary = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(usr1));
    let mut selected_mask = temporary;
    assert_eq!(
        native
            .take_deliverable_after_suspend(&mut selected_mask, SigBlockMask::NONE)
            .unwrap()
            .0,
        usr1
    );
    assert_eq!(
        selected_mask,
        SigBlockMask::NONE,
        "handler mask uses the restored selection mask"
    );
    assert_eq!(native.calls, 2);
    native.calls = 0;
    selected_mask = SigBlockMask::NONE;
    assert!(
        native
            .take_deliverable_after_suspend(&mut selected_mask, temporary)
            .is_some()
    );
    assert_eq!(
        native.calls, 1,
        "one checkpoint selects at most one handler"
    );
    native.calls = 0;
    selected_mask = temporary;
    assert!(
        native
            .take_deliverable_after_suspend(&mut selected_mask, temporary)
            .is_none()
    );
    assert_eq!(native.calls, 1, "unchanged masks need no second pass");
}

#[test]
fn invalid_signal_requests_are_served_without_owner_fallback() {
    for number in [0, 65, u64::MAX, i32::MIN as u64] {
        for (call, args) in [
            (SignalCall::RtSigaction, [number, 0, 0, 8, 0, 0]),
            (SignalCall::Kill, [1, number, 0, 0, 0, 0]),
            (SignalCall::Tkill, [1, number, 0, 0, 0, 0]),
            (SignalCall::Tgkill, [1, 1, number, 0, 0, 0]),
            (SignalCall::RtSigqueueinfo, [1, number, 1, 0, 0, 0]),
            (SignalCall::RtTgsigqueueinfo, [1, 1, number, 1, 0, 0]),
        ] {
            // Signal zero is an existence probe for send calls, not sigaction.
            if number == 0 && call != SignalCall::RtSigaction {
                continue;
            }
            let mut native = Native {
                args,
                calls: 0,
                fail: false,
            };
            assert_eq!(
                result(invoke(call, &mut native)),
                Some(-22),
                "{call:?}: {number}"
            );
            assert_eq!(native.calls, 0, "invalid input must not enter the owner");
        }
    }
}

#[test]
fn installing_kill_and_stop_is_served_einval() {
    for number in [9, 19] {
        let mut native = Native {
            args: [number, 1, 0, 8, 0, 0],
            calls: 0,
            fail: false,
        };
        assert_eq!(
            result(invoke(SignalCall::RtSigaction, &mut native)),
            Some(-22)
        );
        assert_eq!(native.calls, 0);
    }
}

#[test]
fn malformed_signal_sizes_and_thread_groups_are_served_einval() {
    for (call, args) in [
        (SignalCall::RtSigaction, [10, 0, 0, 0, 0, 0]),
        (SignalCall::RtSigpending, [1, 0, 0, 0, 0, 0]),
        (SignalCall::RtSigsuspend, [1, 0, 0, 0, 0, 0]),
        (SignalCall::RtSigtimedwait, [1, 0, 0, 0, 0, 0]),
        (SignalCall::Tgkill, [0, 1, 10, 0, 0, 0]),
        (SignalCall::RtTgsigqueueinfo, [u64::MAX, 1, 10, 1, 0, 0]),
    ] {
        let mut native = Native {
            args,
            calls: 0,
            fail: false,
        };
        assert_eq!(result(invoke(call, &mut native)), Some(-22), "{call:?}");
        assert_eq!(native.calls, 0);
    }
}

#[test]
fn nonpositive_queue_targets_match_native_esrch() {
    // Native Linux SYS_rt_sigqueueinfo, valid SI_QUEUE, timeout 10:
    // PID 0/-1/INT_MIN with signal 0 => ESRCH (3); PID 0 with SIGUSR1
    // also => ESRCH. A self-targeted signal-0 control succeeds.
    for pid in [0, u64::MAX, i32::MIN as u64] {
        for signal in [0, 10] {
            let mut native = Native {
                args: [pid, signal, 1, 0, 0, 0],
                calls: 0,
                fail: false,
            };
            assert_eq!(
                result(invoke(SignalCall::RtSigqueueinfo, &mut native)),
                Some(-3)
            );
            assert_eq!(native.calls, 0);
        }
    }
}
