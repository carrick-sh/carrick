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
    fn restore_signal_frame(&mut self) -> Result<u64, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LinuxErrno::new(14))
    }
}
impl ProcessSignals for Native {
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
    let restored: Result<u64, carrick_syscall_abi::LinuxErrno> = native.restore_signal_frame();
    assert_eq!(restored.unwrap_err().get(), 14);
}

#[test]
fn queued_siginfo_carries_the_admitted_signal_number() {
    let signal = carrick_signal_core::policy::Signal::from_number(10).unwrap();
    let payload = SignalInfo::Queued(carrick_abi::LinuxSiginfo::kill(64, -1, 1, 0))
        .payload(signal)
        .unwrap();
    let number = payload.si_signo;
    assert_eq!(number, 10);
}
