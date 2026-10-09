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
    fn restore_signal_frame(&mut self) -> Result<u64, i32> {
        Err(14)
    }
}
impl ProcessSignals for Native {
    fn force_sigsegv(&mut self, _: SigBlockMask) -> Result<(), i32> {
        Err(22)
    }
    fn rt_sigaction(&mut self, _: i32, _: Option<Action>) -> Result<Action, i32> {
        self.calls += 1;
        if self.fail {
            Err(13)
        } else {
            Ok(Action::default())
        }
    }
    fn rt_sigpending(&self, _: SigBlockMask) -> u64 {
        0
    }
    fn kill(&mut self, _: i32, _: i32, _: Option<carrick_abi::LinuxSiginfo>) -> Result<(), i32> {
        Err(22)
    }
    fn tkill(
        &mut self,
        _: SignalThreadSelector,
        _: i32,
        _: Option<carrick_abi::LinuxSiginfo>,
    ) -> Result<(), i32> {
        Err(22)
    }
    fn tgkill(
        &mut self,
        _: SignalThreadSelector,
        _: SignalThreadSelector,
        _: i32,
        _: Option<carrick_abi::LinuxSiginfo>,
    ) -> Result<(), i32> {
        Err(22)
    }
    fn rt_sigtimedwait(
        &mut self,
        _: SignalSet,
        _: Option<u64>,
        _: UserVa,
    ) -> Result<SignalWaitOutcome, i32> {
        Err(22)
    }
    fn rt_sigsuspend(&mut self, _: SigBlockMask, _: SigBlockMask) -> Result<bool, i32> {
        Err(22)
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
