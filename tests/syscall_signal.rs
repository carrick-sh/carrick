//! Signal syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn rt_signal_stubs_zero_old_state() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(135, SyscallArgs::from([0, 0, 0x4000, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.read_bytes(0x4000, 8).unwrap(), [0; 8]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(134, SyscallArgs::from([2, 0, 0x4010, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        memory
            .read_bytes(0x4010, 32)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn rt_sig_family_bootstrap_validates_args_and_returns_sensible_errnos() {
    const LINUX_EINTR: i32 = 4;
    const LINUX_EAGAIN: i32 = 11;
    const LINUX_EFAULT: i32 = 14;
    const LINUX_EINVAL: i32 = 22;
    const LINUX_ESRCH: i32 = 3;
    const LINUX_ENOSYS: i32 = 38;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // rt_sigsuspend(mask=0x4000, sigsetsize=8) -> EINTR (no signals to wake us).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(133, SyscallArgs::from([0x4000, 8, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EINTR }
    );
    // rt_sigsuspend with wrong sigsetsize -> EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(133, SyscallArgs::from([0x4000, 9, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    // rt_sigsuspend with bad mask pointer -> EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(133, SyscallArgs::from([0xdead_0000, 8, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    // rt_sigtimedwait(set=0x4000, info=NULL, timeout=NULL, sigsetsize=8) -> EAGAIN.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0, 0, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN
        }
    );
    // rt_sigtimedwait with zero timeout -> EAGAIN.
    memory
        .write_bytes(0x4040, LinuxTimespec::new(0, 0).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0, 0x4040, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN
        }
    );
    // rt_sigtimedwait with wrong sigsetsize -> EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0, 0, 9, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    // rt_sigtimedwait with tv_nsec out of range -> EINVAL.
    memory
        .write_bytes(0x4040, LinuxTimespec::new(0, 1_000_000_001).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0, 0x4040, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // rt_sigqueueinfo(1, 65, NULL) -> EINVAL (signum out of range).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(138, SyscallArgs::from([1, 65, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    // rt_sigqueueinfo(99, 1, NULL) -> ESRCH (no such tgid).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(138, SyscallArgs::from([99, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    // rt_sigqueueinfo(1, 1, NULL) -> ENOSYS (no signal delivery).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(138, SyscallArgs::from([1, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS
        }
    );

    // rt_sigreturn now surfaces a `SigReturn` outcome the runtime
    // handles by calling `trap.restore_from_sigframe()`. The dispatcher
    // itself can't perform the restore; the outcome is the only signal.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(139, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::SigReturn
    );
    // Silence unused-const warnings now that the ENOSYS branch is gone.
    let _ = LINUX_ENOSYS;

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn kill_tkill_tgkill_bootstrap_validates_targets_and_signals() {
    const LINUX_EINVAL: i32 = 22;
    const LINUX_ESRCH: i32 = 3;
    // Signal delivery is now real: kill / tkill / tgkill with a valid
    // self-target signum no longer return ENOSYS; they queue the
    // signal for the runtime's between-trap delivery pass.

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // kill(1, 0) -> existence check, success.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(129, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // kill(0, 0) -> existence check against calling pid, success.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(129, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // kill(1, 65) -> EINVAL (signum out of range).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(129, SyscallArgs::from([1, 65, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    // kill(99, 0) -> ESRCH (only pid 1/0 are known).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(129, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    // kill(1, SIGTERM=15) -> success; the signal is queued in the
    // host pending slot for the runtime to deliver on the next pass.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(129, SyscallArgs::from([1, 15, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // Drain the pending slot so subsequent tests aren't surprised by
    // a leftover SIGTERM.
    let _ = carrick::host_signal::take_pending();

    // tkill(1, 0) -> success; tkill(0, 0) -> ESRCH (tid 0 isn't us).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(130, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(130, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    // tkill(1, 65) -> EINVAL, tkill(99, 0) -> ESRCH, tkill(1, 1) -> ENOSYS.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(130, SyscallArgs::from([1, 65, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(130, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    // tkill(1, 1) -> success (SIGHUP queued for self-delivery).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(130, SyscallArgs::from([1, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let _ = carrick::host_signal::take_pending();

    // tgkill(1, 1, 0) -> success.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(131, SyscallArgs::from([1, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // tgkill(1, 1, 65) -> EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(131, SyscallArgs::from([1, 1, 65, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );
    // tgkill(99, 1, 0) and tgkill(1, 99, 0) -> ESRCH.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(131, SyscallArgs::from([99, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(131, SyscallArgs::from([1, 99, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_ESRCH }
    );
    // tgkill(1, 1, 1) -> success; SIGHUP queued for self-delivery.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(131, SyscallArgs::from([1, 1, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let _ = carrick::host_signal::take_pending();

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sigaltstack_bootstrap_zeroes_old_stack_and_validates_new() {
    const LINUX_EINVAL: i32 = 22;
    const LINUX_ENOMEM: i32 = 12;
    const LINUX_SS_DISABLE: i32 = 2;
    const LINUX_SS_ONSTACK: i32 = 1;
    const LINUX_MINSIGSTKSZ: u64 = 2048;

    let mut memory = LinearMemory::new(0x4000, vec![0xaa; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let old_ptr: u64 = 0x4000;
    let new_ptr: u64 = 0x4040;
    let stack_size = core::mem::size_of::<LinuxSigaltstack>();

    // sigaltstack(NULL, old) -> writes SS_DISABLE descriptor into old.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(132, SyscallArgs::from([0, old_ptr, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let read_back = memory.read_bytes(old_ptr, stack_size).unwrap();
    let old_stack = LinuxSigaltstack::read_from_bytes(&read_back).unwrap();
    assert_eq!({ old_stack.ss_sp }, 0u64);
    assert_eq!({ old_stack.ss_flags }, LINUX_SS_DISABLE);
    assert_eq!({ old_stack.ss_size }, 0u64);

    // sigaltstack(SS_DISABLE in ss, NULL) -> success (silent drop).
    let disabled = LinuxSigaltstack {
        ss_sp: 0,
        ss_flags: LINUX_SS_DISABLE,
        __pad: 0,
        ss_size: 0,
    };
    memory.write_bytes(new_ptr, disabled.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(132, SyscallArgs::from([new_ptr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // sigaltstack with SS_ONSTACK (or any unknown flag) -> EINVAL.
    let bad_flags = LinuxSigaltstack {
        ss_sp: 0x9000,
        ss_flags: LINUX_SS_ONSTACK,
        __pad: 0,
        ss_size: LINUX_MINSIGSTKSZ,
    };
    memory.write_bytes(new_ptr, bad_flags.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(132, SyscallArgs::from([new_ptr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // sigaltstack with flags=0 but undersized stack -> ENOMEM.
    let too_small = LinuxSigaltstack {
        ss_sp: 0x9000,
        ss_flags: 0,
        __pad: 0,
        ss_size: 0,
    };
    memory.write_bytes(new_ptr, too_small.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(132, SyscallArgs::from([new_ptr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_ENOMEM
        }
    );

    // sigaltstack with flags=0 and a usable stack -> success.
    let usable = LinuxSigaltstack {
        ss_sp: 0x9000,
        ss_flags: 0,
        __pad: 0,
        ss_size: LINUX_MINSIGSTKSZ,
    };
    memory.write_bytes(new_ptr, usable.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(132, SyscallArgs::from([new_ptr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
