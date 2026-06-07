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
fn rt_sigaction_sig_dfl_resets_host_disposition_for_job_control() {
    // Ctrl-Z / SIGTSTP job control. A job-control shell sets SIGTSTP=SIG_IGN for
    // ITSELF (so ^Z never stops the shell); carrick mirrors that to the host
    // (set_host_ignore). Each forked child then resets SIGTSTP to SIG_DFL BEFORE
    // exec so the pty's ^Z actually stops the job. If carrick mirrors the IGN but
    // never resets the host back to SIG_DFL, the host SIG_IGN — inherited across
    // fork — DISCARDS the pty-generated SIGTSTP and the job never stops (Ctrl-Z
    // does nothing). The host disposition must follow the guest's IGN -> DFL.
    const RT_SIGACTION: u64 = 134;
    const LINUX_SIGTSTP: u64 = 20; // macOS SIGTSTP == libc::SIGTSTP (18)
    const SA_HANDLER_IGN: u64 = 1; // LINUX_SIG_IGN
    const SA_HANDLER_DFL: u64 = 0; // LINUX_SIG_DFL
    let host_sig = libc::SIGTSTP;

    // Save the test process's real SIGTSTP disposition; restore before asserting.
    // SAFETY: standard sigaction query/restore on a benign job-control signal.
    let mut saved: libc::sigaction = unsafe { core::mem::zeroed() };
    unsafe { libc::sigaction(host_sig, core::ptr::null(), &mut saved) };
    let read_host = || -> usize {
        let mut cur: libc::sigaction = unsafe { core::mem::zeroed() };
        unsafe { libc::sigaction(host_sig, core::ptr::null(), &mut cur) };
        cur.sa_sigaction
    };

    let mut memory = LinearMemory::new(0x4000, vec![0u8; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // 1. guest SIGTSTP = SIG_IGN -> host mirrors IGN (sa_handler is at offset 0).
    memory
        .write_bytes(0x4000, &SA_HANDLER_IGN.to_le_bytes())
        .unwrap();
    dispatcher
        .dispatch(
            SyscallRequest::new(
                RT_SIGACTION,
                SyscallArgs::from([LINUX_SIGTSTP, 0x4000, 0, 8, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let after_ign = read_host();

    // 2. guest SIGTSTP = SIG_DFL -> host MUST reset to SIG_DFL (the fix).
    memory
        .write_bytes(0x4000, &SA_HANDLER_DFL.to_le_bytes())
        .unwrap();
    dispatcher
        .dispatch(
            SyscallRequest::new(
                RT_SIGACTION,
                SyscallArgs::from([LINUX_SIGTSTP, 0x4000, 0, 8, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let after_dfl = read_host();

    // Restore the real disposition before any assertion can unwind the test.
    unsafe { libc::sigaction(host_sig, &saved, core::ptr::null_mut()) };

    assert_eq!(
        after_ign,
        libc::SIG_IGN,
        "guest SIG_IGN must mirror to the host disposition"
    );
    assert_eq!(
        after_dfl,
        libc::SIG_DFL,
        "guest SIG_DFL must reset the host disposition to SIG_DFL, else the pty's \
         ^Z (host SIGTSTP) is discarded by an inherited host SIG_IGN and the job \
         never stops (no Ctrl-Z)"
    );
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

    // rt_sigsuspend(mask=0x4000, sigsetsize=8) -> EINTR. A deliverable signal is
    // pending, so the suspend wakes promptly (rt_sigsuspend now installs the
    // mask and waits for a deliverable signal rather than returning instantly).
    dispatcher.mark_signal_pending(0, 10);
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
    assert_eq!(dispatcher.take_deliverable_pending(0), Some(10));
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

    memory
        .write_bytes(0x4000, &(1u64 << 9).to_le_bytes())
        .unwrap();
    // rt_sigtimedwait(set={SIGUSR1}, info=NULL, timeout=NULL, sigsetsize=8)
    // blocks indefinitely when no matching signal is pending, so the dispatcher
    // hands the wait to the runtime instead of returning EAGAIN.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0, 0, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::WaitOnSignals {
            wait_set: 1u64 << 9,
            timeout: None
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
    // rt_sigqueueinfo delivers to self, so block SIGHUP(1) first — the queue
    // then holds it (rt_pending_counts) instead of raising a real host SIGHUP.
    memory.write_bytes(0x4080, &1u64.to_le_bytes()).unwrap(); // mask = {SIGHUP}
    assert_eq!(
        dispatcher
            .dispatch(
                // rt_sigprocmask(SIG_BLOCK=0, set=0x4080, oldset=NULL, size=8)
                SyscallRequest::new(135, SyscallArgs::from([0, 0x4080, 0, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // rt_sigqueueinfo(1, 1, NULL) -> 0: queued to self (SIGHUP blocked).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(138, SyscallArgs::from([1, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // A forked child self-signal uses its real host pid as tgid; that must be
    // accepted as "self" rather than rejected as a nonexistent bootstrap pid.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    138,
                    SyscallArgs::from([std::process::id() as u64, 1, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
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
    let _ = carrick_runtime::host_signal::take_pending();

    // tkill(1, 0) -> success; tkill(0, 0) -> EINVAL (Linux rejects non-positive tids).
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
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
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
    let _ = carrick_runtime::host_signal::take_pending();

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
    let _ = carrick_runtime::host_signal::take_pending();

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

#[test]
fn rt_sigsuspend_applies_mask_then_returns_eintr_on_pending_signal() {
    // rt_sigsuspend installs the given mask, waits for a deliverable signal,
    // then restores the mask and returns -EINTR. Pre-mark a deliverable signal
    // so it returns promptly (rather than busy-waiting to the bound).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Signal 10 already pending for the (no-thread-context) tid 0; with a
    // suspend mask of 0 (block nothing) it is immediately deliverable.
    dispatcher.mark_signal_pending(0, 10);
    memory.write_bytes(0x4000, &0u64.to_le_bytes()).unwrap();

    // rt_sigsuspend(mask_ptr=0x4000, sigsetsize=8) -> EINTR (4).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(133, SyscallArgs::from([0x4000, 8, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 4 }
    );
    // The pre-suspend mask (0) is restored, not left as the suspend mask.
    assert_eq!(dispatcher.signal_mask_for(0), 0);
}

#[test]
fn rt_sigsuspend_restores_nondefault_mask_when_no_handler_runs() {
    // M1: when rt_sigsuspend wakes on a signal that does NOT run a caught
    // handler (here: no handler installed → default action), there is no
    // rt_sigreturn to pop the saved mask, so rt_sigsuspend must restore the
    // ORIGINAL mask itself. Otherwise the thread is stranded under the
    // temporary suspend mask. The pre-existing test can't catch this because
    // its original mask and suspend mask are both 0 (indistinguishable).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Original mask: block SIGRTMIN+... say signal 12 (bit 1<<11). Non-default.
    let original = 1u64 << (12 - 1);
    dispatcher.restore_signal_mask(0, original);

    // Signal 10 pending for tid 0, NO handler installed (default disposition).
    dispatcher.mark_signal_pending(0, 10);
    // suspend_mask = 0 (unblock everything) so signal 10 wakes it immediately.
    memory.write_bytes(0x4000, &0u64.to_le_bytes()).unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(133, SyscallArgs::from([0x4000, 8, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 4 }
    );
    // No handler ran → rt_sigsuspend restored the original mask itself, NOT the
    // suspend mask (0). The bug left it at the suspend mask.
    assert_eq!(
        dispatcher.signal_mask_for(0),
        original,
        "rt_sigsuspend must restore the original mask when no handler runs"
    );
}

#[test]
fn signalfd_read_drains_pending_masked_signals() {
    // H4: read() on a signalfd must drain pending signals that match the fd's
    // mask into signalfd_siginfo records (was: EINVAL — the API was unusable).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // signalfd mask = {SIGUSR1 (10)} = bit 1<<9, written at 0x4000.
    let mask = 1u64 << (10 - 1);
    memory.write_bytes(0x4000, &mask.to_le_bytes()).unwrap();
    // signalfd4(-1, mask@0x4000, 8, 0) -> sfd.
    let sfd = match dispatcher
        .dispatch(
            SyscallRequest::new(74, SyscallArgs::from([u64::MAX, 0x4000, 8, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("signalfd4: {o:?}"),
    };
    assert!(sfd >= 3);

    let read = |d: &mut SyscallDispatcher, m: &mut LinearMemory, count: u64| {
        d.dispatch(
            SyscallRequest::new(63, SyscallArgs::from([sfd, 0x4100, count, 0, 0, 0])),
            m,
            &reporter,
        )
        .unwrap()
    };

    // No signal pending -> EAGAIN (not the old EINVAL).
    assert_eq!(
        read(&mut dispatcher, &mut memory, 128),
        DispatchOutcome::Errno { errno: 11 }
    );

    // Mark SIGUSR1 pending for tid 0 (the harness ctx_tid).
    dispatcher.mark_signal_pending(0, 10);

    // read drains one 128-byte signalfd_siginfo; ssi_signo == 10.
    assert_eq!(
        read(&mut dispatcher, &mut memory, 128),
        DispatchOutcome::Returned { value: 128 }
    );
    let ssi_signo = u32::from_le_bytes(memory.read_bytes(0x4100, 4).unwrap().try_into().unwrap());
    assert_eq!(ssi_signo, 10);

    // Drained: a second read is EAGAIN again.
    assert_eq!(
        read(&mut dispatcher, &mut memory, 128),
        DispatchOutcome::Errno { errno: 11 }
    );

    // A buffer smaller than one signalfd_siginfo is EINVAL.
    assert_eq!(
        read(&mut dispatcher, &mut memory, 64),
        DispatchOutcome::Errno { errno: 22 }
    );
}

#[test]
fn rt_sigtimedwait_writes_full_siginfo_from_queued_payload() {
    // M9: a successful rt_sigtimedwait must fill the caller's siginfo with the
    // queued payload (si_code/si_pid/si_uid), not just si_signo.
    use carrick_runtime::linux_abi::LinuxSiginfo;
    const SI_QUEUE: i32 = -1;

    let mut memory = LinearMemory::new(0x4000, vec![0xee; 0x300]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Queue a payload for SIGUSR1 (10) on tid 0 and mark it pending.
    dispatcher.mark_signal_pending(0, 10);
    dispatcher.record_pending_siginfo(0, 10, LinuxSiginfo::kill(10, SI_QUEUE, 1234, 5678));

    // rt_sigtimedwait(set={10}@0x4000, info=0x4100, timeout=NULL, size=8).
    memory
        .write_bytes(0x4000, &(1u64 << 9).to_le_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(137, SyscallArgs::from([0x4000, 0x4100, 0, 8, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    // si_signo @0, si_code @8, si_pid @16 (low word of si_addr), si_uid @20.
    let rd = |off: u64| {
        i32::from_le_bytes(
            memory
                .read_bytes(0x4100 + off, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    assert_eq!(rd(0), 10, "si_signo");
    assert_eq!(rd(8), SI_QUEUE, "si_code from the queued payload");
    assert_eq!(rd(16), 1234, "si_pid from the queued payload");
    assert_eq!(rd(20), 5678, "si_uid from the queued payload");
}
