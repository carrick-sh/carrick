//! Process-lifecycle syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "integration/common/syscall_support.rs"]
mod support;

use support::*;

static PROCESS_WAIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn process_wait_test_lock() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_WAIT_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn exit_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(93, SyscallArgs::from([42, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 42 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn exit_group_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(94, SyscallArgs::from([7, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 7 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unknown_syscall_returns_enosys_and_records_report_entry() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });
    let report = reporter.finish();
    assert_eq!(report.unhandled_syscalls[0].number, 9999);
    assert_eq!(report.unhandled_syscalls[0].name, "unknown");
    assert_eq!(report.unhandled_syscalls[0].count, 1);
}

#[test]
fn syscall_request_can_be_built_from_aarch64_register_frame() {
    let frame = Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 17,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    };

    assert_eq!(
        SyscallRequest::from_aarch64_frame(frame),
        SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0]))
    );
}

#[test]
fn getrandom_fills_guest_buffer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 32]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(278, SyscallArgs::from([0x4000, 16, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 16 }
    );
    assert!(
        memory
            .read_bytes(0x4000, 16)
            .unwrap()
            .iter()
            .any(|byte| *byte != 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn privileged_op_stubs_return_eperm_or_enosys() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // ptrace → ENOSYS (no debugger surface yet).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(117, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 38 }
    );
    // reboot / sethostname / setdomainname / settimeofday → EPERM.
    for number in [142_u64, 161, 162, 170] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 1 },
            "syscall {number} should return EPERM"
        );
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn job_control_queries_match_host_process_group_state() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let host_pgid = unsafe { libc::getpgid(0) };
    let host_sid = unsafe { libc::getsid(0) };
    assert!(host_pgid > 0);
    assert!(host_sid > 0);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([0, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    // Successful setpgid(0, 0) and setsid() mutate process-global state for the
    // test harness, so this unit test covers non-mutating host-backed queries
    // and validation errors only.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(155, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: i64::from(host_pgid),
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(155, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(156, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: i64::from(host_sid),
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(156, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unhandled_named_syscall_surfaces_by_name_in_compat_report() {
    // A syscall that IS known in the aarch64 name table but has no handler in
    // the normalized dispatch table returns ENOSYS and surfaces in the compat
    // report under its REAL name (not "unknown" — that path is covered by
    // `unknown_syscall_returns_enosys_and_records_report_entry`).
    //
    // execveat(281) is such a syscall today. The original version of this test
    // also listed clone(220)/execve(221)/clone3(435), but those now have real
    // handlers (clone→Fork, execve→Execve, clone3), so they no longer report
    // ENOSYS. If a real execveat handler lands, point this at the next
    // still-unimplemented named syscall.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(281, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });

    let report = reporter.finish();
    // execveat(281) is a number the aarch64 table recognises (Planned), so it
    // surfaces in the `deferred_syscalls` bucket — "recognised, not yet
    // emulated" — under its real name, NOT in `unhandled_syscalls` (which is
    // reserved for genuinely unknown numbers like 9999).
    assert!(
        report.unhandled_syscalls.iter().all(|e| e.number != 281),
        "recognised syscalls must not land in the truly-unknown bucket",
    );
    let entry = report
        .deferred_syscalls
        .iter()
        .find(|entry| entry.number == 281)
        .expect("execveat should surface as a deferred syscall in the compat report");
    assert_eq!(entry.name, "execveat");
    assert_eq!(entry.count, 1);
}

#[test]
fn wait_family_bootstrap_returns_echild() {
    let _guard = process_wait_test_lock();
    const LINUX_P_ALL: u64 = 0;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_ECHILD: i32 = 10;
    const LINUX_EINVAL: i32 = 22;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // waitid with P_ALL and WEXITED -> ECHILD (no children)
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([LINUX_P_ALL, 0, 0, LINUX_WEXITED, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        }
    );

    // waitid with unknown idtype -> EINVAL
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(95, SyscallArgs::from([99, 0, 0, LINUX_WEXITED, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    // waitid with no state-bits set -> EINVAL
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(95, SyscallArgs::from([LINUX_P_ALL, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    // waitid with unknown flag bits -> EINVAL
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([LINUX_P_ALL, 0, 0, LINUX_WEXITED | 0xdead_0000, 0, 0,]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    // wait4(-1, NULL, 0, NULL) -> ECHILD
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(260, SyscallArgs::from([(-1_i64) as u64, 0, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        }
    );

    // wait4 with WNOHANG and no children -> ECHILD
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    260,
                    SyscallArgs::from([(-1_i64) as u64, 0, LINUX_WNOHANG, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        }
    );

    // wait4 with unsupported flag bits -> EINVAL
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    260,
                    SyscallArgs::from([(-1_i64) as u64, 0, 0xdead_0000, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn blocking_wait4_for_specific_child_parks_on_proc_exit() {
    let _guard = process_wait_test_lock();
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe {
            libc::sleep(2);
            libc::_exit(0);
        }
    }

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(260, SyscallArgs::from([child as u64, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }

    assert_eq!(
        outcome,
        DispatchOutcome::WaitOnProcExit {
            pid: child,
            block_signals: 0,
        }
    );
}

#[cfg(target_os = "macos")]
#[test]
fn waitid_wexited_ignores_stopped_child() {
    let _guard = process_wait_test_lock();
    const LINUX_P_PID: u64 = 1;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_WNOWAIT: u64 = 0x0100_0000;

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    unsafe {
        assert_eq!(libc::kill(child, libc::SIGSTOP), 0);
        let mut info: libc::siginfo_t = std::mem::zeroed();
        for _ in 0..100 {
            assert_eq!(
                libc::waitid(
                    libc::P_PID,
                    child as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
                ),
                0
            );
            if info.si_pid == child {
                break;
            }
            libc::usleep(10_000);
        }
        assert_eq!(info.si_pid, child, "child did not report stopped state");
    }

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                95,
                SyscallArgs::from([
                    LINUX_P_PID,
                    child as u64,
                    0,
                    LINUX_WEXITED | LINUX_WNOWAIT,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }

    assert_eq!(
        outcome,
        DispatchOutcome::WaitOnProcExit {
            pid: child,
            block_signals: 0,
        }
    );
}
