//! Process-lifecycle syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn exit_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(93, SyscallArgs::from([42, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 42 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn exit_group_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(94, SyscallArgs::from([7, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 7 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn unknown_syscall_returns_enosys_and_records_report_entry() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut memory,
            &mut reporter,
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
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(278, SyscallArgs::from([0x4000, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
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
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // ptrace → ENOSYS (no debugger surface yet).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(117, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
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
                    &mut reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 1 },
            "syscall {number} should return EPERM"
        );
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn job_control_bootstrap_returns_single_session_values() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([0, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(155, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(155, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(156, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(157, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn planned_process_syscalls_surface_by_name_in_compat_report() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let expected: &[(u64, &str)] = &[
        (220, "clone"),
        (221, "execve"),
        (281, "execveat"),
        (435, "clone3"),
    ];

    for (number, _name) in expected {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(*number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DispatchOutcome::Errno { errno: 38 },
            "syscall {number} should report ENOSYS until a real handler lands"
        );
    }

    let report = reporter.finish();
    for (number, name) in expected {
        let entry = report
            .unhandled_syscalls
            .iter()
            .find(|entry| entry.number == *number)
            .unwrap_or_else(|| panic!("missing compat entry for {name}"));
        assert_eq!(entry.name, *name);
        assert_eq!(entry.count, 1);
    }
}


#[test]
fn wait_family_bootstrap_returns_echild() {
    const LINUX_P_ALL: u64 = 0;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_ECHILD: i32 = 10;
    const LINUX_EINVAL: i32 = 22;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
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
                &mut reporter,
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
                &mut reporter,
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
                &mut reporter,
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
                    SyscallArgs::from([
                        LINUX_P_ALL,
                        0,
                        0,
                        LINUX_WEXITED | 0xdead_0000,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &mut reporter,
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
                SyscallRequest::new(
                    260,
                    SyscallArgs::from([(-1_i64) as u64, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
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
                &mut reporter,
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
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

