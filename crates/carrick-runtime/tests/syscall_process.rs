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

#[cfg(target_os = "macos")]
struct ForkedChild(i32);

#[cfg(target_os = "macos")]
impl Drop for ForkedChild {
    fn drop(&mut self) {
        unsafe {
            let mut status = 0;
            if libc::waitpid(self.0, &mut status, libc::WNOHANG) == 0 {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, &mut status, 0);
            }
        }
        carrick_runtime::guest_cpu::reap_child_guest_ns(self.0 as u32);
    }
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

    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(38)
        }
    );
    let report = reporter.finish();
    assert_eq!(report.unhandled_syscalls[0].number, 9999);
    assert_eq!(report.unhandled_syscalls[0].name, "unknown");
    assert_eq!(report.unhandled_syscalls[0].count, 1);
}

#[test]
fn syscall_request_can_be_built_from_a_raw_syscall() {
    // The per-ISA register decode lives behind `GuestArch::decode_syscall`
    // (covered by carrick-hal's aarch64 tests); the dispatcher consumes the
    // ISA-neutral `RawSyscall`.
    let raw = carrick_hal::RawSyscall {
        number: carrick_abi::CanonicalNr(64),
        args: [1, 0x4000, 17, 0, 0, 0],
        guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
        native_number: carrick_abi::NativeNr(64),
    };

    assert_eq!(
        SyscallRequest::from_raw(raw),
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

    // An unimplemented ptrace request (PTRACE_ATTACH = 16) reports ENOSYS. We
    // avoid PEEK/POKE here: those now do a target-existence check first and
    // return ESRCH for a missing pid (pid 0). TRACEME/CONT are exercised by
    // ptracetraceme instead, since PTRACE_TRACEME mutates the current host
    // process's debug state.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(117, SyscallArgs::from([16, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(3)
        }
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
            DispatchOutcome::Errno {
                errno: LinuxErrno::new(1)
            },
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
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(3)
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(154, SyscallArgs::from([0, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        }
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
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(3)
        }
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
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(3)
        }
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
    // lookup_dcookie(18) is such a syscall today: it's in the aarch64 name
    // table but Linux removed it, so carrick will never give it a handler (it
    // falls through to the unimplemented catch-all → ENOSYS). The original
    // version of this test listed clone(220)/execve(221)/clone3(435)/
    // execveat(281), but those all gained real handlers, so they no longer
    // report ENOSYS. If lookup_dcookie ever gains a handler (it won't), point
    // this at the next still-unimplemented named syscall.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(18, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(38)
        }
    );

    let report = reporter.finish();
    // lookup_dcookie(18) is a number the aarch64 table recognises (Deferred),
    // so it surfaces in the `deferred_syscalls` bucket — "recognised, not yet
    // emulated" — under its real name, NOT in `unhandled_syscalls` (which is
    // reserved for genuinely unknown numbers like 9999).
    assert!(
        report.unhandled_syscalls.iter().all(|e| e.number != 18),
        "recognised syscalls must not land in the truly-unknown bucket",
    );
    let entry = report
        .deferred_syscalls
        .iter()
        .find(|entry| entry.number == 18)
        .expect("lookup_dcookie should surface as a deferred syscall in the compat report");
    assert_eq!(entry.name, "lookup_dcookie");
    assert_eq!(entry.count, 1);
}

#[test]
fn wait_family_bootstrap_returns_echild() {
    let _guard = process_wait_test_lock();
    const LINUX_P_ALL: u64 = 0;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_ECHILD: LinuxErrno = LinuxErrno::new(10);
    const LINUX_EINVAL: LinuxErrno = LinuxErrno::new(22);

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
            // The blocking wait folds the default-ignored signals
            // (SIGCHLD|SIGURG|SIGWINCH) into its ADDITIVE block set so an inert
            // pending signal can't spuriously EINTR it. A fresh dispatcher has
            // no installed handlers, so that default-ignore set is the whole
            // set.
            sig_mask: carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::from_raw(
                (1 << 16) | (1 << 22) | (1 << 27)
            )),
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
            // The blocking wait folds the default-ignored signals
            // (SIGCHLD|SIGURG|SIGWINCH) into its ADDITIVE block set so an inert
            // pending signal can't spuriously EINTR it. A fresh dispatcher has
            // no installed handlers, so that default-ignore set is the whole
            // set.
            sig_mask: carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::from_raw(
                (1 << 16) | (1 << 22) | (1 << 27)
            )),
        }
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_waitid_translates_and_controls_virtual_ptrace_stop() {
    let _guard = process_wait_test_lock();
    const LINUX_P_PID: u64 = 1;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WSTOPPED: u64 = 2;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_WCONTINUED: u64 = 8;
    const LINUX_WNOWAIT: u64 = 0x0100_0000;
    const LINUX_SIGUSR2: i32 = 12;
    const LINUX_CLD_TRAPPED: i32 = 4;
    const INFO_ADDR: u64 = 0x4000;

    carrick_runtime::guest_cpu::init_child_table();
    let tracer_pid = std::process::id();
    let prepared =
        carrick_runtime::guest_cpu::prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0)
            .expect("prepare virtual-ptrace child record");
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        let ready = carrick_runtime::guest_cpu::register_self_virtual_ptrace(tracer_pid)
            && carrick_runtime::guest_cpu::request_self_virtual_ptrace_stop(LINUX_SIGUSR2);
        if !ready {
            unsafe { libc::_exit(70) };
        }
        unsafe {
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
    }
    let child_guard = ForkedChild(child);
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);

    let geometry = carrick_runtime::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    };
    let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(geometry);

    let mut host_stop_ready = false;
    for _ in 0..100 {
        let mut host_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    child as libc::id_t,
                    &mut host_info,
                    libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
                )
            },
            0,
        );
        if host_info.si_pid == child {
            host_stop_ready = true;
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert!(host_stop_ready, "host carrier stop did not become waitable");
    memory.write_bytes(INFO_ADDR, &[0xff; 28]).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([
                        LINUX_P_PID,
                        child as u64,
                        INFO_ADDR,
                        LINUX_WEXITED | LINUX_WNOHANG,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
    );
    assert_eq!(memory.read_bytes(INFO_ADDR, 28).unwrap(), vec![0; 28]);

    let mut observed = false;
    for _ in 0..100 {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([
                        LINUX_P_PID,
                        child as u64,
                        INFO_ADDR,
                        LINUX_WSTOPPED | LINUX_WNOHANG | LINUX_WNOWAIT,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(INFO_ADDR, 28).unwrap();
        let si_pid = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        if si_pid == child {
            let si_code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
            let si_status = i32::from_ne_bytes(bytes[24..28].try_into().unwrap());
            assert_eq!(si_code, LINUX_CLD_TRAPPED);
            assert_eq!(si_status, LINUX_SIGUSR2);
            observed = true;
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert!(observed, "virtual ptrace stop was not reported");

    memory.write_bytes(INFO_ADDR, &[0; 28]).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([
                        LINUX_P_PID,
                        child as u64,
                        INFO_ADDR,
                        LINUX_WSTOPPED | LINUX_WNOHANG,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
    );
    let consumed = memory.read_bytes(INFO_ADDR, 28).unwrap();
    assert_eq!(
        i32::from_ne_bytes(consumed[8..12].try_into().unwrap()),
        LINUX_CLD_TRAPPED,
    );
    assert_eq!(
        i32::from_ne_bytes(consumed[16..20].try_into().unwrap()),
        child,
    );
    assert_eq!(
        i32::from_ne_bytes(consumed[24..28].try_into().unwrap()),
        LINUX_SIGUSR2,
    );

    memory.write_bytes(INFO_ADDR, &[0xff; 28]).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    95,
                    SyscallArgs::from([
                        LINUX_P_PID,
                        child as u64,
                        INFO_ADDR,
                        LINUX_WSTOPPED | LINUX_WNOHANG,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
    );
    assert_eq!(memory.read_bytes(INFO_ADDR, 28).unwrap(), vec![0; 28]);

    let continued_waitid = dispatcher
        .dispatch(
            SyscallRequest::new(
                95,
                SyscallArgs::from([LINUX_P_PID, child as u64, 0, LINUX_WCONTINUED, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(matches!(
        continued_waitid,
        DispatchOutcome::WaitOnProcState { pid, .. } if pid == child
    ));
    let continued_wait4 = dispatcher
        .dispatch(
            SyscallRequest::new(
                260,
                SyscallArgs::from([child as u64, 0, LINUX_WCONTINUED, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(matches!(
        continued_wait4,
        DispatchOutcome::WaitOnProcState { pid, .. } if pid == child
    ));

    let prepared_sibling =
        carrick_runtime::guest_cpu::prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0)
            .expect("prepare sibling child record");
    let sibling = unsafe { libc::fork() };
    assert!(sibling >= 0, "sibling fork failed");
    if sibling == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        unsafe { libc::_exit(23) };
    }
    let sibling_guard = ForkedChild(sibling);
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(
        prepared_sibling,
        sibling as u32,
    );
    let mut sibling_ready = false;
    for _ in 0..100 {
        let mut sibling_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    sibling as libc::id_t,
                    &mut sibling_info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            },
            0,
        );
        if sibling_info.si_pid == sibling {
            sibling_ready = true;
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert!(sibling_ready, "sibling did not become waitable");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    260,
                    SyscallArgs::from([u64::MAX, 0, LINUX_WNOHANG, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: sibling as i64,
        },
    );
    std::mem::forget(sibling_guard);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(117, SyscallArgs::from([7, child as u64, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
    );

    std::mem::forget(child_guard);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    carrick_runtime::guest_cpu::reap_child_guest_ns(child as u32);
}

#[cfg(target_os = "macos")]
#[test]
fn native_ptrace_wait_without_wuntraced_uses_state_readiness() {
    let _guard = process_wait_test_lock();
    carrick_runtime::guest_cpu::init_child_table();
    let tracer_pid = std::process::id();
    let prepared =
        carrick_runtime::guest_cpu::prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0)
            .expect("prepare virtual-ptrace child record");
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        let ready = carrick_runtime::guest_cpu::register_self_virtual_ptrace(tracer_pid)
            && carrick_runtime::guest_cpu::request_self_virtual_ptrace_stop(12);
        if !ready {
            unsafe { libc::_exit(70) };
        }
        loop {
            unsafe { libc::pause() };
        }
    }
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
    let _child_guard = ForkedChild(child);

    let mut requested = false;
    for _ in 0..100 {
        if carrick_runtime::guest_cpu::child_virtual_ptrace_stop_requested(child as u32) {
            requested = true;
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert!(requested, "virtual ptrace stop was not requested");

    let geometry = carrick_runtime::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    };
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(geometry);
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(260, SyscallArgs::from([child as u64, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert!(matches!(
        outcome,
        DispatchOutcome::WaitOnProcState { pid, .. } if pid == child
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn native_broad_waitid_skips_unrequested_stop_for_exited_sibling() {
    let _guard = process_wait_test_lock();
    const LINUX_P_ALL: u64 = 0;
    const LINUX_P_PGID: u64 = 2;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_WNOWAIT: u64 = 0x0100_0000;
    const INFO_ADDR: u64 = 0x4000;

    carrick_runtime::guest_cpu::init_child_table();
    let parent = std::process::id();
    let stopped_record =
        carrick_runtime::guest_cpu::prepare_child_record_pre_fork(parent, 0, 0, false, 0)
            .expect("prepare stopped child record");
    let stopped = unsafe { libc::fork() };
    assert!(stopped >= 0, "fork failed");
    if stopped == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        loop {
            unsafe { libc::pause() };
        }
    }
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(
        stopped_record,
        stopped as u32,
    );
    let _stopped_guard = ForkedChild(stopped);
    unsafe {
        assert_eq!(libc::kill(stopped, libc::SIGSTOP), 0);
    }
    let mut stopped_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    for _ in 0..100 {
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    stopped as libc::id_t,
                    &mut stopped_info,
                    libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
                )
            },
            0,
        );
        if stopped_info.si_pid == stopped {
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert_eq!(stopped_info.si_pid, stopped, "child did not stop");

    let exited_record =
        carrick_runtime::guest_cpu::prepare_child_record_pre_fork(parent, 0, 0, false, 0)
            .expect("prepare exited child record");
    let exited = unsafe { libc::fork() };
    assert!(exited >= 0, "fork failed");
    if exited == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        unsafe { libc::_exit(23) };
    }
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(
        exited_record,
        exited as u32,
    );
    let _exited_guard = ForkedChild(exited);
    let mut exited_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    for _ in 0..100 {
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    exited as libc::id_t,
                    &mut exited_info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            },
            0,
        );
        if exited_info.si_pid == exited {
            break;
        }
        unsafe { libc::usleep(10_000) };
    }
    assert_eq!(exited_info.si_pid, exited, "sibling did not exit");

    let geometry = carrick_runtime::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    };
    let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(geometry);
    for idtype in [LINUX_P_ALL, LINUX_P_PGID].into_iter().cycle().take(16) {
        memory.write_bytes(INFO_ADDR, &[0; 28]).unwrap();
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        95,
                        SyscallArgs::from([
                            idtype,
                            0,
                            INFO_ADDR,
                            LINUX_WEXITED | LINUX_WNOHANG | LINUX_WNOWAIT,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 },
        );
        let bytes = memory.read_bytes(INFO_ADDR, 28).unwrap();
        assert_eq!(
            i32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
            exited,
            "broad waitid must not starve behind the stopped child",
        );
        assert_eq!(i32::from_ne_bytes(bytes[24..28].try_into().unwrap()), 23,);
    }

    let mut still_stopped: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                stopped as libc::id_t,
                &mut still_stopped,
                libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
            )
        },
        0,
    );
    assert_eq!(
        still_stopped.si_pid, stopped,
        "skipped stop must remain waitable"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_process_group_waits_park_without_blocking_in_host_wait() {
    let _guard = process_wait_test_lock();
    carrick_runtime::guest_cpu::init_child_table();
    let prepared = carrick_runtime::guest_cpu::prepare_child_record_pre_fork(
        std::process::id(),
        0,
        0,
        false,
        0,
    )
    .expect("prepare native wait child record");
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
    let _child_guard = ForkedChild(child);

    let geometry = carrick_runtime::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    };
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(geometry);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(260, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert!(matches!(
        outcome,
        DispatchOutcome::WaitOnProcExit { pid: -1, .. }
    ));

    let waitid_outcome = dispatcher
        .dispatch(
            SyscallRequest::new(95, SyscallArgs::from([2, 0, 0, 4, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(
        matches!(
            waitid_outcome,
            DispatchOutcome::WaitOnProcExit { pid: -1, .. }
        ),
        "unexpected waitid outcome: {waitid_outcome:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_untraced_wait_uses_child_state_readiness() {
    let _guard = process_wait_test_lock();
    carrick_runtime::guest_cpu::init_child_table();
    let prepared = carrick_runtime::guest_cpu::prepare_child_record_pre_fork(
        std::process::id(),
        0,
        0,
        false,
        0,
    )
    .expect("prepare native state-wait child record");
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        carrick_runtime::guest_cpu::complete_child_record_post_fork_child();
        loop {
            unsafe { libc::pause() };
        }
    }
    carrick_runtime::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
    let _child_guard = ForkedChild(child);

    let geometry = carrick_runtime::page_profile::PageGeometry {
        host_page_size: 16 * 1024,
        linux_page_size: 16 * 1024,
        native_profile: Some(carrick_spec::NativePageProfile::Native16k),
    };
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(geometry);
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(260, SyscallArgs::from([child as u64, 0, 2, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert!(matches!(
        outcome,
        DispatchOutcome::WaitOnProcState { pid, .. } if pid == child
    ));
}

#[test]
fn seccomp_filter_blocks_the_targeted_syscall_with_errno() {
    // Install (via the real seccomp(2) syscall) the canonical libseccomp-style
    // filter "deny getpid(172) with EPERM, allow everything else", then confirm
    // the dispatcher enforces it before the handler runs.
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let write_insn = |m: &mut LinearMemory, addr: u64, code: u16, jt: u8, jf: u8, k: u32| {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&code.to_ne_bytes());
        b[2] = jt;
        b[3] = jf;
        b[4..8].copy_from_slice(&k.to_ne_bytes());
        m.write_bytes(addr, &b).unwrap();
    };
    // Filter program @0x4020: LD nr; JEQ 172 -> RET ERRNO|EPERM else RET ALLOW.
    write_insn(&mut memory, 0x4020, BPF_LD_W_ABS, 0, 0, 0);
    write_insn(&mut memory, 0x4028, BPF_JMP_JEQ, 0, 1, 172);
    write_insn(&mut memory, 0x4030, BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 1);
    write_insn(&mut memory, 0x4038, BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
    // struct sock_fprog @0x4000: len=4 @0, filter ptr=0x4020 @8.
    memory.write_bytes(0x4000, &4u16.to_ne_bytes()).unwrap();
    memory
        .write_bytes(0x4008, &0x4020u64.to_ne_bytes())
        .unwrap();

    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // getpid before the filter is installed -> a real pid.
    assert!(matches!(
        run(&mut dispatcher, &mut memory, 172, [0; 6]),
        DispatchOutcome::Returned { value } if value > 0
    ));

    // PR_SET_NO_NEW_PRIVS (38) is required before SECCOMP_SET_MODE_FILTER.
    assert_eq!(
        run(&mut dispatcher, &mut memory, 167, [38, 1, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    // seccomp(SECCOMP_SET_MODE_FILTER=1, flags=0, &fprog) -> 0.
    assert_eq!(
        run(&mut dispatcher, &mut memory, 277, [1, 0, 0x4000, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    // getpid(172) is now denied with EPERM (1); getppid(173) still works.
    assert_eq!(
        run(&mut dispatcher, &mut memory, 172, [0; 6]),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(1)
        }
    );
    assert!(matches!(
        run(&mut dispatcher, &mut memory, 173, [0; 6]),
        DispatchOutcome::Returned { value } if value >= 0
    ));
}
