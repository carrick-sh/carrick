//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

#[cfg(target_os = "macos")]
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend};
use carrick_runtime::linux_abi::{
    LINUX_AT_FDCWD, LINUX_AT_REMOVEDIR, LINUX_EFBIG, LINUX_O_CREAT, LINUX_O_RDWR,
};
use carrick_runtime::vfs::{BindVfs, MAX_IN_MEMORY_FILE_SIZE};
use support::*;

#[test]
fn write_syscall_reads_guest_memory_and_writes_stdout() {
    let mut memory = LinearMemory::new(0x4000, b"hello from linux\n".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 17 });
    assert_eq!(dispatcher.stdout(), b"hello from linux\n");
    assert!(dispatcher.stderr().is_empty());

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn write_syscall_rejects_bad_guest_pointer_with_efault() {
    let mut memory = LinearMemory::new(0x4000, b"short".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x5000, 5, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 14 });
    assert!(dispatcher.stdout().is_empty());
}

#[test]
fn ioctl_writes_packed_winsize_and_reports_unknown_requests() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // TIOCGWINSZ on a default stdio fd reflects the *real* backing host fd:
    // a TTY → 80x24 stub (or live winsize); a pipe/file/closed → ENOTTY,
    // matching Linux `ioctl(pipe, TIOCGWINSZ)`. The cargo-test process's
    // fd 1 may be either, so assert against the host's actual answer.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                29,
                SyscallArgs::from([1, LINUX_TIOCGWINSZ, 0x4000, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if carrick_runtime::host_tty::host_isatty(1) {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let winsize = read_winsize(&memory, 0x4000);
        // rows/cols come from the live terminal; just confirm they are non-zero.
        assert!(winsize.ws_row > 0 && winsize.ws_col > 0);
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, 0xdead_beef, 0x4040, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.unhandled_ioctls[0].request, 0xdead_beef);
    assert_eq!(report.unhandled_ioctls[0].count, 1);
}

#[test]
fn ioctl_tcgets_writes_default_termios_for_stdio_and_enotty_for_files() {
    // 1. TCGETS on fd 0 reflects the *real* backing host fd. A default stdio
    //    fd (no dup3 overlay) is a TTY iff the carrick process's own host fd 0
    //    is a TTY. When it is → cooked-TTY defaults; when it is a pipe / file
    //    (e.g. `cargo test` under CI, or the cpython-parity harness) → ENOTTY,
    //    matching Linux `ioctl(pipe, TCGETS)`.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let stdin_is_tty = carrick_runtime::host_tty::host_isatty(0);
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCGETS, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    // 2. TCGETS on bogus fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_TCGETS, 0x4080, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // 3. TCGETS on a rootfs-backed file fd → ENOTTY.
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let file_fd = match opened {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected fd, got {:?}", other),
    };
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TCGETS, 0x4080, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );

    // 4. TCSETS on fd 0 with a valid termios buffer. On a real backing TTY
    //    this succeeds (→ 0); on a non-tty stdio fd it is ENOTTY, same as
    //    Linux `ioctl(pipe, TCSETS)`.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    // Seed any plausible bytes — the dispatcher only does a size check.
    memory
        .write_bytes(0x4000, LinuxTermios::default_cooked().as_bytes())
        .unwrap();
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

        // 5. TCSETS on fd 0 with a bad pointer → EFAULT (only reached on a
        //    real tty; a non-tty short-circuits to ENOTTY before the read).
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS, 0x1, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 14 }
        );
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

#[test]
fn tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // TIOCGPGRP on stdio fd 0 → writes pgid=1.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCGPGRP, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4000), 1);

    // TIOCGSID on stdio fd 2 → writes sid=1.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([2, LINUX_TIOCGSID, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4010), 1);

    // TIOCGPGRP on unknown fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([99, LINUX_TIOCGPGRP, 0x4020, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // TIOCSPGRP on stdio with pgid=1 → 0; with pgid=99 → EPERM.
    memory.write_bytes(0x4030, &1_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCSPGRP, 0x4030, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    memory.write_bytes(0x4040, &99_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCSPGRP, 0x4040, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 1 }
    );

    // TIOCSCTTY / TIOCNOTTY on stdio → 0.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, LINUX_TIOCSCTTY, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCNOTTY, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // On a rootfs-backed file fd: TIOCGPGRP/TIOCGSID → ENOTTY.
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let file_fd = match opened {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected fd, got {:?}", other),
    };
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TIOCGPGRP, 0x4040, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TIOCGSID, 0x4048, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

/// Verify that `host_tty_tcgetpgrp` on a real pty slave returns the HOST
/// `tcgetpgrp` value, never the synthesised `LINUX_BOOTSTRAP_PGID` constant.
///
/// We open a fresh pty pair (posix_openpt / grantpt / unlockpt), call
/// `host_tty_tcgetpgrp` on the slave side, and assert it matches a direct
/// `libc::tcgetpgrp` call.  We intentionally do NOT check for a specific
/// numeric value — a freshly-opened slave that has never been made the
/// controlling tty may return -1 (ENOTTY or ENXIO on some kernels) — but we
/// DO assert that it never returns the faked bootstrap constant (1).
#[test]
fn tiocgpgrp_on_real_tty_uses_host_value_not_bootstrap() {
    // SAFETY: posix_openpt / grantpt / unlockpt / ptsname / open are standard
    // POSIX calls; we close the fds in the cleanup block.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open pty slave failed");
        (m, s)
    };

    // The slave is a real tty.
    assert!(
        carrick_runtime::host_tty::host_isatty(slave),
        "pty slave must be a tty"
    );

    // Direct libc call — this is the reference value.
    // SAFETY: slave is a valid open fd.
    let direct = unsafe { libc::tcgetpgrp(slave) };

    // Our helper must agree with the direct call.
    let via_helper = carrick_runtime::host_tty::host_tty_tcgetpgrp(slave);
    match via_helper {
        Ok(pgrp) => {
            assert_eq!(
                pgrp, direct,
                "host_tty_tcgetpgrp must match direct tcgetpgrp"
            );
            // Must never be the synthesised bootstrap constant on a real tty.
            assert_ne!(
                pgrp,
                carrick_runtime::linux_abi::LINUX_BOOTSTRAP_PGID,
                "host_tty_tcgetpgrp must not return the faked bootstrap pgid on a real tty"
            );
        }
        Err(_raw_errno) => {
            // tcgetpgrp returned -1: the slave has no controlling process group
            // (e.g. no session has made it the ctty yet).  The important
            // invariant is that our helper propagated the failure rather than
            // silently returning LINUX_BOOTSTRAP_PGID.
            assert!(
                direct < 0,
                "helper returned Err but direct tcgetpgrp returned {}",
                direct
            );
        }
    }

    // Cleanup.
    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// Verify that `host_tty_tcgetsid` on a real pty slave follows the host
/// `tcgetsid` result, instead of silently returning Carrick's synthetic
/// bootstrap SID fallback.
#[test]
fn tiocgsid_on_real_tty_uses_host_value_not_bootstrap() {
    // SAFETY: same pty-open pattern as the pgrp test.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open pty slave failed");
        (m, s)
    };

    assert!(
        carrick_runtime::host_tty::host_isatty(slave),
        "pty slave must be a tty"
    );

    // SAFETY: slave is a valid open fd.
    let direct = unsafe { libc::tcgetsid(slave) };
    let via_helper = carrick_runtime::host_tty::host_tty_tcgetsid(slave);
    match via_helper {
        Ok(sid) => {
            assert_eq!(sid, direct, "host_tty_tcgetsid must match tcgetsid");
            assert_ne!(
                sid,
                carrick_runtime::linux_abi::LINUX_BOOTSTRAP_SID,
                "host_tty_tcgetsid must not return the faked bootstrap sid on a real tty"
            );
        }
        Err(_) => {
            assert!(
                direct < 0,
                "helper returned Err but direct tcgetsid returned {}",
                direct
            );
        }
    }

    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// Verify that `host_tty_tcsetpgrp` on a real pty slave either succeeds or
/// returns a real errno (not silently EPERM-ing as the headless fallback does).
///
/// In a test-harness the slave is not the controlling tty of any session, so
/// `tcsetpgrp` will typically EPERM/ENOTTY.  The important property is that
/// `host_tty_tcsetpgrp` does NOT silently succeed on the bootstrap pgid the
/// way the non-tty fake path does — it actually calls the host.
#[test]
fn tiocspgrp_on_real_tty_calls_host_not_fake() {
    // SAFETY: same pty-open pattern as the get test.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null());
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0);
        (m, s)
    };

    let our_pgrp = unsafe { libc::getpgrp() };
    // Call our helper — it may succeed or fail (EPERM/ENOTTY in harness), but
    // it must not panic.  Verify it returns the same outcome as a direct call.
    let result_helper = carrick_runtime::host_tty::host_tty_tcsetpgrp(slave, our_pgrp);
    // SAFETY: same fd, same call.
    let direct_r = unsafe { libc::tcsetpgrp(slave, our_pgrp) };
    match result_helper {
        Ok(()) => assert_eq!(
            direct_r, 0,
            "helper Ok but direct call returned {}",
            direct_r
        ),
        Err(_) => assert!(
            direct_r < 0,
            "helper Err but direct call returned {}",
            direct_r
        ),
    }

    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

#[test]
fn flock_accepts_bootstrap_advisory_locks_on_open_files() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    32,
                    SyscallArgs::from([3, LINUX_LOCK_SH | LINUX_LOCK_NB, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([3, LINUX_LOCK_UN, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([99, LINUX_LOCK_SH, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_read_close_round_trip_through_rootfs_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(opened, DispatchOutcome::Returned { value: 3 });

    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 18 });
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    let closed = dispatcher
        .dispatch(
            SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_missing_rootfs_file_returns_enoent() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, b"/missing\0".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat2_reads_open_how_and_opens_readonly_rootfs_paths() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_open_how(&mut memory, 0x4020, LINUX_O_CLOEXEC, 0, 0);
    write_open_how(&mut memory, 0x4060, LINUX_O_WRONLY, 0, 0);
    write_open_how(&mut memory, 0x40a0, 0, 0, 0x4);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4020, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 18 }
    );
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4060, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x40a0, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4020, 16, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn cwd_and_access_syscalls_use_rootfs_state() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    memory.write_bytes(0x4010, b"motd\0").unwrap();
    memory.write_bytes(0x4020, b"/\0").unwrap();
    memory.write_bytes(0x4030, b"//..\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Linux getcwd(2) returns the length of the filled buffer including the
        // terminating NUL ("/\0" -> 2), not the buffer address.
        DispatchOutcome::Returned { value: 2 }
    );
    assert_eq!(memory.read_bytes(0x4100, 2).unwrap(), b"/\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // "/etc\0" -> 5 bytes filled (length, not address).
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(memory.read_bytes(0x4100, 5).unwrap(), b"/etc\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 4, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 2, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // W_OK on an existing file: the overlay is writable and the guest is
        // root, so this succeeds (it used to report EACCES under the obsolete
        // read-only rootfs model).
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 18 }
    );
    assert_eq!(
        memory.read_bytes(0x4200, 18).unwrap(),
        b"rootfs says hello\n"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4030, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(50, SyscallArgs::from([4, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn faccessat2_supports_bootstrap_access_flags_and_fd_checks() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("etc/motd", b"rootfs says hello\n".as_slice())],
        [("etc/motd-link", "motd")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd-link\0").unwrap();
    memory.write_bytes(0x4040, b"/proc/cpuinfo\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_R_OK,
                        LINUX_AT_EACCESS,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_W_OK,
                        LINUX_AT_EACCESS,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // The rootfs is backed by a writable overlay and the guest runs as root
        // (root bypasses DAC write checks), so W_OK on an existing file succeeds
        // just as it does on a real overlayfs mounted by root.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4020,
                        LINUX_X_OK,
                        LINUX_AT_SYMLINK_NOFOLLOW,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // motd-link points at the 0o644 regular file "motd": even as root,
        // X_OK on a regular file with no execute bit set returns EACCES, which
        // is exactly what real Linux does.
        DispatchOutcome::Errno { errno: 13 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([3, 0x4060, LINUX_R_OK, LINUX_AT_EMPTY_PATH, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4040,
                        LINUX_R_OK,
                        LINUX_AT_EACCESS,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    439,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_R_OK, 0x80, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn statfs_writes_packed_linux_statfs_for_rootfs_path() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(43, SyscallArgs::from([0x4000, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let block_size = statfs.f_bsize;
    let name_len = statfs.f_namelen;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert_eq!(block_size, 4096);
    assert!(name_len >= 255);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fstatfs_writes_packed_linux_statfs_for_open_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(44, SyscallArgs::from([3, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let free_blocks = statfs.f_bfree;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert!(free_blocks > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn lseek_repositions_rootfs_file_reads() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(62, SyscallArgs::from([3, 7, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 7 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"says");
}

#[test]
fn pread64_reads_from_offset_without_changing_file_offset() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(67, SyscallArgs::from([3, 0x4100, 4, 7, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"says");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"root");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn preadv_reads_from_offset_across_iovecs_without_changing_file_offset() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 5)],
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(69, SyscallArgs::from([3, 0x4100, 2, 7, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"says");
    assert_eq!(memory.read_bytes(0x4300, 5).unwrap(), b" hell");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4400, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4400, 4).unwrap(), b"root");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sendfile_copies_rootfs_file_to_stdout_and_updates_offset_pointer() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_u64(&mut memory, 0x4100, 7);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(71, SyscallArgs::from([1, 3, 0x4100, 4, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(dispatcher.stdout(), b"says");
    assert_eq!(read_u64(&memory, 0x4100), 11);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"root");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sendfile_without_offset_pointer_advances_file_offset_and_writes_pipe() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4100, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4100);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(71, SyscallArgs::from([pair.write_fd as u64, 3, 0, 6, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 6 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([pair.read_fd as u64, 0x4200, 6, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 6 }
    );
    assert_eq!(memory.read_bytes(0x4200, 6).unwrap(), b"rootfs");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4300, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(memory.read_bytes(0x4300, 1).unwrap(), b" ");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

/// Regression: `sendfile(out, in, NULL, n)` on a HOST-backed (`HostFile`) input
/// must advance the file's offset across calls. `sendfile_bytes` reads a
/// HostFile via `pread`, which does NOT move the kernel offset, so without the
/// explicit `lseek` advance every call re-sent byte 0 — busybox `cat`, which
/// copies a file with exactly this loop, spun forever re-printing the first
/// chunk. The in-memory `File` variant (covered above) was unaffected; this
/// pins the `HostFile` arm specifically.
#[test]
fn sendfile_null_offset_advances_host_backed_file_across_calls() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::write(scratch.path().join("data"), b"ABCDEFGH").unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = HostFsBackend::from_existing_dir(dir);

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/data\0").unwrap();

    // openat(AT_FDCWD, "/data", O_RDONLY) → first free fd (3); a HostFile.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    // pipe2(O_NONBLOCK) so the reader never blocks between sendfiles.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4100, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4100);

    // Two NULL-offset sendfiles of 4 bytes each must yield the FIRST then the
    // SECOND half — proving the offset advanced rather than re-reading "ABCD".
    let mut sendfile_then_read = |expect: &[u8]| {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        71,
                        SyscallArgs::from([pair.write_fd as u64, 3, 0, 4, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        63,
                        SyscallArgs::from([pair.read_fd as u64, 0x4200, 4, 0, 0, 0])
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), expect);
    };
    sendfile_then_read(b"ABCD");
    sendfile_then_read(b"EFGH"); // pre-fix this re-read "ABCD" (offset stuck at 0)

    // A third sendfile is at EOF → 0 bytes (terminates the copy loop).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(71, SyscallArgs::from([pair.write_fd as u64, 3, 0, 4, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn splice_moves_bytes_between_rootfs_files_pipes_and_stdout() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_u64(&mut memory, 0x4100, 7);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4200, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4200);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    76,
                    SyscallArgs::from(
                        [3, 0x4100, pair.write_fd as u64, 0, 4, LINUX_SPLICE_F_MORE,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(read_u64(&memory, 0x4100), 11);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(76, SyscallArgs::from([pair.read_fd as u64, 0, 1, 0, 4, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(dispatcher.stdout(), b"says");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4300, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"root");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    76,
                    SyscallArgs::from([3, 0, pair.write_fd as u64, 0, 1, 0x10]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn splice_moves_bytes_between_sockets_and_pipes() {
    // Go's io.Copy(pipe, conn) / io.Copy(conn, pipe) splices between a socket
    // and a pipe. socket->pipe was the gap (socket input fell through to the
    // sendfile path and failed); pipe->socket already worked via write_output_fd.
    const LINUX_AF_UNIX: u64 = 1;
    const LINUX_SOCK_STREAM: u64 = 1;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let ret = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| -> i64 {
        match d
            .dispatch(
                SyscallRequest::new(nr, SyscallArgs::from(args)),
                m,
                &reporter,
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } => value,
            other => panic!("nr {nr} unexpected outcome: {other:?}"),
        }
    };

    // socketpair(AF_UNIX, SOCK_STREAM) @0x4000; pipe2 @0x4010.
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            199,
            [LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0, 0x4000, 0, 0]
        ),
        0
    );
    let sock = read_fd_pair(&memory, 0x4000);
    assert_eq!(
        ret(&mut dispatcher, &mut memory, 59, [0x4010, 0, 0, 0, 0, 0]),
        0
    );
    let pipe = read_fd_pair(&memory, 0x4010);

    // socket -> pipe: write "ping" into sock end B, splice sock end A -> pipe
    // write end, read it back off the pipe read end.
    memory.write_bytes(0x4100, b"ping").unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            64,
            [sock.write_fd as u64, 0x4100, 4, 0, 0, 0]
        ),
        4
    );
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            76,
            [sock.read_fd as u64, 0, pipe.write_fd as u64, 0, 4, 0]
        ),
        4,
        "splice socket->pipe must move bytes"
    );
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            63,
            [pipe.read_fd as u64, 0x4200, 4, 0, 0, 0]
        ),
        4
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"ping");

    // pipe -> socket: write "pong" into the pipe, splice pipe read end -> sock
    // end A, recv it on sock end B.
    memory.write_bytes(0x4300, b"pong").unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            64,
            [pipe.write_fd as u64, 0x4300, 4, 0, 0, 0]
        ),
        4
    );
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            76,
            [pipe.read_fd as u64, 0, sock.read_fd as u64, 0, 4, 0]
        ),
        4,
        "splice pipe->socket must move bytes"
    );
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            63,
            [sock.write_fd as u64, 0x4400, 4, 0, 0, 0]
        ),
        4
    );
    assert_eq!(memory.read_bytes(0x4400, 4).unwrap(), b"pong");
}

#[test]
fn inotify_init_add_watch_read_dispatch_plumbing() {
    // The event mechanism itself is unit-tested against a real vnode in
    // src/inotify.rs; here we verify the syscall plumbing at the dispatch seam.
    // The in-memory backend has no host vnode, so watching an existing path is
    // ENOSPC (inotify watches require `--fs host`); we exercise the fd
    // lifecycle and the error paths.
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"hi\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // inotify_init1(IN_NONBLOCK) -> a fresh fd >= 3.
    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => {
            assert!(value >= 3, "init1 fd {value}");
            value as u64
        }
        other => panic!("inotify_init1: {other:?}"),
    };

    // read with no events queued -> EAGAIN (11).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 63, [ifd, 0x4100, 64, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 11 }
    );

    // add_watch on an existing in-memory path -> ENOSPC (28): no host vnode.
    memory.write_bytes(0x4200, b"/etc/motd\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4200, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 28 }
    );

    // add_watch on a nonexistent path -> ENOENT (2).
    memory.write_bytes(0x4280, b"/no/such\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4280, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 2 }
    );

    // add_watch on an empty path -> ENOENT (2); unlike fstatat-style metadata
    // syscalls, inotify_add_watch has no AT_EMPTY_PATH form.
    memory.write_bytes(0x4300, b"\0").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            27,
            [ifd, 0x4300, IN_MODIFY, 0, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 2 }
    );

    // rm_watch of an unknown wd -> EINVAL (22).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 28, [ifd, 99, 0, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 22 }
    );

    // add_watch / rm_watch on a non-inotify fd -> EINVAL (22).
    assert_eq!(
        run(&mut dispatcher, &mut memory, 28, [0, 1, 0, 0, 0, 0]),
        DispatchOutcome::Errno { errno: 22 }
    );
}

#[test]
fn inotify_add_watch_under_bind_mount_uses_host_vnode() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindwatch")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindwatch/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindwatch/watch_file\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4000, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "watch descriptor {value}"),
        other => panic!("inotify_add_watch: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-bindwatch/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(&mut dispatcher, &mut memory, 63, [ifd, 0x4100, 64, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => assert!(value >= 16, "inotify bytes {value}"),
        other => panic!("inotify read after bind write: {other:?}"),
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_cwd_relative_stat_open_mkdir_and_inotify_use_host_tree() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcwd")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindcwd/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindcwd\0")
        .unwrap();
    memory.write_bytes(0x4040, b"child\0").unwrap();
    memory.write_bytes(0x4060, b"child/file.txt\0").unwrap();
    memory.write_bytes(0x4080, b".\0").unwrap();
    memory.write_bytes(0x40a0, b"watch_file\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0],),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindcwd/child").is_dir());
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4060,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [3, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        scratch
            .path()
            .join("nodejs-bindcwd/child/file.txt")
            .is_file()
    );

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4060, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    assert_eq!(stat.st_mode & LINUX_S_IFMT, LINUX_S_IFREG);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            291,
            [
                LINUX_AT_FDCWD,
                0x4080,
                0,
                LINUX_STATX_BASIC_STATS as u64,
                0x4300,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4300);
    assert_eq!(statx.stx_mode as u32 & LINUX_S_IFMT, LINUX_S_IFDIR);

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x40a0, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "file wd {value}"),
        other => panic!("relative inotify_add_watch file: {other:?}"),
    }
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4080, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "dir wd {value}"),
        other => panic!("relative inotify_add_watch cwd: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-bindcwd/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(&mut dispatcher, &mut memory, 63, [ifd, 0x4400, 64, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => assert!(value >= 16, "inotify bytes {value}"),
        other => panic!("relative inotify read after bind write: {other:?}"),
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_directory_inotify_reports_child_file_write_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-binddirwatch")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-binddirwatch/watch_file"),
        b"watch payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-binddirwatch\0")
        .unwrap();
    memory.write_bytes(0x4040, b".\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4040, IN_MODIFY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 1, "dir wd {value}"),
        other => panic!("directory inotify_add_watch: {other:?}"),
    }
    std::fs::write(
        scratch.path().join("nodejs-binddirwatch/watch_file"),
        b"changed payload",
    )
    .unwrap();
    match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4100, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => assert!(value >= 28, "inotify bytes {value}"),
        other => panic!("directory inotify read after child write: {other:?}"),
    }
    let event = memory.read_bytes(0x4100, 32).unwrap();
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "watch_file\0".len(), "name len {name_len}");
    assert_eq!(&event[16..16 + "watch_file".len()], b"watch_file");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn open_o_tmpfile_creates_anonymous_writable_file() {
    // O_TMPFILE returns an unnamed, writable regular file; verify the
    // write -> lseek -> read round-trip, and that O_RDONLY|O_TMPFILE is EINVAL.
    const LINUX_O_RDWR: u64 = 2;
    const LINUX_O_TMPFILE: u64 = 0o20000000;
    const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // openat(AT_FDCWD, <dir>, O_TMPFILE|O_RDWR, 0600); pathname is unused for
    // O_TMPFILE, so a null pointer is fine.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0,
            LINUX_O_TMPFILE | LINUX_O_RDWR,
            0o600,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { value } => {
            assert!(value >= 3, "tmpfile fd {value}");
            value as u64
        }
        other => panic!("openat O_TMPFILE: {other:?}"),
    };

    memory.write_bytes(0x4100, b"hi").unwrap();
    assert_eq!(
        run(&mut dispatcher, &mut memory, 64, [fd, 0x4100, 2, 0, 0, 0]),
        DispatchOutcome::Returned { value: 2 }
    );
    // lseek(fd, 0, SEEK_SET) -> 0
    assert_eq!(
        run(&mut dispatcher, &mut memory, 62, [fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 63, [fd, 0x4200, 2, 0, 0, 0]),
        DispatchOutcome::Returned { value: 2 }
    );
    assert_eq!(memory.read_bytes(0x4200, 2).unwrap(), b"hi");

    // O_TMPFILE requires write access; O_RDONLY|O_TMPFILE is EINVAL.
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [LINUX_AT_FDCWD, 0, LINUX_O_TMPFILE, 0o600, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 22 }
    );
}

#[test]
fn readv_reads_file_across_packed_iovecs() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 6), LinuxIovec::new(0x4300, 4)],
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(65, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    assert_eq!(memory.read_bytes(0x4200, 6).unwrap(), b"rootfs");
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b" say");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readv_reads_host_pipe_across_packed_iovecs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4400, b"abcdefg").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 3), LinuxIovec::new(0x4300, 4)],
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 59, [0x4000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    let write_fd = pair.write_fd as u64;
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            64,
            [write_fd, 0x4400, 7, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 7 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            65,
            [read_fd, 0x4100, 2, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 7 }
    );
    assert_eq!(memory.read_bytes(0x4200, 3).unwrap(), b"abc");
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"defg");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn dup_shares_rootfs_file_offset_with_original_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(23, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([4, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"root");
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"fs s");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn dup3_installs_requested_fd_and_cloexec_is_per_descriptor() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(24, SyscallArgs::from([3, 9, LINUX_O_CLOEXEC, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([9, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_gets_and_sets_descriptor_and_status_flags() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_O_CLOEXEC, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_SETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([3, LINUX_F_DUPFD_CLOEXEC, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([8, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_DUPFD, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn writev_writes_stdout_from_packed_iovecs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4200, b"hello ").unwrap();
    memory.write_bytes(0x4300, b"linux\n").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 6), LinuxIovec::new(0x4300, 6)],
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(66, SyscallArgs::from([1, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 12 }
    );
    assert_eq!(dispatcher.stdout(), b"hello linux\n");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readlinkat_reads_rootfs_symlink_target_without_nul() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("lib/ld-musl-aarch64.so.1", b"loader".as_slice())],
        [("lib/ld-linux-aarch64.so.1", "ld-musl-aarch64.so.1")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory
        .write_bytes(0x4000, b"/lib/ld-linux-aarch64.so.1\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    let target = b"ld-musl-aarch64.so.1";
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: target.len() as i64
        }
    );
    assert_eq!(memory.read_bytes(0x4100, target.len()).unwrap(), target);
    assert_eq!(
        memory.read_bytes(0x4100 + target.len() as u64, 1).unwrap(),
        [0xff]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readlinkat_reports_synthetic_proc_self_exe() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "bin/app",
        b"app".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory.write_bytes(0x4000, b"/proc/self/exe\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert_eq!(memory.read_bytes(0x4100, 8).unwrap(), b"/bin/app");
    assert_eq!(memory.read_bytes(0x4108, 1).unwrap(), [0xff]);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn proc_self_magic_links_readlink_and_lstat() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "bin/app",
        b"app".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x600]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    // readlink /proc/self/cwd → the working dir ("/" by default).
    memory.write_bytes(0x4000, b"/proc/self/cwd\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(out, DispatchOutcome::Returned { value: 1 });
    assert_eq!(memory.read_bytes(0x4100, 1).unwrap(), b"/");

    // readlink /proc/self → the caller's (numeric) pid, even though it is
    // modeled as a traversable directory.
    memory.write_bytes(0x4000, b"/proc/self\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4200, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: n } = out else {
        panic!("readlink /proc/self: {out:?}");
    };
    let pid = String::from_utf8(memory.read_bytes(0x4200, n as usize).unwrap()).unwrap();
    assert!(
        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "/proc/self should readlink to a pid, got {pid:?}"
    );

    // lstat /proc/self/exe → an existing S_IFLNK (was ENOENT before).
    memory.write_bytes(0x4000, b"/proc/self/exe\0").unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                79,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4300, 0x100, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(
        out,
        DispatchOutcome::Returned { value: 0 },
        "lstat exe: {out:?}"
    );
    let st = read_stat(&memory, 0x4300);
    assert_eq!(
        st.st_mode & LINUX_S_IFMT,
        LINUX_S_IFLNK,
        "/proc/self/exe should lstat as a symlink"
    );
}

#[test]
fn proc_self_fd_readlink_synthesizes_anon_inode_target() {
    // An fd with no backing path (here an eventfd) must readlink to the
    // anon_inode:[…] target Linux shows, not an empty string.
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0, 0) = syscall 19.
    let DispatchOutcome::Returned { value: fd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/proc/self/fd/{fd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: n } = out else {
        panic!("readlink /proc/self/fd/{fd}: {out:?}");
    };
    let target = String::from_utf8(memory.read_bytes(0x4100, n as usize).unwrap()).unwrap();
    assert_eq!(target, "anon_inode:[eventfd]");
}

#[test]
fn dev_fd_opens_descriptor_like_proc_self_fd() {
    // /dev/fd is a symlink to /proc/self/fd on Linux; bash process substitution
    // (`cat <(...)`) passes /dev/fd/N to the spawned command, which open()s it to
    // dup the pipe. carrick had no /dev/fd at all → ENOENT, breaking process
    // substitution and the libuv conformance harness. open(/dev/fd/N) must dup
    // fd N (works for an anon/pipe fd with no backing path), exactly like
    // open(/proc/self/fd/N).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0,0) → a non-stdio fd with no backing path (the process-sub case).
    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/dev/fd/{efd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    // openat(AT_FDCWD, "/dev/fd/{efd}", O_RDONLY)
    let out = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: dup_fd } = out else {
        panic!("open(/dev/fd/{efd}) should dup the descriptor, got {out:?}");
    };
    assert!(dup_fd >= 3, "expected a fresh fd, got {dup_fd}");
    assert_ne!(dup_fd, efd, "open(/dev/fd/N) must return a NEW fd");
}

#[test]
fn proc_self_fd_directory_lists_open_fds() {
    // `ls /proc/self/fd` / `for fd in /proc/self/fd/*`: opendir + getdents must
    // enumerate the guest's open fds as symlink entries.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x4000]);
    memory.write_bytes(0x4000, b"/proc/self/fd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // eventfd2(0, 0) = syscall 19 → a non-stdio fd that must appear in the list.
    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    // openat(AT_FDCWD, "/proc/self/fd", O_RDONLY) — a directory open.
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: dirfd } = open else {
        panic!("opendir /proc/self/fd: {open:?}");
    };

    // getdents64(dirfd, buf, count) = syscall 61.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                61,
                SyscallArgs::from([dirfd as u64, 0x4400, 0x1000, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("getdents64 /proc/self/fd: {outcome:?}");
    };
    assert!(value > 0, "getdents should return entries");

    let dirent = memory.read_bytes(0x4400, value as usize).unwrap();
    let mut names: Vec<String> = Vec::new();
    let mut off = 0usize;
    while off < dirent.len() {
        let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent[off..]).unwrap();
        let reclen = header.d_reclen as usize;
        if reclen == 0 {
            break;
        }
        let name_start = off + LINUX_DIRENT64_HEADER_SIZE;
        let name_end = dirent[name_start..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| name_start + p)
            .unwrap();
        names.push(String::from_utf8_lossy(&dirent[name_start..name_end]).into_owned());
        off += reclen;
    }
    // The eventfd and the stdio fds must be listed.
    assert!(
        names.contains(&efd.to_string()),
        "/proc/self/fd should list the eventfd {efd}: {names:?}"
    );
    for stdio in ["0", "1", "2"] {
        assert!(
            names.iter().any(|n| n == stdio),
            "/proc/self/fd should list stdio {stdio}: {names:?}"
        );
    }
}

#[test]
fn proc_self_auxv_refreshes_when_image_state_is_updated() {
    // execve now re-applies the new image's /proc state via the same setters; a
    // second set_auxv_image (as a fresh image would trigger) must be reflected,
    // not stuck on the first image's auxv.
    let read_auxv = |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory| -> Vec<u8> {
        let reporter = CompatReporter::default();
        memory.write_bytes(0x4000, b"/proc/self/auxv\0").unwrap();
        let DispatchOutcome::Returned { value: fd } = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                memory,
                &reporter,
            )
            .unwrap()
        else {
            panic!("open /proc/self/auxv");
        };
        let DispatchOutcome::Returned { value: n } = dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4400, 0x400, 0, 0, 0])),
                memory,
                &reporter,
            )
            .unwrap()
        else {
            panic!("read /proc/self/auxv");
        };
        memory.read_bytes(0x4400, n as usize).unwrap().to_vec()
    };

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let mut dispatcher = SyscallDispatcher::new();

    dispatcher.set_auxv_image(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        read_auxv(&mut dispatcher, &mut memory),
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );

    // A subsequent image (the execve refresh) replaces it.
    dispatcher.set_auxv_image(vec![9, 10, 11, 12]);
    assert_eq!(read_auxv(&mut dispatcher, &mut memory), vec![9, 10, 11, 12]);
}

#[test]
fn proc_self_fdinfo_renders_pos_flags_ino() {
    // proc_pid_fdinfo(5): pos/flags/mnt_id/ino for an fd. libuv/Node read the
    // octal flags to recover an inherited fd's O_NONBLOCK/append/access mode.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let DispatchOutcome::Returned { value: efd } = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    else {
        panic!("eventfd2 should succeed");
    };

    let path = format!("/proc/self/fdinfo/{efd}\0");
    memory.write_bytes(0x4000, path.as_bytes()).unwrap();
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = open else {
        panic!("open /proc/self/fdinfo/{efd}: {open:?}");
    };
    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4400, 0x400, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: nbytes } = read else {
        panic!("read fdinfo: {read:?}");
    };
    let content = String::from_utf8(memory.read_bytes(0x4400, nbytes as usize).unwrap()).unwrap();
    for label in ["pos:\t", "flags:\t0", "mnt_id:\t", "ino:\t"] {
        assert!(
            content.contains(label),
            "fdinfo missing {label:?}: {content:?}"
        );
    }

    // A closed/unopened fd's fdinfo is ENOENT.
    memory
        .write_bytes(0x4000, b"/proc/self/fdinfo/4242\0")
        .unwrap();
    let missing = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(missing, DispatchOutcome::Errno { errno: 2 });
}

#[test]
fn openat_reads_synthetic_proc_maps_and_cpuinfo() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/self/maps\0").unwrap();
    memory.write_bytes(0x4040, b"/proc/cpuinfo\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    let maps_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 0x400, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: maps_len } = maps_read else {
        panic!("expected /proc/self/maps read success, got {maps_read:?}");
    };
    let maps = String::from_utf8(memory.read_bytes(0x4100, maps_len as usize).unwrap()).unwrap();
    assert!(maps.contains(" r-xp "));
    assert!(maps.contains("/proc/self/exe"));
    assert!(maps.contains("[heap]"));
    assert!(maps.ends_with('\n'));

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let cpuinfo_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([4, 0x4500, 0x200, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: cpuinfo_len } = cpuinfo_read else {
        panic!("expected /proc/cpuinfo read success, got {cpuinfo_read:?}");
    };
    let cpuinfo =
        String::from_utf8(memory.read_bytes(0x4500, cpuinfo_len as usize).unwrap()).unwrap();
    assert!(cpuinfo.contains("processor\t: 0"));
    assert!(cpuinfo.contains("CPU architecture: 8"));
    assert!(cpuinfo.contains("Features\t:"));

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert!(report.proc_read_unimplemented.is_empty());
}

#[test]
fn synthetic_proc_surface_serves_common_process_and_system_files() {
    let paths: [(&str, &[u8]); 19] = [
        ("/proc/cmdline", b"BOOT_IMAGE="),
        ("/proc/diskstats", b""),
        ("/proc/filesystems", b"overlay"),
        ("/proc/loadavg", b"0.00"),
        ("/proc/meminfo", b"MemTotal:"),
        ("/proc/mounts", b"overlay / overlay"),
        ("/proc/partitions", b"major minor"),
        ("/proc/stat", b"cpu  "),
        ("/proc/uptime", b" "),
        ("/proc/version", b"Linux version"),
        ("/proc/self/auxv", &[0u8; 16]),
        ("/proc/self/cmdline", b"/proc/self/exe"),
        ("/proc/self/comm", b"exe"),
        ("/proc/self/limits", b"Max open files"),
        ("/proc/self/statm", b"0 0"),
        ("/proc/self/status", b"Name:\texe"),
        ("/proc/sys/kernel/osrelease", b"carrick"),
        // --net=host contract: /proc/sys/kernel/hostname is the live host short
        // name (guest_hostname(), in lockstep with uname nodename), NOT a fixed
        // string. Derive from the single source of truth so any host name passes;
        // it falls back to "carrick" when the host has no usable name.
        (
            "/proc/sys/kernel/hostname",
            carrick_runtime::execute::guest_hostname().as_bytes(),
        ),
        // boot_id is now a random v4 UUID (was an all-zero sentinel); the only
        // value-stable marker is the version-4 nibble at the 3rd group.
        ("/proc/sys/kernel/random/boot_id", b"-4"),
    ];

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let path_address = 0x4000_u64;
    let read_buffer = 0x4400_u64;
    let read_len_max = 0xC00_u64;
    for (next_fd, (path, expected_substr)) in (3_i64..).zip(paths) {
        let path_bytes: Vec<u8> = path.bytes().chain([0]).collect();
        memory.write_bytes(path_address, &path_bytes).unwrap();
        let open = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, path_address, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(
            open,
            DispatchOutcome::Returned { value: next_fd },
            "expected fd {next_fd} for {path}, got {open:?}"
        );
        let read = dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([next_fd as u64, read_buffer, read_len_max, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        let DispatchOutcome::Returned { value: read_len } = read else {
            panic!("expected read success for {path}, got {read:?}");
        };
        let bytes = memory.read_bytes(read_buffer, read_len as usize).unwrap();
        if expected_substr.is_empty() {
            assert_eq!(
                bytes.len(),
                0,
                "{path} expected empty file, got {} bytes",
                bytes.len()
            );
        } else {
            let found = bytes
                .windows(expected_substr.len())
                .any(|window| window == expected_substr);
            assert!(
                found,
                "{path} did not contain {expected_substr:?}: {bytes:?}"
            );
        }
    }

    let report = reporter.finish();
    assert!(report.proc_read_unimplemented.is_empty());
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn synthetic_proc_files_write_regular_packed_stat_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/cpuinfo\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode & 0o777, 0o444);
    assert!(size > 0);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let fd_stat = read_stat(&memory, 0x4200);
    let fd_mode = fd_stat.st_mode;
    let fd_size = fd_stat.st_size;
    assert_eq!(fd_mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(fd_mode & 0o777, 0o444);
    assert_eq!(fd_size, size);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn proc_self_oom_score_adj_is_writable() {
    // systemd/runc write oom_score_adj at startup; carrick accepts-and-ignores
    // the write (no EACCES on open, no EBADF on write) so they don't warn.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory
        .write_bytes(0x4000, b"/proc/self/oom_score_adj\0")
        .unwrap();
    memory.write_bytes(0x4200, b"-1000\n").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // openat(AT_FDCWD, path, O_WRONLY) — must NOT EACCES.
    let open = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 1, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = open else {
        panic!("oom_score_adj should open O_WRONLY, got {open:?}");
    };
    // write(fd, "-1000\n", 6) — accepted, returns the byte count.
    let write = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([fd as u64, 0x4200, 6, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(write, DispatchOutcome::Returned { value: 6 });
}

#[test]
fn missing_proc_file_records_compat_report_entry() {
    // /proc/self/sched is unserved by carrick (and ENOENT in the Docker oracle
    // too), so it stands in as a still-unimplemented proc path for the
    // compat-report wiring.
    let mut memory = LinearMemory::new(0x4000, b"/proc/self/sched\0".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.proc_read_unimplemented[0].path, "/proc/self/sched");
    assert_eq!(report.proc_read_unimplemented[0].count, 1);
}

#[test]
fn synthetic_sys_surface_serves_common_cpu_and_mm_files() {
    let ncpu = carrick_runtime::host_facts::logical_cpu_count();
    let cpu_range = if ncpu <= 1 {
        b"0\n".to_vec()
    } else {
        format!("0-{}\n", ncpu - 1).into_bytes()
    };
    let kernel_max = format!("{}\n", ncpu.max(1) - 1).into_bytes();
    let paths: Vec<(&str, Vec<u8>)> = vec![
        ("/sys/devices/system/cpu/online", cpu_range.clone()),
        ("/sys/devices/system/cpu/possible", cpu_range.clone()),
        ("/sys/devices/system/cpu/present", cpu_range),
        ("/sys/devices/system/cpu/kernel_max", kernel_max),
        ("/sys/devices/system/cpu/cpu0/online", b"1\n".to_vec()),
        (
            "/sys/devices/system/cpu/cpu0/topology/physical_package_id",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/core_id",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
            b"0\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
            b"2400000\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq",
            b"2400000\n".to_vec(),
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq",
            b"600000\n".to_vec(),
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/enabled",
            b"always [madvise] never\n".to_vec(),
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/defrag",
            b"always defer defer+madvise [madvise] never\n".to_vec(),
        ),
        (
            "/sys/kernel/random/uuid",
            b"00000000-0000-4000-8000-000000000000\n".to_vec(),
        ),
        (
            "/sys/kernel/random/boot_id",
            b"00000000-0000-4000-8000-000000000000\n".to_vec(),
        ),
        ("/sys/fs/cgroup/cgroup.controllers", b"\n".to_vec()),
    ];

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let path_address = 0x4000_u64;
    let read_buffer = 0x4400_u64;
    let read_len_max = 0xC00_u64;
    for (next_fd, (path, expected)) in (3_i64..).zip(paths) {
        let path_bytes: Vec<u8> = path.bytes().chain([0]).collect();
        memory.write_bytes(path_address, &path_bytes).unwrap();
        let open = dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, path_address, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(
            open,
            DispatchOutcome::Returned { value: next_fd },
            "expected fd {next_fd} for {path}, got {open:?}"
        );
        let read = dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([next_fd as u64, read_buffer, read_len_max, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        let DispatchOutcome::Returned { value: read_len } = read else {
            panic!("expected read success for {path}, got {read:?}");
        };
        let bytes = memory.read_bytes(read_buffer, read_len as usize).unwrap();
        assert_eq!(
            bytes.as_slice(),
            expected.as_slice(),
            "{path} content mismatch: got {bytes:?}"
        );
    }

    let report = reporter.finish();
    assert!(report.sys_read_unimplemented.is_empty());
    assert!(report.proc_read_unimplemented.is_empty());
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn missing_sys_file_records_compat_report_entry() {
    let mut memory = LinearMemory::new(
        0x4000,
        b"/sys/devices/virtual/dmi/id/product_uuid\0".to_vec(),
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(
        report.sys_read_unimplemented[0].path,
        "/sys/devices/virtual/dmi/id/product_uuid"
    );
    assert_eq!(report.sys_read_unimplemented[0].count, 1);
}

#[test]
fn newfstatat_and_fstat_write_typed_linux_stat() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(size, 18);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(size, 18);

    memory.write_bytes(0x4300, b"/etc\0").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4300, 0x4400, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4400);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
}

#[test]
fn statx_writes_basic_rootfs_fd_and_symlink_metadata() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("etc/motd", b"rootfs says hello\n".as_slice())],
        [("etc/motd-link", "motd")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x700]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd-link\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4100,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4100);
    let mask = statx.stx_mask;
    let blksize = statx.stx_blksize;
    let mode = statx.stx_mode;
    let nlink = statx.stx_nlink;
    let uid = statx.stx_uid;
    let gid = statx.stx_gid;
    let size = statx.stx_size;
    let blocks = statx.stx_blocks;
    assert_eq!(mask & LINUX_STATX_BASIC_STATS, LINUX_STATX_BASIC_STATS);
    assert_eq!(blksize, 4096);
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode as u32 & 0o777, 0o644);
    assert_eq!(nlink, 1);
    assert_eq!(uid, 0);
    assert_eq!(gid, 0);
    assert_eq!(size, 18);
    assert_eq!(blocks, 1);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        3,
                        0x4040,
                        LINUX_AT_EMPTY_PATH,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4200,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4200);
    let mode = statx.stx_mode;
    let size = statx.stx_size;
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(size, 18);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4020,
                        LINUX_AT_SYMLINK_NOFOLLOW,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4300,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statx = read_statx(&memory, 0x4300);
    let mode = statx.stx_mode;
    let size = statx.stx_size;
    assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFLNK);
    assert_eq!(size, 4);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_RESERVED,
                        0x4400,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0x80,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x4400,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        0,
                        LINUX_STATX_BASIC_STATS as u64,
                        0x5000,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn host_stat_following_symlink_reports_target_inode() {
    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = HostFsBackend::from_existing_dir(dir);
    backend.make_dir("/tmp").unwrap();
    backend.make_dir("/target").unwrap();
    backend.symlink("/target", "/tmp/link").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/target\0").unwrap();
    memory.write_bytes(0x4020, b"/tmp/link\0").unwrap();

    for (path_addr, stat_addr, flags) in [
        (0x4000, 0x4100, 0),
        (0x4020, 0x4200, 0),
        (0x4020, 0x4300, LINUX_AT_SYMLINK_NOFOLLOW),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        79,
                        SyscallArgs::from([(-100_i64) as u64, path_addr, stat_addr, flags, 0, 0,]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
    }

    let target = read_stat(&memory, 0x4100);
    let followed_link = read_stat(&memory, 0x4200);
    let link = read_stat(&memory, 0x4300);
    assert_eq!(target.st_mode & LINUX_S_IFMT, LINUX_S_IFDIR);
    assert_eq!(followed_link.st_mode & LINUX_S_IFMT, LINUX_S_IFDIR);
    assert_eq!(link.st_mode & LINUX_S_IFMT, LINUX_S_IFLNK);
    let target_ino = target.st_ino;
    let followed_link_ino = followed_link.st_ino;
    let link_ino = link.st_ino;
    assert_eq!(target_ino, followed_link_ino);
    assert_ne!(target_ino, link_ino);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

fn assert_fstat_and_statx_empty_path_agree(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    reporter: &CompatReporter,
    fd: i32,
    expected_mode_type: u32,
) {
    let stat_addr = 0x7000;
    let statx_addr = 0x7200;
    memory.write_bytes(0x7400, b"\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([fd as u64, stat_addr, 0, 0, 0, 0])),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    291,
                    SyscallArgs::from([
                        fd as u64,
                        0x7400,
                        LINUX_AT_EMPTY_PATH,
                        LINUX_STATX_BASIC_STATS as u64,
                        statx_addr,
                        0,
                    ]),
                ),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let stat = read_stat(memory, stat_addr);
    let statx = read_statx(memory, statx_addr);
    let stat_mode = stat.st_mode;
    let stat_size = stat.st_size;
    let stat_nlink = stat.st_nlink;
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    let stat_blocks = stat.st_blocks;
    let statx_mode = statx.stx_mode;
    let statx_size = statx.stx_size;
    let statx_nlink = statx.stx_nlink;
    let statx_uid = statx.stx_uid;
    let statx_gid = statx.stx_gid;
    let statx_blocks = statx.stx_blocks;
    assert_eq!(stat_mode, statx_mode as u32, "fd {fd} mode");
    assert_eq!(stat_mode & LINUX_S_IFMT, expected_mode_type, "fd {fd} type");
    assert_eq!(stat_size as u64, statx_size, "fd {fd} size");
    assert_eq!(stat_nlink, statx_nlink, "fd {fd} nlink");
    assert_eq!(stat_uid, statx_uid, "fd {fd} uid");
    assert_eq!(stat_gid, statx_gid, "fd {fd} gid");
    assert_eq!(stat_blocks as u64, statx_blocks, "fd {fd} blocks");
}

#[test]
fn fstat_and_statx_empty_path_agree_for_anonymous_fd_kinds() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x4000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let eventfd = dispatcher
        .dispatch(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: eventfd } = eventfd else {
        panic!("expected eventfd2 success, got {eventfd:?}");
    };

    let timerfd = dispatcher
        .dispatch(
            SyscallRequest::new(85, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: timerfd } = timerfd else {
        panic!("expected timerfd_create success, got {timerfd:?}");
    };

    let epoll = dispatcher
        .dispatch(
            SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: epoll } = epoll else {
        panic!("expected epoll_create1 success, got {epoll:?}");
    };

    let pipe_addr = 0x7600;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([pipe_addr, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pipe = read_fd_pair(&memory, pipe_addr);

    let socket = dispatcher
        .dispatch(
            SyscallRequest::new(
                198,
                SyscallArgs::from([
                    LINUX_AF_INET as u64,
                    (LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK) as u64,
                    0,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: socket } = socket else {
        panic!("expected socket success, got {socket:?}");
    };

    for fd in [eventfd, timerfd, epoll] {
        assert_fstat_and_statx_empty_path_agree(
            &mut dispatcher,
            &mut memory,
            &reporter,
            fd as i32,
            0,
        );
    }
    for fd in [pipe.read_fd, pipe.write_fd] {
        assert_fstat_and_statx_empty_path_agree(
            &mut dispatcher,
            &mut memory,
            &reporter,
            fd,
            LINUX_S_IFIFO,
        );
    }
    assert_fstat_and_statx_empty_path_agree(
        &mut dispatcher,
        &mut memory,
        &reporter,
        socket as i32,
        LINUX_S_IFSOCK,
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getdents64_lists_rootfs_directory_entries() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("expected getdents64 success, got {outcome:?}");
    };
    // A real Linux directory lists `.` and `..` first, then its entries, so the
    // listing is the three records ., .., motd.
    assert!(value as usize > LINUX_DIRENT64_HEADER_SIZE + "motd".len());

    let dirent = memory.read_bytes(0x4100, value as usize).unwrap();
    // Parse every dirent64 record and collect (name, d_type).
    let mut entries: Vec<(String, u8)> = Vec::new();
    let mut off = 0usize;
    while off < dirent.len() {
        let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent[off..]).unwrap();
        let reclen = header.d_reclen as usize;
        assert!(reclen > 0 && off + reclen <= dirent.len());
        let name_start = off + LINUX_DIRENT64_HEADER_SIZE;
        let name_end = dirent[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .unwrap();
        entries.push((
            String::from_utf8_lossy(&dirent[name_start..name_end]).into_owned(),
            header.d_type,
        ));
        off += reclen;
    }
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == "." && *t == 4u8 /* DT_DIR */)
    );
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == ".." && *t == 4u8 /* DT_DIR */)
    );
    assert!(
        entries
            .iter()
            .any(|(n, t)| n == "motd" && *t == LINUX_DT_REG)
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[test]
fn fchown_and_fchownat_succeed_on_writable_overlay_and_validate_args() {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fchown fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(55, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // The rootfs is backed by a writable overlay (tmpfs-like; owner/mode are
        // not tracked) and the guest runs as root, so fchown is accepted as a
        // no-op success rather than the obsolete read-only-rootfs EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(55, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchownat on an existing path: no-op success on the writable overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(54, SyscallArgs::from([3, 0x4040, 0, 0, AT_EMPTY_PATH, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchownat(AT_EMPTY_PATH) on an open fd: no-op success on the overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    54,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0xdead, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fchmod_and_fchmodat_succeed_on_writable_overlay_and_validate_args() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fchmod fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(52, SyscallArgs::from([1, 0o644, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Writable overlay + root guest: fchmod succeeds (no-op on the
        // tmpfs-like backend) instead of the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(52, SyscallArgs::from([99, 0o644, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fchmodat on an existing path applies to the writable overlay backend
        // and succeeds.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux and IGNORES
    // the 4th register, so a non-zero flags value must NOT fail. glibc leaves
    // AT_SYMLINK_NOFOLLOW (0x100) there — `apt-get update` issues exactly
    // fchmodat(AT_FDCWD, path, 0644, 0x100) on every downloaded index, and the
    // real kernel succeeds. (We previously returned EINVAL here, which made
    // every apt download chmod fail.)
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    53,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o644, 0x100, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // fchmodat2 (452) with a real flags argument also applies the mode.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    452,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o600, 0x100, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn linkat_reports_eexist_enoent_and_links_into_writable_overlay() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"linkat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/new-link\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4000, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4040, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Hard-linking an existing file to a new name lands in the writable
        // overlay (the backend's hard_link), so it succeeds rather than
        // reporting the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4020, (-100_i64) as u64, 0x4040, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4060, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        (-100_i64) as u64,
                        0x4040,
                        0xdead,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn symlinkat_bootstrap_reports_eexist_for_known_links_and_erofs_for_new_paths() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"symlinkat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"target\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/new-link\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4020, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4040, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 30 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4060, (-100_i64) as u64, 0x4040, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, (-100_i64) as u64, 0x4060, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn renameat_renames_known_sources_into_overlay_and_enoent_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"renameat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/motd.bak\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Renaming an existing rootfs file copies it up into the writable
        // overlay and renames there, so it succeeds rather than the obsolete
        // read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4040, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4060, (-100_i64) as u64, 0x4020, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from(
                        [(-100_i64) as u64, 0x4000, (-100_i64) as u64, 0x4060, 0, 0,]
                    ),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unlinkat_removes_files_on_overlay_and_validates_directory_kind() {
    const AT_REMOVEDIR: u64 = 0x200;
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [
            ("etc/motd", b"unlinkat fixture\n".as_slice()),
            ("etc/conf.d/.gitkeep", b"".as_slice()),
        ],
        [],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/conf.d\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    // unlinkat(AT_REMOVEDIR) on a regular file is ENOTDIR (checked while motd
    // still exists, before the destructive unlink below).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 20 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Unlinking an existing file records a whiteout/tombstone in the
        // writable overlay and succeeds, instead of the obsolete read-only
        // EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    // unlinkat without AT_REMOVEDIR on a directory is EISDIR.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 21 }
    );
    // rmdir of a non-empty directory (/etc/conf.d holds .gitkeep) is ENOTEMPTY,
    // matching real Linux on the writable overlay (no longer read-only EROFS).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 39 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4060, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0xdead, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mknodat_returns_eexist_for_known_paths_and_creates_in_overlay_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"mknodat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/new-node\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // mknod with an S_IFREG (regular-file) mode on a new path materialises
        // an empty file in the writable overlay and succeeds, rather than the
        // obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    33,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o100644, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mkdirat_returns_eexist_for_known_paths_and_creates_in_overlay_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"mkdirat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/new-dir\0").unwrap();
    memory.write_bytes(0x4040, b"\0").unwrap();
    memory.write_bytes(0x4060, b"/proc/self/maps\0").unwrap();
    memory.write_bytes(0x4080, b"relative/dir\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4060, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 17 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // mkdir on a new path under an existing parent creates the directory in
        // the writable overlay and succeeds, rather than the obsolete EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(34, SyscallArgs::from([99, 0x4080, 0o755, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mkdirat_under_bind_mount_creates_host_directory_for_openat_children() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/tmp/nodejs-bindcp\0").unwrap();
    memory
        .write_bytes(0x4020, b"/tmp/nodejs-bindcp/test\0")
        .unwrap();
    memory
        .write_bytes(0x4060, b"/tmp/nodejs-bindcp/test/file.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0o700, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindcp/test").is_dir());

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([
                        LINUX_AT_FDCWD,
                        0x4060,
                        LINUX_O_CREAT | LINUX_O_RDWR,
                        0o644,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert!(scratch.path().join("nodejs-bindcp/test/file.txt").is_file());
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(35, SyscallArgs::from([LINUX_AT_FDCWD, 0x4060, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindcp/test/file.txt").exists());
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    35,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, LINUX_AT_REMOVEDIR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindcp/test").exists());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_create_stamps_guest_owner_on_files_and_directories() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindowner\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindowner/file.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4080, b"/tmp/nodejs-bindowner/dir\0")
        .unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 144, [1001, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4080, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4040,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [3, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4040, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let file_stat = read_stat(&memory, 0x4100);
    let file_uid = file_stat.st_uid;
    let file_gid = file_stat.st_gid;
    assert_eq!(file_uid, 1000);
    assert_eq!(file_gid, 1001);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4080, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let dir_stat = read_stat(&memory, 0x4200);
    let dir_uid = dir_stat.st_uid;
    let dir_gid = dir_stat.st_gid;
    assert_eq!(dir_uid, 1000);
    assert_eq!(dir_gid, 1001);

    assert!(scratch.path().join("nodejs-bindowner/file.txt").is_file());
    assert!(scratch.path().join("nodejs-bindowner/dir").is_dir());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_directory_inotify_reports_created_child_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    const IN_CREATE: u64 = 0x100;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcreate")).unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindcreate/watch_dir")).unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindcreate/watch_dir\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindcreate/watch_dir/fsevent-0\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    let wd = match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4000, IN_MODIFY | IN_CREATE, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("directory inotify_add_watch: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4040,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [4, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4200, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("directory inotify read after child create: {other:?}"),
    };
    assert!(n >= 28, "inotify bytes {n}");
    let event = memory.read_bytes(0x4200, n).unwrap();
    let got_wd = i32::from_ne_bytes(event[0..4].try_into().unwrap());
    assert_eq!(got_wd, wd);
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "fsevent-0\0".len(), "name len {name_len}");
    let name = &event[16..16 + "fsevent-0".len()];
    assert_eq!(name, b"fsevent-0");

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn host_overlay_directory_inotify_reports_created_child_name() {
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_MODIFY: u64 = 0x2;
    const IN_CREATE: u64 = 0x100;
    let scratch_root = tempfile::TempDir::new().unwrap();
    let backend = HostFsBackend::new_in(scratch_root.path()).unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/nodejs-hostcreate\0").unwrap();
    memory
        .write_bytes(0x4040, b"/nodejs-hostcreate/watch_dir\0")
        .unwrap();
    memory
        .write_bytes(0x4080, b"/nodejs-hostcreate/watch_dir/fsevent-0\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    let ifd = match run(
        &mut dispatcher,
        &mut memory,
        26,
        [IN_NONBLOCK, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("inotify_init1: {other:?}"),
    };
    let wd = match run(
        &mut dispatcher,
        &mut memory,
        27,
        [ifd, 0x4040, IN_MODIFY | IN_CREATE, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("directory inotify_add_watch: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [
                LINUX_AT_FDCWD,
                0x4080,
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o644,
                0,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 57, [4, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    let n = match run(
        &mut dispatcher,
        &mut memory,
        63,
        [ifd, 0x4200, 128, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as usize,
        other => panic!("directory inotify read after child create: {other:?}"),
    };
    assert!(n >= 28, "inotify bytes {n}");
    let event = memory.read_bytes(0x4200, n).unwrap();
    let got_wd = i32::from_ne_bytes(event[0..4].try_into().unwrap());
    assert_eq!(got_wd, wd);
    let name_len = u32::from_ne_bytes(event[12..16].try_into().unwrap()) as usize;
    assert!(name_len >= "fsevent-0\0".len(), "name len {name_len}");
    let name = &event[16..16 + "fsevent-0".len()];
    assert_eq!(name, b"fsevent-0");

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn bind_mount_repeated_relative_stat_after_guest_mkdir_uses_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindstat\0")
        .unwrap();
    memory.write_bytes(0x4040, b"test_dir\0").unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 144, [1001, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 49, [0x4000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4040, 0o755, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(scratch.path().join("nodejs-bindstat/test_dir").is_dir());

    for _ in 0..300 {
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                79,
                [LINUX_AT_FDCWD, 0x4040, 0x4200, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let stat = read_stat(&memory, 0x4200);
        let mode = stat.st_mode;
        let uid = stat.st_uid;
        let gid = stat.st_gid;
        assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1001);
    }

    for _ in 0..300 {
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                291,
                [
                    LINUX_AT_FDCWD,
                    0x4040,
                    0,
                    LINUX_STATX_BASIC_STATS as u64,
                    0x4380,
                    0,
                ],
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let statx = read_statx(&memory, 0x4380);
        let mode = statx.stx_mode;
        let uid = statx.stx_uid;
        let gid = statx.stx_gid;
        assert_eq!(mode as u32 & LINUX_S_IFMT, LINUX_S_IFDIR);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1001);
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn renameat_under_bind_mount_moves_host_entries() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindmv")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindmv/old.txt"),
        b"rename payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindmv/old.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindmv/new.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    38,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4040, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindmv/old.txt").exists());
    assert_eq!(
        std::fs::read(scratch.path().join("nodejs-bindmv/new.txt")).unwrap(),
        b"rename payload"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn symlinkat_and_readlinkat_under_bind_mount_use_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"target-name\0").unwrap();
    memory.write_bytes(0x4020, b"/tmp/nodejs-bindln\0").unwrap();
    memory
        .write_bytes(0x4060, b"/tmp/nodejs-bindln/link\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    34,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4020, 0o755, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    36,
                    SyscallArgs::from([0x4000, LINUX_AT_FDCWD, 0x4060, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::read_link(scratch.path().join("nodejs-bindln/link")).unwrap(),
        std::path::PathBuf::from("target-name")
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    78,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4060, 0x4100, 64, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 11 }
    );
    assert_eq!(memory.read_bytes(0x4100, 11).unwrap(), b"target-name");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn linkat_and_unlinkat_under_bind_mount_use_host_tree() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindhard")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindhard/source.txt"),
        b"hard payload",
    )
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindhard/source.txt\0")
        .unwrap();
    memory
        .write_bytes(0x4040, b"/tmp/nodejs-bindhard/linked.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    37,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4040, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::read(scratch.path().join("nodejs-bindhard/linked.txt")).unwrap(),
        b"hard payload"
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(35, SyscallArgs::from([LINUX_AT_FDCWD, 0x4040, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!scratch.path().join("nodejs-bindhard/linked.txt").exists());
    assert!(scratch.path().join("nodejs-bindhard/source.txt").exists());
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn chmod_and_fchmod_under_bind_mount_update_host_mode() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindchmod")).unwrap();
    let host_file = scratch.path().join("nodejs-bindchmod/file.txt");
    std::fs::write(&host_file, b"chmod payload").unwrap();
    std::fs::set_permissions(&host_file, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindchmod/file.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            53,
            [LINUX_AT_FDCWD, 0x4000, 0o600, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::metadata(&host_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    assert_eq!(stat.st_mode & 0o777, 0o600);

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat bind file: {other:?}"),
    };
    assert_eq!(
        run(&mut dispatcher, &mut memory, 52, [fd, 0o640, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        std::fs::metadata(&host_file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 80, [fd, 0x4200, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    assert_eq!(stat.st_mode & 0o777, 0o640);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn utimensat_under_bind_mount_updates_host_times() {
    use std::os::unix::fs::MetadataExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindutime")).unwrap();
    let host_file = scratch.path().join("nodejs-bindutime/file.txt");
    std::fs::write(&host_file, b"utime payload").unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindutime/file.txt\0")
        .unwrap();
    let times = 0x4100;
    write_linux_timespec(&mut memory, times, 123, 456);
    write_linux_timespec(&mut memory, times + 16, 789, 12);

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            88,
            [LINUX_AT_FDCWD, 0x4000, times, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let host_meta = std::fs::metadata(&host_file).unwrap();
    assert_eq!(host_meta.atime(), 123);
    assert_eq!(host_meta.mtime(), 789);

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4200, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let st_atime = stat.st_atime;
    let st_mtime = stat.st_mtime;
    assert_eq!(st_atime, 123);
    assert_eq!(st_mtime, 789);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn non_root_chown_under_bind_mount_to_root_returns_eperm() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindchown")).unwrap();
    std::fs::write(
        scratch.path().join("nodejs-bindchown/file.txt"),
        b"chown payload",
    )
    .unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindchown/file.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(&mut dispatcher, &mut memory, 146, [1000, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            54,
            [LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0],
        ),
        DispatchOutcome::Errno { errno: 1 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn root_chown_under_bind_mount_records_guest_owner_without_host_chown() {
    use std::os::unix::fs::MetadataExt;

    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindrootchown")).unwrap();
    let host_file = scratch.path().join("nodejs-bindrootchown/file.txt");
    std::fs::write(&host_file, b"root chown payload").unwrap();
    let host_before = std::fs::metadata(&host_file).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory
        .write_bytes(0x4000, b"/tmp/nodejs-bindrootchown/file.txt\0")
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            54,
            [LINUX_AT_FDCWD, 0x4000, 1000, 1001, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    let host_after = std::fs::metadata(&host_file).unwrap();
    assert_eq!(host_after.uid(), host_before.uid());
    assert_eq!(host_after.gid(), host_before.gid());

    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4100, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    assert_eq!(stat_uid, 1000);
    assert_eq!(stat_gid, 1001);

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat bind file: {other:?}"),
    };
    assert_eq!(
        run(&mut dispatcher, &mut memory, 55, [fd, 1002, 1003, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 80, [fd, 0x4200, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let stat_uid = stat.st_uid;
    let stat_gid = stat.st_gid;
    assert_eq!(stat_uid, 1002);
    assert_eq!(stat_gid, 1003);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn utimensat_sets_times_on_writable_overlay_and_validates_timestamps() {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;

    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"utimensat fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/missing\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let now_pair = 0x4100;
    write_linux_timespec(&mut memory, now_pair, 0, UTIME_NOW);
    write_linux_timespec(&mut memory, now_pair + 16, 0, UTIME_NOW);
    let omit_pair = 0x4140;
    write_linux_timespec(&mut memory, omit_pair, 0, UTIME_OMIT);
    write_linux_timespec(&mut memory, omit_pair + 16, 0, 1_000_000_001);
    let valid_pair = 0x4180;
    write_linux_timespec(&mut memory, valid_pair, 123, 456);
    write_linux_timespec(&mut memory, valid_pair + 16, 789, 12);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, valid_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // Setting explicit atime/mtime on an existing file persists to the
        // writable overlay backend (no-op on the in-memory backend) and
        // succeeds, instead of the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, now_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // UTIME_NOW on an existing file: success on the writable overlay.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // NULL times (set both to now) on an existing file: success.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4020, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, valid_pair, 0xdead, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    88,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, omit_pair, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(88, SyscallArgs::from([(-100_i64) as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(88, SyscallArgs::from([3, 0, valid_pair, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // futimens form (pathname == NULL with a valid open fd): success on the
        // writable overlay rather than the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(88, SyscallArgs::from([99, 0, valid_pair, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn truncate_bootstrap_returns_erofs_for_known_paths_and_enoent_for_missing() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([
        ("etc/motd", b"truncate fixture\n".as_slice()),
        ("etc/dir/.gitkeep", b"".as_slice()),
    ]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"/etc/dir\0").unwrap();
    memory.write_bytes(0x4040, b"/etc/missing\0").unwrap();
    memory.write_bytes(0x4060, b"\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 30 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 21 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4040, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4060, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(45, SyscallArgs::from([0x4000, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn xattr_family_dispatches_per_target_on_in_memory_backend() {
    // The xattr family is fully wired (no longer a blanket ENOTSUP stub):
    // path/fd targets are resolved BEFORE the attribute store is consulted.
    // Linux resolves the path first for every *xattr syscall, so a path that
    // does not exist is ENOENT — for set/get/list AND remove alike (Docker
    // linux/arm64 debian:stable: set/get/list/removexattr on a missing path
    // all return errno 2). The fd-variants validate the fd first and report
    // EBADF for an unopened descriptor. The real `user.*` round-trip on an
    // existing file is exercised against the host backend by the conformance
    // suite; here we pin the in-memory dispatch ordering.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"user.test\0").unwrap();
    memory.write_bytes(0x4040, b"data").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Path-variants set/get/list (5,6 set; 8,9 get; 11,12 list) and the
    // remove*xattr path variants (14,15) all resolve the path first; /etc/motd
    // is absent on the bare in-memory backend, so each is ENOENT. Args:
    // (path, name, value, size).
    for number in [5, 6, 8, 9, 11, 12, 14, 15] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        number,
                        SyscallArgs::from([0x4000, 0x4020, 0x4040, 4, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 2 },
            "path-variant xattr syscall {number} on a missing path should be ENOENT"
        );
    }

    // Fd-variants (7 fsetxattr, 10 fgetxattr, 13 flistxattr) validate the fd
    // before anything else: an unopened fd is EBADF.
    // 16 fremovexattr is also an fd variant: the unopened fd 0x4000 is
    // validated before path resolution, so EBADF wins.
    for number in [7, 10, 13, 16] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        number,
                        SyscallArgs::from([0x4000, 0x4020, 0x4040, 4, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 9 },
            "fd-variant syscall {number} should return EBADF for an unopened fd"
        );
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fallocate_grows_open_files_on_writable_overlay_and_validates_arguments() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"fallocate fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([999, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0xdead, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([1, 0, (-1_i64) as u64, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(47, SyscallArgs::from([3, 0, 0, 4096, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        // fallocate on an open regular file grows it in the writable overlay
        // (in-memory backend resizes the cached bytes) and succeeds, instead of
        // the obsolete read-only EROFS.
        DispatchOutcome::Returned { value: 0 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ftruncate_bootstrap_rejects_streams_and_read_only_rootfs_fds() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"ftruncate fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([2, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([1, (-1_i64) as u64, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(46, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ftruncate_rejects_unbounded_in_memory_file_growth() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/big\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([
                        (-100_i64) as u64,
                        0x4000,
                        LINUX_O_CREAT | LINUX_O_RDWR,
                        0o644,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    46,
                    SyscallArgs::from([3, MAX_IN_MEMORY_FILE_SIZE + 1, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EFBIG }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pwritev_bootstrap_validates_iovecs_and_reports_stream_errors() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"pwritev fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4200, b"head").unwrap();
    memory.write_bytes(0x4300, b"tailpiece").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 9)],
    );
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([1, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([2, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([99, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([1, 0x4100, 2, (-1_i64) as u64, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    write_iovecs(
        &mut memory,
        0x4150,
        [LinuxIovec::new(0xdead_0000, 4), LinuxIovec::new(0x4300, 9)],
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([1, 0x4150, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pwrite64_bootstrap_returns_espipe_for_streams_and_ebadf_for_rootfs_fds() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"pwrite fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4100, b"payload!").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(68, SyscallArgs::from([1, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(68, SyscallArgs::from([2, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(68, SyscallArgs::from([99, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(68, SyscallArgs::from([1, 0x4100, 8, (-1_i64) as u64, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(68, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    let pipe_pair_address = 0x4180;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([pipe_pair_address, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, pipe_pair_address);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    68,
                    SyscallArgs::from([pair.write_fd as u64, 0x4100, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    68,
                    SyscallArgs::from([pair.read_fd as u64, 0x4100, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 29 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sync_and_fsync_family_return_zero_for_valid_fds_and_ebadf_otherwise() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"sync fixture\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(81, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(82, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(83, SyscallArgs::from([2, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(82, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(83, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(82, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(83, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn fsync_family_flushes_host_backed_files() {
    use carrick_runtime::fs_backend::HostFsBackend;

    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/durable.log\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0o100 | 0o2, 0o644, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    memory.write_bytes(0x4040, b"durable").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4040, 7, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 7 }
    );
    for syscall in [82, 83, 267] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(syscall, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 },
            "syscall {syscall} should flush host-backed fd"
        );
    }
    assert_eq!(
        std::fs::read(scratch.path().join("durable.log")).unwrap(),
        b"durable"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn copy_file_range_uses_darwin_fast_path_for_whole_host_files() {
    use carrick_runtime::fs_backend::HostFsBackend;

    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/source.bin\0").unwrap();
    memory.write_bytes(0x4020, b"/dest.bin\0").unwrap();

    for (path, expected_fd) in [(0x4000, 3), (0x4020, 4)] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        56,
                        SyscallArgs::from([(-100_i64) as u64, path, 0o100 | 0o2, 0o644, 0, 0,]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected_fd }
        );
    }

    memory
        .write_bytes(0x4100, b"copyfile-backed copy\n")
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4100, 21, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 21 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(62, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(285, SyscallArgs::from([3, 0, 4, 0, 21, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 21 }
    );
    assert_eq!(
        std::fs::read(scratch.path().join("dest.bin")).unwrap(),
        b"copyfile-backed copy\n"
    );
    for fd in [3, 4] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(62, SyscallArgs::from([fd, 0, 1, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 21 }
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_on_bare_stdio_succeeds_not_ebadf() {
    // Regression: F_SETFL on bare stdio (fd 0/1/2, which have no
    // OpenDescription in open_files) used to return EBADF, while
    // F_GETFD/F_SETFD/F_GETFL all special-cased stdio. apt's dpkg child sets
    // stdin non-blocking via fcntl(0, F_SETFL, O_NONBLOCK) before exec and
    // treated the EBADF as fatal (_exit(100)) — it broke `apt install`.
    const LINUX_F_SETFL: u64 = 4;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x40]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    for fd in [0u64, 1, 2] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        25,
                        SyscallArgs::from([fd, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 },
            "fcntl(F_SETFL, O_NONBLOCK) on stdio fd {fd} must succeed, not EBADF",
        );
        for cmd in [LINUX_F_GETFD, LINUX_F_GETFL] {
            let outcome = dispatcher
                .dispatch(
                    SyscallRequest::new(25, SyscallArgs::from([fd, cmd, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(
                matches!(outcome, DispatchOutcome::Returned { .. }),
                "fcntl(cmd {cmd}) on stdio fd {fd} must not error: {outcome:?}",
            );
        }
    }

    // A genuinely invalid fd still returns EBADF (we didn't blanket-accept).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([999, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 },
        "fcntl(F_SETFL) on an invalid fd must still be EBADF",
    );
}

#[test]
fn ptmx_tiocgptn_returns_index_and_tcgets_succeeds() {
    // SyscallDispatcher::new() mounts /dev (including /dev/ptmx) and /dev/pts
    // as part of FsState::new(), so no rootfs is needed.
    let mut dispatcher = SyscallDispatcher::new();
    // Layout: path at 0x4000, output slots above that.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2)
    let fd = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // ioctl(fd, TIOCGPTN, &out) → index 0 (first pty allocated)
    let out_ptr = 0x4100u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd, LINUX_TIOCGPTN, out_ptr, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCGPTN must succeed"
    );
    assert_eq!(
        memory.read_bytes(out_ptr, 4).unwrap(),
        0u32.to_le_bytes(),
        "TIOCGPTN must write index 0"
    );

    // unlockpt: TIOCSPTLCK with *arg == 0 succeeds.
    let lockarg = 0x4300u64;
    memory.write_bytes(lockarg, &0i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd, LINUX_TIOCSPTLCK, lockarg, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSPTLCK unlock must succeed"
    );

    // ioctl(fd, TCGETS, &buf) must NOT return ENOTTY — it must return 0
    let buf_ptr = 0x4200u64;
    let r = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([fd, LINUX_TCGETS, buf_ptr, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(
        matches!(r, DispatchOutcome::Returned { .. }),
        "TCGETS on ptmx must succeed, got: {:?}",
        r
    );
}

#[test]
fn closing_ptmx_master_removes_pts_entry() {
    // SyscallDispatcher::new() mounts /dev (including /dev/ptmx) and
    // /dev/pts as part of FsState::new(), so no rootfs is needed.
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    // open /dev/ptmx (O_RDWR=2) -> master fd; allocates pts index 0.
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // Unlock the slave so open succeeds (TIOCSPTLCK with *arg == 0).
    let lockarg = 0x4100u64;
    memory.write_bytes(lockarg, &0i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCSPTLCK, lockarg, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSPTLCK unlock must succeed"
    );

    // /dev/pts/0 should open successfully before the master is closed.
    assert!(
        matches!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        56,
                        SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { .. }
        ),
        "slave should open before master close"
    );

    // close(master) — this must remove pts index 0 from the PtyTable.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([master, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "close(master) must succeed"
    );

    // Now /dev/pts/0 must be ENOENT (errno 2): the table entry was removed.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 },
        "/dev/pts/0 must be ENOENT after master close"
    );
}

#[test]
fn pty_master_slave_data_roundtrip() {
    // Prove that pty fds are bidirectional: a write(slave, …) is
    // readable on the master.  Direction chosen: slave→master avoids
    // the canonical-mode line-discipline requirement (a newline would
    // be needed before data is visible to a slave reader in cooked
    // mode).  We exercise the write handler on the slave fd (was
    // incorrectly gated by is_read_end) and the read handler on the
    // master fd (already worked but re-confirmed here).
    //
    // Memory layout:
    //   0x4000  "/dev/ptmx\0"
    //   0x4040  "/dev/pts/0\0"
    //   0x4100  lockarg (i32, value 0)
    //   0x4200  write buffer ("ping")
    //   0x4300  read buffer (4 bytes, cleared to 0)
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0u8; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2) → master fd
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // unlockpt: ioctl(master, TIOCSPTLCK, &0)
    memory.write_bytes(0x4100, &0i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCSPTLCK, 0x4100, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSPTLCK unlock must succeed"
    );

    // openat(AT_FDCWD, "/dev/pts/0", O_RDWR=2) → slave fd
    let slave = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/pts/0 failed: {:?}", o),
    };

    // write(slave, "ping", 4) — this was EBADF before the fix
    memory.write_bytes(0x4200, b"ping").unwrap();
    let w = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([slave, 0x4200, 4, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(
        matches!(w, DispatchOutcome::Returned { value } if value == 4),
        "write(slave, \"ping\") must return 4, got: {:?}",
        w
    );

    // read(master, buf, 4) — slave output goes to master read buffer
    let r = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([master, 0x4300, 4, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert!(
        matches!(r, DispatchOutcome::Returned { value } if value == 4),
        "read(master) must return 4, got: {:?}",
        r
    );
    assert_eq!(
        memory.read_bytes(0x4300, 4).unwrap(),
        b"ping",
        "master read must yield the bytes written to the slave"
    );
}

// ── close_range frees pty master entry ────────────────────────────────────────

#[test]
fn close_range_frees_pty_master_entry() {
    // Regression test: close_range(first, last, 0) must drop the PtyTable
    // entry for any pty master in the range, just like close(2) does.
    // Without the fix, close_range called the bare close_open_file() helper
    // which freed the host fd but left the /dev/pts/N entry alive.
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2) → master fd; allocates pts index 0.
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // Unlock the slave so we can verify it is reachable before the master closes.
    let lockarg = 0x4100u64;
    memory.write_bytes(lockarg, &0i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCSPTLCK, lockarg, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSPTLCK unlock must succeed"
    );

    // /dev/pts/0 must be openable before the master is closed.
    assert!(
        matches!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        56,
                        SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { .. }
        ),
        "slave should be openable before master is closed"
    );

    // close_range(master, master, 0) — syscall 436.
    // This must remove the pts index from the PtyTable.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(436, SyscallArgs::from([master, master, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "close_range(master, master, 0) must succeed"
    );

    // /dev/pts/0 must now be ENOENT (errno 2): the table entry was removed.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 },
        "/dev/pts/0 must be ENOENT after close_range frees the master"
    );
}

// ── fstat on a pty fd reports S_IFCHR ─────────────────────────────────────────

#[test]
fn fstat_pty_reports_char_device() {
    // A pty master is a character device (S_IFCHR = 0o020000), not a pipe
    // (S_IFIFO). fstat(2) on the master fd must report the S_IFCHR type bits.
    //
    // LinuxStat layout (aarch64):
    //   offset 0  : st_dev  (u64, 8 bytes)
    //   offset 8  : st_ino  (u64, 8 bytes)
    //   offset 16 : st_mode (u32, 4 bytes)  ← we check this
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2) → master fd.
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // fstat(master, statbuf) — syscall 80.
    let statbuf = 0x4100u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([master, statbuf, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "fstat on pty master must succeed"
    );

    // st_mode is at offset 16; read 4 bytes and check the S_IFMT bits.
    let mode_bytes = memory.read_bytes(statbuf + 16, 4).unwrap();
    let mode = u32::from_le_bytes([mode_bytes[0], mode_bytes[1], mode_bytes[2], mode_bytes[3]]);
    assert_eq!(
        mode & LINUX_S_IFMT,
        LINUX_S_IFCHR,
        "fstat on pty master must report S_IFCHR, got mode {:o}",
        mode
    );
}
