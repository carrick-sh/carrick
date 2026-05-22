//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

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

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([1, LINUX_TIOCGWINSZ, 0x4000, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let winsize = read_winsize(&memory, 0x4000);
    let rows = winsize.ws_row;
    let cols = winsize.ws_col;
    assert_eq!(rows, 24);
    assert_eq!(cols, 80);

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
    // 1. TCGETS on fd 0 → returns 0; struct has cooked-TTY defaults.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCGETS, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let termios = read_termios(&memory, 0x4000);
    let c_iflag = termios.c_iflag;
    let c_lflag = termios.c_lflag;
    let c_cc = termios.c_cc;
    assert_eq!(c_iflag, 0x4502);
    assert_eq!(c_lflag, 0x803b);
    assert_eq!(c_cc[0], 0x03); // VINTR
    assert_eq!(c_cc[4], 0x04); // VEOF

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

    // 4. TCSETS on fd 0 with a valid termios buffer → 0.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    // Seed any plausible bytes — the dispatcher only does a size check.
    memory
        .write_bytes(0x4000, LinuxTermios::default_cooked().as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // 5. TCSETS on fd 0 with a bad pointer → EFAULT.
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
        DispatchOutcome::Errno { errno: 22 }
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
        DispatchOutcome::Errno { errno: 22 }
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
    assert!(cpuinfo.contains("CPU architecture\t: 8"));
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
        ("/proc/sys/kernel/hostname", b"carrick"),
        ("/proc/sys/kernel/random/boot_id", b"-4000-8000-"),
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
fn missing_proc_file_records_compat_report_entry() {
    let mut memory = LinearMemory::new(0x4000, b"/proc/self/io\0".to_vec());
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
    assert_eq!(report.proc_read_unimplemented[0].path, "/proc/self/io");
    assert_eq!(report.proc_read_unimplemented[0].count, 1);
}

#[test]
fn synthetic_sys_surface_serves_common_cpu_and_mm_files() {
    let paths: [(&str, &[u8]); 17] = [
        ("/sys/devices/system/cpu/online", b"0\n"),
        ("/sys/devices/system/cpu/possible", b"0\n"),
        ("/sys/devices/system/cpu/present", b"0\n"),
        ("/sys/devices/system/cpu/kernel_max", b"0\n"),
        ("/sys/devices/system/cpu/cpu0/online", b"1\n"),
        (
            "/sys/devices/system/cpu/cpu0/topology/physical_package_id",
            b"0\n",
        ),
        ("/sys/devices/system/cpu/cpu0/topology/core_id", b"0\n"),
        (
            "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
            b"0\n",
        ),
        (
            "/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
            b"0\n",
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
            b"2400000\n",
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq",
            b"2400000\n",
        ),
        (
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq",
            b"600000\n",
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/enabled",
            b"always [madvise] never\n",
        ),
        (
            "/sys/kernel/mm/transparent_hugepage/defrag",
            b"always defer defer+madvise [madvise] never\n",
        ),
        (
            "/sys/kernel/random/uuid",
            b"00000000-0000-4000-8000-000000000000\n",
        ),
        (
            "/sys/kernel/random/boot_id",
            b"00000000-0000-4000-8000-000000000000\n",
        ),
        ("/sys/fs/cgroup/cgroup.controllers", b"\n"),
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
            expected,
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
    assert!(value as usize > LINUX_DIRENT64_HEADER_SIZE + "motd".len());

    let dirent = memory.read_bytes(0x4100, value as usize).unwrap();
    let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent).unwrap();
    let reclen = header.d_reclen;
    let dtype = header.d_type;
    assert_eq!(reclen as usize, value as usize);
    assert_eq!(dtype, LINUX_DT_REG);
    let name_start = LINUX_DIRENT64_HEADER_SIZE;
    let name_end = dirent[name_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| name_start + offset)
        .unwrap();
    assert_eq!(&dirent[name_start..name_end], b"motd");

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
    // path/fd targets are resolved and arguments validated before the backend
    // is consulted. On the default in-memory overlay backend the actual
    // attribute store is not modelled, so the path-variant set/get/list and
    // every remove*xattr report ENOTSUP, while the fd-variants validate the fd
    // first and report EBADF for an unopened descriptor. The real `user.*`
    // round-trip is exercised against the host backend by the conformance
    // suite; here we pin the in-memory dispatch behaviour.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    memory.write_bytes(0x4020, b"user.test\0").unwrap();
    memory.write_bytes(0x4040, b"data").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Path-variant set/get/list (5,6 set; 8,9 get; 11,12 list) and the
    // remove*xattr family (14,15,16) all reach the backend and report ENOTSUP
    // on the in-memory overlay. Args: (path, name, value, size).
    for number in [5, 6, 8, 9, 11, 12, 14, 15, 16] {
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
            DispatchOutcome::Errno { errno: 95 },
            "syscall {number} should return ENOTSUP on the in-memory backend"
        );
    }

    // Fd-variants (7 fsetxattr, 10 fgetxattr, 13 flistxattr) validate the fd
    // before anything else: an unopened fd is EBADF.
    for number in [7, 10, 13] {
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
        DispatchOutcome::Errno { errno: 9 }
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
