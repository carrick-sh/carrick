//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

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
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(2)
        },
        "/dev/pts/0 must be ENOENT after master close"
    );
}

#[test]
fn tiocswinsz_on_pty_master_succeeds_via_slave() {
    // Linux honours TIOCGWINSZ/TIOCSWINSZ on a pty *master* (forkpty/openpty +
    // TIOCSWINSZ(master) is the standard way to size a pty). macOS rejects them
    // on the master with ENOTTY — the winsize lives on the slave tty — so a
    // guest program doing this otherwise fails with "Setting TIOCSWINSZ for
    // master fd N failed!". carrick must redirect a master's winsize ioctls to
    // the slave. (musl/glibc both issue raw TIOCSWINSZ here, so this is libc-
    // independent.)
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0u8; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    // open /dev/ptmx (O_RDWR=2) -> master fd.
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

    // Unlock + open the slave /dev/pts/0 (kept open). This is the persistent
    // slave the child uses; the master's winsize ioctls retarget it (macOS
    // resets a pts winsize when its last slave fd closes, so a child needs the
    // slave already open — exactly the forkpty(3) order: openpty, then set size).
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
    );
    let _slave = match dispatcher
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

    // TIOCSWINSZ on the MASTER: 40 rows x 120 cols. Pre-fix this returned ENOTTY.
    let ws_ptr = 0x4100u64;
    let ws: [u8; 8] = [40, 0, 120, 0, 0, 0, 0, 0]; // row=40, col=120, xpixel=0, ypixel=0
    memory.write_bytes(ws_ptr, &ws).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCSWINSZ, ws_ptr, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSWINSZ on a pty master must succeed (redirected to the slave)"
    );

    // TIOCGWINSZ on the MASTER reads it back through the same slave.
    let got_ptr = 0x4200u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCGWINSZ, got_ptr, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCGWINSZ on a pty master must succeed"
    );
    let got = memory.read_bytes(got_ptr, 4).unwrap();
    assert_eq!(
        (
            u16::from_le_bytes([got[0], got[1]]),
            u16::from_le_bytes([got[2], got[3]])
        ),
        (40, 120),
        "winsize set on the master must read back from the slave"
    );

    assert!(reporter.finish().unhandled_ioctls.is_empty());
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
