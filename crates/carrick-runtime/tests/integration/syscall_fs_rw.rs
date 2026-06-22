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
use carrick_runtime::fs_backend::HostFsBackend;
use carrick_runtime::linux_abi::LINUX_AT_FDCWD;
// `LINUX_EFAULT`/`LINUX_O_CREAT`/`LINUX_O_RDWR` are only referenced by the
// macOS-only (`--fs host`) tests below, so gate their import to match.
#[cfg(target_os = "macos")]
use carrick_runtime::linux_abi::{LINUX_EFAULT, LINUX_O_CREAT, LINUX_O_RDWR};
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
///
/// `HostFsBackend` (the `--fs host` cap-std backend) is macOS-only, so this
/// host-backed regression test is gated to macOS to match its import.
#[cfg(target_os = "macos")]
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
fn writev_writes_host_pipe_from_packed_iovecs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4200, b"hello ").unwrap();
    memory.write_bytes(0x4300, b"pipe\n").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [
            LinuxIovec::new(0x4200, 6),
            LinuxIovec::new(0xdead_0000, 0),
            LinuxIovec::new(0x4300, 5),
        ],
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
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            66,
            [pair.write_fd as u64, 0x4100, 3, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 11 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            63,
            [pair.read_fd as u64, 0x4400, 16, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 11 }
    );
    assert_eq!(memory.read_bytes(0x4400, 11).unwrap(), b"hello pipe\n");
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

#[cfg(target_os = "macos")]
struct HostPtrPayloadMemory {
    base: u64,
    bytes: Vec<u8>,
    host_ptr_ranges: Vec<(u64, usize)>,
    host_write_ptr_ranges: Vec<(u64, usize)>,
    unreadable_ranges: Vec<(u64, usize)>,
    watched_ranges: Vec<(u64, usize)>,
    watched_write_ranges: Vec<(u64, usize)>,
    watched_reads: std::cell::Cell<usize>,
    watched_writes: std::cell::Cell<usize>,
    host_ptr_hits: std::cell::Cell<usize>,
    host_write_ptr_hits: std::cell::Cell<usize>,
}

#[cfg(target_os = "macos")]
impl HostPtrPayloadMemory {
    fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self {
            base,
            bytes,
            host_ptr_ranges: Vec::new(),
            host_write_ptr_ranges: Vec::new(),
            unreadable_ranges: Vec::new(),
            watched_ranges: Vec::new(),
            watched_write_ranges: Vec::new(),
            watched_reads: std::cell::Cell::new(0),
            watched_writes: std::cell::Cell::new(0),
            host_ptr_hits: std::cell::Cell::new(0),
            host_write_ptr_hits: std::cell::Cell::new(0),
        }
    }

    fn offset(
        &self,
        address: u64,
        length: usize,
    ) -> Result<usize, carrick_runtime::dispatch::MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(carrick_runtime::dispatch::MemoryError::OutOfBounds { address, length })?;
        let offset = usize::try_from(offset)
            .map_err(|_| carrick_runtime::dispatch::MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(carrick_runtime::dispatch::MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(carrick_runtime::dispatch::MemoryError::OutOfBounds { address, length });
        }
        Ok(offset)
    }

    fn expose_host_ptr(&mut self, address: u64, len: usize) {
        self.host_ptr_ranges.push((address, len));
    }

    fn expose_host_write_ptr(&mut self, address: u64, len: usize) {
        self.host_write_ptr_ranges.push((address, len));
    }

    fn deny_read(&mut self, address: u64, len: usize) {
        self.unreadable_ranges.push((address, len));
    }

    fn watch_payload_read(&mut self, address: u64, len: usize) {
        self.watched_ranges.push((address, len));
    }

    fn watch_payload_write(&mut self, address: u64, len: usize) {
        self.watched_write_ranges.push((address, len));
    }

    fn reset_counts(&self) {
        self.watched_reads.set(0);
        self.watched_writes.set(0);
        self.host_ptr_hits.set(0);
        self.host_write_ptr_hits.set(0);
    }

    fn watched_reads(&self) -> usize {
        self.watched_reads.get()
    }

    fn watched_writes(&self) -> usize {
        self.watched_writes.get()
    }

    fn host_ptr_hits(&self) -> usize {
        self.host_ptr_hits.get()
    }

    fn host_write_ptr_hits(&self) -> usize {
        self.host_write_ptr_hits.get()
    }
}

#[cfg(target_os = "macos")]
impl GuestMemory for HostPtrPayloadMemory {
    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_runtime::dispatch::MemoryError> {
        if self
            .unreadable_ranges
            .iter()
            .any(|(base, len)| address == *base && length == *len)
        {
            return Err(carrick_runtime::dispatch::MemoryError::OutOfBounds { address, length });
        }
        if self
            .watched_ranges
            .iter()
            .any(|(base, len)| address == *base && length == *len)
        {
            self.watched_reads.set(self.watched_reads.get() + 1);
        }
        let offset = self.offset(address, length)?;
        Ok(self.bytes[offset..offset + length].to_vec())
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_runtime::dispatch::MemoryError> {
        if self
            .watched_write_ranges
            .iter()
            .any(|(base, len)| address == *base && bytes.len() == *len)
        {
            self.watched_writes.set(self.watched_writes.get() + 1);
        }
        let offset = self.offset(address, bytes.len())?;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn read_into(
        &self,
        address: u64,
        dst: &mut [u8],
    ) -> Result<(), carrick_runtime::dispatch::MemoryError> {
        let offset = self.offset(address, dst.len())?;
        dst.copy_from_slice(&self.bytes[offset..offset + dst.len()]);
        Ok(())
    }

    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        if !self
            .host_ptr_ranges
            .iter()
            .any(|(base, range_len)| address == *base && len == *range_len)
        {
            return None;
        }
        let offset = self.offset(address, len).ok()?;
        self.host_ptr_hits.set(self.host_ptr_hits.get() + 1);
        Some(unsafe { self.bytes.as_ptr().add(offset) })
    }

    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        if !self
            .host_write_ptr_ranges
            .iter()
            .any(|(base, range_len)| address == *base && len == *range_len)
        {
            return None;
        }
        let offset = self.offset(address, len).ok()?;
        self.host_write_ptr_hits
            .set(self.host_write_ptr_hits.get() + 1);
        Some(unsafe { self.bytes.as_mut_ptr().add(offset) })
    }
}

#[cfg(target_os = "macos")]
fn open_host_file_at_path(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
    path_addr: u64,
    flags: u64,
) {
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, path_addr, flags, 0o644, 0, 0,]),
                ),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
}

#[cfg(target_os = "macos")]
fn open_host_out_file(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
) {
    open_host_file_at_path(
        dispatcher,
        memory,
        reporter,
        0x4000,
        LINUX_O_CREAT | LINUX_O_RDWR,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn readv_host_file_uses_guest_host_ptrs_for_writable_iovecs() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::write(scratch.path().join("in.bin"), b"rootfs says hello\n").unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/in.bin\0").unwrap();
    memory.expose_host_write_ptr(0x4200, 6);
    memory.expose_host_write_ptr(0x4300, 4);
    memory.watch_payload_write(0x4200, 6);
    memory.watch_payload_write(0x4300, 4);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 6), LinuxIovec::new(0x4300, 4)],
    );

    open_host_file_at_path(&mut dispatcher, &mut memory, &reporter, 0x4000, 0);
    memory.reset_counts();

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
    assert_eq!(
        memory.watched_writes(),
        0,
        "borrowed readv should not copy payloads through write_bytes"
    );
    assert_eq!(
        memory.host_write_ptr_hits(),
        2,
        "borrowed readv should resolve each non-empty target to a host pointer"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn preadv_host_file_preserves_offset_with_borrowed_iovecs() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::write(scratch.path().join("in.bin"), b"rootfs says hello\n").unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x900]);
    memory.write_bytes(0x4000, b"/in.bin\0").unwrap();
    memory.expose_host_write_ptr(0x4200, 4);
    memory.expose_host_write_ptr(0x4300, 5);
    memory.watch_payload_write(0x4200, 4);
    memory.watch_payload_write(0x4300, 5);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 5)],
    );

    open_host_file_at_path(&mut dispatcher, &mut memory, &reporter, 0x4000, 0);
    memory.reset_counts();

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
        memory.watched_writes(),
        0,
        "borrowed preadv should not copy payloads through write_bytes"
    );
    assert_eq!(
        memory.host_write_ptr_hits(),
        2,
        "borrowed preadv should resolve each non-empty target to a host pointer"
    );
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

#[cfg(target_os = "macos")]
#[test]
fn readv_host_file_falls_back_to_staging_when_any_iovec_lacks_host_ptr() {
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::write(scratch.path().join("in.bin"), b"abcdefghi").unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/in.bin\0").unwrap();
    memory.expose_host_write_ptr(0x4200, 4);
    memory.watch_payload_write(0x4200, 4);
    memory.watch_payload_write(0x4300, 5);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 5)],
    );

    open_host_file_at_path(&mut dispatcher, &mut memory, &reporter, 0x4000, 0);
    memory.reset_counts();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(65, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"abcd");
    assert_eq!(memory.read_bytes(0x4300, 5).unwrap(), b"efghi");
    assert_eq!(
        memory.watched_writes(),
        2,
        "fallback readv should write each filled payload through write_bytes"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn pwritev_host_file_uses_guest_host_ptrs_without_payload_reads() {
    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/out.bin\0").unwrap();
    memory.write_bytes(0x4200, b"head").unwrap();
    memory.write_bytes(0x4300, b"tailpiece").unwrap();
    memory.expose_host_ptr(0x4200, 4);
    memory.expose_host_ptr(0x4300, 9);
    memory.watch_payload_read(0x4200, 4);
    memory.watch_payload_read(0x4300, 9);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 9)],
    );

    open_host_out_file(&mut dispatcher, &mut memory, &reporter);
    memory.reset_counts();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 13 }
    );
    assert_eq!(
        memory.watched_reads(),
        0,
        "borrowed pwritev should not copy payloads through read_bytes"
    );
    assert_eq!(
        memory.host_ptr_hits(),
        2,
        "borrowed pwritev should resolve each non-empty payload to a host pointer"
    );
    assert_eq!(
        std::fs::read(scratch.path().join("out.bin")).unwrap(),
        b"headtailpiece"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn pwritev_host_file_falls_back_to_staging_when_any_iovec_lacks_host_ptr() {
    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/out.bin\0").unwrap();
    memory.write_bytes(0x4200, b"head").unwrap();
    memory.write_bytes(0x4300, b"tailpiece").unwrap();
    memory.expose_host_ptr(0x4200, 4);
    memory.watch_payload_read(0x4200, 4);
    memory.watch_payload_read(0x4300, 9);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 9)],
    );

    open_host_out_file(&mut dispatcher, &mut memory, &reporter);
    memory.reset_counts();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 13 }
    );
    assert_eq!(
        memory.watched_reads(),
        2,
        "fallback pwritev should stage each payload exactly once"
    );
    assert_eq!(
        std::fs::read(scratch.path().join("out.bin")).unwrap(),
        b"headtailpiece"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn pwritev_host_file_reports_efault_when_fallback_payload_is_unreadable() {
    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = HostPtrPayloadMemory::new(0x4000, vec![0; 0x800]);
    memory.write_bytes(0x4000, b"/out.bin\0").unwrap();
    memory.write_bytes(0x4200, b"head").unwrap();
    memory.write_bytes(0x4300, b"tailpiece").unwrap();
    memory.expose_host_ptr(0x4200, 4);
    memory.deny_read(0x4300, 9);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 9)],
    );

    open_host_out_file(&mut dispatcher, &mut memory, &reporter);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );
    assert_eq!(
        std::fs::read(scratch.path().join("out.bin")).unwrap(),
        b"",
        "invalid iovec validation must finish before any host write"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn pwritev_host_file_reads_each_guest_iovec_once() {
    use carrick_runtime::dispatch::MemoryError;
    use std::cell::Cell;

    struct CountingPayloadMemory {
        inner: LinearMemory,
        watched_ranges: Vec<(u64, usize)>,
        watched_reads: Cell<usize>,
    }

    impl CountingPayloadMemory {
        fn new(inner: LinearMemory) -> Self {
            Self {
                inner,
                watched_ranges: Vec::new(),
                watched_reads: Cell::new(0),
            }
        }

        fn watch(&mut self, address: u64, len: usize) {
            self.watched_ranges.push((address, len));
        }

        fn reset_watched_reads(&mut self) {
            self.watched_reads.set(0);
        }

        fn watched_reads(&self) -> usize {
            self.watched_reads.get()
        }
    }

    impl GuestMemory for CountingPayloadMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            if self
                .watched_ranges
                .iter()
                .any(|(base, len)| address == *base && length == *len)
            {
                self.watched_reads.set(self.watched_reads.get() + 1);
            }
            self.inner.read_bytes(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes(address, bytes)
        }

        fn read_into(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
            self.inner.read_into(address, dst)
        }
    }

    let scratch = tempfile::TempDir::new().unwrap();
    let dir =
        cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(HostFsBackend::from_existing_dir(dir)));
    let reporter = CompatReporter::default();
    let mut memory = CountingPayloadMemory::new(LinearMemory::new(0x4000, vec![0; 0x800]));
    memory.write_bytes(0x4000, b"/out.bin\0").unwrap();
    memory.write_bytes(0x4200, b"head").unwrap();
    memory.write_bytes(0x4300, b"tailpiece").unwrap();
    memory.watch(0x4200, 4);
    memory.watch(0x4300, 9);
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 4), LinuxIovec::new(0x4300, 9)],
    );

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
    memory.reset_watched_reads();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(70, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 13 }
    );
    assert_eq!(
        memory.watched_reads(),
        2,
        "pwritev should stage each guest payload once, not reread for validation"
    );
    assert_eq!(
        std::fs::read(scratch.path().join("out.bin")).unwrap(),
        b"headtailpiece"
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
fn f_getfl_strips_creation_only_open_flags() {
    // M8: fcntl(F_GETFL) reports only file STATUS flags. Creation-only flags
    // (O_CREAT/O_EXCL/O_TRUNC/O_DIRECTORY/…) are consumed by open() and must not
    // be reported back (Linux clears them from f_flags). O_NONBLOCK is a status
    // flag and must remain.
    const O_NONBLOCK: u64 = 0o4000;
    const O_CREAT: u64 = 0o100;
    const F_GETFL: u64 = 3;

    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"motd\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
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

    // openat(AT_FDCWD, "/etc/motd", O_NONBLOCK|O_CREAT) — O_CREAT is a no-op on
    // an existing file but is recorded in status_flags (the leak).
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [LINUX_AT_FDCWD, 0x4000, O_NONBLOCK | O_CREAT, 0o644, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("openat: {other:?}"),
    };

    let flags = match run(&mut dispatcher, &mut memory, 25, [fd, F_GETFL, 0, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("F_GETFL: {other:?}"),
    };
    assert_eq!(flags & O_CREAT, 0, "F_GETFL must not report O_CREAT");
    assert_eq!(
        flags & O_NONBLOCK,
        O_NONBLOCK,
        "F_GETFL must keep O_NONBLOCK"
    );
}
