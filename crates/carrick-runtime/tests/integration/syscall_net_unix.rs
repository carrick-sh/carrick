//! Networking / I/O multiplexing syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use carrick_runtime::linux_abi::{
    LINUX_AT_FDCWD, LINUX_EADDRINUSE, LINUX_ECONNREFUSED, LINUX_ENOENT, LINUX_ENXIO, LINUX_O_CREAT,
    LINUX_O_RDWR, LINUX_SOCK_STREAM,
};
#[cfg(target_os = "macos")]
use carrick_runtime::vfs::BindVfs;
use support::*;

/// Regression for the Go `net` unix-socket hang: carrick translates a guest
/// unix path to a hashed host path under
/// carrick-unix-sockets/, but `getsockname` returned that HOST path verbatim — so
/// Go's `ln.Addr()` reported it and a subsequent Dial re-translated (double-hash)
/// → `connect: no such file or directory`. getsockname must reverse-translate to
/// the original guest path.
#[cfg(target_os = "macos")]
#[test]
fn getsockname_returns_the_guest_unix_path_not_the_host_translation() {
    const LINUX_AF_UNIX: u16 = 1;
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

    // Unique guest path so repeated runs don't collide on the host socket node.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let guest_path = format!("/carrick-ut-{nanos}.sock");
    let gpb = guest_path.as_bytes();

    // socket(AF_UNIX, SOCK_STREAM)
    let fd = ret(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    );
    assert!(fd >= 0, "socket(AF_UNIX) failed: {fd}");
    let fd = fd as u64;

    // sockaddr_un at 0x4200: family(2) + path + NUL; bind it.
    let mut sa = vec![0u8; 2 + gpb.len() + 1];
    sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    sa[2..2 + gpb.len()].copy_from_slice(gpb);
    memory.write_bytes(0x4200, &sa).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            200,
            [fd, 0x4200, sa.len() as u64, 0, 0, 0]
        ),
        0,
        "bind failed"
    );

    // getsockname(fd, buf=0x4300, *0x4400 = capacity)
    memory.write_bytes(0x4400, &256u32.to_ne_bytes()).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            204,
            [fd, 0x4300, 0x4400, 0, 0, 0]
        ),
        0,
        "getsockname failed"
    );
    let outlen = {
        let b = memory.read_bytes(0x4400, 4).unwrap();
        u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize
    };
    let out = memory.read_bytes(0x4300, outlen.min(256)).unwrap();
    let path = &out[2..];
    let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
    assert_eq!(
        path, gpb,
        "getsockname returned the carrick-unix-sockets host path, not the guest path"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn unix_bind_existing_guest_socket_path_returns_eaddrinuse() {
    const LINUX_AF_UNIX: u16 = 1;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x600]);
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let guest_path = format!("/carrick-bind-inuse-{nanos}.sock");
    let gpb = guest_path.as_bytes();
    let mut sa = vec![0u8; 2 + gpb.len() + 1];
    sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    sa[2..2 + gpb.len()].copy_from_slice(gpb);
    memory.write_bytes(0x4200, &sa).unwrap();

    let fd1 = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("socket 1 failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [fd1, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    let fd2 = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("socket 2 failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [fd2, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Errno {
            errno: LINUX_EADDRINUSE
        }
    );

    let missing_path = b"/path/to/unix/socket/that/really/should/not/be/there";
    let mut missing_sa = vec![0u8; 2 + missing_path.len() + 1];
    missing_sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    missing_sa[2..2 + missing_path.len()].copy_from_slice(missing_path);
    memory.write_bytes(0x4400, &missing_sa).unwrap();
    let fd3 = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("socket 3 failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [fd3, 0x4400, missing_sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Errno {
            errno: LINUX_ENOENT
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn unix_connect_checks_guest_path_before_host_hash_path() {
    const LINUX_AF_UNIX: u16 = 1;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
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

    let missing_path = b"/path/to/unix/socket/that/really/should/not/be/there";
    let mut missing_sa = vec![0u8; 2 + missing_path.len() + 1];
    missing_sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    missing_sa[2..2 + missing_path.len()].copy_from_slice(missing_path);
    memory.write_bytes(0x4200, &missing_sa).unwrap();
    let missing_fd = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("missing socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            203,
            [missing_fd, 0x4200, missing_sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Errno {
            errno: LINUX_ENOENT
        }
    );

    let file_path = b"/plain-unix-connect-file";
    let mut file_path_cstr = file_path.to_vec();
    file_path_cstr.push(0);
    memory.write_bytes(0x4400, &file_path_cstr).unwrap();
    match run(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0x4400,
            LINUX_O_CREAT | LINUX_O_RDWR,
            0o644,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { .. } => {}
        other => panic!("openat regular file failed: {other:?}"),
    }
    let mut file_sa = vec![0u8; 2 + file_path.len() + 1];
    file_sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    file_sa[2..2 + file_path.len()].copy_from_slice(file_path);
    memory.write_bytes(0x4600, &file_sa).unwrap();
    let file_fd = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("file socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            203,
            [file_fd, 0x4600, file_sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Errno {
            errno: LINUX_ECONNREFUSED
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn unix_pathname_stream_listener_accepts_local_client() {
    const LINUX_AF_UNIX: u16 = 1;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
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

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let guest_path = format!("/carrick-loopback-{nanos}.sock");
    let gpb = guest_path.as_bytes();
    let mut sa = vec![0u8; 2 + gpb.len() + 1];
    sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    sa[2..2 + gpb.len()].copy_from_slice(gpb);
    memory.write_bytes(0x4200, &sa).unwrap();

    let listener = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("listener socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [listener, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 201, [listener, 1, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );

    let client = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("client socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            203,
            [client, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    match run(&mut dispatcher, &mut memory, 202, [listener, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => assert!(value >= 0, "accept returned {value}"),
        other => panic!("accept failed: {other:?}"),
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn unix_relative_socket_getsockname_can_be_chmodded() {
    const LINUX_AF_UNIX: u16 = 1;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0xa00]);
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

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let guest_path = format!("uv-test-sock-{nanos}");
    let gpb = guest_path.as_bytes();
    let mut sa = vec![0u8; 2 + gpb.len() + 1];
    sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    sa[2..2 + gpb.len()].copy_from_slice(gpb);
    memory.write_bytes(0x4200, &sa).unwrap();

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [fd, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    memory.write_bytes(0x4500, &128u32.to_ne_bytes()).unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            204,
            [fd, 0x4400, 0x4500, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let out_len = {
        let b = memory.read_bytes(0x4500, 4).unwrap();
        u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize
    };
    let out = memory.read_bytes(0x4400, out_len).unwrap();
    let returned_path = &out[2..];
    let returned_path = &returned_path[..returned_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(returned_path.len())];
    assert_eq!(returned_path, gpb);

    let mut chmod_path = returned_path.to_vec();
    chmod_path.push(0);
    memory.write_bytes(0x4600, &chmod_path).unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            53,
            [LINUX_AT_FDCWD, 0x4600, 0o444, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4600, 0x4700, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4700);
    let mode = stat.st_mode;
    assert_eq!(mode & 0o777, 0o444);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn unix_relative_socket_under_bind_mount_can_be_chmodded() {
    const LINUX_AF_UNIX: u16 = 1;
    let scratch = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(scratch.path().join("nodejs-bindsock")).unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0xa00]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        std::path::PathBuf::from("/tmp"),
        Box::new(BindVfs::new("/tmp", scratch.path().to_path_buf(), false)),
    );
    dispatcher.set_cwd("/tmp/nodejs-bindsock");
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let guest_path = format!("uv-test-sock-{nanos}");
    let gpb = guest_path.as_bytes();
    let mut sa = vec![0u8; 2 + gpb.len() + 1];
    sa[0..2].copy_from_slice(&LINUX_AF_UNIX.to_ne_bytes());
    sa[2..2 + gpb.len()].copy_from_slice(gpb);
    memory.write_bytes(0x4200, &sa).unwrap();

    let fd = match run(
        &mut dispatcher,
        &mut memory,
        198,
        [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("socket failed: {other:?}"),
    };
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            200,
            [fd, 0x4200, sa.len() as u64, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    memory.write_bytes(0x4500, &128u32.to_ne_bytes()).unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            204,
            [fd, 0x4400, 0x4500, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let out_len = {
        let b = memory.read_bytes(0x4500, 4).unwrap();
        u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize
    };
    let out = memory.read_bytes(0x4400, out_len).unwrap();
    let returned_path = &out[2..];
    let returned_path = &returned_path[..returned_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(returned_path.len())];
    assert_eq!(returned_path, gpb);

    let mut chmod_path = returned_path.to_vec();
    chmod_path.push(0);
    memory.write_bytes(0x4600, &chmod_path).unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            53,
            [LINUX_AT_FDCWD, 0x4600, 0o444, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4600, 0x4700, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4700);
    assert_eq!(stat.st_mode & LINUX_S_IFMT, LINUX_S_IFSOCK);
    assert_eq!(stat.st_mode & 0o777, 0o444);
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [LINUX_AT_FDCWD, 0x4600, LINUX_O_RDWR, 0, 0, 0],
        ),
        DispatchOutcome::Errno { errno: LINUX_ENXIO }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

/// Regression for the Go `net` `TestFileListener` hang: a dup'd socket shares
/// ONE host fd, but carrick's epoll kqueue is keyed by
/// host fd. An `EPOLL_CTL_DEL` of one dup must NOT deafen the OTHER guest fds that
/// still watch the same host socket — Linux epoll interest is per-fd. Before the
/// fix, DEL of the dup did an unconditional `EV_DELETE` on the shared host fd, so
/// the surviving fd never saw readiness → accept/read blocked forever.
#[cfg(target_os = "macos")]
#[test]
fn epoll_del_of_one_dup_keeps_readiness_for_the_shared_host_socket() {
    const LINUX_AF_UNIX: u64 = 1;
    const LINUX_EPOLL_CTL_DEL: u64 = 2;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
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

    // socketpair(AF_UNIX, SOCK_STREAM) -> a real connected host pair; fds @0x4000.
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            199,
            [LINUX_AF_UNIX, LINUX_SOCK_STREAM as u64, 0, 0x4000, 0, 0]
        ),
        0
    );
    let pair = memory.read_bytes(0x4000, 8).unwrap();
    let fd_a = i32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]) as u64; // readable end
    let fd_b = i32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]) as u64; // peer end

    // dup(fd_a) -> a second guest fd sharing fd_a's host socket.
    let fd_dup = ret(&mut dispatcher, &mut memory, 23, [fd_a, 0, 0, 0, 0, 0]) as u64;
    assert!(fd_dup >= 3 && fd_dup != fd_a && fd_dup != fd_b);

    // epoll_create1 -> epfd.
    let epfd = ret(&mut dispatcher, &mut memory, 20, [0, 0, 0, 0, 0, 0]) as u64;

    // epoll_ctl ADD fd_a (data 0xAAAA) and ADD fd_dup (data 0xBBBB) — same host fd.
    let ev_a = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        _pad: 0,
        data: 0xAAAA,
    };
    memory.write_bytes(0x4040, ev_a.as_bytes()).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            21,
            [epfd, LINUX_EPOLL_CTL_ADD, fd_a, 0x4040, 0, 0]
        ),
        0
    );
    let ev_d = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        _pad: 0,
        data: 0xBBBB,
    };
    memory.write_bytes(0x4060, ev_d.as_bytes()).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            21,
            [epfd, LINUX_EPOLL_CTL_ADD, fd_dup, 0x4060, 0, 0]
        ),
        0
    );

    // DEL the dup — must keep fd_a's interest alive.
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            21,
            [epfd, LINUX_EPOLL_CTL_DEL, fd_dup, 0, 0, 0]
        ),
        0
    );

    // Make fd_a readable by writing a byte to its peer end (fd_b).
    memory.write_bytes(0x4080, b"x").unwrap();
    assert_eq!(
        ret(&mut dispatcher, &mut memory, 64, [fd_b, 0x4080, 1, 0, 0, 0]),
        1
    );

    // epoll_pwait(timeout=0): fd_a MUST be reported readable (data 0xAAAA).
    let n = ret(&mut dispatcher, &mut memory, 22, [epfd, 0x4100, 4, 0, 0, 0]);
    assert_eq!(
        n, 1,
        "DEL of the dup deafened the shared host socket (the TestFileListener hang)"
    );
    let ready_data = read_epoll_event(&memory, 0x4100).data;
    assert_eq!(ready_data, 0xAAAA);
}

#[cfg(target_os = "macos")]
#[test]
fn getsockopt_so_peercred_returns_linux_ucred_from_local_peercred() {
    // SO_PEERCRED has no direct macOS equivalent; carrick synthesizes the Linux
    // `struct ucred { pid, uid, gid }` from LOCAL_PEERCRED + LOCAL_PEERPID. A
    // socketpair's peer is this very process, so the credentials must be ours.
    const LINUX_AF_UNIX: u64 = 1;
    const LINUX_SOL_SOCKET: u64 = 1;
    const LINUX_SO_PEERCRED: u64 = 17;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
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

    // socketpair(AF_UNIX, SOCK_STREAM) -> connected host pair; fds @0x4000.
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            199,
            [LINUX_AF_UNIX, LINUX_SOCK_STREAM as u64, 0, 0x4000, 0, 0]
        ),
        0
    );
    let pair = memory.read_bytes(0x4000, 8).unwrap();
    let fd_a = i32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]) as u64;

    // optlen @0x4010 = 12 (sizeof ucred); ucred written @0x4020.
    memory.write_bytes(0x4010, &12u32.to_ne_bytes()).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            209,
            [fd_a, LINUX_SOL_SOCKET, LINUX_SO_PEERCRED, 0x4020, 0x4010, 0]
        ),
        0
    );

    let written_len = u32::from_ne_bytes(memory.read_bytes(0x4010, 4).unwrap().try_into().unwrap());
    assert_eq!(written_len, 12, "ucred is 12 bytes (pid,uid,gid)");
    let cred = memory.read_bytes(0x4020, 12).unwrap();
    let pid = u32::from_ne_bytes([cred[0], cred[1], cred[2], cred[3]]);
    let uid = u32::from_ne_bytes([cred[4], cred[5], cred[6], cred[7]]);
    let gid = u32::from_ne_bytes([cred[8], cred[9], cred[10], cred[11]]);

    assert_eq!(uid, unsafe { libc::geteuid() }, "peer uid is our euid");
    assert_eq!(gid, unsafe { libc::getegid() }, "peer gid is our egid");
    // LOCAL_PEERPID is best-effort: our pid when supported, else 0.
    let me = unsafe { libc::getpid() } as u32;
    assert!(pid == me || pid == 0, "peer pid {pid} should be {me} or 0");

    // A short optlen must clamp, not overflow the guest buffer.
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        ret(
            &mut dispatcher,
            &mut memory,
            209,
            [fd_a, LINUX_SOL_SOCKET, LINUX_SO_PEERCRED, 0x4020, 0x4010, 0]
        ),
        0
    );
    let clamped = u32::from_ne_bytes(memory.read_bytes(0x4010, 4).unwrap().try_into().unwrap());
    assert_eq!(clamped, 4, "optlen must clamp to the guest-provided size");
}

#[cfg(target_os = "macos")]
#[test]
fn so_passcred_set_get_round_trips() {
    // M2: setsockopt(SO_PASSCRED) must be accepted + round-trip (was ENOPROTOOPT),
    // enabling the SCM_CREDENTIALS receive path.
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOL_SOCKET: u64 = 1;
    const SO_PASSCRED: u64 = 16;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let call = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // socketpair(AF_UNIX, SOCK_STREAM) -> fds @0x4000.
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            199,
            [AF_UNIX, SOCK_STREAM, 0, 0x4000, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = memory.read_bytes(0x4000, 8).unwrap();
    let fd = i32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]) as u64;

    // getsockopt(SO_PASSCRED) initially 0.
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_PASSCRED, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(memory.read_bytes(0x4020, 4).unwrap().try_into().unwrap()),
        0
    );

    // setsockopt(SO_PASSCRED, 1) -> 0 (NOT ENOPROTOOPT).
    memory.write_bytes(0x4000, &1i32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_SOCKET, SO_PASSCRED, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    // getsockopt(SO_PASSCRED) -> 1.
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_PASSCRED, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(memory.read_bytes(0x4020, 4).unwrap().try_into().unwrap()),
        1,
        "SO_PASSCRED must round-trip"
    );
}
