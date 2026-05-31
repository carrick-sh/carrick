//! Networking / I/O multiplexing syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[cfg(target_os = "macos")]
use carrick_runtime::io_wait::{ThreadWaiter, WaitResult};
use carrick_runtime::linux_abi::{
    LINUX_AF_INET, LINUX_AT_FDCWD, LINUX_EADDRINUSE, LINUX_ECONNREFUSED, LINUX_EINTR, LINUX_ENOENT,
    LINUX_ENXIO, LINUX_EPOLLOUT, LINUX_O_CREAT, LINUX_O_RDWR, LINUX_SOCK_CLOEXEC,
    LINUX_SOCK_NONBLOCK, LINUX_SOCK_STREAM, LINUX_SOL_TCP,
};
#[cfg(target_os = "macos")]
use carrick_runtime::thread::{FutexTable, ThreadRegistry};
#[cfg(target_os = "macos")]
use carrick_runtime::vfs::BindVfs;
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const LINUX_TCP_KEEPIDLE: u64 = 4;

/// Regression for the Go `net` unix-socket hang (docs/go-conformance-punchlist.md
/// P1b): carrick translates a guest unix path to a hashed host path under
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

/// Regression for the Go `net` `TestFileListener` hang (docs/go-conformance-punchlist.md
/// P1): a dup'd socket shares ONE host fd, but carrick's epoll kqueue is keyed by
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

#[test]
fn epoll_event_matches_aarch64_c_abi_layout() {
    assert_eq!(core::mem::size_of::<LinuxEpollEvent>(), 16);
    assert_eq!(
        <LinuxEpollEvent as carrick_runtime::linux_abi::KernelAbi>::ABI_SIZE,
        16
    );
    let event = LinuxEpollEvent {
        events: 0xaabb_ccdd,
        _pad: 0,
        data: 0x1122_3344_5566_7788,
    };
    let bytes = event.as_bytes();
    assert_eq!(&bytes[0..4], &0xaabb_ccdd_u32.to_le_bytes());
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    assert_eq!(&bytes[8..16], &0x1122_3344_5566_7788_u64.to_le_bytes());
}

#[test]
fn fionread_and_fionbio_bootstrap_succeed_for_valid_fds() {
    let mut memory = LinearMemory::new(0x4000, vec![0xee; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // FIONREAD on stdio writes 0.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_FIONREAD, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4000), 0);

    // FIONBIO on stdio with enable=1 → 0.
    memory.write_bytes(0x4010, &1_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, LINUX_FIONBIO, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // FIONBIO on fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_FIONBIO, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // FIONREAD on unknown fd 99 → EBADF too.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_FIONREAD, 0x4020, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

#[test]
fn fionbio_updates_pipe_status_flags_and_host_nonblocking_mode() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    memory.write_bytes(0x4020, &1_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([pair.read_fd as u64, LINUX_FIONBIO, 0x4020, 0, 0, 0]),
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
                    63,
                    SyscallArgs::from([pair.read_fd as u64, 0x4040, 1, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    memory.write_bytes(0x4020, &0_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([pair.read_fd as u64, LINUX_FIONBIO, 0x4020, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    match dispatcher
        .dispatch(
            SyscallRequest::new(
                63,
                SyscallArgs::from([pair.read_fd as u64, 0x4040, 1, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::WaitOnFds { .. } => {}
        other => panic!("expected blocking read handoff after FIONBIO(0), got {other:?}"),
    }
}

#[test]
fn eventfd2_read_write_round_trip_uses_packed_counter() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([7, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let value = read_eventfd_value(&memory, 0x4000).value;
    assert_eq!(value, 7);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    memory
        .write_bytes(0x4010, LinuxEventfdValue { value: 5 }.as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4010, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4020, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let value = read_eventfd_value(&memory, 0x4020).value;
    assert_eq!(value, 5);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pipe2_writes_packed_fd_pair_and_round_trips_bytes() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    let write_fd = pair.write_fd as u64;
    assert_eq!(read_fd, 3);
    assert_eq!(write_fd, 4);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([read_fd, LINUX_F_GETFD, 0, 0, 0, 0])),
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
                SyscallRequest::new(25, SyscallArgs::from([read_fd, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_O_NONBLOCK as i64
        }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    memory.write_bytes(0x4040, b"pipe data").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([write_fd, 0x4040, 9, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 32, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(memory.read_bytes(0x4080, 9).unwrap(), b"pipe data");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pipe2_duplicate_writer_keeps_pipe_open_until_all_writers_close() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    let write_fd = pair.write_fd as u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(23, SyscallArgs::from([write_fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([write_fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([5, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_getpipe_size_reports_bootstrap_pipe_capacity() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([pair.read_fd as u64, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 65536 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_settime_read_round_trip_uses_packed_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_O_NONBLOCK as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    let one_shot = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    memory.write_bytes(0x4000, one_shot.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4000, 0x4080, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let old = read_itimerspec(&memory, 0x4080);
    let old_value_sec = old.it_value.tv_sec;
    let old_value_nsec = old.it_value.tv_nsec;
    assert_eq!(old_value_sec, 0);
    assert_eq!(old_value_nsec, 0);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let expirations = read_timerfd_expirations(&memory, 0x4100).expirations;
    assert!(expirations >= 1);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_gettime_writes_packed_itimerspec_for_armed_timer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    let armed = LinuxItimerspec {
        it_interval: LinuxTimespec::new(2, 0),
        it_value: LinuxTimespec::new(5, 0),
    };
    memory.write_bytes(0x4000, armed.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(87, SyscallArgs::from([3, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let current = read_itimerspec(&memory, 0x4080);
    let interval_sec = current.it_interval.tv_sec;
    let remaining_sec = current.it_value.tv_sec;
    assert_eq!(interval_sec, 2);
    assert!((0..=5).contains(&remaining_sec));
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_reports_timerfd_readiness_with_packed_event() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        _pad: 0,
        data: 0x544d,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let one_shot = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    memory.write_bytes(0x4040, one_shot.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4040, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let ready = read_epoll_event(&memory, 0x4100);
    let data = ready.data;
    assert_eq!(data, 0x544d);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn blocking_timerfd_read_waits_until_timer_is_armed() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = Arc::new(CompatReporter::default());
    let registry = Arc::new(ThreadRegistry::new(20));
    let futex = Arc::new(FutexTable::new());
    assert_eq!(registry.register_child(20), 21);

    let mut setup_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let created = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(85, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
            &mut setup_memory,
            &reporter,
            20,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = created else {
        panic!("expected timerfd_create success, got {created:?}");
    };

    let (tx, rx) = mpsc::channel();
    let read_dispatcher = Arc::clone(&dispatcher);
    let read_reporter = Arc::clone(&reporter);
    let read_registry = Arc::clone(&registry);
    let read_futex = Arc::clone(&futex);
    let reader = std::thread::spawn(move || {
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
        let outcome = read_dispatcher
            .dispatch_threaded(
                SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &read_reporter,
                20,
                &read_registry,
                &read_futex,
            )
            .unwrap();
        let expirations = read_timerfd_expirations(&memory, 0x4000).expirations;
        tx.send((outcome, expirations)).unwrap();
    });

    std::thread::sleep(Duration::from_millis(25));
    assert!(
        rx.try_recv().is_err(),
        "blocking timerfd read returned before timer was armed"
    );

    let mut arm_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let one_shot = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    arm_memory.write_bytes(0x4000, one_shot.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(86, SyscallArgs::from([fd as u64, 0, 0x4000, 0, 0, 0])),
                &mut arm_memory,
                &reporter,
                21,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let (outcome, expirations) = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking timerfd reader should wake after arming");
    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert!(expirations >= 1);
    reader.join().expect("reader thread panicked");
}

#[cfg(target_os = "macos")]
#[test]
fn timerfd_rearm_wakes_blocked_reader_without_waiting_for_old_deadline() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = Arc::new(CompatReporter::default());
    let registry = Arc::new(ThreadRegistry::new(30));
    let futex = Arc::new(FutexTable::new());
    assert_eq!(registry.register_child(30), 31);

    let mut setup_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let created = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(85, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
            &mut setup_memory,
            &reporter,
            30,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = created else {
        panic!("expected timerfd_create success, got {created:?}");
    };

    let long_timer = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 250_000_000),
    };
    setup_memory
        .write_bytes(0x4000, long_timer.as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(86, SyscallArgs::from([fd as u64, 0, 0x4000, 0, 0, 0])),
                &mut setup_memory,
                &reporter,
                30,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let (tx, rx) = mpsc::channel();
    let read_dispatcher = Arc::clone(&dispatcher);
    let read_reporter = Arc::clone(&reporter);
    let read_registry = Arc::clone(&registry);
    let read_futex = Arc::clone(&futex);
    let reader = std::thread::spawn(move || {
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
        let outcome = read_dispatcher
            .dispatch_threaded(
                SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &read_reporter,
                30,
                &read_registry,
                &read_futex,
            )
            .unwrap();
        tx.send(outcome).unwrap();
    });

    std::thread::sleep(Duration::from_millis(25));
    let started = Instant::now();
    let short_timer = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    let mut rearm_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    rearm_memory
        .write_bytes(0x4000, short_timer.as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(86, SyscallArgs::from([fd as u64, 0, 0x4000, 0, 0, 0])),
                &mut rearm_memory,
                &reporter,
                31,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        rx.recv_timeout(Duration::from_millis(150))
            .expect("re-armed timerfd reader should wake promptly"),
        DispatchOutcome::Returned { value: 8 }
    );
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "reader waited for the stale long deadline"
    );
    reader.join().expect("reader thread panicked");
}

#[cfg(target_os = "macos")]
#[test]
fn blocking_eventfd_read_waits_until_writer_updates_counter() {
    let dispatcher = Arc::new(SyscallDispatcher::new());
    let reporter = Arc::new(CompatReporter::default());
    let registry = Arc::new(ThreadRegistry::new(10));
    let futex = Arc::new(FutexTable::new());
    assert_eq!(registry.register_child(10), 11);

    let mut setup_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let eventfd = dispatcher
        .dispatch_threaded(
            SyscallRequest::new(19, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut setup_memory,
            &reporter,
            10,
            &registry,
            &futex,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: fd } = eventfd else {
        panic!("expected eventfd2 success, got {eventfd:?}");
    };

    let (tx, rx) = mpsc::channel();
    let read_dispatcher = Arc::clone(&dispatcher);
    let read_reporter = Arc::clone(&reporter);
    let read_registry = Arc::clone(&registry);
    let read_futex = Arc::clone(&futex);
    let reader = std::thread::spawn(move || {
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
        let outcome = read_dispatcher
            .dispatch_threaded(
                SyscallRequest::new(63, SyscallArgs::from([fd as u64, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &read_reporter,
                10,
                &read_registry,
                &read_futex,
            )
            .unwrap();
        let value = read_eventfd_value(&memory, 0x4000).value;
        tx.send((outcome, value)).unwrap();
    });

    std::thread::sleep(Duration::from_millis(25));
    assert!(
        rx.try_recv().is_err(),
        "blocking read returned before writer"
    );

    let mut write_memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    write_memory
        .write_bytes(0x4000, &5_u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch_threaded(
                SyscallRequest::new(64, SyscallArgs::from([fd as u64, 0x4000, 8, 0, 0, 0])),
                &mut write_memory,
                &reporter,
                11,
                &registry,
                &futex,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );

    let (outcome, value) = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking eventfd reader should wake");
    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert_eq!(value, 5);
    reader.join().expect("reader thread panicked");
}

#[test]
fn epoll_reports_eventfd_readiness_with_packed_events() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        _pad: 0,
        data: 0xabc,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
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
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let ready = read_epoll_event(&memory, 0x4100);
    let events = ready.events;
    let data = ready.data;
    assert_eq!(events & LINUX_EPOLLIN, LINUX_EPOLLIN);
    assert_eq!(data, 0xabc);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_edge_triggered_eventfd_reports_only_new_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN | LINUX_EPOLLET,
        _pad: 0,
        data: 0xfeed,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
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
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let first = read_epoll_event(&memory, 0x4100);
    let first_data = first.data;
    assert_eq!(first.events & LINUX_EPOLLIN, LINUX_EPOLLIN);
    assert_eq!(first_data, 0xfeed);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let one = LinuxEventfdValue { value: 1 };
    memory.write_bytes(0x4300, one.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4300, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_edge_triggered_ready_overflow_is_returned_on_next_wait() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x700]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    for fd in 3..=5 {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        19,
                        SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: fd }
        );
    }
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 6 }
    );
    for (fd, data, addr) in [
        (3, 0x301_u64, 0x4000_u64),
        (4, 0x401, 0x4010),
        (5, 0x501, 0x4020),
    ] {
        let wanted = LinuxEpollEvent {
            events: LINUX_EPOLLIN | LINUX_EPOLLET,
            _pad: 0,
            data,
        };
        memory.write_bytes(addr, wanted.as_bytes()).unwrap();
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        21,
                        SyscallArgs::from([6, LINUX_EPOLL_CTL_ADD, fd, addr, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
    }

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([6, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 2 }
    );
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..2_u64 {
        let event = read_epoll_event(&memory, 0x4100 + index * 16);
        assert_eq!(event.events & LINUX_EPOLLIN, LINUX_EPOLLIN);
        seen.insert(event.data);
    }

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([6, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let leftover = read_epoll_event(&memory, 0x4100);
    assert_eq!(leftover.events & LINUX_EPOLLIN, LINUX_EPOLLIN);
    seen.insert(leftover.data);
    assert_eq!(
        seen,
        std::collections::BTreeSet::from([0x301_u64, 0x401, 0x501])
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_timed_wait_blocks_after_edge_event_was_already_reported() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN | LINUX_EPOLLET,
        _pad: 0,
        data: 0xfeed,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
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
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 25, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::WaitOnPollFds {
        fds,
        timeout,
        on_timeout,
        block_signals,
    } = outcome
    else {
        panic!("expected timed epoll wait handoff, got {outcome:?}");
    };
    assert_eq!(fds.len(), 1);
    assert!(fds[0].0 >= 0);
    assert_eq!(fds[0].1 & libc::POLLIN, libc::POLLIN);
    assert_eq!(timeout, Some(std::time::Duration::from_millis(25)));
    assert_eq!(on_timeout, 0);
    assert_eq!(block_signals, 0);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_waits_on_host_backed_edge_interests_when_no_event_is_ready() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN | LINUX_EPOLLET,
        _pad: 0,
        data: 0xbeef,
    };
    memory.write_bytes(0x4040, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([5, LINUX_EPOLL_CTL_ADD, read_fd, 0x4040, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(22, SyscallArgs::from([5, 0x4100, 4, 25, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let DispatchOutcome::WaitOnPollFds {
        fds,
        timeout,
        on_timeout,
        block_signals,
    } = outcome
    else {
        panic!("expected epoll wait handoff, got {outcome:?}");
    };
    assert_eq!(fds.len(), 1);
    assert!(fds[0].0 >= 0);
    assert_eq!(fds[0].1 & libc::POLLIN, libc::POLLIN);
    assert_eq!(timeout, Some(std::time::Duration::from_millis(25)));
    assert_eq!(on_timeout, 0);
    assert_eq!(block_signals, 0);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn epoll_wakes_accepted_socket_after_peer_write() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x4000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let socket_type = (LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC) as u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    198,
                    SyscallArgs::from([LINUX_AF_INET as u64, socket_type, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    write_sockaddr_in(&mut memory, 0x4000, 0);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(200, SyscallArgs::from([3, 0x4000, 16, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(201, SyscallArgs::from([3, 128, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    memory.write_bytes(0x4020, &16_u32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(204, SyscallArgs::from([3, 0x4010, 0x4020, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let port = read_sockaddr_in_port(&memory, 0x4010);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    add_epoll_interest(&mut dispatcher, &mut memory, &reporter, 4, 3, 0x5000);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    198,
                    SyscallArgs::from([LINUX_AF_INET as u64, socket_type, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    write_sockaddr_in(&mut memory, 0x4030, port);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(203, SyscallArgs::from([5, 0x4030, 16, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 115 }
    );
    add_epoll_interest(&mut dispatcher, &mut memory, &reporter, 4, 5, 0x5020);

    memory.write_bytes(0x4060, &16_u32.to_le_bytes()).unwrap();
    let accepted_fd = loop {
        match dispatcher
            .dispatch(
                SyscallRequest::new(
                    242,
                    SyscallArgs::from([
                        3,
                        0x4050,
                        0x4060,
                        (LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC) as u64,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } => break value as u64,
            DispatchOutcome::Errno { errno: 11 } => {
                let _ = dispatch_with_wait(
                    &mut dispatcher,
                    SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 100, 0, 0])),
                    &mut memory,
                    &reporter,
                );
            }
            other => panic!("unexpected accept4 outcome: {other:?}"),
        }
    };
    add_epoll_interest(
        &mut dispatcher,
        &mut memory,
        &reporter,
        4,
        accepted_fd,
        0x5040,
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([accepted_fd, 0x5200, 64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    let initial_count = match dispatcher
        .dispatch(
            SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value,
        other => panic!("unexpected initial epoll outcome: {other:?}"),
    };
    assert!(initial_count >= 1);
    let mut saw_accepted_out = false;
    for index in 0..initial_count as u64 {
        let initial_event = read_epoll_event(&memory, 0x5100 + index * 16);
        let initial_event_data = initial_event.data;
        let initial_event_events = initial_event.events;
        if initial_event_data == accepted_fd {
            assert_eq!(initial_event_events & LINUX_EPOLLOUT, LINUX_EPOLLOUT);
            saw_accepted_out = true;
        }
    }
    assert!(saw_accepted_out);

    set_tcp_keepidle(&mut dispatcher, &mut memory, &reporter, 5, 0x5400);
    set_tcp_keepidle(&mut dispatcher, &mut memory, &reporter, accepted_fd, 0x5410);

    memory
        .write_bytes(0x5300, b"GET /demo HTTP/1.1\r\n\r\n")
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([5, 0x5300, 22, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 22 }
    );

    let outcome = dispatch_with_wait(
        &mut dispatcher,
        SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 100, 0, 0])),
        &mut memory,
        &reporter,
    );
    let ready_count = match outcome {
        DispatchOutcome::Returned { value } => value,
        other => panic!("unexpected epoll outcome after peer write: {other:?}"),
    };
    assert!(ready_count >= 1);
    let mut saw_accepted_in = false;
    for index in 0..ready_count as u64 {
        let event = read_epoll_event(&memory, 0x5100 + index * 16);
        let event_data = event.data;
        let event_events = event.events;
        if event_data == accepted_fd && event_events & LINUX_EPOLLIN != 0 {
            saw_accepted_in = true;
        }
    }
    assert!(saw_accepted_in);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn threaded_epoll_wait_wakes_when_peer_thread_writes_to_accepted_socket() {
    let memory = Arc::new(Mutex::new(LinearMemory::new(0x4000, vec![0; 0x4000])));
    let threaded = ThreadedDispatch::new(1000);
    let server_tid = 1000;
    let client_tid = threaded.registry.register_child(0);
    let wait_tid = threaded.registry.register_child(0);

    let socket_type = (LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC) as u64;
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(
                198,
                SyscallArgs::from([LINUX_AF_INET as u64, socket_type, 0, 0, 0, 0]),
            ),
        ),
        DispatchOutcome::Returned { value: 3 }
    );
    {
        let mut memory = memory.lock().unwrap();
        write_sockaddr_in(&mut *memory, 0x4000, 0);
    }
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(200, SyscallArgs::from([3, 0x4000, 16, 0, 0, 0])),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(201, SyscallArgs::from([3, 128, 0, 0, 0, 0])),
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    {
        let mut memory = memory.lock().unwrap();
        memory.write_bytes(0x4020, &16_u32.to_le_bytes()).unwrap();
    }
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(204, SyscallArgs::from([3, 0x4010, 0x4020, 0, 0, 0])),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let port = {
        let memory = memory.lock().unwrap();
        read_sockaddr_in_port(&*memory, 0x4010)
    };

    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
        ),
        DispatchOutcome::Returned { value: 4 }
    );
    add_epoll_interest_threaded(&threaded, &memory, server_tid, 4, 3, 0x5000);

    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            client_tid,
            SyscallRequest::new(
                198,
                SyscallArgs::from([LINUX_AF_INET as u64, socket_type, 0, 0, 0, 0]),
            ),
        ),
        DispatchOutcome::Returned { value: 5 }
    );
    {
        let mut memory = memory.lock().unwrap();
        write_sockaddr_in(&mut *memory, 0x4030, port);
    }
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            client_tid,
            SyscallRequest::new(203, SyscallArgs::from([5, 0x4030, 16, 0, 0, 0])),
        ),
        DispatchOutcome::Errno { errno: 115 }
    );
    add_epoll_interest_threaded(&threaded, &memory, client_tid, 4, 5, 0x5020);

    {
        let mut memory = memory.lock().unwrap();
        memory.write_bytes(0x4060, &16_u32.to_le_bytes()).unwrap();
    }
    let accepted_fd = loop {
        match dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(
                242,
                SyscallArgs::from([
                    3,
                    0x4050,
                    0x4060,
                    (LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC) as u64,
                    0,
                    0,
                ]),
            ),
        ) {
            DispatchOutcome::Returned { value } => break value as u64,
            DispatchOutcome::Errno { errno: 11 } => {
                let _ = dispatch_threaded_with_wait(
                    &threaded,
                    &memory,
                    server_tid,
                    SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 100, 0, 0])),
                );
            }
            other => panic!("unexpected accept4 outcome: {other:?}"),
        }
    };
    add_epoll_interest_threaded(&threaded, &memory, server_tid, 4, accepted_fd, 0x5040);

    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            server_tid,
            SyscallRequest::new(63, SyscallArgs::from([accepted_fd, 0x5200, 64, 0, 0, 0])),
        ),
        DispatchOutcome::Errno { errno: 11 }
    );
    let initial_count = match dispatch_threaded_once(
        &threaded,
        &memory,
        server_tid,
        SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 0, 0, 0])),
    ) {
        DispatchOutcome::Returned { value } => value,
        other => panic!("unexpected epoll outcome: {:?}", other),
    };
    assert!(initial_count >= 1);

    let (wait_tx, wait_rx) = mpsc::channel();
    let wait_threaded = threaded.clone();
    let wait_memory = Arc::clone(&memory);
    let wait_handle = std::thread::spawn(move || {
        dispatch_threaded_with_wait_notify(
            &wait_threaded,
            &wait_memory,
            wait_tid,
            SyscallRequest::new(22, SyscallArgs::from([4, 0x5100, 8, 1500, 0, 0])),
            Some(wait_tx),
        )
    });
    let wait_fds = wait_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("epoll_pwait should hand off to a host-fd wait before the peer writes");
    assert!(
        wait_fds
            .iter()
            .any(|(_, events)| events & libc::POLLIN != 0)
    );

    {
        let mut memory = memory.lock().unwrap();
        memory
            .write_bytes(0x5300, b"GET /demo HTTP/1.1\r\n\r\n")
            .unwrap();
    }
    assert_eq!(
        dispatch_threaded_once(
            &threaded,
            &memory,
            client_tid,
            SyscallRequest::new(64, SyscallArgs::from([5, 0x5300, 22, 0, 0, 0])),
        ),
        DispatchOutcome::Returned { value: 22 }
    );

    let outcome = match wait_handle.join() {
        Ok(outcome) => outcome,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    let DispatchOutcome::Returned { value: ready_count } = outcome else {
        panic!("unexpected epoll outcome: {outcome:?}");
    };
    assert!(ready_count >= 1);
    let memory = memory.lock().unwrap();
    let mut saw_accepted_read = false;
    for index in 0..ready_count as u64 {
        let event = read_epoll_event(&*memory, 0x5100 + index * 16);
        let event_data = event.data;
        let event_events = event.events;
        if event_data == accepted_fd && event_events & LINUX_EPOLLIN != 0 {
            saw_accepted_read = true;
        }
    }
    assert!(saw_accepted_read);
    drop(memory);

    let reporter = match Arc::try_unwrap(threaded.reporter) {
        Ok(reporter) => reporter,
        Err(_) => panic!("threaded dispatch reporter still has outstanding references"),
    };
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[cfg(target_os = "macos")]
fn write_sockaddr_in(memory: &mut impl GuestMemory, address: u64, port: u16) {
    let mut sockaddr = [0u8; 16];
    sockaddr[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
    sockaddr[2..4].copy_from_slice(&port.to_be_bytes());
    sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    memory.write_bytes(address, &sockaddr).unwrap();
}

#[cfg(target_os = "macos")]
fn read_sockaddr_in_port(memory: &impl GuestMemory, address: u64) -> u16 {
    let bytes = memory.read_bytes(address, 16).unwrap();
    u16::from_be_bytes([bytes[2], bytes[3]])
}

#[cfg(target_os = "macos")]
fn add_epoll_interest(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
    epfd: u64,
    fd: u64,
    event_addr: u64,
) {
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN | LINUX_EPOLLOUT | LINUX_EPOLLET | 0x2000,
        _pad: 0,
        data: fd,
    };
    memory.write_bytes(event_addr, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([epfd, LINUX_EPOLL_CTL_ADD, fd, event_addr, 0, 0]),
                ),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[cfg(target_os = "macos")]
fn dispatch_with_wait(
    dispatcher: &mut SyscallDispatcher,
    request: SyscallRequest,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
) -> DispatchOutcome {
    loop {
        match dispatcher.dispatch(request, memory, reporter).unwrap() {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                let waiter = ThreadWaiter::new(unsafe { libc::getpid() });
                match waiter.wait(&fds, timeout, block_signals) {
                    WaitResult::Ready => {}
                    WaitResult::TimedOut => return DispatchOutcome::Returned { value: on_timeout },
                    WaitResult::Interrupted => {
                        return DispatchOutcome::Errno { errno: LINUX_EINTR };
                    }
                    WaitResult::Errno(errno) => {
                        return DispatchOutcome::Errno { errno };
                    }
                }
            }
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                let waiter = ThreadWaiter::new(unsafe { libc::getpid() });
                match waiter.wait_poll(&fds, timeout, block_signals) {
                    WaitResult::Ready => {}
                    WaitResult::TimedOut => return DispatchOutcome::Returned { value: on_timeout },
                    WaitResult::Interrupted => {
                        return DispatchOutcome::Errno { errno: LINUX_EINTR };
                    }
                    WaitResult::Errno(errno) => {
                        return DispatchOutcome::Errno { errno };
                    }
                }
            }
            other => return other,
        }
    }
}

#[cfg(target_os = "macos")]
fn set_tcp_keepidle(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
    fd: u64,
    opt_addr: u64,
) {
    memory.write_bytes(opt_addr, &15_i32.to_ne_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    208,
                    SyscallArgs::from([
                        fd,
                        LINUX_SOL_TCP as u64,
                        LINUX_TCP_KEEPIDLE,
                        opt_addr,
                        4,
                        0
                    ]),
                ),
                memory,
                reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct ThreadedDispatch {
    dispatcher: Arc<SyscallDispatcher>,
    reporter: Arc<CompatReporter>,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
}

#[cfg(target_os = "macos")]
impl ThreadedDispatch {
    fn new(main_tid: i32) -> Self {
        Self {
            dispatcher: Arc::new(SyscallDispatcher::new()),
            reporter: Arc::new(CompatReporter::default()),
            registry: Arc::new(ThreadRegistry::new(main_tid)),
            futex: Arc::new(FutexTable::new()),
        }
    }
}

#[cfg(target_os = "macos")]
fn dispatch_threaded_once(
    threaded: &ThreadedDispatch,
    memory: &Arc<Mutex<LinearMemory>>,
    tid: i32,
    request: SyscallRequest,
) -> DispatchOutcome {
    let mut memory = memory.lock().unwrap();
    threaded
        .dispatcher
        .dispatch_threaded(
            request,
            &mut *memory,
            threaded.reporter.as_ref(),
            tid,
            threaded.registry.as_ref(),
            threaded.futex.as_ref(),
        )
        .unwrap()
}

#[cfg(target_os = "macos")]
fn add_epoll_interest_threaded(
    threaded: &ThreadedDispatch,
    memory: &Arc<Mutex<LinearMemory>>,
    tid: i32,
    epfd: u64,
    fd: u64,
    event_addr: u64,
) {
    {
        let mut memory = memory.lock().unwrap();
        let wanted = LinuxEpollEvent {
            events: LINUX_EPOLLIN | LINUX_EPOLLOUT | LINUX_EPOLLET | 0x2000,
            _pad: 0,
            data: fd,
        };
        memory.write_bytes(event_addr, wanted.as_bytes()).unwrap();
    }
    assert_eq!(
        dispatch_threaded_once(
            threaded,
            memory,
            tid,
            SyscallRequest::new(
                21,
                SyscallArgs::from([epfd, LINUX_EPOLL_CTL_ADD, fd, event_addr, 0, 0]),
            ),
        ),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[cfg(target_os = "macos")]
fn dispatch_threaded_with_wait(
    threaded: &ThreadedDispatch,
    memory: &Arc<Mutex<LinearMemory>>,
    tid: i32,
    request: SyscallRequest,
) -> DispatchOutcome {
    dispatch_threaded_with_wait_notify(threaded, memory, tid, request, None)
}

#[cfg(target_os = "macos")]
fn dispatch_threaded_with_wait_notify(
    threaded: &ThreadedDispatch,
    memory: &Arc<Mutex<LinearMemory>>,
    tid: i32,
    request: SyscallRequest,
    mut wait_notify: Option<mpsc::Sender<Vec<(i32, i16)>>>,
) -> DispatchOutcome {
    loop {
        let outcome = dispatch_threaded_once(threaded, memory, tid, request);
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                if let Some(sender) = wait_notify.take() {
                    sender.send(fds.clone()).unwrap();
                }
                let waiter = ThreadWaiter::new(tid);
                match waiter.wait(&fds, timeout, block_signals) {
                    WaitResult::Ready => {}
                    WaitResult::TimedOut => return DispatchOutcome::Returned { value: on_timeout },
                    WaitResult::Interrupted => {
                        return DispatchOutcome::Errno { errno: LINUX_EINTR };
                    }
                    WaitResult::Errno(errno) => {
                        return DispatchOutcome::Errno { errno };
                    }
                }
            }
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                if let Some(sender) = wait_notify.take() {
                    sender.send(fds.clone()).unwrap();
                }
                let waiter = ThreadWaiter::new(tid);
                match waiter.wait_poll(&fds, timeout, block_signals) {
                    WaitResult::Ready => {}
                    WaitResult::TimedOut => return DispatchOutcome::Returned { value: on_timeout },
                    WaitResult::Interrupted => {
                        return DispatchOutcome::Errno { errno: LINUX_EINTR };
                    }
                    WaitResult::Errno(errno) => {
                        return DispatchOutcome::Errno { errno };
                    }
                }
            }
            other => return other,
        }
    }
}

#[test]
fn ppoll_reports_eventfd_pipe_and_invalid_fd_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
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
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    memory.write_bytes(0x4080, b"x").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([pair.write_fd as u64, 0x4080, 1, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    write_pollfds(
        &mut memory,
        0x4100,
        [
            LinuxPollFd {
                fd: 3,
                events: LINUX_POLLIN,
                revents: 0,
            },
            LinuxPollFd {
                fd: pair.read_fd,
                events: LINUX_POLLIN,
                revents: 0,
            },
            LinuxPollFd {
                fd: pair.write_fd,
                events: LINUX_POLLOUT,
                revents: 0,
            },
            LinuxPollFd {
                fd: 99,
                events: LINUX_POLLIN,
                revents: 0,
            },
        ],
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(73, SyscallArgs::from([0x4100, 4, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );

    let pollfds = read_pollfds(&memory, 0x4100, 4);
    assert_eq!(pollfds[0].2 & LINUX_POLLIN, LINUX_POLLIN);
    assert_eq!(pollfds[1].2 & LINUX_POLLIN, LINUX_POLLIN);
    assert_eq!(pollfds[2].2 & LINUX_POLLOUT, LINUX_POLLOUT);
    assert_eq!(pollfds[3].2, LINUX_POLLNVAL);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ppoll_reports_epoll_fd_readiness_when_registered_fd_is_ready() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);

    let event = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        _pad: 0,
        data: pair.read_fd as u64,
    };
    memory.write_bytes(0x4100, event.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([3, LINUX_EPOLL_CTL_ADD, pair.read_fd as u64, 0x4100, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    memory.write_bytes(0x4200, b"x").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([pair.write_fd as u64, 0x4200, 1, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    write_pollfds(
        &mut memory,
        0x4300,
        [LinuxPollFd {
            fd: 3,
            events: LINUX_POLLIN,
            revents: 0,
        }],
    );
    memory
        .write_bytes(0x4400, LinuxTimespec::new(0, 0).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(73, SyscallArgs::from([0x4300, 1, 0x4400, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    let pollfds = read_pollfds(&memory, 0x4300, 1);
    assert_eq!(pollfds[0].2 & LINUX_POLLIN, LINUX_POLLIN);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pselect6_reports_eventfd_pipe_and_write_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
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
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    memory.write_bytes(0x4080, b"x").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([pair.write_fd as u64, 0x4080, 1, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    let nfds = (pair.write_fd + 1) as usize;
    write_fd_set(&mut memory, 0x4100, nfds, [3, pair.read_fd]);
    write_fd_set(&mut memory, 0x4200, nfds, [pair.write_fd]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    72,
                    SyscallArgs::from([nfds as u64, 0x4100, 0x4200, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    assert_eq!(read_fd_set(&memory, 0x4100, nfds), vec![3, pair.read_fd]);
    assert_eq!(read_fd_set(&memory, 0x4200, nfds), vec![pair.write_fd]);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pselect6_invalid_fd_returns_ebadf() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    write_fd_set(&mut memory, 0x4100, 100, [99]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(72, SyscallArgs::from([100, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn socket_syscalls_dispatch_to_real_host_handlers() {
    // Now that the BSD socket family is wired through to libc, syscall
    // numbers 198..=212 / 242 must NOT come back as ENOSYS. We don't
    // care which specific errno the all-zero argument vector produces —
    // we only require that the dispatcher answered itself rather than
    // falling through to the "unhandled syscall" branch (which would
    // set ENOSYS and record an entry in `unhandled_syscalls`).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let numbers: &[u64] = &[
        198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242,
    ];

    for number in numbers {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(*number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        if let DispatchOutcome::Errno { errno } = outcome {
            assert_ne!(
                errno, 38,
                "socket syscall {number} returned ENOSYS — handler not installed"
            );
        }
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn signalfd4_vmsplice_tee_bootstrap_return_enosys() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // signalfd4 (nr 74) is implemented. With sizemask=0 (!= sizeof(sigset_t)=8)
    // Linux rejects with EINVAL(22) before touching the mask pointer
    // (fs/signalfd.c: `if (sizemask != sizeof(sigset_t)) return -EINVAL`),
    // verified against docker linux/arm64.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(74, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 },
        "signalfd4 with sizemask != 8 should return EINVAL"
    );

    // vmsplice (75) and tee (77) are not yet implemented; carrick returns ENOSYS.
    for number in [75_u64, 77] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 38 },
            "syscall {number} should return ENOSYS"
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
