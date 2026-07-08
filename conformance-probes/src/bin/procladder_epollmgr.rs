//! Cluster-B reproducer shape: N children, each THREE-threaded —
//!   * thread A: epoll_wait on an epfd holding an AF_UNIX SOCK_STREAM
//!     LISTENER (fd-backed park; the 38232 manager's accept loop),
//!   * main:     epoll_wait on an epfd holding a socketpair peer
//!     (fd-backed park; the manager's alive/command channel),
//!   * thread B: loop { nanosleep(3s) } (release-safe; drives the deferred
//!     whole-VM upgrade attempt — vacuous without it, see procladder_mixed).
//!
//! Default (veto ON): the fd-backed parks veto the release; probe is a
//! mechanism gate and must stay GREEN. With CARRICK_MT_VM_LEASE_FDBACKED=1
//! the release actually happens under the two epoll waiters — the
//! wake-correctness question cluster B left open (a plain pipe read survived
//! release, b01e18e2; an epoll/AF_UNIX manager is the un-root-caused shape).
//!
//! Parent waits 2.6 s (past the ~2 s first upgrade attempt), then connects to
//! each child's listener AND writes one byte to each socketpair — BOTH
//! fd-backed waiters must wake. A stranded waiter hangs the parent's
//! unbounded waitpid → harness-timeout red (same recorded property as
//! procladder_mixed).
//!
//! Invariants: mgr_forked_all, mgr_children_ok. N default 4 (gate-safe);
//! PROC_LADDER_N overrides.
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::{errno, report};
use std::env;
use std::fs;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 1024)
}

fn add_epoll(epfd: i32, fd: i32, events: u32) -> bool {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}

/// Block in `epoll_wait(-1)` (indefinite timeout — the fd-backed park) until
/// at least one event is ready. Retries EINTR; returns false on any other
/// error.
fn wait_one(epfd: i32) -> bool {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        if n > 0 {
            return true;
        }
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
    }
}

fn sockaddr_un_for(path: &str) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() {
        return None;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *slot = *byte as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Some((addr, len))
}

/// `unlink` + `socket` + `bind` + `listen(8)` an AF_UNIX SOCK_STREAM
/// listener at `path` (the 38232 manager's accept-loop listener). The
/// unlink clears a stale socket file left behind by an interrupted prior
/// run — without it the bind fails EADDRINUSE, the child `_exit(3)`s, and
/// the probe reads as a spurious DIFF. Returns the raw fd, or -1.
fn make_listener(path: &str) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return -1;
        }
        let Some((addr, len)) = sockaddr_un_for(path) else {
            libc::close(fd);
            return -1;
        };
        libc::unlink(addr.sun_path.as_ptr());
        if libc::bind(fd, (&raw const addr).cast(), len) != 0 {
            libc::close(fd);
            return -1;
        }
        if libc::listen(fd, 8) != 0 {
            libc::close(fd);
            return -1;
        }
        fd
    }
}

/// `socket` + `connect` to the AF_UNIX listener at `path`. Returns the raw
/// fd, or -1.
fn connect_to(path: &str) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return -1;
        }
        let Some((addr, len)) = sockaddr_un_for(path) else {
            libc::close(fd);
            return -1;
        };
        if libc::connect(fd, (&raw const addr).cast(), len) != 0 {
            libc::close(fd);
            return -1;
        }
        fd
    }
}

fn listener_path(idx: usize) -> String {
    format!("/tmp/pl_mgr_{idx}.sock")
}

/// Child body: three threads sharing one process/VM.
///   * thread A — own epfd holding the AF_UNIX listener (fd-backed park);
///     on wake: accept, read 1 byte, notify the main thread via an internal
///     pipe, then park forever in `pause()`.
///   * thread B — release-safe slicing sibling: `loop { nanosleep(3s) }`.
///   * main    — own epfd holding the inherited socketpair peer AND the
///     notify-pipe read end (both fd-backed); exits 0 once BOTH have
///     delivered their byte.
fn child_body(idx: usize, sock_peer_fd: i32) -> ! {
    let listen_fd = make_listener(&listener_path(idx));
    if listen_fd < 0 {
        unsafe { libc::_exit(3) };
    }
    let mut notify_fds = [-1i32; 2];
    if unsafe { libc::pipe(notify_fds.as_mut_ptr()) } != 0 {
        unsafe { libc::_exit(3) };
    }
    let notify_read = notify_fds[0];
    let notify_write = notify_fds[1];

    std::thread::spawn(move || unsafe {
        let epfd = libc::epoll_create1(0);
        if epfd < 0 || !add_epoll(epfd, listen_fd, libc::EPOLLIN as u32) {
            libc::_exit(3);
        }
        if !wait_one(epfd) {
            libc::_exit(3);
        }
        let conn = libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut());
        if conn < 0 {
            libc::_exit(3);
        }
        let mut byte = 0u8;
        if libc::read(conn, (&raw mut byte).cast(), 1) != 1 {
            libc::_exit(3);
        }
        libc::close(conn);
        let one = 1u8;
        libc::write(notify_write, (&raw const one).cast(), 1);
        // Stay parked (and stay alive) so the process doesn't exit under
        // the main thread; reaped with the process.
        loop {
            libc::pause();
        }
    });

    std::thread::spawn(|| {
        loop {
            let ts = libc::timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
        }
    });

    unsafe {
        let epfd = libc::epoll_create1(0);
        if epfd < 0
            || !add_epoll(epfd, sock_peer_fd, libc::EPOLLIN as u32)
            || !add_epoll(epfd, notify_read, libc::EPOLLIN as u32)
        {
            libc::_exit(3);
        }
        let mut sock_done = false;
        let mut notify_done = false;
        while !(sock_done && notify_done) {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
            let n = libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1);
            if n < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                libc::_exit(3);
            }
            for ev in events.iter().take(n.max(0) as usize) {
                if ev.u64 == sock_peer_fd as u64 && !sock_done {
                    let mut byte = 0u8;
                    if libc::read(sock_peer_fd, (&raw mut byte).cast(), 1) == 1 {
                        sock_done = true;
                    }
                } else if ev.u64 == notify_read as u64 && !notify_done {
                    let mut byte = 0u8;
                    if libc::read(notify_read, (&raw mut byte).cast(), 1) == 1 {
                        notify_done = true;
                    }
                }
            }
        }
        libc::_exit(0);
    }
}

fn main() {
    let n = ladder_n();
    // (pid, parent's socketpair end)
    let mut children: Vec<(i32, i32)> = Vec::with_capacity(n);
    unsafe {
        // A child that died early closes its socketpair end; the wake write
        // below must then produce clean false booleans (EPIPE), not a
        // SIGPIPE crash-red (mirrors procladder_mixed).
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        for idx in 0..n {
            let mut sv = [-1i32; 2];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
                break;
            }
            let pid = libc::fork();
            if pid == 0 {
                libc::close(sv[0]); // parent's end
                child_body(idx, sv[1]);
            }
            if pid < 0 {
                libc::close(sv[0]);
                libc::close(sv[1]);
                break;
            }
            libc::close(sv[1]); // child's end
            children.push((pid, sv[0]));
        }
        let forked = children.len();

        // Sit WELL past any would-be whole-VM release: the sleeper's first
        // upgrade ATTEMPT lands at its second full parked slice (~2 s), so
        // 2.6 s ensures that if the fd-backed veto were broken, the release
        // (and any stranded fd-waiter) has already happened before the wake
        // bytes go out (same margin as procladder_mixed).
        let ts = libc::timespec {
            tv_sec: 2,
            tv_nsec: 600_000_000,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());

        for (idx, &(_, sock_fd)) in children.iter().enumerate() {
            let path = listener_path(idx);
            let conn = connect_to(&path);
            if conn >= 0 {
                let one = 1u8;
                libc::write(conn, (&raw const one).cast(), 1);
                libc::close(conn);
            }
            let _ = fs::remove_file(&path);
            let one = 1u8;
            libc::write(sock_fd, (&raw const one).cast(), 1);
        }

        let mut exited_clean = 0usize;
        for &(pid, sock_fd) in &children {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                exited_clean += 1;
            }
            libc::close(sock_fd);
        }
        report!(
            mgr_forked_all = forked == n,
            mgr_children_ok = exited_clean == forked,
        );
    }
}
