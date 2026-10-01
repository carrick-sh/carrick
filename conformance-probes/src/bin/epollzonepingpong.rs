//! Eventfd and pipe ping-pong through epoll, between two threads and between
//! two processes that share inherited epoll descriptions.
//!
//! Contract `kernel.el1.epoll-zone`: the readiness a peer's write produces
//! must reach an epoll waiter blocked on an eventfd or pipe, every round, in
//! both directions, whether the peer is a sibling thread or a forked process
//! waiting on the SAME (inherited) epoll open description.
//!
//! Invariants encoded (one per line):
//!   * `<kind>_<peer>_rounds_ok`: all ROUNDS round trips completed, each wait
//!     returning exactly one event whose data names the expected member;
//!   * `<kind>_<peer>_peer_ok`: the partner thread/child finished its side;
//!   * `<kind>_<peer>_drained`: after the loop the set reports nothing
//!     (timeout 0 returns 0), so no stale readiness was left behind.
//!
//! Every wait is bounded at 5 s; a lost wake prints `false`, never hangs.
//! Deterministic output only.

use conformance_probes::{reap, report};

const ROUNDS: usize = 200;
const WAIT_MS: i32 = 5000;
const EPOLLIN: u32 = 0x001;

#[derive(Clone, Copy)]
struct Channel {
    /// The fd the waiter reads (eventfd, or a pipe read end).
    read: i32,
    /// The fd the peer writes (the same eventfd, or the pipe write end).
    write: i32,
    /// The epoll instance that watches `read`.
    ep: i32,
    /// The epoll_data the waiter expects back.
    tag: u64,
}

unsafe fn channel(pipe: bool, tag: u64) -> Channel {
    let (read, write) = if pipe {
        let mut fds = [0i32; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "pipe");
        (fds[0], fds[1])
    } else {
        let fd = libc::eventfd(0, 0);
        assert!(fd >= 0, "eventfd");
        (fd, fd)
    };
    let ep = libc::epoll_create1(0);
    assert!(ep >= 0, "epoll_create1");
    let mut ev = libc::epoll_event {
        events: EPOLLIN,
        u64: tag,
    };
    assert_eq!(
        libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, read, &mut ev),
        0,
        "epoll_ctl add"
    );
    Channel {
        read,
        write,
        ep,
        tag,
    }
}

unsafe fn post(c: Channel, pipe: bool) -> bool {
    if pipe {
        let b = 1u8;
        libc::write(c.write, (&b as *const u8).cast(), 1) == 1
    } else {
        let one = 1u64;
        libc::write(c.write, (&one as *const u64).cast(), 8) == 8
    }
}

/// Wait for exactly one event naming `c.tag`, then consume it.
unsafe fn take(c: Channel, pipe: bool) -> bool {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = libc::epoll_wait(c.ep, out.as_mut_ptr(), 4, WAIT_MS);
    if n != 1 || out[0].u64 != c.tag || out[0].events & EPOLLIN == 0 {
        return false;
    }
    if pipe {
        let mut b = 0u8;
        libc::read(c.read, (&mut b as *mut u8).cast(), 1) == 1
    } else {
        let mut v = 0u64;
        libc::read(c.read, (&mut v as *mut u64).cast(), 8) == 8 && v == 1
    }
}

unsafe fn quiet(c: Channel) -> bool {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    libc::epoll_wait(c.ep, out.as_mut_ptr(), 4, 0) == 0
}

unsafe fn close_channel(c: Channel) {
    libc::close(c.ep);
    libc::close(c.read);
    if c.write != c.read {
        libc::close(c.write);
    }
}

/// `to_b` carries A's posts to B; `to_a` carries B's replies to A.
unsafe fn side_b(to_b: Channel, to_a: Channel, pipe: bool) -> bool {
    for _ in 0..ROUNDS {
        if !take(to_b, pipe) || !post(to_a, pipe) {
            return false;
        }
    }
    true
}

unsafe fn side_a(to_b: Channel, to_a: Channel, pipe: bool) -> bool {
    for _ in 0..ROUNDS {
        if !post(to_b, pipe) || !take(to_a, pipe) {
            return false;
        }
    }
    true
}

unsafe fn threads(pipe: bool) -> (bool, bool, bool) {
    let to_b = channel(pipe, 0xb0b);
    let to_a = channel(pipe, 0xa1a);
    let partner = std::thread::spawn(move || unsafe { side_b(to_b, to_a, pipe) });
    let rounds = side_a(to_b, to_a, pipe);
    let peer = partner.join().unwrap_or(false);
    let drained = quiet(to_a) && quiet(to_b);
    close_channel(to_a);
    close_channel(to_b);
    (rounds, peer, drained)
}

unsafe fn processes(pipe: bool) -> (bool, bool, bool) {
    let to_b = channel(pipe, 0xb0b);
    let to_a = channel(pipe, 0xa1a);
    let child = libc::fork();
    if child == 0 {
        // The child waits on the inherited epoll description of `to_b`.
        let ok = side_b(to_b, to_a, pipe);
        libc::_exit(if ok { 0 } else { 3 });
    }
    let rounds = side_a(to_b, to_a, pipe);
    let (rc, status) = reap(child);
    let peer = rc == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    let drained = quiet(to_a) && quiet(to_b);
    close_channel(to_a);
    close_channel(to_b);
    (rounds, peer, drained)
}

fn main() {
    unsafe {
        let (r, p, d) = threads(false);
        report!(
            eventfd_threads_rounds_ok = r,
            eventfd_threads_peer_ok = p,
            eventfd_threads_drained = d
        );
        let (r, p, d) = threads(true);
        report!(
            pipe_threads_rounds_ok = r,
            pipe_threads_peer_ok = p,
            pipe_threads_drained = d
        );
        let (r, p, d) = processes(false);
        report!(
            eventfd_processes_rounds_ok = r,
            eventfd_processes_peer_ok = p,
            eventfd_processes_drained = d
        );
        let (r, p, d) = processes(true);
        report!(
            pipe_processes_rounds_ok = r,
            pipe_processes_peer_ok = p,
            pipe_processes_drained = d
        );
    }
}
