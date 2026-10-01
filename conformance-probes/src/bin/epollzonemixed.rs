//! One epoll set mixing in-zone members (eventfd, pipe) with a host-backed
//! member (an AF_UNIX socketpair end): readiness from either kind is
//! reported with the right tag, both at once are reported together, and a
//! blocked wait is woken by either kind.
//!
//! Contract `kernel.el1.epoll-zone`: a set containing a member Carrick
//! cannot serve in the zone must still behave exactly as Linux does through
//! the host path. Authority `man 7 epoll`, `man 2 epoll_wait`.
//!
//! Invariants encoded (counts and tag sums; order-independent):
//!   * idle set: timeout 0 returns 0;
//!   * each member alone is reported with its own tag;
//!   * all three ready at once: three events, tag sum 7;
//!   * a blocked wait (5 s bound) is woken by a thread writing the socket
//!     peer, and separately by a thread posting the eventfd.

use conformance_probes::report;
use std::time::Duration;

const IN: u32 = 0x001;

unsafe fn add(ep: i32, fd: i32, data: u64) {
    let mut ev = libc::epoll_event {
        events: IN,
        u64: data,
    };
    assert_eq!(libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev), 0);
}

unsafe fn poll(ep: i32, timeout: i32) -> (i32, u64) {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let n = libc::epoll_wait(ep, out.as_mut_ptr(), 8, timeout);
    (n, (0..n.max(0) as usize).map(|i| out[i].u64).sum())
}

unsafe fn post_efd(fd: i32) {
    let one = 1u64;
    assert_eq!(libc::write(fd, (&one as *const u64).cast(), 8), 8);
}

unsafe fn drain_efd(fd: i32) {
    let mut v = 0u64;
    libc::read(fd, (&mut v as *mut u64).cast(), 8);
}

unsafe fn put(fd: i32) {
    assert_eq!(libc::write(fd, b"z".as_ptr().cast(), 1), 1);
}

unsafe fn get(fd: i32) {
    let mut b = 0u8;
    libc::read(fd, (&mut b as *mut u8).cast(), 1);
}

fn main() {
    unsafe {
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let mut pfd = [0i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);
        let mut sv = [0i32; 2];
        assert_eq!(
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()),
            0
        );
        let ep = libc::epoll_create1(0);
        add(ep, efd, 1);
        add(ep, pfd[0], 2);
        add(ep, sv[0], 4);

        let (idle, _) = poll(ep, 0);
        post_efd(efd);
        let (n_e, t_e) = poll(ep, 0);
        drain_efd(efd);
        put(pfd[1]);
        let (n_p, t_p) = poll(ep, 0);
        get(pfd[0]);
        put(sv[1]);
        let (n_s, t_s) = poll(ep, 0);
        get(sv[0]);
        report!(
            idle_n = idle,
            eventfd_only_n = n_e,
            eventfd_only_tag = t_e,
            pipe_only_n = n_p,
            pipe_only_tag = t_p,
            socket_only_n = n_s,
            socket_only_tag = t_s
        );

        post_efd(efd);
        put(pfd[1]);
        put(sv[1]);
        let (n_all, t_all) = poll(ep, 0);
        drain_efd(efd);
        get(pfd[0]);
        get(sv[0]);
        let (n_drained, _) = poll(ep, 0);
        report!(all_n = n_all, all_tag_sum = t_all, drained_n = n_drained);

        let peer = sv[1];
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            put(peer);
        });
        let (n_sw, t_sw) = poll(ep, 5000);
        let _ = writer.join();
        get(sv[0]);
        let poster = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            post_efd(efd);
        });
        let (n_ew, t_ew) = poll(ep, 5000);
        let _ = poster.join();
        drain_efd(efd);
        report!(
            socket_wakes_blocked_n = n_sw,
            socket_wakes_blocked_tag = t_sw,
            eventfd_wakes_blocked_n = n_ew,
            eventfd_wakes_blocked_tag = t_ew
        );

        libc::close(ep);
        libc::close(efd);
        libc::close(pfd[0]);
        libc::close(pfd[1]);
        libc::close(sv[0]);
        libc::close(sv[1]);
    }
}
