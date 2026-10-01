//! Level-triggered, edge-triggered and one-shot epoll semantics over eventfd
//! and pipe members, plus the hang-up masks a pipe close produces.
//!
//! Contract `kernel.el1.epoll-zone`; authority `man 7 epoll`, `man 2
//! epoll_ctl`, `man 7 pipe`, `man 2 eventfd`.
//!
//! Each `*_n<k>` line is the return value of one `epoll_wait(timeout=0)` in
//! sequence; each `*_mask` line is the event mask (decimal) reported. The
//! sequences encode:
//!   * LT reports a still-ready member on every wait until it is drained;
//!   * ET reports once per new arrival: a still-ready member that received
//!     nothing new is not reported again, a partial pipe read does not
//!     re-arm, and a fresh write does;
//!   * an eventfd read (which only changes writability) does not produce an
//!     EPOLLIN edge for an EPOLLIN|EPOLLET registration;
//!   * EPOLLONESHOT disarms after one report, stays disarmed through new
//!     arrivals, and EPOLL_CTL_MOD re-arms it;
//!   * a pipe read end whose last writer closed reports EPOLLHUP (with
//!     EPOLLIN while bytes remain), a pipe write end whose last reader
//!     closed reports EPOLLERR (with EPOLLOUT), and EPOLLRDHUP is not a pipe
//!     event.
//! Deterministic output only; every wait has timeout 0.

use conformance_probes::report;

const IN: u32 = 0x001;
const OUT: u32 = 0x004;
const RDHUP: u32 = 0x2000;
const ONESHOT: u32 = 1 << 30;
const ET: u32 = 1 << 31;

unsafe fn ep_with(fd: i32, events: u32, data: u64) -> i32 {
    let ep = libc::epoll_create1(0);
    assert!(ep >= 0, "epoll_create1");
    let mut ev = libc::epoll_event { events, u64: data };
    assert_eq!(
        libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev),
        0,
        "add"
    );
    ep
}

/// One timeout-0 wait: (count, mask of the first event or 0).
unsafe fn poll(ep: i32) -> (i32, u32) {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 0);
    (n, if n > 0 { out[0].events } else { 0 })
}

unsafe fn efd_add(fd: i32, v: u64) {
    assert_eq!(
        libc::write(fd, (&v as *const u64).cast(), 8),
        8,
        "efd write"
    );
}

unsafe fn efd_drain(fd: i32) {
    let mut v = 0u64;
    assert_eq!(
        libc::read(fd, (&mut v as *mut u64).cast(), 8),
        8,
        "efd read"
    );
}

unsafe fn pipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK), 0, "pipe2");
    (fds[0], fds[1])
}

unsafe fn put(fd: i32, n: usize) {
    let buf = [7u8; 8];
    assert_eq!(
        libc::write(fd, buf.as_ptr().cast(), n),
        n as isize,
        "pipe write"
    );
}

unsafe fn get(fd: i32, n: usize) -> isize {
    let mut buf = [0u8; 8];
    libc::read(fd, buf.as_mut_ptr().cast(), n)
}

fn main() {
    unsafe {
        // --- LT eventfd --------------------------------------------------
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = ep_with(efd, IN, 1);
        efd_add(efd, 1);
        let (n1, m1) = poll(ep);
        let (n2, _) = poll(ep);
        efd_drain(efd);
        let (n3, _) = poll(ep);
        report!(
            lt_eventfd_n1 = n1,
            lt_eventfd_mask = m1,
            lt_eventfd_n2 = n2,
            lt_eventfd_n3 = n3
        );
        libc::close(ep);
        libc::close(efd);

        // --- ET eventfd --------------------------------------------------
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = ep_with(efd, IN | ET, 2);
        efd_add(efd, 1);
        let (n1, m1) = poll(ep);
        let (n2, _) = poll(ep);
        efd_add(efd, 1);
        let (n3, _) = poll(ep);
        efd_drain(efd);
        let (n4, _) = poll(ep);
        report!(
            et_eventfd_n1 = n1,
            et_eventfd_mask = m1,
            et_eventfd_n2 = n2,
            et_eventfd_n3_new_write = n3,
            et_eventfd_n4_after_read = n4
        );
        libc::close(ep);
        libc::close(efd);

        // --- ET pipe -----------------------------------------------------
        let (r, w) = pipe();
        let ep = ep_with(r, IN | ET, 3);
        put(w, 2);
        let (n1, _) = poll(ep);
        let partial = get(r, 1);
        let (n2, _) = poll(ep);
        put(w, 1);
        let (n3, _) = poll(ep);
        report!(
            et_pipe_n1 = n1,
            et_pipe_partial_read = partial,
            et_pipe_n2_after_partial = n2,
            et_pipe_n3_new_write = n3
        );
        libc::close(ep);

        // --- LT pipe, writer closes with bytes left, then drained ---------
        let ep = ep_with(r, IN | RDHUP, 4);
        libc::close(w);
        let (n1, m1) = poll(ep);
        let drained = get(r, 8);
        let (n2, m2) = poll(ep);
        report!(
            hup_pipe_with_data_n = n1,
            hup_pipe_with_data_mask = m1,
            hup_pipe_drained_bytes = drained,
            hup_pipe_empty_n = n2,
            hup_pipe_empty_mask = m2
        );
        libc::close(ep);
        libc::close(r);

        // --- ET pipe read end at EOF ---------------------------------------
        let (r, w) = pipe();
        let ep = ep_with(r, IN | RDHUP | ET, 5);
        let (n0, _) = poll(ep);
        libc::close(w);
        let (n1, m1) = poll(ep);
        let (n2, _) = poll(ep);
        report!(
            et_hup_n0 = n0,
            et_hup_n1 = n1,
            et_hup_mask = m1,
            et_hup_n2 = n2
        );
        libc::close(ep);
        libc::close(r);

        // --- pipe write end, reader closes -----------------------------------
        let (r, w) = pipe();
        let ep = ep_with(w, OUT, 6);
        let (n0, m0) = poll(ep);
        libc::close(r);
        let (n1, m1) = poll(ep);
        report!(
            writer_n0 = n0,
            writer_mask0 = m0,
            writer_reader_closed_n = n1,
            writer_reader_closed_mask = m1
        );
        libc::close(ep);
        libc::close(w);

        // --- EPOLLONESHOT ------------------------------------------------
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = ep_with(efd, IN | ONESHOT, 7);
        efd_add(efd, 1);
        let (n1, _) = poll(ep);
        let (n2, _) = poll(ep);
        efd_add(efd, 1);
        let (n3, _) = poll(ep);
        let mut ev = libc::epoll_event {
            events: IN | ONESHOT,
            u64: 7,
        };
        let rearm = libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, efd, &mut ev);
        let (n4, _) = poll(ep);
        let (n5, _) = poll(ep);
        report!(
            oneshot_n1 = n1,
            oneshot_n2_disarmed = n2,
            oneshot_n3_new_write = n3,
            oneshot_mod_rc = rearm,
            oneshot_n4_rearmed = n4,
            oneshot_n5_disarmed = n5
        );
        libc::close(ep);
        libc::close(efd);

        // --- interest mask filters what is reported --------------------------
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = ep_with(efd, OUT, 8);
        let (n1, m1) = poll(ep);
        let mut ev = libc::epoll_event {
            events: IN | OUT,
            u64: 8,
        };
        efd_add(efd, 1);
        let modrc = libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, efd, &mut ev);
        let (n2, m2) = poll(ep);
        report!(
            out_only_n = n1,
            out_only_mask = m1,
            in_out_mod_rc = modrc,
            in_out_n = n2,
            in_out_mask = m2
        );
        libc::close(ep);
        libc::close(efd);
    }
}
