//! Lifetime of epoll items over in-zone members: an item belongs to the
//! (fd, open description) pair it was added with and goes away only when the
//! last descriptor of that open description closes; dup'd descriptors are
//! independent items; epoll_ctl errnos.
//!
//! Contract `kernel.el1.epoll-zone`; authority `man 7 epoll` (Q6: "closing
//! a file descriptor ... removed from all epoll interest lists only after
//! all the file descriptors referring to the underlying open file
//! description have been closed"), `man 2 epoll_ctl` (EEXIST, ENOENT, EBADF,
//! EINVAL, ELOOP-free self add).
//!
//! Invariants encoded (counts, data tags, errno numbers):
//!   * closing the registered fd while a dup keeps the description open:
//!     a post through the dup is still reported with the original tag;
//!   * EPOLL_CTL_DEL on the closed number is EBADF;
//!   * once the last descriptor closes the item is gone: a new eventfd that
//!     reuses the number is not reported, and adding it succeeds (no EEXIST);
//!   * an fd and its dup can both be registered; one post reports both tags,
//!     and closing the dup leaves BOTH items (the description is still open);
//!   * closing a pipe read end that holds unread bytes removes its item;
//!   * ADD twice is EEXIST, MOD/DEL of an unregistered fd is ENOENT, adding
//!     the epoll fd to itself is EINVAL.
//! Every wait has timeout 0. Deterministic output only.

use conformance_probes::{errno, report};

const IN: u32 = 0x001;

unsafe fn add(ep: i32, fd: i32, data: u64) -> (i32, i32) {
    let mut ev = libc::epoll_event {
        events: IN,
        u64: data,
    };
    let rc = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev);
    (rc, if rc < 0 { errno() } else { 0 })
}

unsafe fn post(fd: i32) {
    let one = 1u64;
    assert_eq!(libc::write(fd, (&one as *const u64).cast(), 8), 8);
}

/// Count of ready events and the sum of their tags (order-independent).
unsafe fn poll(ep: i32) -> (i32, u64) {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let n = libc::epoll_wait(ep, out.as_mut_ptr(), 8, 0);
    let sum = (0..n.max(0) as usize).map(|i| out[i].u64).sum();
    (n, sum)
}

fn main() {
    unsafe {
        // --- survive the registered fd's close through a dup -------------
        let ep = libc::epoll_create1(0);
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let (rc, _) = add(ep, efd, 111);
        let dupfd = libc::dup(efd);
        libc::close(efd);
        post(dupfd);
        let (n, tag) = poll(ep);
        report!(
            dup_add_rc = rc,
            survives_close_n = n,
            survives_close_tag = tag
        );
        let mut ev = libc::epoll_event { events: IN, u64: 0 };
        let rc = libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, efd, &mut ev);
        report!(del_closed_rc = rc, del_closed_errno = errno());

        // --- last close removes the item; the number is reusable ----------
        libc::close(dupfd);
        let fresh = libc::eventfd(0, libc::EFD_NONBLOCK);
        post(fresh);
        let (n, _) = poll(ep);
        let (rc, e) = add(ep, fresh, 222);
        let (n2, tag2) = poll(ep);
        report!(
            gone_after_last_close_n = n,
            readd_rc = rc,
            readd_errno = e,
            readd_n = n2,
            readd_tag = tag2
        );
        libc::close(fresh);
        libc::close(ep);

        // --- fd and its dup are separate items -----------------------------
        let ep = libc::epoll_create1(0);
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let dupfd = libc::dup(efd);
        let (rc1, _) = add(ep, efd, 1000);
        let (rc2, _) = add(ep, dupfd, 2000);
        post(efd);
        let (n, sum) = poll(ep);
        libc::close(dupfd);
        let (n_after, sum_after) = poll(ep);
        report!(
            two_items_add_rc1 = rc1,
            two_items_add_rc2 = rc2,
            two_items_n = n,
            two_items_tag_sum = sum,
            after_dup_close_n = n_after,
            after_dup_close_tag_sum = sum_after
        );

        // --- ctl errnos ------------------------------------------------------
        let (rc, e) = add(ep, efd, 1);
        report!(add_twice_rc = rc, add_twice_errno = e);
        let other = libc::eventfd(0, 0);
        let mut ev = libc::epoll_event { events: IN, u64: 0 };
        let rc = libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, other, &mut ev);
        report!(mod_unregistered_rc = rc, mod_unregistered_errno = errno());
        let rc = libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, other, &mut ev);
        report!(del_unregistered_rc = rc, del_unregistered_errno = errno());
        let (rc, e) = add(ep, ep, 1);
        report!(add_self_rc = rc, add_self_errno = e);
        libc::close(other);
        libc::close(efd);
        libc::close(ep);

        // --- closing a pipe read end with unread bytes ---------------------
        let ep = libc::epoll_create1(0);
        let mut fds = [0i32; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let (rc, _) = add(ep, fds[0], 5);
        assert_eq!(libc::write(fds[1], b"xy".as_ptr().cast(), 2), 2);
        let (n_before, _) = poll(ep);
        libc::close(fds[0]);
        let (n_after, _) = poll(ep);
        report!(
            pipe_add_rc = rc,
            pipe_ready_before_close = n_before,
            pipe_gone_after_close = n_after
        );
        libc::close(fds[1]);
        libc::close(ep);
    }
}
