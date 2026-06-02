//! Closing a fd auto-removes it from epoll interest sets (audit H5): Linux drops
//! a closed fd from every epoll it was added to, even without EPOLL_CTL_DEL.
//! carrick keyed interest by fd number and leaked the entry, so re-adding the
//! reused fd number returned a spurious EEXIST.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - EPOLL_CTL_ADD of an eventfd → 0.
//!   - close() WITHOUT EPOLL_CTL_DEL, then a fresh eventfd reuses the number.
//!   - EPOLL_CTL_ADD of the reused fd → 0 (NOT EEXIST).

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        let epfd = libc::epoll_create1(0);
        report!(epoll_create_ok = epfd >= 0);

        let efd = libc::eventfd(0, 0);
        report!(eventfd_ok = efd >= 0);

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0xC0FFEE,
        };
        report!(add_ok = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, efd, &mut ev) == 0);

        // Close WITHOUT EPOLL_CTL_DEL — Linux auto-removes efd from the epoll.
        report!(close_ok = libc::close(efd) == 0);

        // A fresh eventfd reuses the lowest free fd number (== efd).
        let efd2 = libc::eventfd(0, 0);
        report!(reused_fd_number = efd2 == efd);

        // Re-ADD the reused number: must be 0, not a leaked-interest EEXIST.
        let r = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, efd2, &mut ev);
        report!(readd_ok = r == 0);
        report!(readd_not_eexist = !(r == -1 && errno() == libc::EEXIST));

        libc::close(efd2);
        libc::close(epfd);
    }
}
