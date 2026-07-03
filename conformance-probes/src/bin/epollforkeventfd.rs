//! A forked child writing an inherited eventfd must wake the parent's epoll.
//!
//! This is the guest-visible cross-process shape behind the in-memory epoll
//! wake registry: eventfd readiness produced after `fork` must still reach an
//! already-blocking epoll waiter in the parent.

use conformance_probes::{reap, report};

fn main() {
    unsafe {
        let efd = libc::eventfd(0, 0);
        let ep = libc::epoll_create1(0);
        let setup_ok = efd >= 0 && ep >= 0;
        report!(setup_ok = setup_ok);
        if !setup_ok {
            if efd >= 0 {
                libc::close(efd);
            }
            if ep >= 0 {
                libc::close(ep);
            }
            return;
        }

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: efd as u64,
        };
        let epoll_add_ok = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev) == 0;
        report!(epoll_add_ok = epoll_add_ok);
        if !epoll_add_ok {
            libc::close(efd);
            libc::close(ep);
            return;
        }

        let child = libc::fork();
        if child == 0 {
            let one: u64 = 1;
            let wrote = libc::write(efd, (&one as *const u64).cast(), 8) == 8;
            libc::_exit(if wrote { 0 } else { 7 });
        }

        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let woke = libc::epoll_wait(ep, out.as_mut_ptr(), 1, 2000) == 1;
        let epollin = woke && (out[0].events & libc::EPOLLIN as u32) != 0;

        let mut value = 0u64;
        let read_ok = libc::read(efd, (&mut value as *mut u64).cast(), 8) == 8;
        let (wait_rc, status) = reap(child);
        let child_write_ok =
            wait_rc == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        report!(
            child_write_ok = child_write_ok,
            parent_epoll_woke = woke,
            parent_epollin = epollin,
            eventfd_value_one = read_ok && value == 1,
        );

        libc::close(efd);
        libc::close(ep);
    }
}
