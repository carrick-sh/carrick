//! FIFO EOF readiness must survive fork inheritance.
//!
//! A forked child inherits the FIFO writer fd. After the child closes its copy
//! and the parent closes its copy, the read end must observe EOF through epoll.
//! This pins the guest-visible shape behind carrick's fork-child FIFO beacon
//! reconciliation: stale process-local writer bookkeeping must not keep the
//! EOF beacon alive after the real writer fds are gone.

use conformance_probes::{reap, report};

fn main() {
    unsafe {
        let path = c"/tmp/fifoforkeof.fifo";
        libc::unlink(path.as_ptr());
        let mkfifo_ok = libc::mkfifo(path.as_ptr(), 0o600) == 0;
        report!(mkfifo_ok = mkfifo_ok);
        if !mkfifo_ok {
            return;
        }

        let r = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
        let w = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
        let open_ok = r >= 0 && w >= 0;
        report!(open_ok = open_ok);
        if !open_ok {
            if r >= 0 {
                libc::close(r);
            }
            if w >= 0 {
                libc::close(w);
            }
            libc::unlink(path.as_ptr());
            return;
        }

        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLHUP) as u32,
            u64: r as u64,
        };
        let epoll_add_ok = ep >= 0 && libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0;
        report!(epoll_add_ok = epoll_add_ok);
        if !epoll_add_ok {
            libc::close(r);
            libc::close(w);
            if ep >= 0 {
                libc::close(ep);
            }
            libc::unlink(path.as_ptr());
            return;
        }

        let child = libc::fork();
        if child == 0 {
            libc::close(w);
            libc::_exit(0);
        }
        let (wait_rc, status) = reap(child);
        let child_closed_writer =
            wait_rc == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(child_closed_writer = child_closed_writer);

        libc::close(w);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 1, 2000);
        let epoll_woke_after_all_writers_closed = n == 1;
        let reported_hup_or_in = n == 1 && (out[0].events & (libc::EPOLLHUP | libc::EPOLLIN) as u32) != 0;
        let mut buf = [0u8; 1];
        let read_returns_eof = libc::read(r, buf.as_mut_ptr().cast(), 1) == 0;

        report!(
            epoll_woke_after_all_writers_closed = epoll_woke_after_all_writers_closed,
            reported_hup_or_in = reported_hup_or_in,
            read_returns_eof = read_returns_eof,
        );

        libc::close(r);
        libc::close(ep);
        libc::unlink(path.as_ptr());
    }
}
