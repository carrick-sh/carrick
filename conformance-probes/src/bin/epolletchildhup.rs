//! Edge-triggered epoll, EOF from a CHILD PROCESS exit while the parent is
//! already blocked — the faithful `cmd/go` ↔ `cgo`/`gcc` shape.
//!
//! The `go build <cgo>` hang: the parent's netpoller parks in a blocking
//! edge-triggered `epoll_wait` on a pipe whose only remaining writer is a child
//! process (a compiler); when that child exits, its write end closes and the
//! parent's read end reaches EOF, which must WAKE the parked `epoll_wait`. The
//! parent closes its OWN copy of the write end first, so the child is the last
//! writer — a leaked parent/sibling write-end copy (fork fd hygiene) OR a lost
//! cross-process EOF wake both manifest as a hang here.
//!
//! INVARIANT: the parent's already-blocked edge-triggered `epoll_wait` wakes
//! (does not time out) when the child exits, reports IN/HUP/RDHUP, and the read
//! returns 0 (EOF). Deterministic booleans; bounded wait.

use conformance_probes::report;

const EPOLLET: u32 = 0x8000_0000;

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(pipe_ok = false);
            return;
        }
        let (r, w) = (fds[0], fds[1]);
        let fl = libc::fcntl(r, libc::F_GETFL, 0);
        libc::fcntl(r, libc::F_SETFL, fl | libc::O_NONBLOCK);

        let ep = libc::epoll_create1(0);
        let mask = libc::EPOLLIN as u32 | libc::EPOLLOUT as u32 | libc::EPOLLRDHUP as u32 | EPOLLET;
        let mut ev = libc::epoll_event {
            events: mask,
            u64: r as u64,
        };
        if libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) != 0 {
            report!(epoll_add_ok = false);
            return;
        }

        let pid = libc::fork();
        if pid == 0 {
            // Child: it is the LAST writer. Hold the write end briefly so the
            // parent reaches epoll_wait first, then exit (closing the write end).
            libc::close(r);
            libc::close(ep);
            libc::usleep(300_000);
            libc::_exit(0);
        }

        // Parent: drop its own writer copy so the child is the only writer.
        libc::close(w);

        // Parked edge-triggered wait must wake when the child exits → EOF.
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 3000);
        let woke = n > 0;
        let revents = if woke { out[0].events } else { 0 };
        let reported_eof_edge =
            revents & (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLRDHUP) as u32 != 0;
        let mut buf = [0u8; 8];
        let read_eof = woke && libc::read(r, buf.as_mut_ptr().cast(), buf.len()) == 0;

        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        libc::close(r);
        libc::close(ep);

        report!(
            parent_wait_woke_on_child_exit = woke,
            reported_in_or_hup = reported_eof_edge,
            read_returns_eof = read_eof,
        );
    }
}
