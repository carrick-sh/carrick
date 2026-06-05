//! Edge-triggered epoll, EOF arrives WHILE the waiter is already blocked.
//!
//! `epolletpipeeof` closes the writer BEFORE `epoll_wait`, so carrick's
//! wait-entry kqueue drain catches the edge. The `go build <cgo>` hang is the
//! OTHER ordering: the netpoller is already parked in a blocking `epoll_wait`
//! when the last writer closes, and the EOF edge must WAKE the parked waiter.
//! This variant closes the write end from a SECOND THREAD ~300ms after the main
//! thread is already blocked.
//!
//! INVARIANT: a blocked edge-triggered `epoll_wait` wakes (does not time out)
//! when another thread closes the last writer, reports IN/HUP/RDHUP, and the
//! following read returns 0 (EOF). Deterministic booleans only; the wait is
//! bounded so a lost wake prints `false` instead of hanging.

use conformance_probes::report;
use std::thread;
use std::time::Duration;

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

        // Close the writer ~300ms from now, after main is parked in epoll_wait.
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            libc::close(w);
        });

        // Already-blocked edge-triggered wait must wake on the cross-thread close.
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 3000);
        let woke = n > 0;
        let revents = if woke { out[0].events } else { 0 };
        let reported_eof_edge =
            revents & (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLRDHUP) as u32 != 0;
        let mut buf = [0u8; 8];
        let read_eof = woke && libc::read(r, buf.as_mut_ptr().cast(), buf.len()) == 0;

        libc::close(r);
        libc::close(ep);

        report!(
            blocked_wait_woke_on_close = woke,
            reported_in_or_hup = reported_eof_edge,
            read_returns_eof = read_eof,
        );
    }
}
