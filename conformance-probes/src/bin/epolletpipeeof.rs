//! An anonymous-`pipe(2)` read-end watched with EDGE-triggered epoll
//! (`EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET` — Go's exact netpoll mask 0x80002005)
//! must deliver the writer-close EOF as a FRESH readiness edge, even after an
//! earlier data edge was already consumed and the buffer drained to `EAGAIN`.
//!
//! This is the shape Go's `cmd/go` toolchain (and `cgo`) drives when it reads a
//! child compiler's output pipe and then waits for EOF: read until EAGAIN under
//! EPOLLET, then the child exits and closes its write end. On Linux the close is
//! a new readable/HUP edge, so the next `epoll_wait` wakes. carrick backs the
//! readiness on a kqueue `EVFILT_READ` registered `EV_CLEAR` (edge); if the EOF
//! edge that fires while the guest is NOT inside `epoll_wait` is consumed by a
//! drain without being re-surfaced, the netpoller blocks forever — which is the
//! `go build <cgo>` / `TestCoroCgoCallback` hang.
//!
//! INVARIANT: after draining a first edge to EAGAIN and closing the writer, a
//! bounded `epoll_wait` WAKES (does not time out) and reports IN/HUP/RDHUP, and
//! the subsequent read returns 0 (EOF). Deterministic booleans only.

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
        // Go's netpoll read end is non-blocking so it can drain to EAGAIN.
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

        // First edge: writer puts a byte, reader wakes and drains to EAGAIN.
        // This consumes the EV_CLEAR read edge so the close below must produce a
        // genuinely NEW one (the exact condition that exposed the lost edge).
        libc::write(w, b"x".as_ptr().cast(), 1);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let woke1 = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 2000) > 0;
        let mut buf = [0u8; 64];
        loop {
            let n = libc::read(r, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break; // 0 = EOF (not yet), <0 = EAGAIN: buffer drained
            }
        }

        // Writer closes — on Linux this is a fresh IN/HUP edge on the read end.
        libc::close(w);

        // The netpoll wait that must wake on the EOF edge (or carrick hangs).
        let n2 = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 2000);
        let woke2 = n2 > 0;
        let revents2 = if woke2 { out[0].events } else { 0 };
        let reported_eof_edge =
            revents2 & (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLRDHUP) as u32 != 0;
        let read_eof = woke2 && libc::read(r, buf.as_mut_ptr().cast(), buf.len()) == 0;

        libc::close(r);
        libc::close(ep);

        report!(
            woke_on_first_write = woke1,
            woke_on_writer_close = woke2,
            reported_in_or_hup = reported_eof_edge,
            read_returns_eof = read_eof,
        );
    }
}
