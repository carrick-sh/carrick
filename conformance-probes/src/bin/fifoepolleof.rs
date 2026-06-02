//! A named-FIFO read-end registered in epoll must report EOF when the last
//! writer closes — `EPOLLHUP` (and `EPOLLIN`, read→0). Go's netpoller does
//! exactly this on an `O_NONBLOCK` FIFO and HUNG on carrick (Go issue 66239 /
//! os.TestFIFONonBlockingEOF) because macOS `poll`/`kqueue` never report a named
//! FIFO's writer-close.
//!
//! carrick now backs the readiness on a kernel "beacon" pipe (dispatch::
//! fifo_beacon): the kernel reports the beacon's HUP correctly. This probe
//! reproduces the exact shape that exposed the original bug — the read-end is
//! registered for `EPOLLIN | EPOLLOUT` (Go watches both directions), so the host
//! poll returns a spurious POLLOUT that must NOT mask the EOF. INVARIANT:
//! `epoll_wait` returns (does not time out) with HUP/IN after writer-close, and
//! the subsequent read returns 0 (EOF).

use conformance_probes::report;

fn main() {
    unsafe {
        let path = c"/tmp/fifoepolleof.fifo";
        libc::unlink(path.as_ptr());
        if libc::mkfifo(path.as_ptr(), 0o600) != 0 {
            report!(mkfifo_ok = false);
            return;
        }
        let r = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
        let w = libc::open(path.as_ptr(), libc::O_WRONLY);
        if r < 0 || w < 0 {
            report!(open_ok = false);
            return;
        }

        // Register the read-end for IN|OUT (like Go's netpoller watches both
        // directions). The spurious POLLOUT on the read-end is what masked EOF.
        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLOUT) as u32,
            u64: r as u64,
        };
        libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev);

        // Send + drain so the buffer is empty, then close the writer.
        libc::write(w, b"hi".as_ptr().cast(), 2);
        let mut buf = [0u8; 8];
        libc::read(r, buf.as_mut_ptr().cast(), 2);
        libc::close(w);

        // epoll_wait must WAKE (not time out) and report the read-end ready.
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, 2000);
        let woke = n > 0;
        let revents = if woke { out[0].events } else { 0 };
        // After the wake, a read returns 0 (EOF).
        let eof = woke && libc::read(r, buf.as_mut_ptr().cast(), 8) == 0;

        libc::close(r);
        libc::close(ep);
        libc::unlink(path.as_ptr());

        report!(
            epoll_woke_on_writer_close = woke,
            reported_in_or_hup = revents & (libc::EPOLLIN | libc::EPOLLHUP) as u32 != 0,
            read_returns_eof = eof,
        );
    }
}
