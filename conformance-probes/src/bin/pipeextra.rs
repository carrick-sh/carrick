//! pipe / pipe2 edges beyond what `splicepipe` and `fdio` already own.
//!
//! Stands in for LTP `pipe07`, `pipe08`, `pipe12`, `pipe13`, `pipe2_01`,
//! `pipe2_02`, `pipe2_03`.
//!
//! Invariants encoded, all boolean:
//!
//!   * `pipe2(O_NONBLOCK)` returns 0 and BOTH fds report `O_NONBLOCK`
//!     via `fcntl(F_GETFL)`. (pipe2_01)
//!   * `pipe2(O_CLOEXEC)` returns 0 and BOTH fds report `FD_CLOEXEC`
//!     via `fcntl(F_GETFD)`. (pipe2_02)
//!   * `pipe2(O_DIRECT)` returns 0 (packet-mode pipe); a read of "abc"
//!     written as one write returns ALL THREE bytes as a single packet, and
//!     a follow-up read on an empty packet pipe returns -1/EAGAIN with
//!     `O_NONBLOCK` set. Some kernels (very rare) lack packet-mode pipes
//!     and return -1/EINVAL on the pipe2 call; the assertion accepts that
//!     path too. (pipe2_03)
//!   * `FIONREAD` ioctl reports the readable byte count on a written-but-
//!     unread pipe; a non-blocking write past the pipe buffer returns
//!     -1/EAGAIN; the readable byte count matches what was actually
//!     written.
//!   * A read from a pipe whose write end is closed and that is empty
//!     returns 0 (EOF). (pipe07/08)
//!   * A write to a pipe whose read end is closed returns -1/EPIPE; the
//!     SIGPIPE that would otherwise kill the probe is caught by a no-op
//!     handler installed first. (pipe12/13)
//!
//! Deterministic output: booleans only. No fds, no byte-count numerals, no
//! timestamps.

use conformance_probes::{errno, install_handler, report};

extern "C" fn ignore_sigpipe(_: i32) {
    // No-op. Installed so the EPIPE-write case below doesn't kill the probe.
}

unsafe fn fd_flags(fd: i32) -> i32 {
    libc::fcntl(fd, libc::F_GETFL)
}

unsafe fn fd_cloexec(fd: i32) -> i32 {
    libc::fcntl(fd, libc::F_GETFD)
}

unsafe fn make_pipe2(flags: i32) -> (i32, i32, i32) {
    let mut fds = [0i32; 2];
    let rc = libc::pipe2(fds.as_mut_ptr(), flags);
    (rc, fds[0], fds[1])
}

fn case_nonblock() {
    unsafe {
        let (rc, rd, wr) = make_pipe2(libc::O_NONBLOCK);
        let rd_nb = fd_flags(rd) & libc::O_NONBLOCK != 0;
        let wr_nb = fd_flags(wr) & libc::O_NONBLOCK != 0;
        report!(
            pipe2_nonblock_rc_zero = rc == 0,
            pipe2_nonblock_read_end_nonblock = rd_nb,
            pipe2_nonblock_write_end_nonblock = wr_nb,
        );
        libc::close(rd);
        libc::close(wr);
    }
}

fn case_cloexec() {
    unsafe {
        let (rc, rd, wr) = make_pipe2(libc::O_CLOEXEC);
        let rd_ce = fd_cloexec(rd) & libc::FD_CLOEXEC != 0;
        let wr_ce = fd_cloexec(wr) & libc::FD_CLOEXEC != 0;
        report!(
            pipe2_cloexec_rc_zero = rc == 0,
            pipe2_cloexec_read_end_cloexec = rd_ce,
            pipe2_cloexec_write_end_cloexec = wr_ce,
        );
        libc::close(rd);
        libc::close(wr);
    }
}

fn case_packet_mode() {
    unsafe {
        // Combine O_DIRECT with O_NONBLOCK so we can probe "empty packet pipe
        // returns EAGAIN" without blocking forever.
        let (rc, rd, wr) = make_pipe2(libc::O_DIRECT | libc::O_NONBLOCK);
        if rc != 0 {
            // Rare path — kernel built without packet-mode pipes returns
            // -1/EINVAL on the pipe2 call itself.
            let er = errno();
            report!(
                pipe2_direct_rejected_or_ok = rc == -1 && er == libc::EINVAL,
                pipe2_direct_packet_read_short = false,
                pipe2_direct_empty_returns_eagain = false,
            );
            return;
        }
        // Write one packet of 3 bytes, then read with a buffer LARGER than
        // 3 — packet mode discards anything past the packet's tail, so the
        // read must return exactly 3.
        let payload = b"abc";
        libc::write(wr, payload.as_ptr() as *const libc::c_void, payload.len());

        let mut buf = [0u8; 32];
        let n1 = libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        let one_packet_three_bytes = n1 == 3;

        // Pipe is now empty; nonblocking read returns -1/EAGAIN.
        let n2 = libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        let er = errno();
        let empty_eagain = n2 == -1 && er == libc::EAGAIN;

        report!(
            pipe2_direct_rejected_or_ok = rc == 0,
            pipe2_direct_packet_read_short = one_packet_three_bytes,
            pipe2_direct_empty_returns_eagain = empty_eagain,
        );

        libc::close(rd);
        libc::close(wr);
    }
}

fn case_fionread_and_nonblock_write() {
    unsafe {
        let (rc, rd, wr) = make_pipe2(libc::O_NONBLOCK);
        // 13 bytes; deterministic small write that fits easily in any pipe
        // buffer (default 64 KiB on Linux).
        let payload = b"pipeextra-rdy";
        let n = libc::write(wr, payload.as_ptr() as *const libc::c_void, payload.len());

        // FIONREAD reports the readable byte count. We compare it (as a
        // boolean) to the requested length without emitting either number.
        let mut readable: libc::c_int = 0;
        let ioctl_rc = libc::ioctl(rd, libc::FIONREAD, &mut readable);
        let fionread_matches = ioctl_rc == 0 && readable as isize == n;

        // Fill the pipe to its capacity, then verify a non-blocking write
        // EAGAINs. We use a sizable buffer and a bounded loop so the test
        // can't run away: any modern Linux defaults to 64 KiB pipe capacity;
        // 2 MiB worth of attempts is more than enough.
        let chunk = [0u8; 4096];
        let mut filled = false;
        let mut got_eagain = false;
        for _ in 0..512 {
            let w = libc::write(wr, chunk.as_ptr() as *const libc::c_void, chunk.len());
            if w == -1 {
                got_eagain = errno() == libc::EAGAIN;
                filled = true;
                break;
            }
        }

        report!(
            pipe_setup_rc_zero = rc == 0,
            pipe_fionread_matches_written = fionread_matches,
            pipe_nonblock_fills = filled,
            pipe_nonblock_write_eagains_when_full = got_eagain,
        );

        libc::close(rd);
        libc::close(wr);
    }
}

fn case_eof_on_closed_write_end() {
    unsafe {
        let (rc, rd, wr) = make_pipe2(0);
        // Close the write end with no data buffered; reader sees EOF == 0.
        libc::close(wr);
        let mut buf = [0u8; 4];
        let n = libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        report!(
            pipe_eof_setup_rc_zero = rc == 0,
            pipe_read_after_close_returns_zero = n == 0,
        );
        libc::close(rd);
    }
}

fn case_epipe_on_closed_read_end() {
    unsafe {
        // Install a no-op SIGPIPE handler so the probe survives the write.
        let _ = install_handler(libc::SIGPIPE, ignore_sigpipe, 0);

        let (rc, rd, wr) = make_pipe2(0);
        libc::close(rd);
        let n = libc::write(wr, b"x".as_ptr() as *const libc::c_void, 1);
        let er = errno();
        report!(
            pipe_epipe_setup_rc_zero = rc == 0,
            pipe_write_after_rclose_rc_minus_one = n == -1,
            pipe_write_after_rclose_errno_epipe = er == libc::EPIPE,
        );
        libc::close(wr);
    }
}

fn main() {
    case_nonblock();
    case_cloexec();
    case_packet_mode();
    case_fionread_and_nonblock_write();
    case_eof_on_closed_write_end();
    case_epipe_on_closed_read_end();
}
