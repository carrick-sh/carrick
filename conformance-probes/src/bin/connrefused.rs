//! Non-blocking TCP connect to a port with NO listener: the async-connect error
//! path. Mirrors what `asyncio.loop.sock_connect` does and what CPython
//! `test.test_asyncio.test_sock_lowlevel.test_sock_client_fail` /
//! `test_cancel_sock_accept` assert.
//!
//! The flow: bind a socket to 127.0.0.1:0 to reserve an ephemeral port, read it
//! back, then close (so nothing is listening). A second, NON-blocking socket
//! connect()s to that address: connect returns -1/EINPROGRESS. The kernel then
//! delivers the refusal asynchronously. A correct host must, when asked:
//!
//!   1. `connect()` returns -1 with errno EINPROGRESS (non-blocking in flight).
//!
//!   2. `select()` with the fd in writefds reports it ready (rc >= 1, the write
//!      bit set) once the refusal lands — Linux marks a connect-failed socket
//!      write-ready (POLLOUT|POLLERR|POLLHUP) so the app can collect the error.
//!      macOS poll() reports ONLY POLLHUP for the same socket, so carrick must
//!      treat POLLHUP/POLLERR as write-ready in select's writeback.
//!
//!   3. `poll()` with POLLOUT requested returns the fd with POLLHUP and/or
//!      POLLERR in revents (the hang-up/error conditions Linux always reports).
//!
//!   4. `getsockopt(SO_ERROR)` returns the pending error as a LINUX errno —
//!      ECONNREFUSED == 111. carrick reads the Darwin errno (ECONNREFUSED == 61)
//!      from the host socket; without translation the guest reads 61, which is
//!      Linux ENODATA, and asyncio never raises ConnectionRefusedError. The
//!      getsockopt call itself succeeds (rc 0); only the VALUE is the errno.
//!
//! Deterministic + bounded: the select/poll waits cap at 2 s, and a refused
//! loopback connect resolves in microseconds, so a broken readiness/translation
//! path flips a `true` to `false` rather than hanging the harness.

use conformance_probes::report;
use std::mem::MaybeUninit;

const ECONNREFUSED_LINUX: i32 = 111;

/// Reserve an ephemeral loopback port (bind+getsockname+close), returning the
/// `sockaddr_in` of a port with no listener.
unsafe fn reserve_unused_port() -> libc::sockaddr_in {
    let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let mut addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    // 127.0.0.1 in network byte order.
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    libc::bind(
        s,
        &addr as *const _ as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    libc::getsockname(s, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
    libc::close(s);
    addr
}

fn main() {
    unsafe {
        let addr = reserve_unused_port();

        let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        // Non-blocking, like asyncio's sock_connect.
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);

        let crc = libc::connect(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let connect_einprogress = crc == -1 && {
            let e = *libc::__errno_location();
            e == libc::EINPROGRESS
        };

        // (1) select: the fd should become write-ready once the refusal lands.
        let mut wset: libc::fd_set = MaybeUninit::zeroed().assume_init();
        libc::FD_ZERO(&mut wset);
        libc::FD_SET(sock, &mut wset);
        let mut tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let srct = libc::select(
            sock + 1,
            std::ptr::null_mut(),
            &mut wset,
            std::ptr::null_mut(),
            &mut tv,
        );
        let select_write_ready = srct >= 1 && libc::FD_ISSET(sock, &wset);

        // (2) poll: POLLOUT requested; revents must carry HUP and/or ERR.
        let mut pfd = libc::pollfd {
            fd: sock,
            events: libc::POLLOUT,
            revents: 0,
        };
        let prc = libc::poll(&mut pfd as *mut _, 1, 2000);
        let poll_hup_or_err = prc >= 1 && (pfd.revents & (libc::POLLHUP | libc::POLLERR)) != 0;

        // (3) getsockopt(SO_ERROR): must read back Linux ECONNREFUSED.
        let mut so_err: i32 = -1;
        let mut elen = std::mem::size_of::<i32>() as libc::socklen_t;
        let grc = libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut so_err as *mut _ as *mut libc::c_void,
            &mut elen,
        );
        let getsockopt_ok = grc == 0;
        let so_error_is_econnrefused = so_err == ECONNREFUSED_LINUX;

        libc::close(sock);

        report!(
            connect_einprogress = connect_einprogress,
            select_write_ready = select_write_ready,
            poll_hup_or_err = poll_hup_or_err,
            getsockopt_ok = getsockopt_ok,
            so_error_is_econnrefused = so_error_is_econnrefused,
        );
    }
}
