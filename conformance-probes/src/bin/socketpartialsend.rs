//! Partial stream sends: the count a `send`/`sendmsg` returns is exactly what
//! the kernel queued, never more.
//!
//! Stands in for the asyncio sendfile fallback (`cpython-asyncio`
//! `test_sendfile_*`), which writes a 1 MiB file through a TCP socket whose
//! `SO_SNDBUF` was shrunk to 4 KiB and trusts every partial count.
//!
//! Invariants encoded, all boolean:
//!
//!   * Non-blocking 16 KiB `send`s on a 4 KiB-`SO_SNDBUF` TCP socket, driven
//!     by `poll(POLLOUT)`, deliver exactly the sum of the returned counts to
//!     the peer (no loss, no duplication), and that sum reaches the full
//!     payload.
//!   * The same with `sendmsg`.
//!   * The same when every call carries `MSG_MORE` and the last one does
//!     not: corked bytes still arrive in order and complete.
//!
//! Whether a given kernel actually short-writes is NOT asserted: the native
//! arm64 Docker oracle accepts every 16 KiB send whole even with the shrunk
//! buffer, while Darwin returns short counts routinely, and the invariant
//! under test is only that the counts are truthful either way.
//!
//! Deterministic output: booleans only.

use conformance_probes::{errno, report};
use std::io::Read;

const TOTAL: usize = 1024 * 17 * 64 + 1;
const CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum Mode {
    Send,
    SendMsg,
    SendMore,
}

unsafe fn set_nonblock(fd: i32) {
    let fl = libc::fcntl(fd, libc::F_GETFL);
    libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
}

unsafe fn run(mode: Mode) -> bool {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let receiver = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut got = Vec::with_capacity(TOTAL);
        conn.read_to_end(&mut got).expect("read_to_end");
        got
    });

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let mut sin: libc::sockaddr_in = std::mem::zeroed();
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = addr.port().to_be();
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
    };
    let rc = libc::connect(
        fd,
        &sin as *const libc::sockaddr_in as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    assert_eq!(rc, 0, "connect");
    let small: libc::c_int = 4096;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &small as *const libc::c_int as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
    set_nonblock(fd);

    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let mut sent = 0usize;
    let mut spins = 0u32;
    while sent < TOTAL {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        libc::poll(&mut pfd, 1, 5000);
        let want = CHUNK.min(TOTAL - sent);
        let last = sent + want == TOTAL;
        let n = match mode {
            Mode::Send => libc::send(fd, payload[sent..].as_ptr().cast(), want, 0),
            Mode::SendMore => libc::send(
                fd,
                payload[sent..].as_ptr().cast(),
                want,
                if last { 0 } else { libc::MSG_MORE },
            ),
            Mode::SendMsg => {
                let mut iov = libc::iovec {
                    iov_base: payload[sent..].as_ptr() as *mut libc::c_void,
                    iov_len: want,
                };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                libc::sendmsg(fd, &msg, 0)
            }
        };
        if n < 0 {
            let e = errno();
            assert!(e == libc::EAGAIN || e == libc::EINTR, "send errno {e}");
            spins += 1;
            assert!(spins < 1_000_000, "send never progressed");
            continue;
        }
        sent += n as usize;
    }
    libc::close(fd);
    let got = receiver.join().expect("receiver");
    got == payload
}

fn main() {
    unsafe {
        let send_exact = run(Mode::Send);
        let sendmsg_exact = run(Mode::SendMsg);
        let more_exact = run(Mode::SendMore);
        report!(
            send_counts_match_bytes_received = send_exact,
            sendmsg_counts_match_bytes_received = sendmsg_exact,
            msg_more_counts_match_bytes_received = more_exact,
        );
    }
}
