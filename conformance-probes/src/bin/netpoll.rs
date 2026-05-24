//! Edge-triggered epoll netpoller repro — the shape Go's runtime uses for a
//! loopback HTTP exchange (the conformance_go_fixture). A server thread and a
//! client thread rendezvous over a non-blocking loopback TCP connection, each
//! driving its I/O through an `epoll` instance with `EPOLLET` (edge-triggered),
//! exactly like Go's netpoller. The client sends a request, the server reads it
//! and replies, the client reads the reply. This stresses: non-blocking
//! connect, accept4, edge-triggered epoll readiness across threads, and the
//! cross-thread wakeup of an epoll_wait blocked in one vCPU thread when another
//! vCPU thread makes a socket ready.
//!
//! Deterministic: prints a single boolean. Every wait is bounded (~4s) so a
//! stalled netpoller prints `false` instead of hanging the harness.

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLET: u32 = 0x8000_0000;

fn set_nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn epoll_add(epfd: i32, fd: i32, events: u32) {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev);
    }
}

/// Wait (bounded) until `fd` reports any of `want` via epoll, edge-triggered.
/// Returns true if it became ready before the deadline.
fn epoll_wait_ready(epfd: i32, deadline: Instant) -> bool {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    while Instant::now() < deadline {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 200) };
        if n > 0 {
            return true;
        }
    }
    false
}

fn main() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => {
            println!("netpoll_ok=false");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();
    let lfd = listener.as_raw_fd();
    set_nonblock(lfd);

    let server = std::thread::spawn(move || {
        let epfd = unsafe { libc::epoll_create1(0) };
        epoll_add(epfd, lfd, EPOLLIN | EPOLLET);
        let deadline = Instant::now() + Duration::from_secs(4);
        // Wait for an incoming connection, then accept (non-blocking).
        let mut conn_fd = -1;
        while Instant::now() < deadline && conn_fd < 0 {
            epoll_wait_ready(epfd, deadline);
            conn_fd = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK) };
        }
        if conn_fd < 0 {
            return false;
        }
        let cepfd = unsafe { libc::epoll_create1(0) };
        epoll_add(cepfd, conn_fd, EPOLLIN | EPOLLET);
        // Read the request (edge-triggered: wait then drain to EAGAIN).
        let mut buf = [0u8; 256];
        let mut got = 0;
        while Instant::now() < deadline && got == 0 {
            epoll_wait_ready(cepfd, deadline);
            loop {
                let n = unsafe {
                    libc::read(conn_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n > 0 {
                    got += n;
                } else {
                    break;
                }
            }
        }
        if got == 0 {
            return false;
        }
        // Reply.
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let _ = unsafe { libc::write(conn_fd, reply.as_ptr() as *const libc::c_void, reply.len()) };
        true
    });

    let client = std::thread::spawn(move || {
        let stream = match TcpStream::connect(addr) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let fd = stream.as_raw_fd();
        set_nonblock(fd);
        let epfd = unsafe { libc::epoll_create1(0) };
        epoll_add(epfd, fd, EPOLLIN | EPOLLOUT | EPOLLET);
        let deadline = Instant::now() + Duration::from_secs(4);
        // Send the request.
        let req = b"GET /demo HTTP/1.1\r\nHost: x\r\n\r\n";
        let _ = unsafe { libc::write(fd, req.as_ptr() as *const libc::c_void, req.len()) };
        // Wait for and read the response.
        let mut buf = [0u8; 256];
        let mut got = 0;
        while Instant::now() < deadline && got == 0 {
            epoll_wait_ready(epfd, deadline);
            loop {
                let n =
                    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    got += n;
                } else {
                    break;
                }
            }
        }
        got > 0
    });

    let s_ok = server.join().unwrap_or(false);
    let c_ok = client.join().unwrap_or(false);
    println!("netpoll_ok={}", s_ok && c_ok);
}
