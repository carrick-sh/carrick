//! Repeated delayed-body wakeup for Go's `Expect: 100-continue` transport path.
//!
//! The `go-net_http` reducer that exposed this shape is
//! `TestTransportExpect100Continue500ResponseTimeout -test.count=100`: after
//! dozens of loopback TCP exchanges, the server goroutine can park in a
//! Go-style edge-triggered read wait and never observe the client's delayed
//! request body. This probe removes Go from the equation while preserving the
//! primitive:
//!
//!   1. client writes request headers;
//!   2. server reads headers, drains the accepted socket to EAGAIN, then waits
//!      with `EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`;
//!   3. client waits for a 5 ms `epoll_wait` timeout (matching Go's finite
//!      netpoll timer path), then writes the body;
//!   4. server must wake and read the body.
//!
//! Every wait is bounded so a lost readiness edge reports `false` instead of
//! hanging the harness.
//!
//! The server keeps ONE receive buffer across the headers and body phases.
//! Whenever the server's first read of the connection is delayed past the
//! client's 5 ms timer (trivially common under the parallel gate's load), the
//! kernel coalesces headers+body and the headers-phase drain consumes BOTH; a
//! phase-local buffer would silently DISCARD the body and then wait 2 s for
//! bytes that can never arrive. Real Linux fails that variant identically
//! (verified via the Docker oracle with the 5 ms wait removed), so the
//! carry-over is required for the probe to measure the wakeup — the thing
//! under test — rather than its own scheduling luck. When the body genuinely
//! arrives after the drain, the epoll wait is exercised exactly as before.

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const BODY: &[u8] = b"request body";
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 0x8000_0000;

fn set_nonblock(fd: i32) -> bool {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        fl >= 0 && libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == 0
    }
}

fn close_fd(fd: i32) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn epoll_add(epfd: i32, fd: i32, events: u32) -> bool {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}

fn epoll_del(epfd: i32, fd: i32) {
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
    }
}

fn wait_readable(epfd: i32, deadline: Instant) -> bool {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    while Instant::now() < deadline {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 100) };
        if n > 0 {
            for ev in &events[..n as usize] {
                if ev.events & (EPOLLIN | libc::EPOLLERR as u32 | libc::EPOLLHUP as u32) != 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn wait_timeout_only(epfd: i32, fd: i32) -> bool {
    let added = epoll_add(epfd, fd, EPOLLIN | EPOLLRDHUP | EPOLLET);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = if added {
        unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, 5) }
    } else {
        -1
    };
    epoll_del(epfd, fd);
    n == 0
}

/// Read from `fd` into the caller's connection-lifetime buffer until `needle`
/// is present in it, EAGAIN (caller waits and retries), EOF/error, or the
/// deadline. `seen` accumulates across calls so bytes drained past one phase's
/// needle (coalesced headers+body) stay visible to the next phase instead of
/// being dropped — see the module docs.
fn read_until(fd: i32, seen: &mut Vec<u8>, needle: &[u8], deadline: Instant) -> bool {
    let mut buf = [0u8; 256];
    loop {
        if seen.windows(needle.len()).any(|w| w == needle) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            seen.extend_from_slice(&buf[..n as usize]);
            continue;
        }
        if n == 0 {
            return false;
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
            return false;
        }
        if errno == Some(libc::EINTR) {
            continue;
        }
        return false;
    }
}

fn write_all_nonblock(fd: i32, bytes: &[u8], deadline: Instant) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() && Instant::now() < deadline {
        let n = unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if n > 0 {
            offset += n as usize;
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        if errno == Some(libc::EINTR) {
            continue;
        }
        return false;
    }
    offset == bytes.len()
}

fn run_once(server_epfd: i32, client_epfd: i32) -> bool {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(_) => return false,
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    let lfd = listener.as_raw_fd();
    if !set_nonblock(lfd) {
        return false;
    }

    let client = std::thread::spawn(move || {
        let stream = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(_) => return false,
        };
        let fd = stream.as_raw_fd();
        if !set_nonblock(fd) {
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let headers =
            b"PUT / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 12\r\n\r\n";
        if !write_all_nonblock(fd, headers, deadline) {
            return false;
        }
        if !wait_timeout_only(client_epfd, fd) {
            return false;
        }
        write_all_nonblock(fd, BODY, deadline)
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut server_fd = -1;
    while Instant::now() < deadline && server_fd < 0 {
        server_fd = unsafe {
            libc::accept4(
                lfd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK,
            )
        };
        if server_fd < 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    if server_fd < 0 {
        let _ = client.join();
        return false;
    }

    if !epoll_add(
        server_epfd,
        server_fd,
        EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
    ) {
        close_fd(server_fd);
        let _ = client.join();
        return false;
    }

    // One receive buffer for the CONNECTION, shared by both phases (see module
    // docs: a phase-local buffer drops a coalesced body).
    let mut seen: Vec<u8> = Vec::new();
    let headers_seen = loop {
        let got_headers = read_until(server_fd, &mut seen, b"\r\n\r\n", deadline);
        if got_headers {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        if !wait_readable(server_epfd, deadline) {
            break false;
        }
    };
    if !headers_seen {
        epoll_del(server_epfd, server_fd);
        close_fd(server_fd);
        let _ = client.join();
        return false;
    }

    let body_seen = loop {
        let got_body = read_until(server_fd, &mut seen, BODY, deadline);
        if got_body {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        if !wait_readable(server_epfd, deadline) {
            break false;
        }
    };

    epoll_del(server_epfd, server_fd);
    close_fd(server_fd);
    client.join().unwrap_or(false) && body_seen
}

fn main() {
    let server_epfd = unsafe { libc::epoll_create1(0) };
    let client_epfd = unsafe { libc::epoll_create1(0) };
    if server_epfd < 0 || client_epfd < 0 {
        close_fd(server_epfd);
        close_fd(client_epfd);
        println!("expectcontinue_body_wake=false");
        return;
    }
    let mut ok = true;
    for _ in 0..128 {
        if !run_once(server_epfd, client_epfd) {
            ok = false;
            break;
        }
    }
    close_fd(server_epfd);
    close_fd(client_epfd);
    println!("expectcontinue_body_wake={ok}");
}
