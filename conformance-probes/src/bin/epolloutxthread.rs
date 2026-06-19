//! Cross-thread host-socket EPOLLOUT re-arm under backpressure — the reduced
//! shape of the `go-net` `TestSplice/tcp-to-tcp/multipleWrite` deadlock.
//!
//! One thread fills a non-blocking loopback TCP socket to EAGAIN, registers it
//! `EPOLLOUT|EPOLLET` on its own epoll instance, and blocks in
//! `epoll_pwait(timeout=-1)` for the "became writable" edge. A SECOND thread —
//! after the waiter has parked — drains the peer end, which frees kernel socket
//! buffer and makes the writer's socket writable again. On real Linux the
//! netpoller's blocked `epoll_wait` is woken by that fresh EPOLLOUT edge.
//!
//! This isolates the multi-vCPU cross-thread wake from the net-lane dispatch
//! (already proven correct in isolation, single-threaded): the readiness edge
//! is produced by I/O on a DIFFERENT vCPU thread than the one parked in
//! `epoll_pwait`. A genuinely lost cross-thread wakeup DEADLOCKS the
//! `epoll_pwait(-1)`; a 3s watchdog SIGUSR1 turns that hang into a deterministic
//! `false` instead of stalling the harness.
//!
//!   * `woke_via_epollout`: a cross-thread peer-drain wakes a blocked
//!     `epoll_pwait(timeout=-1, EPOLLOUT|EPOLLET)` promptly.
//!
//! On Linux the drain always wakes the wait → `true`.

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

const EPOLLOUT: u32 = 0x004;
const EPOLLET: u32 = 0x8000_0000;

extern "C" fn noop_handler(_sig: libc::c_int) {}

fn set_nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    // SIGUSR1 handler with no SA_RESTART so the watchdog can break a stranded
    // (lost-wake) epoll_pwait with EINTR instead of hanging the harness.
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = noop_handler as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    sa.sa_flags = 0;
    libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

    // Loopback TCP pair: `writer_fd` (client) is filled to EAGAIN; `peer` (the
    // accepted server side) is drained by the second thread to free buffer.
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => {
            println!("woke_via_epollout=false");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();
    let client = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => {
            println!("woke_via_epollout=false");
            return;
        }
    };
    let (peer, _) = match listener.accept() {
        Ok(p) => p,
        Err(_) => {
            println!("woke_via_epollout=false");
            return;
        }
    };
    let writer_fd = client.as_raw_fd();
    let peer_fd = peer.as_raw_fd();
    set_nonblock(writer_fd);

    // Shrink the buffers so EAGAIN is reached quickly and the drain visibly
    // re-opens the write window (best-effort; ignored if unsupported).
    let bufsz: libc::c_int = 16 * 1024;
    libc::setsockopt(
        writer_fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &bufsz as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
    libc::setsockopt(
        peer_fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &bufsz as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );

    // Fill the writer socket to EAGAIN (the backpressure standoff).
    let chunk = [0u8; 4096];
    let mut total_written: usize = 0;
    loop {
        let n = libc::write(
            writer_fd,
            chunk.as_ptr() as *const libc::c_void,
            chunk.len(),
        );
        if n > 0 {
            total_written += n as usize;
            // Don't fill forever if the kernel buffers are huge; cap generously.
            if total_written > 64 * 1024 * 1024 {
                break;
            }
        } else {
            let e = std::io::Error::last_os_error().raw_os_error();
            if e == Some(libc::EAGAIN) || e == Some(libc::EWOULDBLOCK) {
                break;
            }
            break;
        }
    }

    let epfd = libc::epoll_create1(0);
    if epfd < 0 {
        println!("woke_via_epollout=false");
        return;
    }
    // EPOLLOUT|EPOLLET: edge-triggered, exactly Go's netpoller pollDesc.
    let mut ev = libc::epoll_event {
        events: EPOLLOUT | EPOLLET,
        u64: writer_fd as u64,
    };
    libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, writer_fd, &mut ev);

    // Consume the initial level→edge: do one drain+park cycle so the EPOLLOUT
    // edge is in the consumed state and the NEXT writable transition must be a
    // FRESH cross-thread edge. (We're already at EAGAIN, so the socket is not
    // writable; this epoll_ctl just armed the filter.)

    let pid = libc::getpid();
    let main_tid = libc::syscall(libc::SYS_gettid) as i32;

    // Drainer: after the main thread has parked in epoll_pwait, drain the peer
    // so the writer's socket becomes writable again — a cross-thread EPOLLOUT
    // edge. Keep draining until enough buffer frees that the edge is unambiguous.
    let drainer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        let mut buf = [0u8; 65536];
        let mut drained = 0usize;
        let deadline = Instant::now() + Duration::from_secs(2);
        while drained < total_written && Instant::now() < deadline {
            let n =
                unsafe { libc::read(peer_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                drained += n as usize;
            } else if n < 0 {
                let e = std::io::Error::last_os_error().raw_os_error();
                if e == Some(libc::EAGAIN) || e == Some(libc::EWOULDBLOCK) {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                break;
            } else {
                break;
            }
        }
    });

    // Watchdog: break a stranded epoll_pwait after 3s (thread-directed).
    let watchdog = thread::spawn(move || {
        thread::sleep(Duration::from_millis(3000));
        unsafe {
            libc::syscall(libc::SYS_tgkill, pid, main_tid, libc::SIGUSR1);
        }
    });

    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let started = Instant::now();
    let ret = libc::epoll_pwait(epfd, out.as_mut_ptr(), 1, -1, std::ptr::null());
    let elapsed = started.elapsed();

    let woke_via_epollout =
        ret == 1 && (out[0].events & EPOLLOUT) != 0 && elapsed < Duration::from_millis(2800);

    let _ = drainer.join();
    let _ = watchdog.join();
    libc::close(epfd);

    println!("woke_via_epollout={woke_via_epollout}");
}
