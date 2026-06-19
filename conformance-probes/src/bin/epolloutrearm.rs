//! Edge-triggered EPOLLOUT wakeup under the Go-netpoller registration pattern:
//! a socket registered for BOTH directions (`EPOLLIN | EPOLLOUT | EPOLLET`) on
//! its own epoll instance, blocked on `epoll_wait(timeout = -1)`, must receive a
//! "became writable" EDGE after its send buffer (filled past capacity) drains.
//!
//! This is the precise readiness transition that Go's `net`
//! TestSplice/multipleWrite blocks on (the destination TCP socket is registered
//! IN|OUT|ET and the netpoller blocks for the next EPOLLOUT after a short write).
//! `netpoll.rs` never fills a buffer, so it never needs this second OUT edge.
//!
//! Writer side fills the socket to EAGAIN, then blocks in `epoll_wait(-1)` for
//! the EPOLLOUT edge. A reader thread drains the peer end slowly so the buffer
//! repeatedly empties — each drain MUST re-fire the EPOLLOUT edge or the writer
//! deadlocks. A SIGALRM watchdog turns a lost edge into a deterministic
//! `epolloutrearm_ok=false`. Real Linux fires every edge → `true`.

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLET: u32 = 0x8000_0000;

const TOTAL: usize = 4 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

static TIMED_OUT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_sig: libc::c_int) {
    TIMED_OUT.store(true, Ordering::SeqCst);
}

fn arm_watchdog(secs: u32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as usize;
        sa.sa_flags = 0; // no SA_RESTART: epoll_wait must return EINTR
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        libc::alarm(secs);
    }
}

fn set_nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn main() {
    arm_watchdog(12);

    let ln = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = ln.local_addr().unwrap();
    let writer = TcpStream::connect(addr).expect("connect");
    let (reader, _) = ln.accept().expect("accept");
    let wfd = writer.as_raw_fd();

    // Reader thread: drain TOTAL bytes with small pauses so the writer's send
    // buffer repeatedly fills and empties (forcing repeated EPOLLOUT edges).
    let reader_t = std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        let mut got = 0usize;
        let rfd = reader.as_raw_fd();
        while got < TOTAL {
            if TIMED_OUT.load(Ordering::SeqCst) {
                return false;
            }
            let n = unsafe { libc::read(rfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                got += n as usize;
                // Slow the reader so the writer must block for OUT edges.
                if got % (256 * 1024) == 0 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            } else if n == 0 {
                return got >= TOTAL;
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        true
    });

    // Writer: Go-style — register IN|OUT|ET on a dedicated epoll, block(-1) for
    // each OUT edge after filling to EAGAIN.
    set_nonblock(wfd);
    let epfd = unsafe { libc::epoll_create1(0) };
    let mut ev = libc::epoll_event {
        events: EPOLLIN | EPOLLOUT | EPOLLET,
        u64: wfd as u64,
    };
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wfd, &mut ev) };

    let buf = vec![0xABu8; CHUNK];
    let mut sent = 0usize;
    let mut bailed = false;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    while sent < TOTAL {
        if TIMED_OUT.load(Ordering::SeqCst) {
            bailed = true;
            break;
        }
        // Fill to EAGAIN.
        let mut blocked = false;
        while sent < TOTAL {
            let want = CHUNK.min(TOTAL - sent);
            let n = unsafe { libc::write(wfd, buf.as_ptr() as *const libc::c_void, want) };
            if n > 0 {
                sent += n as usize;
            } else {
                blocked = true;
                break;
            }
        }
        if sent >= TOTAL {
            break;
        }
        if blocked {
            // Block forever for the next EPOLLOUT edge (Go netpoller behavior).
            let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 4, -1) };
            if n < 0 && TIMED_OUT.load(Ordering::SeqCst) {
                bailed = true;
                break;
            }
        }
    }

    let r_ok = reader_t.join().unwrap_or(false);
    let ok = !bailed && !TIMED_OUT.load(Ordering::SeqCst) && sent >= TOTAL && r_ok;
    println!("epolloutrearm_ok={}", ok);
}
