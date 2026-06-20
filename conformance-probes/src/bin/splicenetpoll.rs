//! TCP `splice(2)` under a Go-style edge-triggered netpoll loop.
//!
//! This reduces the `go-net` `TestSplice/tcp-to-tcp/multipleWrite` hang: bytes
//! flow from one loopback TCP connection into a nonblocking pipe, then from the
//! pipe into a second loopback TCP connection. The pump watches the source and
//! destination fds with `EPOLLET`, and a stalled implementation can otherwise
//! spin forever with `epoll_pwait(timeout=0)` reporting `EPOLLOUT` while
//! `splice(pipe -> tcp)` keeps returning `EAGAIN`.
//!
//! Linux makes byte progress and drains the full payload. A broken runtime
//! prints `splicenetpoll_progress=false` instead of hanging.

use conformance_probes::{errno, report};
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 0x8000_0000;

const TOTAL: usize = 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const MAX_STALE_READY: usize = 256;

fn set_nonblock(fd: i32) -> bool {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        fl >= 0 && libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == 0
    }
}

fn set_small_buffers(send_fd: i32, recv_fd: i32) {
    unsafe {
        let size: libc::c_int = 16 * 1024;
        let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            send_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&size as *const libc::c_int).cast(),
            len,
        );
        libc::setsockopt(
            recv_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const libc::c_int).cast(),
            len,
        );
    }
}

fn tcp_pair() -> Option<(i32, i32)> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let addr = listener.local_addr().ok()?;
    let client = TcpStream::connect(addr).ok()?;
    let (server, _) = listener.accept().ok()?;
    Some((client.into_raw_fd(), server.into_raw_fd()))
}

fn add_epoll(epfd: i32, fd: i32, events: u32) -> bool {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}

fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

fn write_source(
    fd: i32,
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicUsize>,
) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let buf = [0x5Au8; 4096];
        while sent.load(Ordering::SeqCst) < TOTAL && !stop.load(Ordering::SeqCst) {
            let done = sent.load(Ordering::SeqCst);
            let want = buf.len().min(TOTAL - done);
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), want) };
            if n > 0 {
                sent.fetch_add(n as usize, Ordering::SeqCst);
            } else {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        let ok = sent.load(Ordering::SeqCst) >= TOTAL;
        close_fd(fd);
        ok
    })
}

fn drain_destination(fd: i32, stop: Arc<AtomicBool>) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut got = 0usize;
        while got < TOTAL && !stop.load(Ordering::SeqCst) {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                got += n as usize;
                if got % (128 * 1024) == 0 {
                    thread::sleep(Duration::from_millis(2));
                }
            } else if n == 0 {
                break;
            } else {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        close_fd(fd);
        got >= TOTAL
    })
}

fn splice_once(in_fd: i32, out_fd: i32, len: usize) -> Result<usize, i32> {
    let n = unsafe {
        libc::splice(
            in_fd,
            std::ptr::null_mut(),
            out_fd,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_NONBLOCK,
        )
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(errno())
    }
}

fn ready_has(events: &[libc::epoll_event], count: i32, fd: i32, mask: u32) -> bool {
    events
        .iter()
        .take(count.max(0) as usize)
        .any(|ev| ev.u64 == fd as u64 && (ev.events & mask) != 0)
}

fn run_probe() -> bool {
    let Some((src_write_fd, src_read_fd)) = tcp_pair() else {
        return false;
    };
    let Some((dst_write_fd, dst_read_fd)) = tcp_pair() else {
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        return false;
    };

    set_small_buffers(dst_write_fd, dst_read_fd);
    if !set_nonblock(src_write_fd)
        || !set_nonblock(src_read_fd)
        || !set_nonblock(dst_write_fd)
        || !set_nonblock(dst_read_fd)
    {
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        close_fd(dst_write_fd);
        close_fd(dst_read_fd);
        return false;
    }

    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        close_fd(dst_write_fd);
        close_fd(dst_read_fd);
        return false;
    }
    let pipe_read_fd = pipe_fds[0];
    let pipe_write_fd = pipe_fds[1];

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        close_fd(dst_write_fd);
        close_fd(dst_read_fd);
        close_fd(pipe_read_fd);
        close_fd(pipe_write_fd);
        return false;
    }
    if !add_epoll(
        epfd,
        src_read_fd,
        EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP | EPOLLET,
    ) || !add_epoll(
        epfd,
        dst_write_fd,
        EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP | EPOLLET,
    ) {
        close_fd(epfd);
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        close_fd(dst_write_fd);
        close_fd(dst_read_fd);
        close_fd(pipe_read_fd);
        close_fd(pipe_write_fd);
        return false;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let writer = write_source(src_write_fd, Arc::clone(&stop), Arc::clone(&sent));
    let drainer = drain_destination(dst_read_fd, Arc::clone(&stop));

    let deadline = Instant::now() + Duration::from_secs(12);
    let mut from_src = 0usize;
    let mut to_dst = 0usize;
    let mut in_pipe = 0usize;
    let mut source_eof = false;
    let mut stale_out_ready = 0usize;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let mut ok = true;

    while to_dst < TOTAL {
        if Instant::now() >= deadline {
            ok = false;
            break;
        }

        let before = from_src + to_dst;

        while in_pipe > 0 {
            match splice_once(pipe_read_fd, dst_write_fd, in_pipe.min(CHUNK)) {
                Ok(0) => break,
                Ok(n) => {
                    in_pipe -= n;
                    to_dst += n;
                    stale_out_ready = 0;
                }
                Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::EINTR => {
                    break;
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            break;
        }

        while !source_eof && in_pipe < CHUNK {
            let want = (TOTAL - from_src).min(CHUNK - in_pipe);
            if want == 0 {
                break;
            }
            match splice_once(src_read_fd, pipe_write_fd, want) {
                Ok(0) => {
                    source_eof = true;
                    break;
                }
                Ok(n) => {
                    from_src += n;
                    in_pipe += n;
                    stale_out_ready = 0;
                }
                Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::EINTR => {
                    break;
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            break;
        }

        if from_src + to_dst != before {
            continue;
        }

        let n0 = unsafe {
            libc::epoll_pwait(
                epfd,
                events.as_mut_ptr(),
                events.len() as i32,
                0,
                std::ptr::null(),
            )
        };
        if n0 > 0 {
            let saw_out = in_pipe > 0
                && ready_has(
                    &events,
                    n0,
                    dst_write_fd,
                    EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP,
                );
            if saw_out {
                stale_out_ready += 1;
                if stale_out_ready > MAX_STALE_READY {
                    ok = false;
                    break;
                }
            }
            continue;
        }
        if n0 < 0 {
            let e = errno();
            if e != libc::EINTR {
                ok = false;
                break;
            }
        }

        let n_wait = unsafe {
            libc::epoll_pwait(
                epfd,
                events.as_mut_ptr(),
                events.len() as i32,
                50,
                std::ptr::null(),
            )
        };
        if n_wait < 0 {
            let e = errno();
            if e != libc::EINTR {
                ok = false;
                break;
            }
        }
    }

    stop.store(true, Ordering::SeqCst);
    close_fd(src_read_fd);
    close_fd(dst_write_fd);
    close_fd(pipe_read_fd);
    close_fd(pipe_write_fd);
    close_fd(epfd);

    let writer_ok = writer.join().unwrap_or(false);
    let _ = drainer.join();
    ok && to_dst >= TOTAL && writer_ok && sent.load(Ordering::SeqCst) >= TOTAL
}

fn main() {
    report!(splicenetpoll_progress = run_probe());
}
