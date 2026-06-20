//! TCP-to-Unix-stream `splice(2)` under a Go-style edge-triggered netpoll loop.
//!
//! This reduces the `go-net` `TestSplice/tcp-to-unix/big` hang. Bytes flow from
//! a loopback TCP connection into a nonblocking pipe, then from the pipe into an
//! AF_UNIX stream socket. The pump watches the TCP source and Unix destination
//! with `EPOLLET`; Linux makes steady progress and drains the full payload.

use conformance_probes::{errno, report};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
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

const TOTAL: usize = 5 * 1024 * 1024;
const MAX_SPLICE_SIZE: usize = 1 << 20;

fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

fn set_nonblock(fd: i32) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
    }
}

fn set_small_buffers(fd: i32) {
    unsafe {
        let size: libc::c_int = 16 * 1024;
        let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&size as *const libc::c_int).cast(),
            len,
        );
        libc::setsockopt(
            fd,
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

fn unix_stream_pair() -> Option<(i32, i32)> {
    let path = format!(
        "/tmp/spliceunixpoll-{}-{}.sock",
        unsafe { libc::getpid() },
        monotonic_nanos()
    );
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).ok()?;
    let client = UnixStream::connect(&path).ok()?;
    let (server, _) = listener.accept().ok()?;
    let _ = fs::remove_file(&path);
    Some((server.into_raw_fd(), client.into_raw_fd()))
}

fn monotonic_nanos() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u128)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u128)
}

fn add_epoll(epfd: i32, fd: i32, events: u32) -> bool {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}

fn write_source(
    fd: i32,
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicUsize>,
) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let buf = vec![0x5Au8; TOTAL];
        while sent.load(Ordering::SeqCst) < TOTAL && !stop.load(Ordering::SeqCst) {
            let done = sent.load(Ordering::SeqCst);
            let n = unsafe {
                libc::write(
                    fd,
                    buf.as_ptr().add(done).cast(),
                    TOTAL.saturating_sub(done),
                )
            };
            if n > 0 {
                sent.fetch_add(n as usize, Ordering::SeqCst);
                continue;
            }
            let e = errno();
            if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let ok = sent.load(Ordering::SeqCst) >= TOTAL;
        close_fd(fd);
        ok
    })
}

fn drain_destination(fd: i32, stop: Arc<AtomicBool>) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let mut buf = vec![0u8; TOTAL];
        let mut got = 0usize;
        while got < TOTAL && !stop.load(Ordering::SeqCst) {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                got += n as usize;
                continue;
            }
            if n == 0 {
                break;
            }
            let e = errno();
            if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                break;
            }
            thread::sleep(Duration::from_millis(1));
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

fn wait_ready(
    epfd: i32,
    fd: i32,
    mask: u32,
    events: &mut [libc::epoll_event],
    deadline: Instant,
) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        let n = unsafe {
            libc::epoll_pwait(
                epfd,
                events.as_mut_ptr(),
                events.len() as i32,
                50,
                std::ptr::null(),
            )
        };
        if n > 0 {
            if ready_has(events, n, fd, mask | EPOLLERR | EPOLLHUP | EPOLLRDHUP) {
                return true;
            }
            continue;
        }
        if n < 0 {
            let e = errno();
            if e != libc::EINTR {
                return false;
            }
        }
    }
}

fn splice_drain(
    epfd: i32,
    src_fd: i32,
    pipe_write_fd: i32,
    max: usize,
    events: &mut [libc::epoll_event],
    deadline: Instant,
) -> Result<usize, ()> {
    loop {
        match splice_once(src_fd, pipe_write_fd, max) {
            Ok(n) => return Ok(n),
            Err(e) if e == libc::EINTR => {}
            Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                if !wait_ready(epfd, src_fd, EPOLLIN, events, deadline) {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
}

fn splice_pump(
    epfd: i32,
    dst_fd: i32,
    pipe_read_fd: i32,
    mut in_pipe: usize,
    events: &mut [libc::epoll_event],
    deadline: Instant,
) -> Result<usize, ()> {
    let mut written = 0usize;
    while in_pipe > 0 {
        match splice_once(pipe_read_fd, dst_fd, in_pipe) {
            Ok(0) => return Err(()),
            Ok(n) => {
                in_pipe -= n;
                written += n;
            }
            Err(e) if e == libc::EINTR => {}
            Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                if !wait_ready(epfd, dst_fd, EPOLLOUT, events, deadline) {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
    Ok(written)
}

fn run_probe() -> bool {
    let Some((src_write_fd, src_read_fd)) = tcp_pair() else {
        return false;
    };
    let Some((dst_write_fd, dst_read_fd)) = unix_stream_pair() else {
        close_fd(src_write_fd);
        close_fd(src_read_fd);
        return false;
    };

    set_small_buffers(dst_write_fd);
    set_small_buffers(dst_read_fd);
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

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut to_dst = 0usize;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let mut ok = true;

    while to_dst < TOTAL {
        if Instant::now() >= deadline {
            ok = false;
            break;
        }

        let remaining = TOTAL - to_dst;
        let max = MAX_SPLICE_SIZE.min(remaining);
        let in_pipe =
            match splice_drain(epfd, src_read_fd, pipe_write_fd, max, &mut events, deadline) {
                Ok(0) => break,
                Ok(n) => n,
                Err(()) => {
                    ok = false;
                    break;
                }
            };
        match splice_pump(
            epfd,
            dst_write_fd,
            pipe_read_fd,
            in_pipe,
            &mut events,
            deadline,
        ) {
            Ok(n) => to_dst += n,
            Err(()) => {
                ok = false;
                break;
            }
        }
        if to_dst > TOTAL {
            ok = false;
            break;
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
    report!(spliceunixpoll_progress = run_probe());
}
