//! FIFO open semantics matrix: validates POSIX / Linux named pipe open rules
//! missing from `fifonode`, `fifoforkeof`, and `fifoepolleof`.
//!
//! Matrix covers:
//!  1. Nonblocking and immediate single-process opens:
//!     - O_RDONLY | O_NONBLOCK without writer succeeds immediately.
//!     - O_WRONLY | O_NONBLOCK without reader fails immediately with ENXIO.
//!     - O_RDWR succeeds immediately without blocking for peer.
//!     - O_CREAT | O_EXCL on an existing FIFO fails with EEXIST.
//!     - O_CLOEXEC and O_NONBLOCK file descriptor and status flags retained.
//!  2. Blocking reader waits for writer handshake:
//!     - Reader blocks without writer; unblocks when writer opens.
//!  3. Blocking writer waits for reader handshake:
//!     - Writer blocks without reader; unblocks when reader opens.
//!  4. Delayed peer arrival beyond 1-second policy timeout:
//!     - Timing-sensitive reducer: probes runtime open retry timeout policy
//!       (Carrick retrying blocking writer open for 500*2ms = 1.0s then returning
//!       ENXIO). On Linux, blocking open waits indefinitely for peer (~2.2s delay).
//!       Documented limitation: under heavy host load, CPU scheduling jitter may
//!       stretch delays; the oracle should be run twice serially.
//!  5. Signal interruption on blocking open:
//!     - Signal handler without SA_RESTART interrupts open with EINTR.
//!     - Signal handler with SA_RESTART keeps open blocking until peer arrives,
//!       then succeeds.
//!
//! Output format: deterministic `key=value` lines diffed line-by-line against
//! the native Linux oracle. No latency assertions or PIDs printed.

use conformance_probes::{errno, pipe2, report};
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

static HANDLER_CALLED: AtomicBool = AtomicBool::new(false);
static HANDLER_PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn sigusr1_handler(_sig: libc::c_int) {
    HANDLER_CALLED.store(true, Ordering::SeqCst);
}

extern "C" fn sigusr1_sa_restart_handler(_sig: libc::c_int) {
    HANDLER_CALLED.store(true, Ordering::SeqCst);
    let fd = HANDLER_PIPE_WRITE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = 1u8;
        unsafe {
            libc::write(fd, &b as *const _ as *const libc::c_void, 1);
        }
    }
}

unsafe fn make_fifo(path: &CStr) -> bool {
    libc::unlink(path.as_ptr());
    libc::mkfifo(path.as_ptr(), 0o600) == 0
}

fn poll_immediate(fd: i32, events: i16) -> i32 {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        return rc;
    }
}

fn poll_until(fd: i32, events: i16, deadline: Instant) -> i32 {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let now = Instant::now();
        if now >= deadline {
            return 0; // timed out
        }
        let remaining_ms = deadline
            .duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms.max(1)) };
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        return rc;
    }
}

fn read_exact_bounded(fd: i32, buf: &mut [u8], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut offset = 0;
    while offset < buf.len() {
        let rc = poll_until(fd, libc::POLLIN, deadline);
        if rc <= 0 {
            return false;
        }
        let n = unsafe {
            libc::read(
                fd,
                buf[offset..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - offset,
            )
        };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 {
            return false;
        } else if errno() != libc::EINTR {
            return false;
        }
    }
    true
}

unsafe fn write_all_child(fd: i32, buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let n = libc::write(
            fd,
            buf[offset..].as_ptr() as *const libc::c_void,
            buf.len() - offset,
        );
        if n > 0 {
            offset += n as usize;
        } else if n != -1 || errno() != libc::EINTR {
            return false;
        }
    }
    true
}

unsafe fn reap_child_exact(pid: i32, timeout: Duration) -> bool {
    if pid <= 0 {
        return false;
    }
    let deadline = Instant::now() + timeout;
    let mut status = 0i32;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
        if rc < 0 && errno() != libc::EINTR {
            return false;
        }
        if Instant::now() >= deadline {
            break;
        }
        libc::usleep(5_000);
    }
    libc::kill(pid, libc::SIGKILL);
    let kill_deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let mut st = 0i32;
        let rc = libc::waitpid(pid, &mut st, libc::WNOHANG);
        if rc == pid || (rc < 0 && errno() != libc::EINTR) {
            break;
        }
        if Instant::now() >= kill_deadline {
            let _ = libc::waitpid(pid, &mut st, 0);
            break;
        }
        libc::usleep(5_000);
    }
    false
}

/// `open(O_WRONLY|O_NONBLOCK)` retried until a reader is present or the
/// deadline passes. Returns the fd, or -1 with the last errno preserved.
unsafe fn open_writer_nonblock_retry(path: &CStr, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    loop {
        let wfd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
        if wfd >= 0 || errno() != libc::ENXIO || Instant::now() >= deadline {
            return wfd;
        }
        libc::usleep(2_000);
    }
}

unsafe fn test_single_process_opens() {
    let path = c"/tmp/fifo_matrix_single.fifo";
    if !make_fifo(path) {
        report!(
            nonblock_reader_without_writer_ok = false,
            nonblock_writer_without_reader_enxio = false,
            rdwr_immediate_success = false,
            creat_excl_existing_fifo_eexist = false,
            flags_o_nonblock_retained = false,
            flags_o_cloexec_retained = false,
            rdwr_cloexec_retained = false,
        );
        return;
    }

    // 1. Nonblocking reader without writer -> succeeds immediately
    let rfd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
    let nonblock_reader_ok = rfd >= 0;
    if rfd >= 0 {
        libc::close(rfd);
    }

    // 2. Nonblocking writer without reader -> fails immediately with ENXIO
    let wfd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
    let nonblock_writer_enxio = wfd == -1 && errno() == libc::ENXIO;
    if wfd >= 0 {
        libc::close(wfd);
    }

    // 3. O_RDWR -> succeeds immediately without waiting for peer
    let rwfd = libc::open(path.as_ptr(), libc::O_RDWR);
    let rdwr_ok = rwfd >= 0;
    if rwfd >= 0 {
        libc::close(rwfd);
    }

    // 4. O_CREAT | O_EXCL on existing FIFO -> fails with EEXIST
    let creat_excl_fd = libc::open(
        path.as_ptr(),
        libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    );
    let creat_excl_eexist = creat_excl_fd == -1 && errno() == libc::EEXIST;
    if creat_excl_fd >= 0 {
        libc::close(creat_excl_fd);
    }

    // 5. Returned flags: O_NONBLOCK and O_CLOEXEC
    let cfd = libc::open(
        path.as_ptr(),
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    );
    let mut flags_nonblock_ok = false;
    let mut flags_cloexec_ok = false;
    if cfd >= 0 {
        let fl = libc::fcntl(cfd, libc::F_GETFL);
        let fdfl = libc::fcntl(cfd, libc::F_GETFD);
        flags_nonblock_ok = fl >= 0 && (fl & libc::O_NONBLOCK) != 0;
        flags_cloexec_ok = fdfl >= 0 && (fdfl & libc::FD_CLOEXEC) != 0;
        libc::close(cfd);
    }

    // 6. O_RDWR with O_CLOEXEC
    let rw_cloexec_fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
    let mut rdwr_cloexec_ok = false;
    if rw_cloexec_fd >= 0 {
        let fdfl = libc::fcntl(rw_cloexec_fd, libc::F_GETFD);
        rdwr_cloexec_ok = fdfl >= 0 && (fdfl & libc::FD_CLOEXEC) != 0;
        libc::close(rw_cloexec_fd);
    }

    libc::unlink(path.as_ptr());

    report!(
        nonblock_reader_without_writer_ok = nonblock_reader_ok,
        nonblock_writer_without_reader_enxio = nonblock_writer_enxio,
        rdwr_immediate_success = rdwr_ok,
        creat_excl_existing_fifo_eexist = creat_excl_eexist,
        flags_o_nonblock_retained = flags_nonblock_ok,
        flags_o_cloexec_retained = flags_cloexec_ok,
        rdwr_cloexec_retained = rdwr_cloexec_ok,
    );
}

unsafe fn test_blocking_reader_handshake() -> (bool, bool) {
    let path = c"/tmp/fifo_matrix_rdwait.fifo";
    if !make_fifo(path) {
        return (false, false);
    }
    let (ready_r, ready_w) = pipe2();
    let (done_r, done_w) = pipe2();

    let pid = libc::fork();
    if pid < 0 {
        libc::close(ready_r);
        libc::close(ready_w);
        libc::close(done_r);
        libc::close(done_w);
        libc::unlink(path.as_ptr());
        return (false, false);
    }
    if pid == 0 {
        libc::alarm(10);
        libc::close(ready_r);
        libc::close(done_r);

        write_all_child(ready_w, &[1]);
        libc::close(ready_w);

        let rfd = libc::open(path.as_ptr(), libc::O_RDONLY);
        let success = (rfd >= 0) as u8;
        if rfd >= 0 {
            libc::close(rfd);
        }
        write_all_child(done_w, &[success]);
        libc::close(done_w);
        libc::_exit(0);
    }

    libc::close(ready_w);
    libc::close(done_w);

    let mut ready_buf = [0u8; 1];
    let ready_ok = read_exact_bounded(ready_r, &mut ready_buf, Duration::from_secs(2));
    libc::close(ready_r);

    if !ready_ok {
        reap_child_exact(pid, Duration::from_millis(500));
        libc::close(done_r);
        libc::unlink(path.as_ptr());
        return (false, false);
    }

    // Bounded check: reader without writer must remain blocked (poll timeout)
    let blocked_without_writer = poll_until(
        done_r,
        libc::POLLIN,
        Instant::now() + Duration::from_millis(50),
    ) == 0;

    // Open writer to unblock reader. A non-blocking writer open fails with
    // ENXIO until the child is actually inside its blocking reader open (a
    // reader blocked in open counts), and the child may not have reached it
    // yet on a loaded host, so retry briefly instead of racing the scheduler.
    let wfd = open_writer_nonblock_retry(path, Duration::from_secs(2));

    let mut res = [0u8; 1];
    let got_res = read_exact_bounded(done_r, &mut res, Duration::from_millis(1500));

    if wfd >= 0 {
        libc::close(wfd);
    }
    let reaped = reap_child_exact(pid, Duration::from_millis(1000));
    libc::close(done_r);
    libc::unlink(path.as_ptr());

    let unblocked_after_writer = got_res && res[0] == 1 && reaped;
    (blocked_without_writer, unblocked_after_writer)
}

unsafe fn test_blocking_writer_handshake() -> (bool, bool) {
    let path = c"/tmp/fifo_matrix_wrwait.fifo";
    if !make_fifo(path) {
        return (false, false);
    }
    let (ready_r, ready_w) = pipe2();
    let (done_r, done_w) = pipe2();

    let pid = libc::fork();
    if pid < 0 {
        libc::close(ready_r);
        libc::close(ready_w);
        libc::close(done_r);
        libc::close(done_w);
        libc::unlink(path.as_ptr());
        return (false, false);
    }
    if pid == 0 {
        libc::alarm(10);
        libc::close(ready_r);
        libc::close(done_r);

        write_all_child(ready_w, &[1]);
        libc::close(ready_w);

        let wfd = libc::open(path.as_ptr(), libc::O_WRONLY);
        let success = (wfd >= 0) as u8;
        if wfd >= 0 {
            libc::close(wfd);
        }
        write_all_child(done_w, &[success]);
        libc::close(done_w);
        libc::_exit(0);
    }

    libc::close(ready_w);
    libc::close(done_w);

    let mut ready_buf = [0u8; 1];
    let ready_ok = read_exact_bounded(ready_r, &mut ready_buf, Duration::from_secs(2));
    libc::close(ready_r);

    if !ready_ok {
        reap_child_exact(pid, Duration::from_millis(500));
        libc::close(done_r);
        libc::unlink(path.as_ptr());
        return (false, false);
    }

    // Bounded check: writer without reader must remain blocked (poll timeout)
    let blocked_without_reader = poll_until(
        done_r,
        libc::POLLIN,
        Instant::now() + Duration::from_millis(50),
    ) == 0;

    // Open reader to unblock writer
    let rfd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);

    let mut res = [0u8; 1];
    let got_res = read_exact_bounded(done_r, &mut res, Duration::from_millis(1500));

    if rfd >= 0 {
        libc::close(rfd);
    }
    let reaped = reap_child_exact(pid, Duration::from_millis(1000));
    libc::close(done_r);
    libc::unlink(path.as_ptr());

    let unblocked_after_reader = got_res && res[0] == 1 && reaped;
    (blocked_without_reader, unblocked_after_reader)
}

unsafe fn test_delayed_peer_arrival() -> (bool, bool) {
    // Timing-sensitive policy reducer: probes Carrick's 500*2ms (1.0s) retry loop.
    // We delay reader arrival by 2200ms (> 2.0s). Linux blocking open waits indefinitely.
    const DELAYED_PEER_WAIT: Duration = Duration::from_millis(2200);

    let path = c"/tmp/fifo_matrix_delayed.fifo";
    if !make_fifo(path) {
        return (false, false);
    }
    let (ready_r, ready_w) = pipe2();
    let (done_r, done_w) = pipe2();

    let pid = libc::fork();
    if pid < 0 {
        libc::close(ready_r);
        libc::close(ready_w);
        libc::close(done_r);
        libc::close(done_w);
        libc::unlink(path.as_ptr());
        return (false, false);
    }
    if pid == 0 {
        libc::alarm(10);
        libc::close(ready_r);
        libc::close(done_r);

        write_all_child(ready_w, &[1]);
        libc::close(ready_w);

        let wfd = libc::open(path.as_ptr(), libc::O_WRONLY);
        let success = (wfd >= 0) as u8;
        let err = if wfd < 0 { errno() as u8 } else { 0 };
        if wfd >= 0 {
            libc::close(wfd);
        }
        write_all_child(done_w, &[success, err]);
        libc::close(done_w);
        libc::_exit(0);
    }

    libc::close(ready_w);
    libc::close(done_w);

    let mut ready_buf = [0u8; 1];
    let ready_ok = read_exact_bounded(ready_r, &mut ready_buf, Duration::from_secs(2));
    libc::close(ready_r);

    if !ready_ok {
        reap_child_exact(pid, Duration::from_millis(500));
        libc::close(done_r);
        libc::unlink(path.as_ptr());
        return (false, false);
    }

    // Delay peer arrival beyond 2.0s
    std::thread::sleep(DELAYED_PEER_WAIT);

    // Negative evidence probe: before peer open, poll(0) checks whether child
    // already completed early (e.g. Carrick giving up with ENXIO after 1.0s).
    let premature_completed = poll_immediate(done_r, libc::POLLIN) > 0;

    // Open read end
    let rfd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);

    let mut res = [0u8; 2];
    let got_res = read_exact_bounded(done_r, &mut res, Duration::from_millis(1500));

    if rfd >= 0 {
        libc::close(rfd);
    }
    let reaped = reap_child_exact(pid, Duration::from_millis(1000));
    libc::close(done_r);
    libc::unlink(path.as_ptr());

    let succeeded = !premature_completed && got_res && res[0] == 1 && reaped;
    let is_enxio = got_res && res[0] == 0 && res[1] == (libc::ENXIO as u8) && reaped;
    (succeeded, is_enxio)
}

unsafe fn test_signal_eintr() -> bool {
    let path = c"/tmp/fifo_matrix_sig_eintr.fifo";
    if !make_fifo(path) {
        return false;
    }
    let (ready_r, ready_w) = pipe2();
    let (done_r, done_w) = pipe2();

    let pid = libc::fork();
    if pid < 0 {
        libc::close(ready_r);
        libc::close(ready_w);
        libc::close(done_r);
        libc::close(done_w);
        libc::unlink(path.as_ptr());
        return false;
    }
    if pid == 0 {
        libc::alarm(10);
        libc::close(ready_r);
        libc::close(done_r);

        HANDLER_CALLED.store(false, Ordering::SeqCst);
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = sigusr1_handler as *const () as usize;
        sa.sa_flags = 0; // No SA_RESTART -> open should return -1 with EINTR
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut());

        write_all_child(ready_w, &[1]);
        libc::close(ready_w);

        let wfd = libc::open(path.as_ptr(), libc::O_WRONLY);
        let handler_ran = HANDLER_CALLED.load(Ordering::SeqCst) as u8;
        let got_eintr = (wfd == -1 && errno() == libc::EINTR) as u8;
        if wfd >= 0 {
            libc::close(wfd);
        }
        write_all_child(done_w, &[handler_ran, got_eintr]);
        libc::close(done_w);
        libc::_exit(0);
    }

    libc::close(ready_w);
    libc::close(done_w);

    let mut ready_buf = [0u8; 1];
    let ready_ok = read_exact_bounded(ready_r, &mut ready_buf, Duration::from_secs(2));
    libc::close(ready_r);

    if !ready_ok {
        reap_child_exact(pid, Duration::from_millis(500));
        libc::close(done_r);
        libc::unlink(path.as_ptr());
        return false;
    }

    // Repeated delivery loop until done_r reports readiness or timeout
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        if poll_until(
            done_r,
            libc::POLLIN,
            Instant::now() + Duration::from_millis(25),
        ) > 0
        {
            break;
        }
        libc::kill(pid, libc::SIGUSR1);
    }

    let mut res = [0u8; 2];
    let got_res = read_exact_bounded(done_r, &mut res, Duration::from_millis(500));

    let reaped = reap_child_exact(pid, Duration::from_millis(1000));
    libc::close(done_r);
    libc::unlink(path.as_ptr());

    got_res && res[0] == 1 && res[1] == 1 && reaped
}

unsafe fn test_signal_sa_restart() -> (bool, bool) {
    let path = c"/tmp/fifo_matrix_sig_restart.fifo";
    if !make_fifo(path) {
        return (false, false);
    }
    let (ready_r, ready_w) = pipe2();
    let (handler_r, handler_w) = pipe2();
    let (done_r, done_w) = pipe2();

    let pid = libc::fork();
    if pid < 0 {
        libc::close(ready_r);
        libc::close(ready_w);
        libc::close(handler_r);
        libc::close(handler_w);
        libc::close(done_r);
        libc::close(done_w);
        libc::unlink(path.as_ptr());
        return (false, false);
    }
    if pid == 0 {
        libc::alarm(10);
        libc::close(ready_r);
        libc::close(handler_r);
        libc::close(done_r);

        HANDLER_CALLED.store(false, Ordering::SeqCst);
        HANDLER_PIPE_WRITE_FD.store(handler_w, Ordering::SeqCst);

        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = sigusr1_sa_restart_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut());

        write_all_child(ready_w, &[1]);
        libc::close(ready_w);

        let wfd = libc::open(path.as_ptr(), libc::O_WRONLY);
        let handler_ran = HANDLER_CALLED.load(Ordering::SeqCst) as u8;
        let success = (wfd >= 0) as u8;
        if wfd >= 0 {
            libc::close(wfd);
        }
        HANDLER_PIPE_WRITE_FD.store(-1, Ordering::SeqCst);
        libc::close(handler_w);

        write_all_child(done_w, &[handler_ran, success]);
        libc::close(done_w);
        libc::_exit(0);
    }

    libc::close(ready_w);
    libc::close(handler_w);
    libc::close(done_w);

    let mut ready_buf = [0u8; 1];
    let ready_ok = read_exact_bounded(ready_r, &mut ready_buf, Duration::from_secs(2));
    libc::close(ready_r);

    if !ready_ok {
        reap_child_exact(pid, Duration::from_millis(500));
        libc::close(handler_r);
        libc::close(done_r);
        libc::unlink(path.as_ptr());
        return (false, false);
    }

    // Repeated delivery loop until handler is observed via handler_r
    let handler_deadline = Instant::now() + Duration::from_millis(1500);
    let mut handler_buf = [0u8; 1];
    let mut handler_observed = false;
    while Instant::now() < handler_deadline {
        libc::kill(pid, libc::SIGUSR1);
        if read_exact_bounded(handler_r, &mut handler_buf, Duration::from_millis(25)) {
            handler_observed = true;
            break;
        }
    }

    // Negative check: open must have restarted and child must remain blocked in open()
    let stayed_blocked = poll_until(
        done_r,
        libc::POLLIN,
        Instant::now() + Duration::from_millis(50),
    ) == 0;

    // Open read end so the restarted open unblocks
    let rfd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);

    let mut res = [0u8; 2];
    let got_res = read_exact_bounded(done_r, &mut res, Duration::from_millis(1500));

    if rfd >= 0 {
        libc::close(rfd);
    }
    let reaped = reap_child_exact(pid, Duration::from_millis(1000));
    libc::close(handler_r);
    libc::close(done_r);
    libc::unlink(path.as_ptr());

    let resumed_and_succeeded =
        handler_observed && stayed_blocked && got_res && res[0] == 1 && res[1] == 1 && reaped;
    (stayed_blocked, resumed_and_succeeded)
}

fn main() {
    unsafe {
        // Overall probe watchdog: 20 seconds maximum execution bound
        libc::alarm(20);
        libc::umask(0);
        libc::mkdir(c"/tmp".as_ptr(), 0o777);

        test_single_process_opens();

        let (reader_blocked, reader_unblocked) = test_blocking_reader_handshake();
        let (writer_blocked, writer_unblocked) = test_blocking_writer_handshake();
        report!(
            reader_blocked_without_writer = reader_blocked,
            reader_unblocked_after_writer = reader_unblocked,
            writer_blocked_without_reader = writer_blocked,
            writer_unblocked_after_reader = writer_unblocked,
        );

        let (delayed_ok, delayed_enxio) = test_delayed_peer_arrival();
        report!(
            delayed_peer_writer_succeeded = delayed_ok,
            delayed_peer_writer_enxio = delayed_enxio,
        );

        let eintr_ok = test_signal_eintr();
        let (sa_restart_blocked, sa_restart_succeeded) = test_signal_sa_restart();
        report!(
            interrupted_open_eintr = eintr_ok,
            sa_restart_stayed_blocked = sa_restart_blocked,
            sa_restart_open_resumed_and_succeeded = sa_restart_succeeded,
        );

        libc::alarm(0);
    }
}
