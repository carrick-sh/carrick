//! Event / polling probe. Exercises eventfd/epoll/poll/ppoll/select/pselect6/
//! timerfd syscalls and prints one labelled line per observation. The
//! conformance harness runs this identical static binary under carrick and
//! real Linux and diffs line by line — a divergent line names the exact
//! failing syscall.
//!
//! Deterministic only: no fd numbers, addresses, or timing values. Booleans,
//! counts, and errnos only. Short timeouts keep output stable across runs.

fn main() {
    eventfd_probe();
    epoll_probe();
    poll_probe();
    select_probe();
    timerfd_probe();
    poll_invalid_probe();
    pipe2_nonblock_probe();
    poll_multi_probe();
}

/// eventfd: create with initial value 0, write 5, read it back (read returns 5
/// and resets the counter to 0). A second non-blocking read then blocks/EAGAIN.
fn eventfd_probe() {
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    if efd < 0 {
        println!("eventfd=ERR:{}", errno());
        return;
    }
    let val: u64 = 5;
    let w = unsafe { libc::write(efd, &val as *const u64 as *const _, 8) };
    if w != 8 {
        println!("eventfd_write=ERR:{}", errno());
        unsafe { libc::close(efd) };
        return;
    }
    let mut got: u64 = 0;
    let r = unsafe { libc::read(efd, &mut got as *mut u64 as *mut _, 8) };
    if r != 8 {
        println!("eventfd_read=ERR:{}", errno());
        unsafe { libc::close(efd) };
        return;
    }
    println!("eventfd_read_value={}", got);
    // After the read the counter is reset to 0: a second read yields EAGAIN.
    let mut again: u64 = 0;
    let r2 = unsafe { libc::read(efd, &mut again as *mut u64 as *mut _, 8) };
    println!("eventfd_reset={}", r2 == -1 && errno() == libc::EAGAIN);
    unsafe { libc::close(efd) };
}

/// epoll: create, register a pipe read-end for EPOLLIN, write to the write-end,
/// epoll_wait with a short timeout → 1 ready event with EPOLLIN set. Then a
/// drained pipe epoll_wait with a short timeout → 0 (timed out).
fn epoll_probe() {
    let ep = unsafe { libc::epoll_create1(0) };
    if ep < 0 {
        println!("epoll_create1=ERR:{}", errno());
        return;
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("epoll_pipe=ERR:{}", errno());
        unsafe { libc::close(ep) };
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: rd as u64,
    };
    let add = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, rd, &mut ev) };
    if add != 0 {
        println!("epoll_ctl_add=ERR:{}", errno());
        unsafe { libc::close(ep); libc::close(rd); libc::close(wr) };
        return;
    }

    // Write to make the read-end readable.
    let msg = b"x";
    unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };

    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), out.len() as i32, 50) };
    if n < 0 {
        println!("epoll_wait=ERR:{}", errno());
    } else {
        println!("epoll_ready_count={}", n);
        let epollin = n >= 1 && (out[0].events & libc::EPOLLIN as u32) != 0;
        println!("epoll_revents_in={}", epollin);
    }

    // Drain the pipe, then epoll_wait should time out (return 0).
    let mut buf = [0u8; 16];
    unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let n2 = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), out.len() as i32, 10) };
    if n2 < 0 {
        println!("epoll_wait_timeout=ERR:{}", errno());
    } else {
        println!("epoll_wait_timeout={}", n2);
    }

    unsafe { libc::close(ep); libc::close(rd); libc::close(wr) };
}

/// poll: a pipe read-end with POLLIN. Nothing written and a 10ms timeout → rc 0
/// (timed out). After writing, poll again → rc 1 and revents has POLLIN.
fn poll_probe() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("poll_pipe=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let mut pfd = libc::pollfd {
        fd: rd,
        events: libc::POLLIN,
        revents: 0,
    };

    let rc0 = unsafe { libc::poll(&mut pfd as *mut _, 1, 10) };
    if rc0 < 0 {
        println!("poll_empty=ERR:{}", errno());
    } else {
        println!("poll_empty_rc={}", rc0);
    }

    let msg = b"y";
    unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
    pfd.revents = 0;
    let rc1 = unsafe { libc::poll(&mut pfd as *mut _, 1, 50) };
    if rc1 < 0 {
        println!("poll_ready=ERR:{}", errno());
    } else {
        println!("poll_ready_rc={}", rc1);
        println!("poll_revents_in={}", (pfd.revents & libc::POLLIN) != 0);
    }

    // ppoll: drain, then nothing written and a short timespec → rc 0.
    let mut buf = [0u8; 16];
    unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    pfd.revents = 0;
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
    let rcp = unsafe {
        libc::ppoll(
            &mut pfd as *mut _,
            1,
            &ts as *const _,
            std::ptr::null(),
        )
    };
    if rcp < 0 {
        println!("ppoll_empty=ERR:{}", errno());
    } else {
        println!("ppoll_empty_rc={}", rcp);
    }

    unsafe { libc::close(rd); libc::close(wr) };
}

/// select / pselect6: a pipe read-end with a short timeout. Nothing written →
/// rc 0; after writing → rc 1.
fn select_probe() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("select_pipe=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    // select with empty pipe → timeout (rc 0).
    let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_ZERO(&mut set) };
    unsafe { libc::FD_SET(rd, &mut set) };
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 10_000 };
    let rc0 = unsafe {
        libc::select(
            rd + 1,
            &mut set as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv as *mut _,
        )
    };
    if rc0 < 0 {
        println!("select_empty=ERR:{}", errno());
    } else {
        println!("select_empty_rc={}", rc0);
    }

    // pselect6 with data available → rc 1.
    let msg = b"z";
    unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
    unsafe { libc::FD_ZERO(&mut set) };
    unsafe { libc::FD_SET(rd, &mut set) };
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    let rc1 = unsafe {
        libc::pselect(
            rd + 1,
            &mut set as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts as *const _,
            std::ptr::null(),
        )
    };
    if rc1 < 0 {
        println!("pselect_ready=ERR:{}", errno());
    } else {
        println!("pselect_ready_rc={}", rc1);
    }

    unsafe { libc::close(rd); libc::close(wr) };
}

/// timerfd: CLOCK_MONOTONIC one-shot 1ms timer; block-read the expiration count
/// after it fires. Report count >= 1 (boolean) — never print the count or any
/// timing value.
fn timerfd_probe() {
    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    if tfd < 0 {
        println!("timerfd_create=ERR:{}", errno());
        return;
    }
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 },
    };
    let set = unsafe {
        libc::timerfd_settime(tfd, 0, &spec as *const _, std::ptr::null_mut())
    };
    if set != 0 {
        println!("timerfd_settime=ERR:{}", errno());
        unsafe { libc::close(tfd) };
        return;
    }
    // Blocking read waits for the timer to fire, yielding the expiration count.
    let mut count: u64 = 0;
    let r = unsafe { libc::read(tfd, &mut count as *mut u64 as *mut _, 8) };
    if r != 8 {
        println!("timerfd_read=ERR:{}", errno());
    } else {
        println!("timerfd_fired={}", count >= 1);
    }
    unsafe { libc::close(tfd) };
}

/// poll on an invalid fd → revents has POLLNVAL set.
fn poll_invalid_probe() {
    let mut pfd = libc::pollfd {
        fd: 9999,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 10) };
    if rc < 0 {
        println!("poll_invalid=ERR:{}", errno());
    } else {
        println!("poll_invalid_nval={}", (pfd.revents & libc::POLLNVAL) != 0);
    }
}

/// pipe2 with O_NONBLOCK: read on an empty pipe → EAGAIN; write then read →
/// the data; closing the write-end then reading → 0 (EOF). Confirms the
/// O_NONBLOCK flag propagated to the read-end (F_GETFL shows it).
fn pipe2_nonblock_probe() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
        println!("pipe2_nb=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    // O_NONBLOCK is visible via F_GETFL on the read-end.
    let fl = unsafe { libc::fcntl(rd, libc::F_GETFL) };
    println!("pipe2_nb_flag={}", (fl & libc::O_NONBLOCK) != 0);

    // Empty non-blocking read → EAGAIN.
    let mut buf = [0u8; 16];
    let r0 = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    println!(
        "pipe2_nb_empty_eagain={}",
        r0 == -1 && errno() == libc::EAGAIN
    );

    // Write then read returns the data.
    let msg = b"nbdata";
    unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
    let r1 = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let got = &buf[..r1.max(0) as usize];
    println!("pipe2_nb_read_match={}", got == msg);

    // Close write-end → read returns 0 (EOF), not EAGAIN.
    unsafe { libc::close(wr) };
    let r2 = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    println!("pipe2_nb_eof={}", r2 == 0);

    unsafe { libc::close(rd) };
}

/// poll over three fds at once: a pipe read-end that HAS data (POLLIN ready), a
/// pipe write-end that HAS space (POLLOUT ready), and an invalid fd (POLLNVAL).
/// Assert the ready COUNT (3 — one revent set per fd) and each fd's revents.
fn poll_multi_probe() {
    // Pipe 1: make the read-end readable.
    let mut p1 = [0i32; 2];
    if unsafe { libc::pipe2(p1.as_mut_ptr(), 0) } != 0 {
        println!("poll_multi_pipe1=ERR:{}", errno());
        return;
    }
    let (rd1, wr1) = (p1[0], p1[1]);
    let msg = b"d";
    unsafe { libc::write(wr1, msg.as_ptr() as *const _, msg.len()) };

    // Pipe 2: a fresh, empty pipe — its write-end has space (POLLOUT ready).
    let mut p2 = [0i32; 2];
    if unsafe { libc::pipe2(p2.as_mut_ptr(), 0) } != 0 {
        println!("poll_multi_pipe2=ERR:{}", errno());
        unsafe { libc::close(rd1); libc::close(wr1) };
        return;
    }
    let (rd2, wr2) = (p2[0], p2[1]);

    let mut pfds = [
        libc::pollfd { fd: rd1, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: wr2, events: libc::POLLOUT, revents: 0 },
        libc::pollfd { fd: 9999, events: libc::POLLIN, revents: 0 },
    ];
    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 50) };
    if rc < 0 {
        println!("poll_multi=ERR:{}", errno());
    } else {
        // All three fds report a revent → poll counts 3.
        println!("poll_multi_ready_count={}", rc);
        println!("poll_multi_rd_in={}", (pfds[0].revents & libc::POLLIN) != 0);
        println!("poll_multi_wr_out={}", (pfds[1].revents & libc::POLLOUT) != 0);
        println!(
            "poll_multi_bad_nval={}",
            (pfds[2].revents & libc::POLLNVAL) != 0
        );
    }

    unsafe {
        libc::close(rd1);
        libc::close(wr1);
        libc::close(rd2);
        libc::close(wr2);
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
