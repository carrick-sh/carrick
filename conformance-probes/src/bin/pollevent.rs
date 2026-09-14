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
    poll_epoll_fd_probe();
    poll_probe();
    select_probe();
    timerfd_probe();
    poll_invalid_probe();
    pipe2_nonblock_probe();
    poll_multi_probe();
    timerfd_worker_progress_probe();
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
        unsafe {
            libc::close(ep);
            libc::close(rd);
            libc::close(wr)
        };
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

    unsafe {
        libc::close(ep);
        libc::close(rd);
        libc::close(wr)
    };
}

/// poll on an epoll fd: registering a readable pipe in the epoll instance makes
/// the epoll fd itself POLLIN-readable. libuv's embedded-loop test waits on
/// `poll(uv_backend_fd(loop))`, so this must wake without consuming the event.
fn poll_epoll_fd_probe() {
    let ep = unsafe { libc::epoll_create1(0) };
    if ep < 0 {
        println!("poll_epoll_create1=ERR:{}", errno());
        return;
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("poll_epoll_pipe=ERR:{}", errno());
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
        println!("poll_epoll_ctl_add=ERR:{}", errno());
        unsafe {
            libc::close(ep);
            libc::close(rd);
            libc::close(wr);
        }
        return;
    }

    unsafe { libc::write(wr, b"e".as_ptr().cast(), 1) };
    let mut pfd = libc::pollfd {
        fd: ep,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 50) };
    if rc < 0 {
        println!("poll_epoll_fd=ERR:{}", errno());
    } else {
        println!("poll_epoll_fd_ready_rc={}", rc);
        println!(
            "poll_epoll_fd_revents_in={}",
            (pfd.revents & libc::POLLIN) != 0
        );
    }

    unsafe {
        libc::close(ep);
        libc::close(rd);
        libc::close(wr);
    }
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
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let rcp = unsafe { libc::ppoll(&mut pfd as *mut _, 1, &ts as *const _, std::ptr::null()) };
    if rcp < 0 {
        println!("ppoll_empty=ERR:{}", errno());
    } else {
        println!("ppoll_empty_rc={}", rcp);
    }

    unsafe {
        libc::close(rd);
        libc::close(wr)
    };
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
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 10_000,
    };
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
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
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

    unsafe {
        libc::close(rd);
        libc::close(wr)
    };
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
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    let set = unsafe { libc::timerfd_settime(tfd, 0, &spec as *const _, std::ptr::null_mut()) };
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

    // A failed copyout must leave a pending expiration readable.  Use a
    // nonblocking descriptor so the unfired observation has a concrete errno
    // and polling bounds the later one-shot expiry.
    let fault_fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) };
    if fault_fd < 0 {
        println!("timerfd_fault_create=ERR:{}", errno());
        return;
    }
    let mut unfired: u64 = 0;
    let unfired_read = unsafe { libc::read(fault_fd, &mut unfired as *mut u64 as *mut _, 8) };
    println!(
        "timerfd_unfired_nonblock_errno={}",
        if unfired_read == -1 { errno() } else { 0 }
    );
    let fault_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    if unsafe { libc::timerfd_settime(fault_fd, 0, &fault_spec, std::ptr::null_mut()) } != 0 {
        println!("timerfd_fault_settime=ERR:{}", errno());
        unsafe { libc::close(fault_fd) };
        return;
    }
    let mut fault_poll = libc::pollfd {
        fd: fault_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut fault_poll, 1, 50) };
    println!("timerfd_fault_ready={ready}");
    println!("timerfd_fault_revents={}", fault_poll.revents);
    let fault_read = unsafe { libc::read(fault_fd, 1_usize as *mut _, 8) };
    let fault_errno = if fault_read == -1 { errno() } else { 0 };
    let mut after_fault: u64 = 0;
    let after_fault_read =
        unsafe { libc::read(fault_fd, &mut after_fault as *mut u64 as *mut _, 8) };
    let after_fault_errno = if after_fault_read == -1 { errno() } else { 0 };
    println!("timerfd_fault_read_rc={fault_read}");
    println!("timerfd_fault_read_errno={fault_errno}");
    println!("timerfd_after_fault_read_rc={after_fault_read}");
    println!("timerfd_after_fault_read_errno={after_fault_errno}");
    println!(
        "timerfd_after_fault_expirations={}",
        if after_fault_read == 8 {
            after_fault
        } else {
            0
        }
    );
    unsafe { libc::close(fault_fd) };
}

/// Thirty-two readers each block on an initially disarmed timerfd.  After all
/// readers reach the barrier, the parent alone arms every timer.  Therefore no
/// worker owns a deadline that can hide executor starvation: scheduling the
/// runnable parent is necessary for any read to complete.
///
/// The parent polls a completion pipe for at most five seconds before joining.
/// If Carrick occupies every executor in the blocking reads, the parent never
/// gets to arm the timers and this function emits no completion result.  It is
/// the final observation in `main`, so `main` returns immediately after this
/// function returns; the external conformance harness must bound and reap that
/// full-starvation case.
fn timerfd_worker_progress_probe() {
    const WORKERS: usize = 32;
    let mut timer_fds = [-1_i32; WORKERS];
    for fd in &mut timer_fds {
        *fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
        if *fd < 0 {
            let error = errno();
            for close_fd in timer_fds {
                if close_fd >= 0 {
                    unsafe { libc::close(close_fd) };
                }
            }
            println!("timerfd_worker_setup_errno={error}");
            return;
        }
    }

    let mut completions = [-1_i32; 2];
    if unsafe { libc::pipe(completions.as_mut_ptr()) } != 0 {
        let error = errno();
        for fd in timer_fds {
            unsafe { libc::close(fd) };
        }
        println!("timerfd_worker_setup_errno={error}");
        return;
    }
    let [completion_read, completion_write] = completions;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for fd in timer_fds {
        let barrier = std::sync::Arc::clone(&barrier);
        let worker_completion = completion_write;
        let worker = std::thread::Builder::new().spawn(move || {
            barrier.wait();
            let mut expirations = 0_u64;
            let read = unsafe { libc::read(fd, &mut expirations as *mut u64 as *mut _, 8) };
            let ok = read == 8 && expirations == 1;
            let marker = [u8::from(ok)];
            // The parent observes exactly one marker per reader before any
            // join; the pipe has ample room for this fixed 32-byte cohort.
            let _ = unsafe { libc::write(worker_completion, marker.as_ptr() as *const _, 1) };
            (read, expirations)
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                for fd in timer_fds {
                    unsafe { libc::close(fd) };
                }
                unsafe {
                    libc::close(completion_read);
                    libc::close(completion_write);
                }
                println!(
                    "timerfd_worker_setup_errno={}",
                    error.raw_os_error().unwrap_or(-1)
                );
                // Existing workers are fixed-size-barrier waiters.  Returning
                // ends this diagnostic process, so the OS reclaims them and
                // their descriptors; close does not pretend to cancel a read.
                return;
            }
        }
    }

    barrier.wait();
    println!("timerfd_worker_startup={WORKERS}");
    // Staging makes the read cohort runnable without giving a worker a timer
    // it could use to mask a parent scheduling failure.
    std::thread::sleep(std::time::Duration::from_millis(10));

    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    };
    let arm_failures = timer_fds
        .iter()
        .filter(|fd| unsafe { libc::timerfd_settime(**fd, 0, &spec, std::ptr::null_mut()) } != 0)
        .count();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut completion_count = 0_usize;
    let mut completion_successes = 0_usize;
    while completion_count < WORKERS && std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let mut pollfd = libc::pollfd {
            fd: completion_read,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis().min(100) as i32) };
        if ready <= 0 {
            continue;
        }
        let mut markers = [0_u8; WORKERS];
        let read = unsafe {
            libc::read(
                completion_read,
                markers.as_mut_ptr() as *mut _,
                markers.len(),
            )
        };
        if read <= 0 {
            break;
        }
        let read = read as usize;
        completion_count += read;
        completion_successes += markers[..read]
            .iter()
            .filter(|marker| **marker == 1)
            .count();
    }

    println!("timerfd_worker_arm_failures={arm_failures}");
    println!("timerfd_worker_completion_count={completion_count}");
    println!("timerfd_worker_completion_successes={completion_successes}");
    if completion_count != WORKERS {
        for fd in timer_fds {
            unsafe { libc::close(fd) };
        }
        unsafe {
            libc::close(completion_read);
            libc::close(completion_write);
        }
        // Do not join a reader that did not report completion: Linux close is
        // not a portable cancellation primitive for a blocked read.
        return;
    }

    let mut read_successes = 0_usize;
    let mut expiration_ones = 0_usize;
    let mut read_failures = 0_usize;
    for worker in workers {
        match worker.join() {
            Ok((8, 1)) => {
                read_successes += 1;
                expiration_ones += 1;
            }
            Ok((8, _)) => {
                read_successes += 1;
                read_failures += 1;
            }
            _ => read_failures += 1,
        }
    }
    for fd in timer_fds {
        unsafe { libc::close(fd) };
    }
    unsafe {
        libc::close(completion_read);
        libc::close(completion_write);
    }
    println!("timerfd_worker_read_successes={read_successes}");
    println!("timerfd_worker_expirations_one={expiration_ones}");
    println!("timerfd_worker_read_failures={read_failures}");
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
        unsafe {
            libc::close(rd1);
            libc::close(wr1)
        };
        return;
    }
    let (rd2, wr2) = (p2[0], p2[1]);

    let mut pfds = [
        libc::pollfd {
            fd: rd1,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wr2,
            events: libc::POLLOUT,
            revents: 0,
        },
        libc::pollfd {
            fd: 9999,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 50) };
    if rc < 0 {
        println!("poll_multi=ERR:{}", errno());
    } else {
        // All three fds report a revent → poll counts 3.
        println!("poll_multi_ready_count={}", rc);
        println!("poll_multi_rd_in={}", (pfds[0].revents & libc::POLLIN) != 0);
        println!(
            "poll_multi_wr_out={}",
            (pfds[1].revents & libc::POLLOUT) != 0
        );
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
