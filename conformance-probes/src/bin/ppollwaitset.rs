//! Conformance probe for ppoll on mixed/synthetic descriptors via wait set.
//!
//! Oracle instrument: every line is an observation, never an assertion, and
//! every wait is bounded (5 s cap) so a lost wakeup is a false line, not a
//! hang. Raw timings are never printed; only bucketed/threshold booleans are,
//! so the oracle is line-exact.
//!
//! Cases:
//!   (a) a set holding a freshly created, UNCONNECTED AF_INET stream socket:
//!       Linux reports POLLHUP on it immediately, so ppoll returns without
//!       blocking. This case exists to pin that answer (it was a real runtime
//!       bug in carrick); it must NOT be reused for the blocking cases below.
//!   (b) wake latency < 5 ms when writing to eventfd after 200 ms (median over
//!       50 iters), exactly one wake.
//!   (c) finite timeout 30 ms returns 0 and never before 30 ms.
//!   (d) wait with nothing ready for 3 s does NOT return before 3 s; writer
//!       fires at 4 s (5 s timeout cap).
//!   (e) SIGALRM interrupts an infinite ppoll with EINTR promptly.
//!   (f) a sibling-thread `kill(getpid(), SIGUSR1)` interrupts ppoll with EINTR.
//!   (g) a signal blocked by the ppoll sigmask does not interrupt the wait.
//! Cases (b)..(g) use a set whose socket member is one end of a connected
//! AF_UNIX socketpair, which is not readable until its peer writes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn create_mixed_set() -> (i32, i32, i32, i32, i32) {
    let mut pipe_fds = [-1i32; 2];
    let _ = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };

    let efd = unsafe { libc::eventfd(0, 0) };
    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };

    (pipe_fds[0], pipe_fds[1], efd, tfd, sock)
}

fn close_mixed_set(pipe_rd: i32, pipe_wr: i32, efd: i32, tfd: i32, sock: i32) {
    unsafe {
        if pipe_rd >= 0 {
            libc::close(pipe_rd);
        }
        if pipe_wr >= 0 {
            libc::close(pipe_wr);
        }
        if efd >= 0 {
            libc::close(efd);
        }
        if tfd >= 0 {
            libc::close(tfd);
        }
        if sock >= 0 {
            libc::close(sock);
        }
    }
}

/// The mixed set for the blocking cases: the socket member is one end of a
/// connected AF_UNIX stream socketpair (its peer is returned last and stays
/// open, so the member is neither readable nor hung up).
fn create_blocking_set() -> (i32, i32, i32, i32, i32, i32) {
    let mut pipe_fds = [-1i32; 2];
    let _ = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };

    let efd = unsafe { libc::eventfd(0, 0) };
    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    let mut pair = [-1i32; 2];
    let _ = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };

    (pipe_fds[0], pipe_fds[1], efd, tfd, pair[0], pair[1])
}

fn close_blocking_set(pipe_rd: i32, pipe_wr: i32, efd: i32, tfd: i32, sock: i32, peer: i32) {
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
    if peer >= 0 {
        unsafe {
            libc::close(peer);
        }
    }
}

fn run_case_a() {
    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

    let t_write = Arc::new(AtomicU64::new(0));
    let t_write_clone = Arc::clone(&t_write);
    let ready_to_block = Arc::new(AtomicBool::new(false));
    let ready_to_block_clone = Arc::clone(&ready_to_block);
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = Arc::clone(&done);

    let writer = thread::spawn(move || {
        while !ready_to_block_clone.load(Ordering::Acquire) {
            thread::yield_now();
        }
        for _ in 0..20 {
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        t_write_clone.store(get_monotonic_ns(), Ordering::Release);
        let b = [1u8];
        let _ = unsafe { libc::write(pipe_wr, b.as_ptr() as *const _, 1) };
    });

    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    ready_to_block.store(true, Ordering::Release);
    let ts = libc::timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, &ts, std::ptr::null()) };
    let t_wake = get_monotonic_ns();
    done.store(true, Ordering::Release);

    let tw = t_write.load(Ordering::Acquire);
    let elapsed_ms = (t_wake.saturating_sub(t0)) / 1_000_000;

    let bucket = if elapsed_ms < 1 {
        "lt1"
    } else if elapsed_ms < 100 {
        "lt100"
    } else {
        "ge100"
    };

    println!("ppoll_rc={}", rc);
    println!("revents_fd0=0x{:x}", pfds[0].revents);
    println!("revents_fd1=0x{:x}", pfds[1].revents);
    println!("revents_fd2=0x{:x}", pfds[2].revents);
    println!("revents_fd3=0x{:x}", pfds[3].revents);
    println!("woke_before_writer={}", tw == 0);
    println!("wake_after_ms_bucket={}", bucket);

    let _ = writer.join();
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
}

fn run_case_b() {
    let iters = 50;
    let mut latencies_us = Vec::with_capacity(iters);
    let mut all_exactly_one = true;

    for _ in 0..iters {
        let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();

        let t_write = Arc::new(AtomicU64::new(0));
        let t_write_clone = Arc::clone(&t_write);
        let ready_to_block = Arc::new(AtomicBool::new(false));
        let ready_to_block_clone = Arc::clone(&ready_to_block);
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);

        let writer = thread::spawn(move || {
            while !ready_to_block_clone.load(Ordering::Acquire) {
                thread::yield_now();
            }
            for _ in 0..20 {
                if done_clone.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            t_write_clone.store(get_monotonic_ns(), Ordering::Release);
            let val: u64 = 1;
            let _ = unsafe { libc::write(efd, &val as *const _ as *const _, 8) };
        });

        let mut pfds = [
            libc::pollfd {
                fd: pipe_rd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: efd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sock,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        ready_to_block.store(true, Ordering::Release);
        let ts = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, &ts, std::ptr::null()) };
        let t_wake = get_monotonic_ns();
        done.store(true, Ordering::Release);

        let tw = t_write.load(Ordering::Acquire);
        let lat_us = if tw > 0 {
            (t_wake.saturating_sub(tw)) / 1_000
        } else {
            0
        };
        latencies_us.push(lat_us);

        let exactly_one = rc == 1
            && pfds[0].revents == 0
            && (pfds[1].revents & libc::POLLIN != 0)
            && pfds[2].revents == 0
            && pfds[3].revents == 0;
        if !exactly_one {
            all_exactly_one = false;
        }

        let _ = writer.join();
        close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);
    }

    latencies_us.sort_unstable();
    let median_us = latencies_us[iters / 2];
    let median_ms = median_us as f64 / 1000.0;
    let fast = median_ms < 5.0;

    println!("ppoll_eventfd_wake_latency_under_5ms={}", fast);
    println!("ppoll_eventfd_exactly_one_wake={}", all_exactly_one);
}

fn run_case_c() {
    let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();
    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 30_000_000,
    };
    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, &ts, std::ptr::null()) };
    let t1 = get_monotonic_ns();
    let elapsed_ms = (t1 - t0) as f64 / 1_000_000.0;

    close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);

    // Linux guarantees the wait lasts at least the requested timeout; how
    // much later it returns is scheduling, not semantics, so only the
    // "never early" half is an oracle line.
    let not_early = rc == 0 && elapsed_ms >= 29.0;
    println!("ppoll_timeout_30ms_returned_zero={}", rc == 0);
    println!("ppoll_timeout_30ms_not_early={}", not_early);
}

fn run_case_d() {
    let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();

    let writer_fired = Arc::new(AtomicBool::new(false));
    let writer_fired_clone = Arc::clone(&writer_fired);

    let writer = thread::spawn(move || {
        // Writer fires after 4 seconds
        thread::sleep(Duration::from_millis(4000));
        writer_fired_clone.store(true, Ordering::Release);
        let b = [1u8];
        let _ = unsafe { libc::write(pipe_wr, b.as_ptr() as *const _, 1) };
    });

    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let ts = libc::timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, &ts, std::ptr::null()) };
    let t1 = get_monotonic_ns();
    let elapsed_sec = (t1 - t0) as f64 / 1_000_000_000.0;

    let fired = writer_fired.load(Ordering::Acquire);
    let ok = rc == 1 && fired && elapsed_sec >= 3.8 && (pfds[0].revents & libc::POLLIN != 0);

    println!("ppoll_infinite_not_spurious_at_3s={}", rc != 0 && elapsed_sec >= 3.8);
    println!("ppoll_infinite_woke_at_4s={}", ok);

    let _ = writer.join();
    close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);
}

static ALARM_COUNT: AtomicU64 = AtomicU64::new(0);

extern "C" fn sigalrm_handler(_sig: libc::c_int) {
    ALARM_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn run_case_e() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigalrm_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        let _ = libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();

    let unblock_fired = Arc::new(AtomicBool::new(false));
    let unblock_fired_clone = Arc::clone(&unblock_fired);

    // Watchdog to prevent hanging forever on a broken binary:
    // If ppoll has not returned after 2.5 seconds, write to pipe_wr to wake it,
    // allowing the test to record false and exit rather than wedging CI.
    let watchdog = thread::spawn(move || {
        thread::sleep(Duration::from_millis(2500));
        if !unblock_fired_clone.load(Ordering::SeqCst) {
            unblock_fired_clone.store(true, Ordering::SeqCst);
            let b = [1u8];
            unsafe {
                libc::write(pipe_wr, b.as_ptr() as *const _, 1);
            }
        }
    });

    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    ALARM_COUNT.store(0, Ordering::SeqCst);

    // Arm SIGALRM after 100 ms using setitimer(ITIMER_REAL)
    let itv = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) };

    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
    let t1 = get_monotonic_ns();
    let errno = if rc == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };

    let elapsed_ms = (t1 - t0) as f64 / 1_000_000.0;
    let alarm_fired = ALARM_COUNT.load(Ordering::SeqCst);
    let watchdog_tripped = unblock_fired.load(Ordering::SeqCst);

    // Disarm timer and disarm watchdog
    let disarm = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    unsafe {
        libc::setitimer(libc::ITIMER_REAL, &disarm, std::ptr::null_mut());
    }
    unblock_fired.store(true, Ordering::SeqCst);

    // Wake latency is the time after the 100 ms alarm; a tight bound is a
    // scheduling statement the oracle itself misses under load, so the line
    // only separates "prompt" from "lost until the 2.5 s watchdog".
    let returned_eintr = rc == -1 && errno == libc::EINTR && !watchdog_tripped;
    let wake_latency_ms = (elapsed_ms - 100.0).max(0.0);
    let prompt = returned_eintr && wake_latency_ms < 500.0;

    println!("ppoll_sigalrm_returned_eintr={}", returned_eintr);
    println!("ppoll_sigalrm_wake_latency_under_500ms={}", prompt);
    println!("ppoll_sigalrm_handler_fired={}", alarm_fired > 0);
    println!("ppoll_sigalrm_errno={}", errno);

    // Reset signal handler to default after threads join
    let _ = watchdog.join();
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);
}

static USR1_COUNT: AtomicU64 = AtomicU64::new(0);
static SIBLING_SEND_TIME_NS: AtomicU64 = AtomicU64::new(0);

extern "C" fn sigusr1_handler(_sig: libc::c_int) {
    USR1_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn run_case_f() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigusr1_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        let _ = libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();

    let unblock_fired = Arc::new(AtomicBool::new(false));
    let unblock_fired_clone = Arc::clone(&unblock_fired);
    let cancel_sender = Arc::new(AtomicBool::new(false));
    let cancel_sender_clone = Arc::clone(&cancel_sender);

    // Watchdog to prevent hanging forever on a broken binary:
    let watchdog = thread::spawn(move || {
        thread::sleep(Duration::from_millis(2500));
        if !unblock_fired_clone.load(Ordering::SeqCst) {
            unblock_fired_clone.store(true, Ordering::SeqCst);
            let b = [1u8];
            unsafe {
                libc::write(pipe_wr, b.as_ptr() as *const _, 1);
            }
        }
    });

    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    USR1_COUNT.store(0, Ordering::SeqCst);
    SIBLING_SEND_TIME_NS.store(0, Ordering::SeqCst);

    let sender = thread::spawn(move || {
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
        }
        thread::sleep(Duration::from_millis(50));
        if cancel_sender_clone.load(Ordering::SeqCst) {
            return;
        }
        let t_send = get_monotonic_ns();
        SIBLING_SEND_TIME_NS.store(t_send, Ordering::SeqCst);
        unsafe {
            libc::kill(libc::getpid(), libc::SIGUSR1);
        }
    });

    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
    let t1 = get_monotonic_ns();
    cancel_sender.store(true, Ordering::SeqCst);
    let errno = if rc == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };

    let elapsed_ms = (t1 - t0) as f64 / 1_000_000.0;
    let t_send = SIBLING_SEND_TIME_NS.load(Ordering::SeqCst);
    let wake_latency_ms = if t_send > 0 && t1 >= t_send {
        (t1 - t_send) as f64 / 1_000_000.0
    } else {
        (elapsed_ms - 50.0).max(0.0)
    };

    let usr1_fired = USR1_COUNT.load(Ordering::SeqCst);
    let watchdog_tripped = unblock_fired.load(Ordering::SeqCst);

    unblock_fired.store(true, Ordering::SeqCst);

    let returned_eintr = rc == -1 && errno == libc::EINTR && !watchdog_tripped;
    let prompt = returned_eintr && wake_latency_ms < 500.0;

    println!("ppoll_sibling_sigusr1_returned_eintr={}", returned_eintr);
    println!("ppoll_sibling_sigusr1_wake_latency_under_500ms={}", prompt);
    println!("ppoll_sibling_sigusr1_handler_fired={}", usr1_fired > 0);
    println!("ppoll_sibling_sigusr1_errno={}", errno);

    let _ = sender.join();
    let _ = watchdog.join();

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);
}

fn run_case_g() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigalrm_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        let _ = libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock, peer) = create_blocking_set();

    let unblock_fired = Arc::new(AtomicBool::new(false));
    let unblock_fired_clone = Arc::clone(&unblock_fired);

    // Watchdog to prevent hanging forever on a broken binary:
    let watchdog = thread::spawn(move || {
        thread::sleep(Duration::from_millis(2500));
        if !unblock_fired_clone.load(Ordering::SeqCst) {
            unblock_fired_clone.store(true, Ordering::SeqCst);
            let b = [1u8];
            unsafe {
                libc::write(pipe_wr, b.as_ptr() as *const _, 1);
            }
        }
    });

    let mut pfds = [
        libc::pollfd {
            fd: pipe_rd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    ALARM_COUNT.store(0, Ordering::SeqCst);

    // Construct a signal mask that blocks SIGALRM
    let mut sigmask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigmask);
        libc::sigaddset(&mut sigmask, libc::SIGALRM);
    }

    // Arm SIGALRM after 50 ms
    let itv = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) };

    // ppoll with 100 ms timeout and sigmask blocking SIGALRM:
    // If blocked signal correctly does NOT interrupt ppoll, ppoll will wait the
    // full 100 ms timeout and return 0 (no fds ready).
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };

    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, &ts, &sigmask) };
    let t1 = get_monotonic_ns();
    let errno = if rc == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };

    let elapsed_ms = (t1 - t0) as f64 / 1_000_000.0;
    let watchdog_tripped = unblock_fired.load(Ordering::SeqCst);

    // Disarm timer and disarm watchdog
    let disarm = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    unsafe {
        libc::setitimer(libc::ITIMER_REAL, &disarm, std::ptr::null_mut());
    }
    unblock_fired.store(true, Ordering::SeqCst);

    let not_interrupted = rc == 0 && !watchdog_tripped && elapsed_ms >= 85.0;
    let alarm_fired = ALARM_COUNT.load(Ordering::SeqCst);

    println!("ppoll_blocked_sigalrm_not_interrupted={}", not_interrupted);
    println!("ppoll_blocked_sigalrm_timed_out={}", rc == 0);
    println!("ppoll_blocked_sigalrm_handler_fired={}", alarm_fired > 0);
    println!("ppoll_blocked_sigalrm_errno={}", errno);

    let _ = watchdog.join();

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    close_blocking_set(pipe_rd, pipe_wr, efd, tfd, sock, peer);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run_all = args.len() <= 1;

    if run_all || args.iter().any(|a| a == "a") {
        run_case_a();
    }
    if run_all || args.iter().any(|a| a == "b") {
        run_case_b();
    }
    if run_all || args.iter().any(|a| a == "c") {
        run_case_c();
    }
    if run_all || args.iter().any(|a| a == "d") {
        run_case_d();
    }
    if run_all || args.iter().any(|a| a == "e") {
        run_case_e();
    }
    if run_all || args.iter().any(|a| a == "f") {
        run_case_f();
    }
    if run_all || args.iter().any(|a| a == "g") {
        run_case_g();
    }
}
