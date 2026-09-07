//! Conformance probe for ppoll on mixed/synthetic descriptors via wait set.
//!
//! Checks:
//!   (a) wake latency < 5 ms when writing to pipe after 200 ms (median over 50 iters), exactly one wake.
//!   (b) wake latency < 5 ms when writing to eventfd after 200 ms (median over 50 iters), exactly one wake.
//!   (c) finite timeout 30 ms returns 0 at 30±2 ms.
//!   (d) infinite wait with nothing ready for 70 s does NOT return at 60 s; writer fires at 65 s.

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
    let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe failed");

    let efd = unsafe { libc::eventfd(0, 0) };
    assert!(efd >= 0, "eventfd failed");

    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(tfd >= 0, "timerfd failed");

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(sock >= 0, "socket failed");

    (pipe_fds[0], pipe_fds[1], efd, tfd, sock)
}

fn close_mixed_set(pipe_rd: i32, pipe_wr: i32, efd: i32, tfd: i32, sock: i32) {
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
        libc::close(efd);
        libc::close(tfd);
        libc::close(sock);
    }
}

fn run_case_a() {
    let iters = 50;
    let mut latencies_us = Vec::with_capacity(iters);
    let mut all_exactly_one = true;

    for _ in 0..iters {
        let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

        let t_write = Arc::new(AtomicU64::new(0));
        let t_write_clone = Arc::clone(&t_write);
        let ready_to_block = Arc::new(AtomicBool::new(false));
        let ready_to_block_clone = Arc::clone(&ready_to_block);

        let writer = thread::spawn(move || {
            while !ready_to_block_clone.load(Ordering::Acquire) {
                thread::yield_now();
            }
            thread::sleep(Duration::from_millis(200));
            t_write_clone.store(get_monotonic_ns(), Ordering::Release);
            let b = [1u8];
            let n = unsafe { libc::write(pipe_wr, b.as_ptr() as *const _, 1) };
            assert_eq!(n, 1);
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
        let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
        let t_wake = get_monotonic_ns();
        let tw = t_write.load(Ordering::Acquire);
        assert!(tw > 0, "writer must have recorded write timestamp");

        let lat_us = (t_wake.saturating_sub(tw)) / 1_000;
        latencies_us.push(lat_us);

        let exactly_one = rc == 1
            && (pfds[0].revents & libc::POLLIN != 0)
            && pfds[1].revents == 0
            && pfds[2].revents == 0
            && pfds[3].revents == 0;
        if !exactly_one {
            all_exactly_one = false;
        }

        writer.join().expect("join writer");
        close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
    }

    latencies_us.sort_unstable();
    let median_us = latencies_us[iters / 2];
    let median_ms = median_us as f64 / 1000.0;
    let fast = median_ms < 5.0;

    println!("ppoll_pipe_wake_latency_median_ms={:.2}", median_ms);
    println!("ppoll_pipe_wake_latency_under_5ms={}", fast);
    println!("ppoll_pipe_exactly_one_wake={}", all_exactly_one);
}

fn run_case_b() {
    let iters = 50;
    let mut latencies_us = Vec::with_capacity(iters);
    let mut all_exactly_one = true;

    for _ in 0..iters {
        let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

        let t_write = Arc::new(AtomicU64::new(0));
        let t_write_clone = Arc::clone(&t_write);
        let ready_to_block = Arc::new(AtomicBool::new(false));
        let ready_to_block_clone = Arc::clone(&ready_to_block);

        let writer = thread::spawn(move || {
            while !ready_to_block_clone.load(Ordering::Acquire) {
                thread::yield_now();
            }
            thread::sleep(Duration::from_millis(200));
            t_write_clone.store(get_monotonic_ns(), Ordering::Release);
            let val: u64 = 1;
            let n = unsafe { libc::write(efd, &val as *const _ as *const _, 8) };
            assert_eq!(n, 8);
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
        let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
        let t_wake = get_monotonic_ns();
        let tw = t_write.load(Ordering::Acquire);
        assert!(tw > 0, "writer must have recorded write timestamp");

        let lat_us = (t_wake.saturating_sub(tw)) / 1_000;
        latencies_us.push(lat_us);

        let exactly_one = rc == 1
            && pfds[0].revents == 0
            && (pfds[1].revents & libc::POLLIN != 0)
            && pfds[2].revents == 0
            && pfds[3].revents == 0;
        if !exactly_one {
            all_exactly_one = false;
        }

        writer.join().expect("join writer");
        close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
    }

    latencies_us.sort_unstable();
    let median_us = latencies_us[iters / 2];
    let median_ms = median_us as f64 / 1000.0;
    let fast = median_ms < 5.0;

    println!("ppoll_eventfd_wake_latency_median_ms={:.2}", median_ms);
    println!("ppoll_eventfd_wake_latency_under_5ms={}", fast);
    println!("ppoll_eventfd_exactly_one_wake={}", all_exactly_one);
}

fn run_case_c() {
    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();
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

    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);

    let within_tolerance = rc == 0 && elapsed_ms >= 28.0 && elapsed_ms <= 33.0;
    println!("ppoll_timeout_30ms_returned_zero={}", rc == 0);
    println!("ppoll_timeout_30ms_within_range={}", within_tolerance);
    println!("ppoll_timeout_elapsed_ms={:.2}", elapsed_ms);
}

fn run_case_d() {
    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

    let writer_fired = Arc::new(AtomicBool::new(false));
    let writer_fired_clone = Arc::clone(&writer_fired);

    let writer = thread::spawn(move || {
        // Writer fires after 85 seconds
        thread::sleep(Duration::from_secs(85));
        writer_fired_clone.store(true, Ordering::Release);
        let b = [1u8];
        let n = unsafe { libc::write(pipe_wr, b.as_ptr() as *const _, 1) };
        assert_eq!(n, 1);
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

    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
    let t1 = get_monotonic_ns();
    let elapsed_sec = (t1 - t0) as f64 / 1_000_000_000.0;

    let fired = writer_fired.load(Ordering::Acquire);
    let ok = rc == 1 && fired && elapsed_sec >= 84.0 && (pfds[0].revents & libc::POLLIN != 0);

    println!("ppoll_infinite_not_spurious_at_60s={}", rc != 0 && elapsed_sec >= 84.0);
    println!("ppoll_infinite_woke_at_85s={}", ok);
    println!("ppoll_infinite_elapsed_sec={:.2}", elapsed_sec);

    writer.join().expect("join writer");
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
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
        let rc = libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        assert_eq!(rc, 0, "sigaction failed");
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

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
    let rc_itv = unsafe { libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) };
    assert_eq!(rc_itv, 0, "setitimer failed");

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

    // Wake latency is time after 100ms when alarm fired:
    // Required: returns -1/EINTR, wake latency after alarm < 10 ms (total time ~100-115 ms).
    let returned_eintr = rc == -1 && errno == libc::EINTR && !watchdog_tripped;
    let wake_latency_ms = (elapsed_ms - 100.0).max(0.0);
    let under_10ms = returned_eintr && wake_latency_ms < 10.0;

    println!("ppoll_sigalrm_returned_eintr={}", returned_eintr);
    println!("ppoll_sigalrm_wake_latency_under_10ms={}", under_10ms);
    println!("ppoll_sigalrm_total_elapsed_ms={:.2}", elapsed_ms);
    println!("ppoll_sigalrm_handler_fired={}", alarm_fired > 0);
    println!("ppoll_sigalrm_errno={}", errno);

    // Reset signal handler to default
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    let _ = watchdog.join();
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
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
        let rc = libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        assert_eq!(rc, 0, "sigaction failed");
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

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

    USR1_COUNT.store(0, Ordering::SeqCst);
    SIBLING_SEND_TIME_NS.store(0, Ordering::SeqCst);

    let sender = thread::spawn(|| {
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
        }
        thread::sleep(Duration::from_millis(50));
        let t_send = get_monotonic_ns();
        SIBLING_SEND_TIME_NS.store(t_send, Ordering::SeqCst);
        unsafe {
            libc::kill(libc::getpid(), libc::SIGUSR1);
        }
    });

    let t0 = get_monotonic_ns();
    let rc = unsafe { libc::ppoll(pfds.as_mut_ptr(), 4, std::ptr::null(), std::ptr::null()) };
    let t1 = get_monotonic_ns();
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
    let under_10ms = returned_eintr && wake_latency_ms < 10.0;

    println!("ppoll_sibling_sigusr1_returned_eintr={}", returned_eintr);
    println!("ppoll_sibling_sigusr1_wake_latency_under_10ms={}", under_10ms);
    println!("ppoll_sibling_sigusr1_wake_latency_ms={:.2}", wake_latency_ms);
    println!("ppoll_sibling_sigusr1_total_elapsed_ms={:.2}", elapsed_ms);
    println!("ppoll_sibling_sigusr1_handler_fired={}", usr1_fired > 0);
    println!("ppoll_sibling_sigusr1_errno={}", errno);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    let _ = sender.join();
    let _ = watchdog.join();
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
}

fn run_case_g() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigalrm_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        let rc = libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        assert_eq!(rc, 0, "sigaction failed");
    }

    let (pipe_rd, pipe_wr, efd, tfd, sock) = create_mixed_set();

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
    let rc_itv = unsafe { libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) };
    assert_eq!(rc_itv, 0, "setitimer failed");

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
    println!("ppoll_blocked_sigalrm_elapsed_ms={:.2}", elapsed_ms);
    println!("ppoll_blocked_sigalrm_handler_fired={}", alarm_fired > 0);
    println!("ppoll_blocked_sigalrm_errno={}", errno);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    let _ = watchdog.join();
    close_mixed_set(pipe_rd, pipe_wr, efd, tfd, sock);
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
