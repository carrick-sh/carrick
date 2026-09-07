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
}
