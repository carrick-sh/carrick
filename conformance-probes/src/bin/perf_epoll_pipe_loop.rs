//! Perf probe: stable-descriptor epoll event-loop wakeups.
//!
//! One data pipe read end is registered in one epoll instance for the whole run.
//! Each iteration asks a worker to write one byte, blocks in epoll_wait, then
//! drains the byte. This keeps descriptor identity stable and measures the
//! event-loop path separately from epoll_ctl add/mod/delete churn.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   epoll_pipe_loop_p50_us=<f> epoll_pipe_loop_p95_us=<f>
//!   epoll_pipe_loop_min_us=<f> iters=<u> warmup=<u> nproc=<u>
use std::thread;
use std::time::Instant;

const WARMUP: usize = 300;
const ITERS: usize = 2000;
const WORKER_SPIN: usize = 128;
const EPOLLIN: u32 = 0x001;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn pipe_pair() -> [libc::c_int; 2] {
    let mut fds = [-1; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        eprintln!("pipe failed errno={}", last_errno());
        std::process::exit(1);
    }
    fds
}

fn read_one(fd: libc::c_int) -> u8 {
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
        if n == 1 {
            return byte[0];
        }
        if n < 0 && last_errno() == libc::EINTR {
            continue;
        }
        eprintln!("read({fd}) failed n={n} errno={}", last_errno());
        std::process::exit(1);
    }
}

fn write_one(fd: libc::c_int, byte: u8) {
    let buf = [byte; 1];
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n == 1 {
            return;
        }
        if n < 0 && last_errno() == libc::EINTR {
            continue;
        }
        eprintln!("write({fd}) failed n={n} errno={}", last_errno());
        std::process::exit(1);
    }
}

fn close_fd(fd: libc::c_int) {
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        eprintln!("close({fd}) failed errno={}", last_errno());
        std::process::exit(1);
    }
}

fn epoll_add(epfd: libc::c_int, fd: libc::c_int) {
    let mut ev = libc::epoll_event {
        events: EPOLLIN,
        u64: fd as u64,
    };
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if rc != 0 {
        eprintln!("epoll_ctl add failed errno={}", last_errno());
        std::process::exit(1);
    }
}

fn epoll_wait_one(epfd: libc::c_int, data_read: libc::c_int) {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, 5000) };
        if n > 0 {
            for event in events.iter().take(n as usize) {
                if event.u64 == data_read as u64 && event.events & EPOLLIN != 0 {
                    return;
                }
            }
            eprintln!("epoll_wait returned only unexpected events n={n}");
            std::process::exit(1);
        }
        if n < 0 && last_errno() == libc::EINTR {
            continue;
        }
        eprintln!("epoll_wait failed_or_timed_out n={n} errno={}", last_errno());
        std::process::exit(1);
    }
}

fn round_trip(control_write: libc::c_int, epfd: libc::c_int, data_read: libc::c_int) {
    write_one(control_write, b'g');
    epoll_wait_one(epfd, data_read);
    let byte = read_one(data_read);
    if byte != b'd' {
        eprintln!("unexpected data byte {byte}");
        std::process::exit(1);
    }
}

fn percentile(sorted_ns: &[u128], p: f64) -> f64 {
    let idx = (((sorted_ns.len() as f64) * p).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_ns.len() - 1);
    sorted_ns[idx] as f64 / 1000.0
}

fn main() {
    let control = pipe_pair();
    let data = pipe_pair();
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        eprintln!("epoll_create1 failed errno={}", last_errno());
        std::process::exit(1);
    }
    epoll_add(epfd, data[0]);

    let total = WARMUP + ITERS;
    let worker_control_read = control[0];
    let worker_data_write = data[1];
    let worker = thread::spawn(move || {
        for _ in 0..total {
            let byte = read_one(worker_control_read);
            if byte != b'g' {
                eprintln!("unexpected control byte {byte}");
                std::process::exit(1);
            }
            for _ in 0..WORKER_SPIN {
                std::hint::spin_loop();
            }
            write_one(worker_data_write, b'd');
        }
    });

    for _ in 0..WARMUP {
        round_trip(control[1], epfd, data[0]);
    }

    let mut samples_ns = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        round_trip(control[1], epfd, data[0]);
        samples_ns.push(t0.elapsed().as_nanos());
    }

    worker.join().expect("worker exits");
    close_fd(epfd);
    close_fd(control[0]);
    close_fd(control[1]);
    close_fd(data[0]);
    close_fd(data[1]);

    samples_ns.sort_unstable();
    println!("epoll_pipe_loop_p50_us={:.3}", percentile(&samples_ns, 0.50));
    println!("epoll_pipe_loop_p95_us={:.3}", percentile(&samples_ns, 0.95));
    println!(
        "epoll_pipe_loop_min_us={:.3}",
        samples_ns[0] as f64 / 1000.0
    );
    println!("iters={}", samples_ns.len());
    println!("warmup={WARMUP}");
    println!("nproc={}", nproc());
}
