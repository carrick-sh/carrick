//! Perf probe: stable-fd blocking pipe wait handoff. The main thread writes a
//! one-byte token to a control pipe, then blocks reading a data pipe. The worker
//! thread consumes the token and writes one byte back. The timed sample is one
//! blocking read wakeup round trip on the same data fd, exposing carrick's
//! per-wait fd pinning, kqueue registration, and wake bookkeeping.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   wait_pipe_pingpong_p50_us=<f> wait_pipe_pingpong_p95_us=<f>
//!   wait_pipe_pingpong_min_us=<f> iters=<u> warmup=<u> nproc=<u>
use std::thread;
use std::time::Instant;

const WARMUP: usize = 500;
const ITERS: usize = 3000;
const WORKER_SPIN: usize = 128;

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

fn round_trip(control_write: libc::c_int, data_read: libc::c_int) {
    write_one(control_write, b'g');
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
        round_trip(control[1], data[0]);
    }

    let mut samples_ns = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        round_trip(control[1], data[0]);
        samples_ns.push(t0.elapsed().as_nanos());
    }

    worker.join().expect("worker exits");
    close_fd(control[0]);
    close_fd(control[1]);
    close_fd(data[0]);
    close_fd(data[1]);

    samples_ns.sort_unstable();
    println!("wait_pipe_pingpong_p50_us={:.3}", percentile(&samples_ns, 0.50));
    println!("wait_pipe_pingpong_p95_us={:.3}", percentile(&samples_ns, 0.95));
    println!(
        "wait_pipe_pingpong_min_us={:.3}",
        samples_ns[0] as f64 / 1000.0
    );
    println!("iters={}", samples_ns.len());
    println!("warmup={}", WARMUP);
    println!("nproc={}", nproc());
}
