//! Perf probe: many small preadv(2) calls from one host-backed file.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   preadv_burst_p50_us=<f> preadv_burst_total_us=<f>
//!   segments=<u> bytes=<u> nproc=<u>
use std::ffi::CString;
use std::thread;
use std::time::Instant;

const WARMUP: usize = 512;
const ITERS: usize = 4096;
const SEGMENTS: usize = 8;
const SEGMENT: &[u8] = b"x\n";

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn preadv_once(fd: i32, iovecs: &[libc::iovec; SEGMENTS]) -> bool {
    let n = unsafe { libc::preadv(fd, iovecs.as_ptr(), iovecs.len() as libc::c_int, 0) };
    n == (SEGMENTS * SEGMENT.len()) as isize
}

fn main() {
    let dir = std::env::var("BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let path = CString::new(format!("{dir}/carrick_preadv_burst_{}.dat", std::process::id()))
        .expect("path cstring");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        std::process::exit(1);
    }
    for _ in 0..SEGMENTS {
        let n = unsafe { libc::write(fd, SEGMENT.as_ptr().cast(), SEGMENT.len()) };
        if n != SEGMENT.len() as isize {
            std::process::exit(1);
        }
    }

    let mut segments = [[0u8; SEGMENT.len()]; SEGMENTS];
    let iovecs = std::array::from_fn(|idx| libc::iovec {
        iov_base: segments[idx].as_mut_ptr() as *mut libc::c_void,
        iov_len: segments[idx].len(),
    });

    for _ in 0..WARMUP {
        if !preadv_once(fd, &iovecs) {
            std::process::exit(1);
        }
    }

    let total_start = Instant::now();
    let mut samples_ns = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        if !preadv_once(fd, &iovecs) {
            std::process::exit(1);
        }
        samples_ns.push(t0.elapsed().as_nanos());
    }
    let total_us = total_start.elapsed().as_secs_f64() * 1_000_000.0;

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };

    unsafe {
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }

    eprintln!("preadv_burst_p50_us={:.3}", pct(0.50));
    eprintln!("preadv_burst_total_us={:.3}", total_us);
    eprintln!("segments={}", SEGMENTS);
    eprintln!("bytes={}", SEGMENTS * SEGMENT.len());
    eprintln!("nproc={}", nproc());
}
