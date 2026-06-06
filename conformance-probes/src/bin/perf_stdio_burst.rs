//! Perf probe: many small writes to fd 1. This is a dynamic-output workload for
//! deciding whether an eventual LD_PRELOAD batching layer is worth building.
//! Metrics are printed to fd 2 so fd 1 remains the measured output path.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   stdio_burst_p50_us=<f> stdio_burst_total_us=<f> writes=<u> nproc=<u>
use std::thread;
use std::time::Instant;

const WARMUP: usize = 512;
const WRITES: usize = 4096;
const LINE: &[u8] = b"x\n";

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn write_line() -> bool {
    let n = unsafe { libc::write(1, LINE.as_ptr().cast(), LINE.len()) };
    n == LINE.len() as isize
}

fn main() {
    for _ in 0..WARMUP {
        if !write_line() {
            std::process::exit(1);
        }
    }

    let total_start = Instant::now();
    let mut samples_ns = Vec::with_capacity(WRITES);
    for _ in 0..WRITES {
        let t0 = Instant::now();
        if !write_line() {
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

    eprintln!("stdio_burst_p50_us={:.3}", pct(0.50));
    eprintln!("stdio_burst_total_us={:.3}", total_us);
    eprintln!("writes={}", samples_ns.len());
    eprintln!("nproc={}", nproc());
}
