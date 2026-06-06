//! Perf probe: private futex wait/wake handoff latency. A worker thread waits on
//! a single process-private futex word; the main thread flips the word, wakes the
//! worker, then waits for the worker to flip it back. The timed sample is one
//! full handoff/ack round trip through `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   futex_pingpong_p50_us=<f> futex_pingpong_p95_us=<f>
//!   futex_pingpong_min_us=<f> iters=<u> wake_zero_ok=<bool> nproc=<u>
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Instant;

const SYS_FUTEX_AARCH64: libc::c_long = 98;
const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_PRIVATE_FLAG: i32 = 128;
const WARMUP: usize = 1000;
const ITERS: usize = 5000;

unsafe fn futex_wait(addr: *const i32, expected: i32) -> i64 {
    libc::syscall(
        SYS_FUTEX_AARCH64,
        addr,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        expected,
        core::ptr::null::<libc::timespec>(),
    ) as i64
}

unsafe fn futex_wake(addr: *const i32, n: i32) -> i64 {
    libc::syscall(SYS_FUTEX_AARCH64, addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, n) as i64
}

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn atomic_ptr(word: &AtomicI32) -> *const i32 {
    word.as_ptr().cast_const()
}

fn wait_while(word: &AtomicI32, expected: i32) {
    let ptr = atomic_ptr(word);
    while word.load(Ordering::SeqCst) == expected {
        let _ = unsafe { futex_wait(ptr, expected) };
    }
}

fn handoff_once(word: &AtomicI32) {
    let ptr = atomic_ptr(word);
    word.store(1, Ordering::SeqCst);
    let _ = unsafe { futex_wake(ptr, 1) };
    wait_while(word, 1);
}

fn main() {
    let zero = AtomicI32::new(0);
    let wake_zero = unsafe { futex_wake(atomic_ptr(&zero), 1) };
    let wake_zero_ok = wake_zero == 0;
    println!("wake_zero_ok={}", wake_zero_ok);
    if !wake_zero_ok {
        std::process::exit(1);
    }

    let word = Arc::new(AtomicI32::new(0));
    let worker_word = Arc::clone(&word);
    let worker = thread::spawn(move || {
        let ptr = atomic_ptr(&worker_word);
        loop {
            match worker_word.load(Ordering::SeqCst) {
                0 => {
                    let _ = unsafe { futex_wait(ptr, 0) };
                }
                1 => {
                    worker_word.store(0, Ordering::SeqCst);
                    let _ = unsafe { futex_wake(ptr, 1) };
                }
                2 => break,
                _ => thread::yield_now(),
            }
        }
    });

    for _ in 0..WARMUP {
        handoff_once(&word);
    }

    let mut samples_ns = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        handoff_once(&word);
        samples_ns.push(t0.elapsed().as_nanos());
    }

    word.store(2, Ordering::SeqCst);
    let _ = unsafe { futex_wake(atomic_ptr(&word), 1) };
    worker.join().expect("worker exits");

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };

    println!("futex_pingpong_p50_us={:.3}", pct(0.50));
    println!("futex_pingpong_p95_us={:.3}", pct(0.95));
    println!(
        "futex_pingpong_min_us={:.3}",
        samples_ns[0] as f64 / 1000.0
    );
    println!("iters={}", samples_ns.len());
    println!("nproc={}", nproc());
}
