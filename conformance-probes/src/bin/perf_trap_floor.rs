//! Perf probe: the syscall trap+dispatch floor. Times raw `getpid` and `gettid`
//! syscalls in tight loops, plus an equal-loop timing control. Carrick services
//! both calls from cached process/thread state with ~zero host syscalls, so the
//! difference from the control approximates the irreducible guest→host
//! transition and dispatch cost. LOWER is better.
//!
//! Raw `syscall(172)` (not `getpid()`) so glibc/musl's pid cache can't elide
//! the trap. Output (key=value, parsed by the perf gate, NOT diffed):
//!   trap_p50_us=<f>  trap_p95_us=<f>  trap_min_us=<f>
//!   trap_trimmed_mean_us=<f>
//!   gettid_p50_us=<f>  gettid_p95_us=<f>  gettid_min_us=<f>
//!   empty_p50_us=<f>  empty_p95_us=<f>  empty_min_us=<f>
//!   iters=<u>  nproc=<u>
use std::thread;

const ITERS: usize = 20000;
const WARMUP: usize = 2000;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
struct TimingSummary {
    p50_us: f64,
    p95_us: f64,
    min_us: f64,
    trimmed_mean_us: f64,
}

#[cfg(target_arch = "aarch64")]
fn read_counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntvct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(target_arch = "aarch64")]
fn counter_frequency() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(not(target_arch = "aarch64"))]
fn read_counter() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

#[cfg(not(target_arch = "aarch64"))]
fn counter_frequency() -> u64 {
    1_000_000_000
}

fn summarize(mut samples: Vec<u64>, frequency: u64) -> TimingSummary {
    assert!(frequency > 0, "counter frequency must be nonzero");
    samples.sort_unstable();
    let ticks_to_us = |ticks: u64| ticks as f64 * 1_000_000.0 / frequency as f64;
    let percentile = |p: f64| -> f64 {
        let idx = (((samples.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1);
        ticks_to_us(samples[idx])
    };
    let trim = samples.len() / 20;
    let trimmed = &samples[trim..samples.len() - trim];
    let trimmed_mean_ticks = trimmed.iter().map(|ticks| *ticks as f64).sum::<f64>()
        / trimmed.len() as f64;
    TimingSummary {
        p50_us: percentile(0.50),
        p95_us: percentile(0.95),
        min_us: ticks_to_us(samples[0]),
        trimmed_mean_us: trimmed_mean_ticks * 1_000_000.0 / frequency as f64,
    }
}

fn measure(frequency: u64, mut operation: impl FnMut()) -> TimingSummary {
    for _ in 0..WARMUP {
        operation();
    }
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = read_counter();
        operation();
        samples.push(read_counter().wrapping_sub(t0));
    }
    summarize(samples, frequency)
}

fn print_summary(prefix: &str, summary: TimingSummary) {
    println!("{prefix}_p50_us={:.3}", summary.p50_us);
    println!("{prefix}_p95_us={:.3}", summary.p95_us);
    println!("{prefix}_min_us={:.3}", summary.min_us);
    println!(
        "{prefix}_trimmed_mean_us={:.3}",
        summary.trimmed_mean_us
    );
}

fn main() {
    // Raw getpid by syscall number, arch-correct (aarch64 __NR_getpid=172,
    // x86_64=39): `libc::SYS_getpid` resolves per target. carrick answers from
    // cached creds, so this measures the bare guest->host trap round trip.
    let frequency = counter_frequency();
    let getpid = measure(frequency, || {
        std::hint::black_box(unsafe { libc::syscall(libc::SYS_getpid) });
    });
    let gettid = measure(frequency, || {
        std::hint::black_box(unsafe { libc::syscall(libc::SYS_gettid) });
    });
    let empty = measure(frequency, || {
        std::hint::black_box(());
    });

    // Retain the established `trap_*` keys for the existing perf runner.
    print_summary("trap", getpid);
    print_summary("gettid", gettid);
    print_summary("empty", empty);
    println!("iters={ITERS}");
    println!("nproc={}", nproc());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_summary_preserves_established_percentiles() {
        let summary = summarize((1_u64..=10).collect(), 1_000_000);
        assert_eq!(summary.p50_us, 5.0);
        assert_eq!(summary.p95_us, 10.0);
        assert_eq!(summary.min_us, 1.0);
        assert_eq!(summary.trimmed_mean_us, 5.5);
    }
}
