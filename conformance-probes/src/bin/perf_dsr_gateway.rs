//! Low-perturbation DSR gateway benchmark.
//!
//! Both lanes time batches of raw `getpid` crossings. The scalar lane executes
//! no guest SIMD instructions. The SIMD lane seeds and verifies all 32 AArch64
//! vector registers around every crossing, so a faster gateway cannot silently
//! drop guest-visible state. The SIMD metric deliberately includes that fixed
//! seed/verify cost; reported values are per crossing and lower is better.

use std::sync::atomic::{compiler_fence, Ordering};

const ITERS: usize = 20_000;
const WARMUP: usize = 2_000;
const BATCH: usize = 16;

#[derive(Clone, Copy)]
struct TimingSummary {
    p50_us: f64,
    p95_us: f64,
    min_us: f64,
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
        let index = (((samples.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1);
        ticks_to_us(samples[index])
    };
    TimingSummary {
        p50_us: percentile(0.50),
        p95_us: percentile(0.95),
        min_us: ticks_to_us(samples[0]),
    }
}

fn elapsed_batch(mut operation: impl FnMut()) -> u64 {
    compiler_fence(Ordering::SeqCst);
    let started = read_counter();
    for _ in 0..BATCH {
        operation();
    }
    let elapsed = read_counter().wrapping_sub(started);
    compiler_fence(Ordering::SeqCst);
    elapsed
}

fn measure(mut operation: impl FnMut()) -> TimingSummary {
    for _ in 0..WARMUP {
        operation();
    }
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        samples.push(elapsed_batch(&mut operation));
    }
    let batch_frequency = counter_frequency()
        .checked_mul(BATCH as u64)
        .expect("batch frequency must fit u64");
    summarize(samples, batch_frequency)
}

fn print_summary(prefix: &str, summary: TimingSummary) {
    println!("{prefix}_p50_us={:.3}", summary.p50_us);
    println!("{prefix}_p95_us={:.3}", summary.p95_us);
    println!("{prefix}_min_us={:.3}", summary.min_us);
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .text
    .p2align 2

    .global dsr_gateway_scalar_round_trip
    .type dsr_gateway_scalar_round_trip,%function
dsr_gateway_scalar_round_trip:
    mov x8, #172
    svc #0
    ret
    .size dsr_gateway_scalar_round_trip, .-dsr_gateway_scalar_round_trip

    .global dsr_gateway_simd_round_trip
    .type dsr_gateway_simd_round_trip,%function
dsr_gateway_simd_round_trip:
    b dsr_gateway_simd_common
    .size dsr_gateway_simd_round_trip, .-dsr_gateway_simd_round_trip

dsr_gateway_simd_common:
    sub sp, sp, #128
    stp q8, q9, [sp, #0]
    stp q10, q11, [sp, #32]
    stp q12, q13, [sp, #64]
    stp q14, q15, [sp, #96]

    mov x9, #0x5a5a
    .macro seed_vector register
    dup v\register\().2d, x9
    .endm
    seed_vector 0
    seed_vector 1
    seed_vector 2
    seed_vector 3
    seed_vector 4
    seed_vector 5
    seed_vector 6
    seed_vector 7
    seed_vector 8
    seed_vector 9
    seed_vector 10
    seed_vector 11
    seed_vector 12
    seed_vector 13
    seed_vector 14
    seed_vector 15
    seed_vector 16
    seed_vector 17
    seed_vector 18
    seed_vector 19
    seed_vector 20
    seed_vector 21
    seed_vector 22
    seed_vector 23
    seed_vector 24
    seed_vector 25
    seed_vector 26
    seed_vector 27
    seed_vector 28
    seed_vector 29
    seed_vector 30
    seed_vector 31

    mov x8, #172
    svc #0
    mov x9, #0x5a5a
    .macro verify_vector register
    umov x10, v\register\().d[0]
    cmp x10, x9
    b.ne 9f
    umov x10, v\register\().d[1]
    cmp x10, x9
    b.ne 9f
    .endm
    verify_vector 0
    verify_vector 1
    verify_vector 2
    verify_vector 3
    verify_vector 4
    verify_vector 5
    verify_vector 6
    verify_vector 7
    verify_vector 8
    verify_vector 9
    verify_vector 10
    verify_vector 11
    verify_vector 12
    verify_vector 13
    verify_vector 14
    verify_vector 15
    verify_vector 16
    verify_vector 17
    verify_vector 18
    verify_vector 19
    verify_vector 20
    verify_vector 21
    verify_vector 22
    verify_vector 23
    verify_vector 24
    verify_vector 25
    verify_vector 26
    verify_vector 27
    verify_vector 28
    verify_vector 29
    verify_vector 30
    verify_vector 31
    mov x0, #0
    b 10f
9:
    mov x0, #1
10:
    ldp q8, q9, [sp, #0]
    ldp q10, q11, [sp, #32]
    ldp q12, q13, [sp, #64]
    ldp q14, q15, [sp, #96]
    add sp, sp, #128
    ret
"#
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn dsr_gateway_scalar_round_trip() -> u64;
    fn dsr_gateway_simd_round_trip() -> u64;
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn dsr_gateway_scalar_round_trip() -> u64 {
    libc::syscall(libc::SYS_getpid) as u64
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn dsr_gateway_simd_round_trip() -> u64 {
    let _ = libc::syscall(libc::SYS_getpid);
    0
}

fn main() {
    let scalar = measure(|| {
        std::hint::black_box(unsafe { dsr_gateway_scalar_round_trip() });
    });
    let simd = measure(|| {
        let result = unsafe { dsr_gateway_simd_round_trip() };
        assert_eq!(result, 0, "SIMD sentinel changed across syscall gateway");
    });

    print_summary("gateway_scalar", scalar);
    print_summary("gateway_simd", simd);
    println!("iters={ITERS}");
    println!("batch={BATCH}");
    println!(
        "nproc={}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_per_crossing_frequency() {
        let summary = summarize(vec![160_u64; 10], 16_000_000);
        assert_eq!(summary.p50_us, 10.0);
        assert_eq!(summary.p95_us, 10.0);
        assert_eq!(summary.min_us, 10.0);
    }
}
