//! Direct-compute control for transport comparisons. The timed loop performs
//! no syscalls, so changing syscall transport should not materially affect it.
use std::thread;

const ITERS: u64 = 8_000_000;

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

fn main() {
    let start = read_counter();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for value in 0..ITERS {
        state ^= value.wrapping_add(state.rotate_left(17));
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        std::hint::black_box(state);
    }
    let ticks = read_counter().wrapping_sub(start);
    let elapsed_us = ticks as f64 * 1_000_000.0 / counter_frequency() as f64;
    println!("direct_compute_total_us={elapsed_us:.3}");
    println!("checksum={state}");
    println!("iters={ITERS}");
    println!(
        "nproc={}",
        thread::available_parallelism().map_or(0, |value| value.get())
    );
}
