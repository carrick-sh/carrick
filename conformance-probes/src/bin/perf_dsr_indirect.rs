//! DSR monomorphic indirect-hit microbenchmark.
//!
//! A single inline `blr` site calls one fixed target and returns to one fixed
//! resume PC. After warmup, both call and return should remain in DSR's emitted
//! indirect target cache. The probe batches calls between architectural counter
//! reads so the reported nanoseconds per call can detect hit-path instruction
//! regressions without DTrace perturbation. LOWER is better.

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    const CALLS_PER_BATCH: usize = 20_000;
    const WARMUP_BATCHES: usize = 20;
    const SAMPLED_BATCHES: usize = 200;

    #[inline(never)]
    extern "C" fn target(value: u64) -> u64 {
        std::hint::black_box(value.rotate_left(7).wrapping_add(0x9e37_79b9))
    }

    #[inline(always)]
    unsafe fn call_indirect(callee: usize, value: u64) -> u64 {
        let mut result = value;
        unsafe {
            core::arch::asm!(
                "blr x9",
                inout("x9") callee => _,
                inout("x0") result,
                clobber_abi("C"),
            );
        }
        result
    }

    #[inline(never)]
    fn run_batch(callee: usize, mut value: u64) -> u64 {
        for _ in 0..CALLS_PER_BATCH {
            value = unsafe { call_indirect(callee, value) };
        }
        value
    }

    fn read_counter() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntvct_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    fn counter_frequency() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntfrq_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    fn nearest_rank(sorted: &[f64], percentile: f64) -> f64 {
        let index = (((sorted.len() as f64) * percentile).ceil() as usize)
            .saturating_sub(1)
            .min(sorted.len() - 1);
        sorted[index]
    }

    pub(super) fn main() {
        let callee = target as *const () as usize;
        let mut value = 1_u64;
        for _ in 0..WARMUP_BATCHES {
            value = run_batch(callee, value);
        }

        let frequency = counter_frequency();
        assert!(frequency > 0, "counter frequency must be nonzero");
        let mut samples = Vec::with_capacity(SAMPLED_BATCHES);
        for _ in 0..SAMPLED_BATCHES {
            let start = read_counter();
            value = run_batch(callee, value);
            let ticks = read_counter().wrapping_sub(start);
            samples
                .push(ticks as f64 * 1_000_000_000.0 / frequency as f64 / CALLS_PER_BATCH as f64);
        }
        std::hint::black_box(value);
        samples.sort_by(f64::total_cmp);
        let trim = samples.len() / 20;
        let trimmed = &samples[trim..samples.len() - trim];
        let trimmed_mean = trimmed.iter().sum::<f64>() / trimmed.len() as f64;

        println!("indirect_p50_ns={:.6}", nearest_rank(&samples, 0.50));
        println!("indirect_p95_ns={:.6}", nearest_rank(&samples, 0.95));
        println!("indirect_min_ns={:.6}", samples[0]);
        println!("indirect_trimmed_mean_ns={trimmed_mean:.6}");
        println!("calls_per_batch={CALLS_PER_BATCH}");
        println!("sampled_batches={SAMPLED_BATCHES}");
    }
}

#[cfg(target_arch = "aarch64")]
fn main() {
    aarch64::main();
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("unsupported_arch=true");
}
