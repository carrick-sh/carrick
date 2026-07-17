//! Shim: the DSR gateway (context, indirect-target cache, and the typed
//! surface over `gateway_aarch64.S`) moved verbatim to
//! `carrick_dsr_aarch64::gateway` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::gateway::*` call paths resolve unchanged.
//!
//! The gateway component MICROBENCHMARKS stay here: they measure the C trap
//! shim's ABI helpers (`carrick_native_dsr_enter_guest_abi` /
//! `..._enter_host_abi` / the `..._benchmark_*` pairs), which are compiled
//! from the runtime's csrc/native_darwin.c and are not linkable from the
//! arch crate before the host-seam slice (M0.6).

// `allow(unused_imports)`: the runtime LIB no longer names `dsr::gateway::*`
// since the translator orchestration moved to the arch crate; the re-export
// stays for the oracle and the gateway microbenchmarks below.
#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr_aarch64::gateway::*;

#[cfg(test)]
use super::super::NativeUcontextSnapshot;
#[cfg(test)]
use super::types::{CacheVa, CodeGeneration, NativeDsrExit};

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct GatewayComponentSummary {
    p50_us: f64,
    p95_us: f64,
    min_us: f64,
}

#[cfg(test)]
fn summarize_component_ticks(
    mut samples: Vec<u64>,
    counter_frequency: u64,
    batch: usize,
) -> GatewayComponentSummary {
    assert!(counter_frequency > 0, "counter frequency must be nonzero");
    assert!(batch > 0, "batch size must be nonzero");
    assert!(!samples.is_empty(), "component samples must be nonempty");
    samples.sort_unstable();
    let denominator = counter_frequency as f64 * batch as f64;
    let ticks_to_us = |ticks: u64| ticks as f64 * 1_000_000.0 / denominator;
    let percentile = |fraction: f64| {
        let index = (((samples.len() as f64) * fraction).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1);
        ticks_to_us(samples[index])
    };
    GatewayComponentSummary {
        p50_us: percentile(0.50),
        p95_us: percentile(0.95),
        min_us: ticks_to_us(samples[0]),
    }
}

#[cfg(test)]
fn format_component_summary(name: &str, summary: GatewayComponentSummary) -> String {
    format!(
        "{name}_p50_us={:.3}\n{name}_p95_us={:.3}\n{name}_min_us={:.3}",
        summary.p50_us, summary.p95_us, summary.min_us
    )
}

#[cfg(all(test, target_arch = "aarch64"))]
#[inline(always)]
fn component_read_counter() -> u64 {
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

#[cfg(all(test, target_arch = "aarch64"))]
fn component_counter_frequency() -> u64 {
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

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_component(mut operation: impl FnMut()) -> GatewayComponentSummary {
    const ITERS: usize = 20_000;
    const WARMUP: usize = 2_000;
    const BATCH: usize = 16;

    for _ in 0..WARMUP {
        operation();
    }
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let started = component_read_counter();
        for _ in 0..BATCH {
            operation();
        }
        let elapsed = component_read_counter().wrapping_sub(started);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        samples.push(elapsed);
    }
    summarize_component_ticks(samples, component_counter_frequency(), BATCH)
}

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_gateway_components() -> (GatewayComponentSummary, GatewayComponentSummary) {
    let result = std::thread::spawn(|| {
        let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut kick);
            libc::sigaddset(&mut kick, libc::SIGPIPE);
        }
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
            0
        );

        let mut snapshot = NativeUcontextSnapshot::default();
        for (index, register) in snapshot.x.iter_mut().enumerate() {
            *register = 0x1100_0000_0000_0000 | index as u64;
        }
        for (index, vector) in snapshot.v.iter_mut().enumerate() {
            *vector =
                (0x2200_0000_0000_0000_0000_0000_0000_0000_u128 | index as u128).to_le_bytes();
        }
        let entry = CacheVa::published(carrick_guest_mem::HostVa(1));
        let exit = NativeDsrExit::Syscall {
            resume: carrick_guest_mem::GuestVa(4),
        };

        let measure_closure = || {
            measure_component(|| {
                let guest = unsafe {
                    super::super::carrick_native_dsr_enter_guest_abi(std::ptr::null_mut())
                };
                std::hint::black_box(guest);
                unsafe { super::super::carrick_native_dsr_enter_host_abi() };
            })
        };
        let measure_wrapper = || {
            measure_component(|| {
                let context = DsrContext::new(
                    std::hint::black_box(snapshot),
                    entry,
                    exit,
                    std::ptr::null(),
                    CodeGeneration::INITIAL,
                    0,
                    usize::MAX,
                    carrick_dsr::address::NativeAddressMode::Direct,
                );
                let published = std::hint::black_box(context).snapshot;
                std::hint::black_box(published);
            })
        };

        let (closure, wrapper) = if unsafe { libc::getpid() } & 1 == 0 {
            (measure_closure(), measure_wrapper())
        } else {
            let wrapper = measure_wrapper();
            (measure_closure(), wrapper)
        };

        let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
            0
        );
        assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 1);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
            0
        );
        (closure, wrapper)
    })
    .join();
    match result {
        Ok(summaries) => summaries,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_closure_subcomponents() -> (
    GatewayComponentSummary,
    GatewayComponentSummary,
    GatewayComponentSummary,
) {
    let result = std::thread::spawn(|| {
        let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut kick);
            libc::sigaddset(&mut kick, libc::SIGPIPE);
        }
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
            0
        );

        assert_eq!(
            unsafe { super::super::carrick_native_dsr_benchmark_custom_x18_pair() },
            0
        );
        let measure_signal_mask = || {
            measure_component(|| {
                let result =
                    unsafe { super::super::carrick_native_dsr_benchmark_signal_mask_pair() };
                std::hint::black_box(result);
            })
        };
        let measure_custom_x18 = || {
            measure_component(|| {
                let result =
                    unsafe { super::super::carrick_native_dsr_benchmark_custom_x18_pair() };
                std::hint::black_box(result);
            })
        };
        let measure_signal_mask_prebuilt = || {
            measure_component(|| {
                let unblock = unsafe {
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &kick, std::ptr::null_mut())
                };
                let block =
                    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, std::ptr::null_mut()) };
                std::hint::black_box((unblock, block));
            })
        };
        let (signal_mask, signal_mask_prebuilt, custom_x18) = if unsafe { libc::getpid() } & 1 == 0
        {
            (
                measure_signal_mask(),
                measure_signal_mask_prebuilt(),
                measure_custom_x18(),
            )
        } else {
            let custom_x18 = measure_custom_x18();
            (
                measure_signal_mask(),
                measure_signal_mask_prebuilt(),
                custom_x18,
            )
        };

        let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
            0
        );
        assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 1);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
            0
        );
        (signal_mask, signal_mask_prebuilt, custom_x18)
    })
    .join();
    match result {
        Ok(summaries) => summaries,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(test, not(target_arch = "aarch64")))]
fn measure_closure_subcomponents() -> (
    GatewayComponentSummary,
    GatewayComponentSummary,
    GatewayComponentSummary,
) {
    panic!("native DSR closure component benchmark requires AArch64")
}

#[cfg(all(test, not(target_arch = "aarch64")))]
fn measure_gateway_components() -> (GatewayComponentSummary, GatewayComponentSummary) {
    panic!("native DSR gateway component benchmark requires AArch64")
}

#[cfg(test)]
mod component_benchmark_tests {
    use super::*;

    #[test]
    fn component_summary_reports_per_operation_latency() {
        let summary = summarize_component_ticks(vec![160_u64; 10], 1_000_000, 16);
        assert_eq!(summary.p50_us, 10.0);
        assert_eq!(summary.p95_us, 10.0);
        assert_eq!(summary.min_us, 10.0);
    }

    #[test]
    fn component_output_has_stable_machine_keys() {
        let summary = GatewayComponentSummary {
            p50_us: 0.101,
            p95_us: 0.202,
            min_us: 0.050,
        };
        let output = format_component_summary("closure", summary);
        assert_eq!(
            output,
            "closure_p50_us=0.101\nclosure_p95_us=0.202\nclosure_min_us=0.050"
        );
    }

    #[test]
    #[ignore = "explicit opt-in native DSR component microbenchmark"]
    fn dsr_gateway_component_benchmark() {
        let (closure, wrapper) = measure_gateway_components();
        for summary in [closure, wrapper] {
            assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
            assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
            assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
        }
        println!("{}", format_component_summary("closure", closure));
        println!("{}", format_component_summary("wrapper", wrapper));
        println!("component_iters=20000");
        println!("component_batch=16");
    }

    #[test]
    #[ignore = "explicit opt-in native DSR closure decomposition"]
    fn dsr_gateway_closure_component_benchmark() {
        let (signal_mask, signal_mask_prebuilt, custom_x18) = measure_closure_subcomponents();
        for summary in [signal_mask, signal_mask_prebuilt, custom_x18] {
            assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
            assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
            assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
        }
        println!(
            "{}",
            format_component_summary("closure_signal_mask", signal_mask)
        );
        println!(
            "{}",
            format_component_summary("closure_signal_mask_prebuilt", signal_mask_prebuilt)
        );
        println!(
            "{}",
            format_component_summary("closure_custom_x18", custom_x18)
        );
        println!("component_iters=20000");
        println!("component_batch=16");
    }
}
