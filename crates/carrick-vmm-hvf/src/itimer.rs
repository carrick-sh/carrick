//! HVF interval-timer (`setitimer`) glue. The neutral per-`which` slot state,
//! the CPU-due math, the ident/signum mapping, and the fallback-thread timing
//! loop now live in [`carrick_timer_core::itimer`]; this module re-exports them
//! and keeps only the HVF-specific wall-clock fallback thread spawn (the kqueue
//! EVFILT_TIMER arming lives in the `setitimer` dispatch + signal pump).

pub use carrick_timer_core::itimer::*;
pub use carrick_hal::timer_delivery::{run_fallback, run_fallback_cpu};

use carrick_timer_core::TimerSpecNs;

/// Linux signal number delivered when `which`'s timer expires.
#[inline]
pub fn signum_for(which: usize) -> i32 {
    match which {
        1 => carrick_abi::LINUX_SIGVTALRM,
        2 => carrick_abi::LINUX_SIGPROF,
        _ => carrick_abi::LINUX_SIGALRM,
    }
}

/// Arm interval timer `which` using host guest CPU time for CPU timers.
pub fn arm(which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
    let cpu_now = if is_cpu_timer(which) {
        carrick_host::guest_cpu::total_ns_including_active()
    } else {
        0
    };
    carrick_timer_core::itimer::arm_with_cpu_now(which, spec, needs_periodic, cpu_now)
}

/// Decide CPU timer expiry using host CPU time and active vCPU count.
pub fn cpu_timer_decision(which: usize) -> Option<CpuTimerDecision> {
    let now = carrick_host::guest_cpu::total_ns_including_active();
    let active = carrick_host::guest_cpu::active_count() as u64;
    carrick_timer_core::itimer::cpu_timer_decision(which, now, active)
}

/// Host CPU sampler for HVF backed by carrick-host guest_cpu counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct HvfCpuSampler;

impl carrick_timer_core::CpuSampler for HvfCpuSampler {
    fn total_cpu_ns(&self) -> u64 {
        carrick_host::guest_cpu::total_ns_including_active()
    }

    fn active_vcpus(&self) -> u64 {
        carrick_host::guest_cpu::active_count() as u64
    }
}

/// Fallback delivery for runtimes that do not have a signal-pump kqueue. The
/// threaded runtime uses EVFILT_TIMER so a busy-waiting vCPU can be kicked; this
/// fallback is for single-threaded fork/exec children parked in host waits, where
/// publishing to the pending pipe is sufficient to interrupt the wait.
///
/// Spawns the thread; the timing loop body is shared
/// (`carrick_hal::timer_delivery::run_fallback`). The per-fire action (probe +
/// publish the process signal) is HVF-specific.
pub fn spawn_fallback_timer(which: usize, generation: u64, spec: TimerSpecNs) {
    let _ = std::thread::Builder::new()
        .name("carrick-itimer-fallback".to_owned())
        .spawn(move || {
            carrick_hal::timer_delivery::run_fallback_with_sampler(
                which,
                generation,
                spec,
                Some(&HvfCpuSampler),
                || {
                    let signum = signum_for(which);
                    crate::probes::itimer_fire(signum, 1);
                    crate::host_signal::publish_process_signal(signum);
                },
            );
        });
}
