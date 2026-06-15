//! HVF interval-timer (`setitimer`) glue. The neutral per-`which` slot state,
//! the CPU-due math, the ident/signum mapping, and the fallback-thread timing
//! loop now live in [`carrick_timer_core::itimer`]; this module re-exports them
//! and keeps only the HVF-specific wall-clock fallback thread spawn (the kqueue
//! EVFILT_TIMER arming lives in the `setitimer` dispatch + signal pump).

pub use carrick_timer_core::itimer::*;

use std::time::Duration;

/// Fallback delivery for runtimes that do not have a signal-pump kqueue. The
/// threaded runtime uses EVFILT_TIMER so a busy-waiting vCPU can be kicked; this
/// fallback is for single-threaded fork/exec children parked in host waits, where
/// publishing to the pending pipe is sufficient to interrupt the wait.
///
/// Spawns the thread; the timing loop body is shared
/// (`carrick_timer_core::itimer::run_fallback`). The per-fire action (probe +
/// publish the process signal) is HVF-specific.
pub fn spawn_fallback_timer(which: usize, generation: u64, value: Duration, interval: Duration) {
    let value_ns = u64::try_from(value.as_nanos()).unwrap_or(u64::MAX);
    let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
    let _ = std::thread::Builder::new()
        .name("carrick-itimer-fallback".to_owned())
        .spawn(move || {
            run_fallback(which, generation, value_ns, interval_ns, || {
                let signum = signum_for(which);
                crate::probes::itimer_fire(signum, 1);
                crate::host_signal::publish_process_signal(signum);
            });
        });
}
