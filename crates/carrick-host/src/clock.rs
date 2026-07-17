//! The host uptime clock backing guest virtual-counter synthesis.
//!
//! The native (DSR) backend and the HVF trap layer synthesise the guest's
//! monotonic counter (`CNTVCT_EL0` on AArch64) from a host clock that ticks
//! with UPTIME, not wall time, and — matching what Darwin exposes to native
//! processes — excludes time the host spends suspended. Raw hardware counters
//! are NOT that clock (Apple Silicon `CNTVCT_EL0` keeps counting through
//! suspend; the measured divergence on a slept host was ~31,237 s), which is
//! why capability/scale planning must come through here rather than sampling
//! the counter directly.
//!
//! Per-OS clock id, one cfg arm each, all with `clock_gettime` semantics:
//!  - macOS: `CLOCK_UPTIME_RAW` — mach_absolute_time's clock; stops in sleep.
//!  - FreeBSD: `CLOCK_UPTIME` — monotonic since boot.
//!  - NetBSD: `CLOCK_MONOTONIC` (no `CLOCK_UPTIME`; equivalent there).
//!  - Linux: `CLOCK_BOOTTIME` deliberately NOT used — a Linux guest's
//!    `CLOCK_MONOTONIC` excludes suspend, so that is the arm we expose.

#[cfg(target_os = "macos")]
const HOST_UPTIME_CLOCK: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
#[cfg(target_os = "freebsd")]
const HOST_UPTIME_CLOCK: libc::clockid_t = libc::CLOCK_UPTIME;
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
const HOST_UPTIME_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// Nanoseconds of host uptime (suspend excluded where the host distinguishes
/// it). `0` only if the host clock read fails, which the callers treat as
/// "capability unavailable", never as a real timestamp.
pub fn host_clock_uptime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid timespec we own.
    let rc = unsafe { libc::clock_gettime(HOST_UPTIME_CLOCK, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).wrapping_mul(1_000_000_000) + ts.tv_nsec as u64
}

/// Raw host monotonic tick counter for interval timing (the DSR profiler's
/// phase clock). Darwin: `mach_absolute_time` (ticks; scale via
/// [`tick_scale`]). Elsewhere: [`host_clock_uptime_ns`] (already nanoseconds;
/// [`tick_scale`] is 1/1).
#[inline]
pub fn monotonic_ticks() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `mach_absolute_time` has no arguments and returns the
        // monotonic host uptime counter.
        #[allow(deprecated)]
        unsafe {
            libc::mach_absolute_time()
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        host_clock_uptime_ns()
    }
}

/// ticks→ns scale for [`monotonic_ticks`]: `ns = ticks * numer / denom`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickScale {
    pub numer: u32,
    pub denom: u32,
}

/// `None` when the host cannot report a usable timebase (fail-closed: callers
/// invalidate their measurement rather than guessing a scale).
pub fn tick_scale() -> Option<TickScale> {
    #[cfg(target_os = "macos")]
    {
        #[allow(deprecated)]
        {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: the call initializes the fixed-size out parameter.
            if unsafe { libc::mach_timebase_info(&mut info) } != libc::KERN_SUCCESS
                || info.denom == 0
            {
                return None;
            }
            Some(TickScale {
                numer: info.numer,
                denom: info.denom,
            })
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // monotonic_ticks already returns nanoseconds off-Darwin.
        Some(TickScale { numer: 1, denom: 1 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_clock_reads_and_advances_monotonically() {
        let a = host_clock_uptime_ns();
        let b = host_clock_uptime_ns();
        assert_ne!(a, 0, "host uptime clock must be readable");
        assert!(b >= a, "uptime must not run backwards: {a} then {b}");
    }

    #[test]
    fn tick_scale_is_available_and_ticks_advance() {
        let scale = tick_scale().expect("host timebase");
        assert_ne!(scale.denom, 0);
        let a = monotonic_ticks();
        let b = monotonic_ticks();
        assert!(b >= a, "ticks must not run backwards: {a} then {b}");
    }
}
