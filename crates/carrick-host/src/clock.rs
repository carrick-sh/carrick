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
}
