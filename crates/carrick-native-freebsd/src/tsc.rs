//! FreeBSD-only x86 vDSO TSC calibration for the native (DSR) backend.
//!
//! Moved verbatim from `carrick-runtime/src/native_freebsd.rs` as the host-ops
//! seam work (Task 3a of the NetBSD native-lane plan): the FreeBSD-welded
//! `machdep.tsc_freq` / `kern.timecounter.{invariant,smp}_tsc` sysctl reads and
//! their clock_gettime bracketing are FreeBSD-specific, so they live here
//! behind `carrick_dsr::lane::NativeHost::vdso_tsc_calibration` rather than in
//! the shared run loop. The FreeBSD lane's run loop reconstructs its
//! `X86VvarClock` from the `(frequency, realtime_off_ns, monotonic_off_ns)`
//! tuple [`calibrate`] returns.
//!
//! This crate is FreeBSD-only and x86_64 in practice (the fault shim reads the
//! amd64 `mcontext_t` named fields), so `std::arch::x86_64::_rdtsc` here adds no
//! constraint the crate did not already have.

fn freebsd_sysctl_i32(name: &std::ffi::CStr) -> Option<i32> {
    let mut value = 0i32;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: `name` is NUL-terminated; output points to a writable i32 and
    // `len` advertises its exact size.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut i32).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<i32>()).then_some(value)
}

fn tsc_vdso_is_safe(invariant_tsc: i32, smp_tsc: i32) -> bool {
    invariant_tsc != 0 && smp_tsc != 0
}

fn freebsd_tsc_vdso_is_safe() -> bool {
    let invariant = freebsd_sysctl_i32(c"kern.timecounter.invariant_tsc").unwrap_or(0);
    let smp = freebsd_sysctl_i32(c"kern.timecounter.smp_tsc").unwrap_or(0);
    tsc_vdso_is_safe(invariant, smp)
}

fn freebsd_tsc_frequency() -> Option<u64> {
    let mut frequency = 0u64;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: the name is NUL-terminated; output points to a writable u64 and
    // `len` advertises its exact size. FreeBSD exports this on amd64 when TSC
    // is available, independently of the selected host timecounter.
    let rc = unsafe {
        libc::sysctlbyname(
            c"machdep.tsc_freq".as_ptr(),
            (&mut frequency as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<u64>() && frequency != 0).then_some(frequency)
}

/// Host clock in nanoseconds, or `None` if the clock is unavailable. `pub` so
/// the FreeBSD-gated `identity_raw_range_tests` in the run loop can still reach
/// it after the move.
pub fn host_clock_ns(clock: libc::clockid_t) -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid output timespec.
    (unsafe { libc::clock_gettime(clock, &mut value) } == 0).then(|| {
        (value.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(value.tv_nsec as u64)
    })
}

/// Convert a raw TSC count to nanoseconds at `frequency`. `pub` for the same
/// FreeBSD-gated test reason as [`host_clock_ns`].
pub fn tsc_ns(tsc: u64, frequency: u64) -> u64 {
    ((tsc as u128 * 1_000_000_000u128) / frequency as u128) as u64
}

fn tsc_clock_offset(clock: libc::clockid_t, frequency: u64) -> Option<u64> {
    // Bracket clock_gettime with TSC reads and use their midpoint. This bounds
    // calibration error to half the host call latency while retaining the exact
    // frequency FreeBSD reports for this virtual/physical CPU.
    let before = unsafe { std::arch::x86_64::_rdtsc() };
    let clock_ns = host_clock_ns(clock)?;
    let after = unsafe { std::arch::x86_64::_rdtsc() };
    let midpoint = before.wrapping_add(after.wrapping_sub(before) / 2);
    Some(clock_ns.wrapping_sub(tsc_ns(midpoint, frequency)))
}

/// Calibrate the x86 vDSO clock as `(frequency_hz, realtime_off_ns,
/// monotonic_off_ns)`, or `None` when TSC is not a valid clocksource.
///
/// A frequency alone does not make TSC a valid clocksource. FreeBSD guests
/// commonly expose `machdep.tsc_freq` while selecting kvmclock and marking
/// TSC non-invariant/non-SMP-safe; those counters can move backwards after
/// a host-vCPU migration. Leave `None` in that case so the vDSO's built-in
/// Linux syscall fallback supplies coherent host-clock semantics.
pub fn calibrate() -> Option<(u64, u64, u64)> {
    if !freebsd_tsc_vdso_is_safe() {
        return None;
    }
    let frequency = freebsd_tsc_frequency()?;
    Some((
        frequency,
        tsc_clock_offset(libc::CLOCK_REALTIME, frequency)?,
        tsc_clock_offset(libc::CLOCK_MONOTONIC, frequency)?,
    ))
}
