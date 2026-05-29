//! `clock_getres(2)` resolution fidelity for the hi-res clocks (CLOCK_REALTIME,
//! CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_MONOTONIC_RAW).
//!
//! HOST-PORTABILITY NOTE: the EXACT resolution value is NOT a host-portable
//! invariant. A CONFIG_HIGH_RES_TIMERS kernel reports tv_nsec==1 (1ns), but a
//! low-res kernel — e.g. Docker Desktop's LinuxKit VM at CONFIG_HZ=1000 —
//! reports tv_nsec==1_000_000 (1ms = TICK_NSEC) for ALL of them. Verified live
//! under `gcc:13` linux/arm64 on this host: clock_getres on every hi-res clock
//! returns rc=0, sec=0, nsec=1000000. An earlier draft of this probe asserted
//! the exact tv_nsec==1, but that DIVERGES on these low-res Docker hosts (the
//! termiosbits precedent: assert only what Linux actually guarantees on the
//! oracle, not a value that varies by host kernel).
//!
//! So this probe asserts only the PORTABLE invariant: rc==0 and tv_sec==0 —
//! i.e. clock_getres succeeds and the resolution is sub-second. The exact
//! tv_nsec is left unasserted (it tracks CONFIG_HZ / hrtimer config). carrick
//! reports the 1ms stand-in (dispatch/time.rs clock_getres ->
//! LINUX_CLOCK_RESOLUTION_NSEC=1_000_000), which matches these Docker hosts.
//!
//! The probe goes through the glibc `clock_getres` wrapper (libc::clock_getres)
//! exactly as a real program would. Under Docker that wrapper may serve hi-res
//! clocks from the vDSO (__kernel_clock_getres), which returns the same
//! `hrtimer_resolution` as the syscall. Under carrick the wrapper routes to the
//! emulated clock_getres handler. Booleans only; no tv_nsec value printed
//! (it is host-variable).

use conformance_probes::report;
use std::mem::MaybeUninit;

// Raw Linux clockid_t numbers (universal across libc versions on aarch64);
// using literals rather than libc::CLOCK_* avoids any glibc-vs-musl constant
// gap on the static-musl probe target.
const CLOCK_REALTIME: libc::clockid_t = 0;
const CLOCK_MONOTONIC: libc::clockid_t = 1;
const CLOCK_MONOTONIC_RAW: libc::clockid_t = 4;
const CLOCK_BOOTTIME: libc::clockid_t = 7;

// Portable invariant only: clock_getres succeeds (rc==0) and the resolution is
// sub-second (tv_sec==0). The exact tv_nsec is host-kernel-dependent (1ns on a
// CONFIG_HIGH_RES_TIMERS kernel, 1ms = TICK_NSEC on a low-res Docker host), so
// it is deliberately NOT asserted.
// SAFETY: libc::timespec is a POD all-integer struct, so a zeroed value is a
// valid initialized timespec; matches the established `timeextra` probe idiom.
unsafe fn res_subsecond(clk: libc::clockid_t) -> (bool, bool) {
    let mut ts: libc::timespec = MaybeUninit::zeroed().assume_init();
    let rc = libc::clock_getres(clk, &mut ts);
    (rc == 0, ts.tv_sec == 0)
}

fn main() {
    unsafe {
        let (rc_r, sec_r) = res_subsecond(CLOCK_REALTIME);
        report!(realtime_rc_zero = rc_r, realtime_sec_zero = sec_r);

        let (rc_m, sec_m) = res_subsecond(CLOCK_MONOTONIC);
        report!(monotonic_rc_zero = rc_m, monotonic_sec_zero = sec_m);

        let (rc_raw, sec_raw) = res_subsecond(CLOCK_MONOTONIC_RAW);
        report!(monoraw_rc_zero = rc_raw, monoraw_sec_zero = sec_raw);

        let (rc_b, sec_b) = res_subsecond(CLOCK_BOOTTIME);
        report!(boottime_rc_zero = rc_b, boottime_sec_zero = sec_b);
    }
}