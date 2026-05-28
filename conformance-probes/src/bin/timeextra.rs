//! Additional clock/time invariants not already covered by `timeclock`. Stands
//! in for the time-class LTP rows still in the backlog:
//!   * `clock_gettime01` (TIMEOUT class — bare success + nondecreasing)
//!   * `gettimeofday02`
//!   * `times03`
//!   * `clock_settime02` (unprivileged → EPERM)
//!   * `clock_adjtime01/02` (unprivileged → EPERM)
//!
//! Invariants encoded (booleans only — NEVER print tv_sec, tv_nsec, tick
//! values, or any actual time; only relationships and errno equality):
//!
//!   * `clock_gettime(CLOCK_MONOTONIC, &ts)` → rc 0 and `ts.tv_sec > 0`
//!     (after the kernel has been up some seconds at probe-launch time).
//!   * `clock_gettime(CLOCK_REALTIME, &ts)` → rc 0 and `ts.tv_sec > 0`.
//!   * Two consecutive `clock_gettime(CLOCK_MONOTONIC, …)` reads (with a
//!     short busy-wait between them so the diff is observable) are
//!     non-decreasing on the (tv_sec, tv_nsec) lexicographic order.
//!   * `clock_getres(CLOCK_MONOTONIC, &ts)` → rc 0 and `ts.tv_nsec > 0`
//!     (the kernel reports a nanosecond-resolution value).
//!   * `gettimeofday(&tv, NULL)` → rc 0 and `tv.tv_sec > 0`.
//!   * `times(&tms)` → rc != -1 (its return is the monotonic clock-tick
//!     count, which varies per run; we report only `rc_nonneg`).
//!   * `clock_settime(CLOCK_REALTIME, &one_sec)` without CAP_SYS_TIME → -1
//!     with errno == EPERM. The Docker container (and carrick guest) runs
//!     without the capability, so EPERM is the deterministic outcome.
//!   * `clock_adjtime(CLOCK_REALTIME, &buf_with_adjtime_modes)` without
//!     CAP_SYS_TIME → -1 with errno == EPERM (same reasoning).
//!
//! Deterministic: no `tv_sec`/`tv_nsec`/tick values reach stdout — only
//! booleans relating two reads or asserting a positive errno.

use conformance_probes::{errno, report};
use std::mem::MaybeUninit;

fn case_clock_gettime_basics() {
    unsafe {
        let mut mono: libc::timespec = MaybeUninit::zeroed().assume_init();
        let rc_mono = libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
        report!(
            clock_gettime_monotonic_rc_zero = rc_mono == 0,
            monotonic_sec_positive = mono.tv_sec > 0,
        );

        let mut real: libc::timespec = MaybeUninit::zeroed().assume_init();
        let rc_real = libc::clock_gettime(libc::CLOCK_REALTIME, &mut real);
        report!(
            clock_gettime_realtime_rc_zero = rc_real == 0,
            realtime_sec_positive = real.tv_sec > 0,
        );
    }
}

fn case_monotonic_nondecreasing() {
    unsafe {
        let mut a: libc::timespec = MaybeUninit::zeroed().assume_init();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut a);

        // Tiny busy-wait so the second read is reliably later than the
        // first. A simple volatile counter is enough — no syscall, no
        // sleeping, deterministic across runtimes.
        let mut spinner: u64 = 0;
        for _ in 0..200_000 {
            spinner = core::ptr::read_volatile(&spinner).wrapping_add(1);
            core::ptr::write_volatile(&mut spinner, spinner);
        }
        let _ = spinner;

        let mut b: libc::timespec = MaybeUninit::zeroed().assume_init();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut b);

        let nondecreasing = (b.tv_sec, b.tv_nsec) >= (a.tv_sec, a.tv_nsec);
        report!(monotonic_nondecreasing = nondecreasing);
    }
}

fn case_clock_getres_monotonic() {
    unsafe {
        let mut res: libc::timespec = MaybeUninit::zeroed().assume_init();
        let rc = libc::clock_getres(libc::CLOCK_MONOTONIC, &mut res);
        report!(
            clock_getres_monotonic_rc_zero = rc == 0,
            clock_getres_monotonic_nsec_positive = res.tv_nsec > 0,
        );
    }
}

fn case_gettimeofday() {
    unsafe {
        let mut tv: libc::timeval = MaybeUninit::zeroed().assume_init();
        let rc = libc::gettimeofday(&mut tv, std::ptr::null_mut());
        report!(
            gettimeofday_rc_zero = rc == 0,
            gettimeofday_sec_positive = tv.tv_sec > 0,
        );
    }
}

fn case_times() {
    unsafe {
        let mut buf: libc::tms = MaybeUninit::zeroed().assume_init();
        let rc = libc::times(&mut buf);
        // times() returns clock_t (signed long); -1 indicates error. We
        // never print the value itself.
        report!(times_rc_nonneg = rc != -1isize as libc::clock_t);
    }
}

fn case_clock_settime_eperm() {
    unsafe {
        // We are NOT CAP_SYS_TIME (Docker default + carrick guest). Setting
        // CLOCK_REALTIME must fail with EPERM. Using an arbitrary value
        // (1 second past epoch) — never actually applied.
        let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
        let rc = libc::clock_settime(libc::CLOCK_REALTIME, &ts);
        let e = errno();
        report!(
            clock_settime_rc_minus_one = rc == -1,
            clock_settime_errno_eperm = e == libc::EPERM,
        );
    }
}

fn case_clock_adjtime_eperm() {
    unsafe {
        // ADJ_OFFSET is the canonical "adjust time" mode flag; without
        // CAP_SYS_TIME the kernel returns -1/EPERM before it even reads
        // the offset. ADJ_OFFSET = 0x0001 on Linux.
        const ADJ_OFFSET: libc::c_uint = 0x0001;
        let mut buf: libc::timex = MaybeUninit::zeroed().assume_init();
        buf.modes = ADJ_OFFSET;
        buf.offset = 0;
        let rc = libc::clock_adjtime(libc::CLOCK_REALTIME, &mut buf);
        let e = errno();
        report!(
            clock_adjtime_rc_minus_one = rc == -1,
            clock_adjtime_errno_eperm = e == libc::EPERM,
        );
    }
}

fn main() {
    case_clock_gettime_basics();
    case_monotonic_nondecreasing();
    case_clock_getres_monotonic();
    case_gettimeofday();
    case_times();
    case_clock_settime_eperm();
    case_clock_adjtime_eperm();
}
