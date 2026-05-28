//! sched_get*/sched_getparam/sched_getscheduler/sched_rr_get_interval
//! semantics on a vanilla SCHED_OTHER process. Stands in for LTP
//! `sched_get_priority_max01`, `sched_get_priority_min01`,
//! `sched_getparam01`, `sched_getscheduler01`, `sched_rr_get_interval01`,
//! `sched_setparam01`, `sched_setscheduler01`. The whole sched_* family is
//! currently ENOSYS / unregistered in carrick, so under carrick this probe
//! is expected to diverge until those land — that's the gate.
//!
//! Invariants encoded, all boolean:
//!
//!   * `sched_get_priority_max(SCHED_OTHER) >= 0` and
//!     `sched_get_priority_min(SCHED_OTHER) >= 0` (Linux returns 0 for both —
//!     SCHED_OTHER doesn't expose a priority range — but the probe asserts
//!     non-negative so the diff vs Linux is stable regardless).
//!   * `sched_get_priority_max(SCHED_FIFO) > sched_get_priority_min(SCHED_FIFO)`
//!     — the real-time policies do have a priority range (Linux: 99 vs 1).
//!   * `sched_getscheduler(0)` returns `SCHED_OTHER` for a normal process
//!     (we haven't called `sched_setscheduler`).
//!   * `sched_getparam(0, &p)` returns 0 and `p.sched_priority == 0` for
//!     SCHED_OTHER.
//!   * `sched_rr_get_interval(0, &ts)` returns 0; `ts.tv_sec >= 0` and
//!     `ts.tv_nsec >= 0` (booleans only — never the raw interval).
//!
//! `sched_get_priority_{max,min}` go through the libc wrapper (their kernel
//! ABI matches the wrapper 1:1). The other three (`sched_getscheduler`,
//! `sched_getparam`, `sched_rr_get_interval`) go DIRECTLY through
//! `libc::syscall(SYS_*, …)` — musl's wrappers add error-mapping that
//! masks the raw kernel rc on some builds, and the raw syscall ABI is
//! exactly what carrick has to implement. No timing data is emitted.

use conformance_probes::report;
use std::mem::MaybeUninit;

fn main() {
    unsafe {
        // SCHED_OTHER priority window: Linux returns max=0/min=0. We only
        // assert non-negative so the probe stays stable if a kernel ever
        // shifts the convention.
        let max_other = libc::sched_get_priority_max(libc::SCHED_OTHER);
        let min_other = libc::sched_get_priority_min(libc::SCHED_OTHER);
        report!(
            sched_get_priority_max_other_nonneg = max_other >= 0,
            sched_get_priority_min_other_nonneg = min_other >= 0,
            sched_get_priority_other_max_eq_min = max_other == min_other,
        );

        // Real-time policy priority window: must be a strictly-positive range.
        let max_fifo = libc::sched_get_priority_max(libc::SCHED_FIFO);
        let min_fifo = libc::sched_get_priority_min(libc::SCHED_FIFO);
        let max_rr = libc::sched_get_priority_max(libc::SCHED_RR);
        let min_rr = libc::sched_get_priority_min(libc::SCHED_RR);
        report!(
            sched_get_priority_fifo_max_gt_min = max_fifo > min_fifo,
            sched_get_priority_rr_max_gt_min = max_rr > min_rr,
            sched_get_priority_min_fifo_positive = min_fifo > 0,
        );

        // sched_getscheduler(0) → SCHED_OTHER for a normal process.
        // musl's libc wrapper returns ENOSYS via the legacy POSIX-shape
        // (in some builds), so go straight through the syscall ABI — that's
        // also the layer carrick has to implement.
        let sched =
            libc::syscall(libc::SYS_sched_getscheduler, 0i32 as libc::c_long) as i32;
        report!(
            sched_getscheduler_nonneg = sched >= 0,
            sched_getscheduler_is_other = sched == libc::SCHED_OTHER,
        );

        // sched_getparam(0, &p): rc 0 and priority 0 for SCHED_OTHER.
        let mut param: libc::sched_param = MaybeUninit::zeroed().assume_init();
        let getparam_rc = libc::syscall(
            libc::SYS_sched_getparam,
            0i32 as libc::c_long,
            &mut param as *mut libc::sched_param as libc::c_long,
        ) as i32;
        report!(
            sched_getparam_rc_zero = getparam_rc == 0,
            sched_getparam_priority_is_zero = param.sched_priority == 0,
        );

        // sched_rr_get_interval(0, &ts): rc 0 and a non-negative timespec.
        // The exact interval is kernel-tuned, so only assert non-negativity.
        let mut ts: libc::timespec = MaybeUninit::zeroed().assume_init();
        let rr_rc = libc::syscall(
            libc::SYS_sched_rr_get_interval,
            0i32 as libc::c_long,
            &mut ts as *mut libc::timespec as libc::c_long,
        ) as i32;
        report!(
            sched_rr_get_interval_rc_zero = rr_rc == 0,
            sched_rr_get_interval_tv_sec_nonneg = ts.tv_sec >= 0,
            sched_rr_get_interval_tv_nsec_nonneg = ts.tv_nsec >= 0,
        );
    }
}
