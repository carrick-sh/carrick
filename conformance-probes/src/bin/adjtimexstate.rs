//! `adjtimex(2)` / `clock_adjtime(CLOCK_REALTIME, ...)` read and errno paths.
//!
//! The LTP `adjtimex*` tests first save the current kernel time discipline with
//! `modes = 0`. That read-only form must succeed even for an unprivileged
//! caller; adjustment modes then fail through the same permission/validation
//! order Linux uses.

use conformance_probes::{errno, report};

const ADJ_STATUS_OR_READONLY: libc::c_uint = 0x4000;
const ADJ_ALL_SAVE_PARAMS: libc::c_uint = 0x403f;
const ADJ_OFFSET_SINGLESHOT_FLAG_ONLY: libc::c_uint = 0x8000;

fn clock_adjtime_call(modes: libc::c_uint) -> (libc::c_long, i32, libc::c_int) {
    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = modes;
    tx.tai = -1;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_adjtime,
            libc::CLOCK_REALTIME,
            &mut tx as *mut libc::timex,
        )
    };
    (rc, errno(), tx.tai)
}

fn adjtimex_call(modes: libc::c_uint) -> (libc::c_long, i32) {
    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = modes;
    let rc = unsafe { libc::syscall(libc::SYS_adjtimex, &mut tx as *mut libc::timex) };
    (rc, errno())
}

fn main() {
    let (clock_read_rc, _, _) = clock_adjtime_call(0);
    report!(clock_adjtime_read_nonnegative = clock_read_rc >= 0);

    let (raw_read_rc, _) = adjtimex_call(0);
    report!(adjtimex_read_nonnegative = raw_read_rc >= 0);

    let (clock_adjust_rc, clock_adjust_errno, _) = clock_adjtime_call(ADJ_ALL_SAVE_PARAMS);
    report!(clock_adjtime_adjust_eperm =
        clock_adjust_rc == -1 && clock_adjust_errno == libc::EPERM);

    let (raw_adjust_rc, raw_adjust_errno) = adjtimex_call(ADJ_ALL_SAVE_PARAMS);
    report!(adjtimex_adjust_eperm = raw_adjust_rc == -1 && raw_adjust_errno == libc::EPERM);

    let (clock_status_rc, clock_status_errno, _) = clock_adjtime_call(ADJ_STATUS_OR_READONLY);
    report!(clock_adjtime_status_flag_eperm =
        clock_status_rc == -1 && clock_status_errno == libc::EPERM);

    let (clock_bad_rc, clock_bad_errno, _) = clock_adjtime_call(ADJ_OFFSET_SINGLESHOT_FLAG_ONLY);
    report!(clock_adjtime_singleshot_flag_einval =
        clock_bad_rc == -1 && clock_bad_errno == libc::EINVAL);
}
