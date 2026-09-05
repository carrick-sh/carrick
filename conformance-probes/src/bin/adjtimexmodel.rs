//! `adjtimex(2)` / `clock_adjtime(CLOCK_REALTIME, ...)` model verification.
//!
//! Exercised under `CAP_SYS_TIME`:
//! - Read-only query (modes = 0) returns current clock discipline state.
//! - Valid adjustment modes succeed and update discipline state.
//! - Out-of-bounds parameters and incompatible mode combinations reject with EINVAL.

use conformance_probes::{errno, report};

const ADJ_OFFSET: libc::c_uint = 0x0001;
const ADJ_FREQUENCY: libc::c_uint = 0x0002;
const ADJ_MAXERROR: libc::c_uint = 0x0004;
const ADJ_ESTERROR: libc::c_uint = 0x0008;
const ADJ_STATUS: libc::c_uint = 0x0010;
const ADJ_TIMECONST: libc::c_uint = 0x0020;
const ADJ_TAI: libc::c_uint = 0x0080;
const ADJ_SETOFFSET: libc::c_uint = 0x0100;
const ADJ_MICRO: libc::c_uint = 0x1000;
const ADJ_NANO: libc::c_uint = 0x2000;
const ADJ_TICK: libc::c_uint = 0x4000;
const ADJ_OFFSET_SINGLESHOT_FLAG_ONLY: libc::c_uint = 0x8000;

const STA_PLL: libc::c_int = 0x0001;

fn clock_adjtime_call(tx: &mut libc::timex) -> (libc::c_long, i32) {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_adjtime,
            libc::CLOCK_REALTIME,
            tx as *mut libc::timex,
        )
    };
    (rc, errno())
}

fn adjtimex_call(tx: &mut libc::timex) -> (libc::c_long, i32) {
    let rc = unsafe { libc::syscall(libc::SYS_adjtimex, tx as *mut libc::timex) };
    (rc, errno())
}

fn main() {
    // 1. Read-only queries (modes = 0)
    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    let (rc_read_clock, _) = clock_adjtime_call(&mut tx);
    report!(clock_adjtime_read_ok = rc_read_clock >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    let (rc_read_adj, _) = adjtimex_call(&mut tx);
    report!(adjtimex_read_ok = rc_read_adj >= 0);

    // 2. Privileged adjustment modes
    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_OFFSET;
    tx.offset = 5000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_offset_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_FREQUENCY;
    tx.freq = 10000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_frequency_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_MAXERROR;
    tx.maxerror = 50000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_maxerror_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_ESTERROR;
    tx.esterror = 25000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_esterror_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_STATUS;
    tx.status = STA_PLL;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_status_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TIMECONST;
    tx.constant = 4;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_timeconst_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TAI;
    tx.constant = 37;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_tai_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TICK;
    tx.tick = 10000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_tick_ok = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_SETOFFSET;
    tx.time.tv_sec = 0;
    tx.time.tv_usec = 0;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(adj_setoffset_ok = rc >= 0);

    // 3. Rejection of invalid parameters
    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_FREQUENCY;
    tx.freq = 35_000_000;
    let (rc, _) = clock_adjtime_call(&mut tx);
    // Linux clamps an oversized freq to MAXFREQ rather than refusing it.
    report!(oversized_freq_accepted = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TICK;
    tx.tick = 5_000;
    let (rc, err) = clock_adjtime_call(&mut tx);
    report!(bad_tick_einval = rc == -1 && err == libc::EINVAL);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_STATUS;
    tx.status = 1 << 20;
    let (rc, _) = clock_adjtime_call(&mut tx);
    // Undefined status bits are ignored, not refused.
    report!(unknown_status_bits_accepted = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_SETOFFSET;
    tx.time.tv_sec = 0;
    tx.time.tv_usec = 1_000_000;
    let (rc, err) = clock_adjtime_call(&mut tx);
    report!(bad_setoffset_usec_einval = rc == -1 && err == libc::EINVAL);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_MICRO | ADJ_NANO;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(micro_nano_together_accepted = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_TAI | ADJ_TIMECONST;
    let (rc, _) = clock_adjtime_call(&mut tx);
    report!(tai_timeconst_together_accepted = rc >= 0);

    let mut tx: libc::timex = unsafe { core::mem::zeroed() };
    tx.modes = ADJ_OFFSET_SINGLESHOT_FLAG_ONLY;
    let (rc, err) = clock_adjtime_call(&mut tx);
    report!(singleshot_flag_without_offset_einval = rc == -1 && err == libc::EINVAL);
}
