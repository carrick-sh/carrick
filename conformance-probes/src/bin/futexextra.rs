//! Extra futex invariants beyond the cross-process MAP_SHARED case `futexshare`
//! already owns. Stands in for LTP `futex_wake04` and `futex_wait_bitset01`.
//! `futex_cmp_requeue01` is an accepted host limitation (Darwin `__ulock`
//! exposes no requeue primitive) and intentionally has no probe row.
//!
//! Invariants encoded:
//!
//!   1. **FUTEX_WAIT mismatched val → EAGAIN**: futex_wait only blocks when
//!      `*addr == expected`; a mismatched expectation must return -1/EAGAIN
//!      immediately, never EINVAL or 0.
//!
//!   2. **FUTEX_WAIT_BITSET on a private futex returns EAGAIN on mismatch**:
//!      same as (1) but exercises the BITSET variant (op `9`). Stand-in for
//!      LTP `futex_wait_bitset01`.
//!
//!   3. **FUTEX_WAKE on a private futex with no waiters returns 0**: poking
//!      an unwatched address must not error, it just wakes nobody. Stand-in
//!      for LTP `futex_wake04`.
//!
//!   4. **Cross-thread FUTEX_WAIT/WAKE on a private futex**: a sibling thread
//!      blocks in FUTEX_WAIT, the main thread updates the word and calls
//!      FUTEX_WAKE; the sibling unblocks promptly and joins. Wall-clock
//!      bounded at 5 s so a broken delivery path turns a `true` into a
//!      `false` rather than hanging.
//!
//! Deterministic output: booleans + errnos only.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_WAIT_BITSET: i32 = 9;
const FUTEX_PRIVATE_FLAG: i32 = 128;

static WORD: AtomicU32 = AtomicU32::new(0);

unsafe fn futex_op(addr: *mut u32, op: i32, val: u32, timeout: *const libc::timespec) -> i64 {
    libc::syscall(
        libc::SYS_futex,
        addr as *const libc::c_void,
        op as i64,
        val as i64,
        timeout as i64,
    )
}

/// FUTEX_WAIT_BITSET specifically uses val3 (the 6th argument) as the bitmask.
/// `0` is rejected by the kernel with EINVAL — passing FUTEX_BITSET_MATCH_ANY
/// (= !0) is the equivalent of an unfiltered FUTEX_WAIT.
unsafe fn futex_wait_bitset(
    addr: *mut u32,
    val: u32,
    timeout: *const libc::timespec,
    bitset: u32,
) -> i64 {
    libc::syscall(
        libc::SYS_futex,
        addr as *const libc::c_void,
        (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG) as i64,
        val as i64,
        timeout as i64,
        std::ptr::null::<libc::c_void>(),
        bitset as i64,
    )
}

unsafe fn futex_wake_n(addr: *mut u32, n: u32) -> i64 {
    futex_op(addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, n, std::ptr::null())
}

fn main() {
    let addr = WORD.as_ptr();

    unsafe {
        // 1. FUTEX_WAIT with mismatched expected → -1/EAGAIN, immediately.
        WORD.store(1, Ordering::SeqCst);
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let rc = futex_op(
            addr,
            FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
            42, /* mismatched */
            &ts,
        );
        let er = errno();
        report!(
            wait_mismatch_rc_is_minus_one = rc == -1,
            wait_mismatch_errno_is_eagain = er == libc::EAGAIN,
        );

        // 2. FUTEX_WAIT_BITSET with mismatched expected (val3=ANY) → -1/EAGAIN.
        let rc = futex_wait_bitset(addr, 42, std::ptr::null(), u32::MAX);
        let er = errno();
        report!(
            waitbitset_mismatch_rc_is_minus_one = rc == -1,
            waitbitset_mismatch_errno_is_eagain = er == libc::EAGAIN,
        );

        // 3. FUTEX_WAKE on a quiet word: returns 0 (no waiters), no error.
        let woke = futex_wake_n(addr, 1);
        report!(wake_no_waiters_rc_is_zero = woke == 0);

        // 4. Cross-thread wait/wake. Sibling parks in FUTEX_WAIT; main thread
        //    updates the word and FUTEX_WAKEs; sibling returns promptly.
        WORD.store(0, Ordering::SeqCst);
        let parked = std::thread::spawn(|| unsafe {
            futex_op(
                WORD.as_ptr(),
                FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                0,
                std::ptr::null(),
            )
        });
        // Brief delay so the sibling is actually parked before we wake it.
        std::thread::sleep(Duration::from_millis(20));
        WORD.store(1, Ordering::SeqCst);
        let woke = futex_wake_n(addr, 1);
        let deadline = Instant::now() + Duration::from_secs(5);
        let joined_in_time = loop {
            if parked.is_finished() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let sibling_rc: i64 = if joined_in_time {
            parked.join().unwrap_or(-2)
        } else {
            -2
        };
        report!(
            xthread_wake_returned_nonneg = woke >= 0,
            xthread_sibling_returned = joined_in_time,
            xthread_sibling_rc_zero_or_eagain = sibling_rc == 0 || sibling_rc == -1,
        );
    }
}
