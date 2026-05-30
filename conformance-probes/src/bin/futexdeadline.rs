//! FUTEX_WAIT_BITSET absolute-deadline conformance probe.
//!
//! A `FUTEX_WAIT_BITSET` with an ABSOLUTE CLOCK_MONOTONIC deadline must block
//! until that deadline and then return ETIMEDOUT — it must NOT return instantly.
//! carrick converted the guest's absolute deadline against the wrong macOS clock
//! (CLOCK_MONOTONIC = mach_continuous_time, which counts suspend) while reporting
//! the guest's CLOCK_MONOTONIC as CLOCK_UPTIME_RAW (no suspend); on any host with
//! accumulated sleep time the deadline computed as already-past → instant
//! spurious ETIMEDOUT. That broke every timed lock/sem/condvar wait in CPython
//! (e.g. threading.Lock.acquire(timeout)).
//!
//! Deterministic: prints booleans only (never the raw elapsed time). The wait is
//! on a MATCHING word that nothing wakes, so it runs to the deadline. We assert
//! it (a) returned ETIMEDOUT and (b) actually blocked for at least half the
//! requested interval. On real Linux both are true; pre-fix carrick returned
//! ETIMEDOUT but blocked ~0ms → `blocked` is false → DIFF.

use std::time::Instant;

const FUTEX_WAIT_BITSET: i64 = 9;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

fn main() {
    let word: u32 = 0;
    // Absolute CLOCK_MONOTONIC deadline 200ms from now (WAIT_BITSET treats the
    // timespec as absolute on CLOCK_MONOTONIC unless FUTEX_CLOCK_REALTIME is set).
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    let mut deadline = libc::timespec {
        tv_sec: now.tv_sec,
        tv_nsec: now.tv_nsec + 200_000_000,
    };
    if deadline.tv_nsec >= 1_000_000_000 {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1_000_000_000;
    }

    let start = Instant::now();
    // FUTEX_WAIT_BITSET: blocks while *uaddr == val (0 == 0), waking only on a
    // matching FUTEX_WAKE_BITSET or the absolute timeout. Nothing wakes it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            &word as *const u32,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
            0u32, // expected value (matches *uaddr → actually waits)
            &deadline as *const libc::timespec,
            std::ptr::null::<u32>(), // uaddr2 (unused)
            FUTEX_BITSET_MATCH_ANY,
        )
    };
    let elapsed = start.elapsed();
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // Returned ETIMEDOUT (the deadline path, not EAGAIN/EINTR).
    println!("timed_out={}", rc == -1 && errno == libc::ETIMEDOUT);
    // Actually waited (at least half the 200ms request) — the bug made this ~0.
    println!("blocked_for_deadline={}", elapsed.as_millis() >= 100);
}
