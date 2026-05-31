//! FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME absolute-deadline conformance probe.
//!
//! A `FUTEX_WAIT_BITSET` with `FUTEX_CLOCK_REALTIME` treats the timespec as an
//! ABSOLUTE deadline on CLOCK_REALTIME. The guest builds that deadline from its
//! OWN `clock_gettime(CLOCK_REALTIME)` (exactly as glibc's sem_timedwait /
//! pthread_cond_timedwait do). carrick converts the absolute deadline to a
//! remaining duration by subtracting the HOST's CLOCK_REALTIME "now". For the
//! wait to block (not instantly time out), the guest's CLOCK_REALTIME and the
//! host's must agree.
//!
//! They did not: carrick calibrated the vDSO realtime offset against the raw
//! `cntvct_el0` MRS, which (unlike the guest's HVF-virtualised CNTVCT, aligned
//! to macOS CLOCK_UPTIME_RAW) keeps ticking across system SUSPEND. On a host
//! that had slept, the guest's CLOCK_REALTIME ran HOURS behind real wall time,
//! so `deadline(guest_now + 200ms)` was still far in the host's past →
//! `relative_from_absolute_timespec` clamped to 0 → instant spurious ETIMEDOUT.
//! That broke every multiprocessing SemLock/Condition timed wait on /dev/shm.
//!
//! Deterministic: booleans only. Nothing wakes the matching word, so a correct
//! kernel blocks to the deadline and returns ETIMEDOUT. Pre-fix carrick returned
//! ETIMEDOUT but blocked ~0ms → `blocked_for_deadline` is false → DIFF.

use std::time::Instant;

const FUTEX_WAIT_BITSET: i64 = 9;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_CLOCK_REALTIME: i64 = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

fn main() {
    let word: u32 = 0;
    // Absolute CLOCK_REALTIME deadline 200ms from the guest's OWN realtime clock.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let mut deadline = libc::timespec {
        tv_sec: now.tv_sec,
        tv_nsec: now.tv_nsec + 200_000_000,
    };
    if deadline.tv_nsec >= 1_000_000_000 {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1_000_000_000;
    }

    let start = Instant::now();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            &word as *const u32,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME,
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
