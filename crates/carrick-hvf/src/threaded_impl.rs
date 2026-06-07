//! `PlatformFutex` implementation for HVF.
//!
//! `HvfFutex` wraps the process-private `carrick_thread::thread::FutexTable`
//! (parking-lot-backed) for private-anonymous futex operations, and delegates
//! the `MAP_SHARED` / cross-process futex operations to the Darwin
//! `os_sync_wait_on_address` / `os_sync_wake_by_address` API via
//! `carrick_host::ulock`.
//!
//! This is a forwarding shim only.  All semantics are owned by the existing
//! `FutexTable` / ulock implementations; this file just names the
//! `carrick_hal::PlatformFutex` surface and routes each method to the
//! correct existing call.

use std::sync::Arc;
use std::time::Duration;

use carrick_abi::LINUX_ETIMEDOUT;
use carrick_hal::{FutexOutcome, PlatformFutex, ThreadId};
use carrick_thread::thread::{FutexTable, FutexWaitOutcome};

// ---------------------------------------------------------------------------
// The shared-futex (MAP_SHARED, cross-process) slice constant.
//
// The existing `shared_futex_wait` loop in runtime.rs slices each __ulock
// wait to ≤20 ms so a pending guest signal is observed promptly (the kick
// cannot interrupt __ulock).  We apply the same cap here.
// ---------------------------------------------------------------------------
const SHARED_FUTEX_MAX_SLICE_US: u32 = 20_000;

/// The HVF `PlatformFutex` implementation.
///
/// Wraps the per-process `FutexTable` for private futex ops and delegates
/// MAP_SHARED / cross-process futex ops to the Darwin ulock API.
pub struct HvfFutex(pub Arc<FutexTable>);

impl PlatformFutex for HvfFutex {
    /// Park the calling thread on a private (anonymous) futex.
    ///
    /// The value-equality check was already performed by the dispatcher BEFORE
    /// it returned `DispatchOutcome::FutexWait`, so we do NOT re-check here —
    /// we call `prepare_wait` (which captures the generation) and then
    /// `wait_prepared_for_thread` directly, so that a thread-directed signal
    /// (tgkill) can wake this specific parked thread via its `ParkToken(tid)`.
    fn private_wait(
        &self,
        addr: u64,
        _val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome {
        let wait = self.0.prepare_wait(addr);
        match self
            .0
            .wait_prepared_for_thread(wait, timeout, tid, interrupted)
        {
            FutexWaitOutcome::Woken => FutexOutcome::Woken,
            FutexWaitOutcome::TimedOut => FutexOutcome::TimedOut,
            FutexWaitOutcome::Interrupted => FutexOutcome::Interrupted,
        }
    }

    fn private_wake(&self, addr: u64, n: u32) -> u32 {
        self.0.wake(addr, n)
    }

    /// Wait on a MAP_SHARED (cross-process) futex via `os_sync_wait_on_address`.
    ///
    /// Mirrors the `shared_futex_wait` loop in runtime.rs: slices each kernel
    /// wait to ≤20 ms, re-checks `interrupted()` between slices, and returns
    /// the raw `i64` (-errno on error, ≥0 on woken/value-mismatch) that the
    /// run loop translates to Linux errno.
    fn shared_wait(
        &self,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64 {
        let deadline = timeout.map(|d| std::time::Instant::now() + d);
        loop {
            if interrupted() {
                // Translate: EINTR is -4 on both macOS and Linux.
                return -(libc::EINTR as i64);
            }
            let slice_us: u32 = match deadline {
                Some(dl) => {
                    let now = std::time::Instant::now();
                    if now >= dl {
                        return -(LINUX_ETIMEDOUT as i64);
                    }
                    u32::try_from(
                        (dl - now)
                            .as_micros()
                            .min(SHARED_FUTEX_MAX_SLICE_US as u128),
                    )
                    .unwrap_or(SHARED_FUTEX_MAX_SLICE_US)
                }
                None => SHARED_FUTEX_MAX_SLICE_US,
            };
            let r = carrick_host::ulock::wait(host_addr, value, slice_us);
            if r >= 0 {
                // Woken or value already differed — caller re-checks its
                // condition.  Linux FUTEX_WAIT returns 0.
                return 0;
            }
            let host_errno = (-r) as i32;
            if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
                // Slice expired or signal nudge — re-check at loop top.
                continue;
            }
            // Any other error (e.g. EFAULT) is returned directly; errno values
            // happen to agree between macOS and Linux for EFAULT (14).
            return r;
        }
    }

    fn shared_wake(&self, host_addr: usize, n: u32) -> i64 {
        // Mirror the existing shared-futex wake sites (dispatch/proc.rs:1366,
        // dispatch/mod.rs): wake ONE waiter at a time with a sched_yield between
        // iterations. macOS's os_sync_wake_by_address_any reports spurious
        // successes when called back-to-back on a SHARED address; the
        // sched_yield between iterations is the cure. Returns the count woken.
        let mut woke = 0i64;
        for _ in 0..n {
            let rc = carrick_host::ulock::wake(host_addr, false);
            if rc < 0 {
                break;
            }
            woke += 1;
            unsafe {
                libc::sched_yield();
            }
        }
        woke
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.0.requeue(from, to, wake, requeue)
    }
}
