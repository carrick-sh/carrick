//! `PlatformFutex` for HVF: [`FutexTableFutex<HvfShared>`].
//!
//! The PRIVATE (process-anonymous) futex path is verbatim delegation to the
//! shared parking-lot [`carrick_thread::thread::FutexTable`]; only the SHARED
//! (`MAP_SHARED`, cross-process) path is host-specific — one Darwin
//! `os_sync_wait_on_address` / `os_sync_wake_by_address` (`__ulock`) slice + wake.
//! That is exactly the [`carrick_thread::platform_futex::FutexTableFutex<S>`]
//! shape KVM/bhyve/NVMM already use, so HVF folds onto it: it supplies only the
//! ~25-line [`HvfShared`] `SharedFutexSyscall` impl.
//!
//! HVF previously kept a hand-rolled `HvfFutex` SOLELY to layer carrick-trace
//! probes into the wait path (`futex_route` once before the wait; `ulock_wait`
//! per slice). With the `SharedFutexSyscall::pre_wait` hook (the once-before
//! peek) and the per-slice probes inside `wait_one_slice`, those live in
//! `HvfShared` and the whole duplicate impl + slice/deadline loop is gone.

use std::sync::Arc;

use carrick_hal::SharedWaitStep;
use carrick_thread::platform_futex::{FutexTableFutex, SharedFutexSyscall};
use carrick_thread::thread::FutexTable;

// The shared-futex (MAP_SHARED, cross-process) slice cap: each `__ulock` wait is
// sliced to ≤20 ms so a pending guest signal is observed promptly (the kick
// cannot interrupt `__ulock`). The deadline/slice/interrupt loop around this is
// shared (`carrick_hal::shared_wait_sliced`, driven by `FutexTableFutex`).
const SHARED_FUTEX_MAX_SLICE_US: u32 = 20_000;

/// HVF's `MAP_SHARED` (cross-process) futex primitive: Darwin `os_sync` /
/// `__ulock`, carrying the carrick-trace probes the module deliberately keeps.
pub struct HvfShared;

impl SharedFutexSyscall for HvfShared {
    /// Pre-wait peek: read the current shared word so carrick-trace can see it
    /// before any wait commences (once, at the top of `shared_wait`).
    fn pre_wait(&self, host_addr: usize, val: u32) {
        let host_value = unsafe { (host_addr as *const u32).read() };
        crate::probes::futex_route(host_addr as u64, 99, val as i32, host_value as u64);
    }

    /// One ≤20 ms `os_sync_wait_on_address` slice + its macOS-errno
    /// classification. `Woken` for a wake / at-entry value mismatch (the guest
    /// re-checks; Linux `FUTEX_WAIT` returns 0), `Retry` for a slice timeout or
    /// signal nudge (the shared loop re-checks the deadline + interrupt), `Error`
    /// for any other terminal `-errno` (EFAULT agrees macOS↔Linux at 14).
    fn wait_one_slice(&self, host_addr: usize, val: u32, slice_ns: i64) -> SharedWaitStep {
        // Re-validate the shared word at the TOP of every slice before re-parking.
        // A macOS os_sync wake can be LOST: `os_sync_wake_by_address` fires before
        // the waiter is parked (the cross-process wake-before-park race), and
        // `os_sync_wait_on_address` does NOT re-observe *addr once parked. So a
        // value change that landed while we were parked in the PREVIOUS slice is
        // invisible to os_sync, and the waiter blocks until its deadline (or
        // forever). The Linux kernel re-checks the futex word atomically under the
        // bucket lock; do that explicitly here so a lost cross-process wake is
        // recovered within one ≤20 ms slice: if the word no longer equals the wait
        // value the condition changed, so report Woken (Linux FUTEX_WAIT returns 0)
        // and let the guest re-check and proceed.
        // SAFETY: host_addr is a live 4-byte-aligned host word in the shared page.
        let current = unsafe {
            (*(host_addr as *const std::sync::atomic::AtomicU32))
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        if current != val {
            return SharedWaitStep::Woken;
        }
        let slice_us = u32::try_from((slice_ns / 1_000).min(i64::from(SHARED_FUTEX_MAX_SLICE_US)))
            .unwrap_or(SHARED_FUTEX_MAX_SLICE_US);
        crate::probes::ulock_wait(host_addr as u64, val, slice_us, 0, 0);
        let r = carrick_host::ulock::wait(host_addr, val, slice_us);
        crate::probes::ulock_wait(host_addr as u64, val, slice_us, 1, r);
        if r >= 0 {
            return SharedWaitStep::Woken;
        }
        let host_errno = (-r) as i32;
        if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
            return SharedWaitStep::Retry;
        }
        // ABI guard: a Linux FUTEX_WAIT only ever reports 0 / EAGAIN / EINTR /
        // ETIMEDOUT (the value-mismatch EAGAIN is handled before the wait), and
        // glibc's nptl FATALLY aborts on any other errno ("the futex facility
        // returned an unexpected error code"). `os_sync_wait_on_address` can
        // return a Darwin-specific errno (e.g. EINVAL) that has no Linux-futex
        // meaning — surfacing it raw killed cpython multiprocessing workers
        // waiting on a process-shared semaphore. A FUTEX_WAIT is permitted to
        // wake SPURIOUSLY, so map any such errno to a spurious wake: the guest
        // re-reads its word and re-waits. Never propagate a non-Linux futex
        // errno across the ABI boundary. (phase=2 = unexpected-errno, for trace.)
        crate::probes::ulock_wait(host_addr as u64, val, 0, 2, r);
        SharedWaitStep::Woken
    }

    /// Wake up to `n` waiters on the shared-page word. macOS's
    /// `os_sync_wake_by_address_any` reports spurious successes when called
    /// back-to-back on a SHARED address, so wake ONE at a time with a
    /// `sched_yield` between iterations. Returns the count woken.
    fn wake(&self, host_addr: usize, n: u32) -> i64 {
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
}

/// HVF's `PlatformFutex`: the shared `FutexTableFutex` over the `HvfShared`
/// cross-process primitive. (Was a hand-rolled `HvfFutex` struct + impl.)
pub type HvfFutex = FutexTableFutex<HvfShared>;

/// Construct HVF's futex over a process-private `FutexTable` (the
/// `HvfFutex(table)` tuple-construction replacement).
pub fn hvf_futex(table: Arc<FutexTable>) -> HvfFutex {
    FutexTableFutex::new(table, HvfShared)
}
