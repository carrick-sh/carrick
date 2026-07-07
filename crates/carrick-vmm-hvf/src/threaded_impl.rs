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

use carrick_hal::{SharedFutexLocation, SharedWaitStep};
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
    fn pre_wait(&self, location: SharedFutexLocation, val: u32) {
        let host_addr = location.wait_addr().raw();
        let host_value = unsafe { (host_addr as *const u32).read() };
        crate::probes::futex_route(host_addr as u64, 99, val as i32, host_value as u64);
    }

    fn wait_start(&self, waiter_key: usize) {
        carrick_host::ulock::waiter_enter(waiter_key);
    }

    fn wait_start_requeued(&self, waiter_key: usize) -> bool {
        carrick_host::ulock::requeued_waiter_enter(waiter_key)
    }

    fn wait_end(&self, waiter_key: usize) {
        carrick_host::ulock::waiter_exit(waiter_key);
    }

    fn wait_end_requeued(
        &self,
        location: SharedFutexLocation,
        waiter_key: usize,
        value: u32,
    ) -> bool {
        carrick_host::ulock::requeued_waiter_exit(waiter_key, location.wait_addr().raw(), value)
    }

    fn try_complete_requeued(&self, waiter_key: usize) -> bool {
        carrick_host::ulock::requeued_waiter_complete(waiter_key)
    }

    fn take_requeue(&self, waiter_key: usize) -> Option<(usize, usize, u32)> {
        carrick_host::ulock::take_requeue(waiter_key)
    }

    /// One ≤20 ms `os_sync_wait_on_address` slice + its macOS-errno
    /// classification. `Woken` for a wake / at-entry value mismatch (the guest
    /// re-checks; Linux `FUTEX_WAIT` returns 0), `Retry` for a slice timeout or
    /// signal nudge (the shared loop re-checks the deadline + interrupt), `Error`
    /// for any other terminal `-errno` (EFAULT agrees macOS↔Linux at 14).
    fn wait_one_slice(
        &self,
        location: SharedFutexLocation,
        waiter_key: usize,
        val: u32,
        slice_ns: i64,
    ) -> SharedWaitStep {
        let _ = waiter_key;
        let host_addr = location.wait_addr().raw();
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
        if host_errno != libc::ETIMEDOUT && host_errno != libc::EINTR {
            carrick_observability::probes::futex_unexpected_errno(host_addr as u64, host_errno);
            let current = unsafe {
                (*(host_addr as *const std::sync::atomic::AtomicU32))
                    .load(std::sync::atomic::Ordering::SeqCst)
            };
            return if current != val {
                SharedWaitStep::Woken
            } else {
                SharedWaitStep::Retry
            };
        }
        // Shared ABI guard + observability (single-sourced with bhyve/NVMM for
        // the ordinary ETIMEDOUT/EINTR cases). Host-specific os_sync errnos were
        // handled above: they retry while the word is unchanged and become a
        // guest wake only if the condition actually changed, so Darwin-specific
        // errno values never leak into glibc's futex ABI.
        carrick_thread::platform_futex::classify_observed_wait_slice(
            r,
            host_addr,
            libc::ETIMEDOUT,
            libc::EINTR,
        )
    }

    /// Wake up to `n` waiters on the shared-page word. Darwin's os_sync wake API
    /// reports success/failure rather than a Linux-style waiter count, so the
    /// host ulock wrapper uses its fork-shared parked-waiter table.
    fn wake(&self, location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64 {
        let host_addr = location.wait_addr().raw();
        carrick_host::ulock::wake_counted(host_addr, waiter_key, n)
    }

    fn requeue(
        &self,
        from: SharedFutexLocation,
        from_key: usize,
        to: SharedFutexLocation,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32) {
        trace_requeue(0, from_key, to_key, wake, requeue, 0, 0);
        let result = carrick_host::ulock::requeue_counted(
            from.wait_addr().raw(),
            from_key,
            to.wait_addr().raw(),
            to_key,
            wake,
            requeue,
        );
        trace_requeue(1, from_key, to_key, wake, requeue, result.0, result.1);
        result
    }
}

fn trace_requeue(
    phase: u32,
    from_key: usize,
    to_key: usize,
    wake_req: u32,
    requeue_req: u32,
    wake_ret: u32,
    requeue_ret: u32,
) {
    let from = carrick_host::ulock::waiter_debug_counts(from_key);
    let to = carrick_host::ulock::waiter_debug_counts(to_key);
    carrick_observability::probes::ulock_requeue(
        carrick_observability::probes::UlockRequeueProbe {
            phase,
            from_key: from_key as u64,
            to_key: to_key as u64,
            wake_req,
            requeue_req,
            wake_ret,
            requeue_ret,
            from_count: from.count,
            from_requeue_wake: from.requeue_wake,
            from_requeue_count: from.requeue_count,
            from_logical_requeued: from.logical_requeued,
            from_logical_wake: from.logical_wake,
            to_count: to.count,
            to_requeue_wake: to.requeue_wake,
            to_requeue_count: to.requeue_count,
            to_logical_requeued: to.logical_requeued,
            to_logical_wake: to.logical_wake,
        },
    );
}

/// HVF's `PlatformFutex`: the shared `FutexTableFutex` over the `HvfShared`
/// cross-process primitive. (Was a hand-rolled `HvfFutex` struct + impl.)
pub type HvfFutex = FutexTableFutex<HvfShared>;

/// Construct HVF's futex over a process-private `FutexTable` (the
/// `HvfFutex(table)` tuple-construction replacement).
pub fn hvf_futex(table: Arc<FutexTable>) -> HvfFutex {
    FutexTableFutex::new(table, HvfShared)
}
