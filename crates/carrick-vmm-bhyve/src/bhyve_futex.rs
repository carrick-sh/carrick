//! bhyve's shared-page futex syscall shim.
//!
//! The whole `PlatformFutex` impl is now the shared
//! [`carrick_thread::platform_futex::FutexTableFutex<S>`]; bhyve supplies only
//! the one per-host divergence — the `MAP_SHARED` (cross-process) futex kernel
//! call — as a [`SharedFutexSyscall`] shim. On FreeBSD that is `_umtx_op`
//! (`carrick_host::umtx`), which keys sleep queues by PHYSICAL address so a
//! shared page survives `fork`. Like the KVM (Linux `SYS_futex`) shim it is a
//! single atomic WAKE, no macOS `sched_yield` workaround.
//!
//! `BhyveFutex` is now a thin alias for `FutexTableFutex<BhyveSharedFutex>`;
//! build it with [`make_bhyve_futex`].

use std::sync::Arc;

use carrick_hal::SharedWaitStep;
use carrick_thread::platform_futex::{FutexTableFutex, SharedFutexSyscall};
use carrick_thread::thread::FutexTable;

/// bhyve's per-host shared-page futex shim: FreeBSD `_umtx_op`.
pub struct BhyveSharedFutex;

impl SharedFutexSyscall for BhyveSharedFutex {
    fn wait_one_slice(&self, host_addr: usize, val: u32, slice_ns: i64) -> SharedWaitStep {
        let slice_us = u32::try_from((slice_ns / 1_000).max(0)).unwrap_or(u32::MAX);
        let r = carrick_host::umtx::wait(host_addr, val, slice_us);
        // Shared ABI guard + observability: a non-{ETIMEDOUT,EINTR} `_umtx_op`
        // errno folds to a spurious wake (never `Error(raw)` — a raw FreeBSD errno
        // leaked here fatally aborts the guest's glibc nptl) and fires the
        // `futex-unexpected-errno` probe. Single-sourced with HVF/NVMM; previously
        // hand-rolled with the wrong `Error(r)` else-arm and no observability.
        carrick_thread::platform_futex::classify_observed_wait_slice(
            r,
            host_addr,
            libc::ETIMEDOUT,
            libc::EINTR,
        )
    }

    fn wake(&self, host_addr: usize, _waiter_key: usize, n: u32) -> i64 {
        let all = n > 1;
        let r = carrick_host::umtx::wake(host_addr, all);
        r.max(0)
    }
}

/// The bhyve `PlatformFutex`: the shared `FutexTableFutex` over the `_umtx_op`
/// shim. Construct with [`make_bhyve_futex`].
pub type BhyveFutex = FutexTableFutex<BhyveSharedFutex>;

/// Pair the process-private `FutexTable` with bhyve's shared-page shim.
pub fn make_bhyve_futex(table: Arc<FutexTable>) -> BhyveFutex {
    FutexTableFutex::new(table, BhyveSharedFutex)
}
