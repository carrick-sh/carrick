//! NVMM's shared-page futex syscall shim.
//!
//! The private futex path is the shared [`carrick_thread::thread::FutexTable`].
//! The only NetBSD-specific piece is the shared/cross-process wait and wake on a
//! host address, backed by NetBSD `__futex(2)`. NetBSD requires file-backed
//! `MAP_SHARED` memory for cross-process wakes; `NvmmRamBacking::Shared` supplies
//! that backing for guest shared windows.

use std::sync::Arc;

use carrick_hal::SharedWaitStep;
use carrick_thread::platform_futex::{FutexTableFutex, SharedFutexSyscall};
use carrick_thread::thread::FutexTable;

pub struct NvmmSharedFutex;

impl SharedFutexSyscall for NvmmSharedFutex {
    fn wait_one_slice(&self, host_addr: usize, val: u32, slice_ns: i64) -> SharedWaitStep {
        let slice_us = u32::try_from((slice_ns / 1_000).max(0)).unwrap_or(u32::MAX);
        let r = carrick_host::netbsd_futex::wait(host_addr, val, slice_us);
        if r >= 0 {
            return SharedWaitStep::Woken;
        }
        let host_errno = (-r) as i32;
        if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
            return SharedWaitStep::Retry;
        }
        SharedWaitStep::Error(r)
    }

    fn wake(&self, host_addr: usize, n: u32) -> i64 {
        let all = n > 1;
        carrick_host::netbsd_futex::wake(host_addr, all).max(0)
    }
}

pub type NvmmFutex = FutexTableFutex<NvmmSharedFutex>;

pub fn make_nvmm_futex(table: Arc<FutexTable>) -> NvmmFutex {
    FutexTableFutex::new(table, NvmmSharedFutex)
}
