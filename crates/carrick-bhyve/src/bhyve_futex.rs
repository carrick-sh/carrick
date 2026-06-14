//! `BhyveFutex` — the FreeBSD `PlatformFutex` backend for the threaded loop.
//!
//! Private (intra-process) path: parking-lot `FutexTable`, byte-identical to
//! `KvmFutex`/`HvfFutex`. Shared (cross-process `MAP_SHARED`) path: FreeBSD
//! `_umtx_op` (`carrick_host::umtx`), which keys sleep queues by PHYSICAL
//! address so a shared page survives `fork`. Mirrors `KvmFutex` (Linux
//! `SYS_futex`): a single atomic `_umtx_op` WAKE, no macOS `sched_yield`
//! workaround.

use std::sync::Arc;
use std::time::Duration;

use carrick_hal::{FutexOutcome, PlatformFutex, SharedWaitStep, shared_wait_sliced};
use carrick_thread::thread::{FutexTable, FutexWaitOutcome, ThreadId};

/// Newtype over the shared process-private `FutexTable`.
pub struct BhyveFutex(pub Arc<FutexTable>);

impl PlatformFutex for BhyveFutex {
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

    fn shared_wait(
        &self,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64 {
        shared_wait_sliced(timeout, interrupted, &|slice_ns| {
            let slice_us = u32::try_from((slice_ns / 1_000).max(0)).unwrap_or(u32::MAX);
            let r = carrick_host::umtx::wait(host_addr, value, slice_us);
            if r >= 0 {
                return SharedWaitStep::Woken;
            }
            let host_errno = (-r) as i32;
            if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
                return SharedWaitStep::Retry;
            }
            SharedWaitStep::Error(r)
        })
    }

    fn shared_wake(&self, host_addr: usize, n: u32) -> i64 {
        let all = n > 1;
        let r = carrick_host::umtx::wake(host_addr, all);
        r.max(0)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.0.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.0.notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.0.notify_signal_pending_for(tid);
    }
}
