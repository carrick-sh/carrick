//! One `PlatformFutex` implementation, parameterized over the host's shared-page
//! futex syscall.
//!
//! Every backend's `PlatformFutex` impl (HVF, KVM, bhyve, NVMM) was the same
//! shape: the PRIVATE (process-anonymous) path is verbatim delegation to the
//! shared parking-lot [`crate::thread::FutexTable`], and only the SHARED (`MAP_SHARED`,
//! cross-process) path differs — by exactly one kernel call:
//!
//!   * macOS  → `os_sync_wait_on_address` / `os_sync_wake_by_address` (`__ulock`)
//!   * FreeBSD → `_umtx_op`
//!   * Linux  → bare `SYS_futex` (no `FUTEX_PRIVATE_FLAG`)
//!   * NetBSD → `__futex`  (a future arm)
//!   * illumos → `lwp_park` (a future arm)
//!
//! So the whole impl is hoisted here ONCE over [`crate::platform_futex::FutexTableFutex`], and each
//! host plugs in only its best shared-page primitive behind the tiny
//! [`crate::platform_futex::SharedFutexSyscall`] shim — NOT a lowest-common-denominator. The shared
//! deadline/slice/interrupt loop is [`carrick_hal::shared_wait_sliced`]; the
//! per-host residue is a ~15-line `SharedFutexSyscall` impl.
//!
//! HVF deliberately keeps its own `HvfFutex` (it layers carrick-trace probes
//! into the wait path); that is a per-host extra, not a divergence the shim must
//! model. KVM and bhyve use `FutexTableFutex` directly.

use std::sync::Arc;
use std::time::Duration;

use carrick_hal::{FutexOutcome, PlatformFutex, SharedWaitStep, ThreadId, shared_wait_sliced};

use crate::thread::{FutexTable, FutexWaitOutcome};

/// The single per-host divergence the generic [`FutexTableFutex`] needs: the
/// host's `MAP_SHARED` (cross-process) futex kernel calls. The deadline/slice/
/// interrupt control around `wait_one_slice` lives in
/// [`carrick_hal::shared_wait_sliced`]; the host supplies only the one kernel
/// wait slice (classified into a [`SharedWaitStep`]) and the wake.
pub trait SharedFutexSyscall: Send + Sync {
    /// One ≤20 ms cross-process wait slice on the shared-page word at
    /// `host_addr`. Return [`SharedWaitStep::Woken`] for a wake or an
    /// at-entry value mismatch (the guest re-checks), [`SharedWaitStep::Retry`]
    /// for a slice timeout / signal nudge (the loop re-checks the deadline +
    /// interrupt), or [`SharedWaitStep::Error`] for any other terminal `-errno`
    /// (in the value space the guest expects).
    fn wait_one_slice(&self, host_addr: usize, val: u32, slice_ns: i64) -> SharedWaitStep;

    /// Wake up to `n` waiters on the shared-page word at `host_addr`. Returns the
    /// count woken (≥0) or `-errno`.
    fn wake(&self, host_addr: usize, n: u32) -> i64;

    /// Optional once-before-wait hook (default no-op), run once at the top of
    /// [`FutexTableFutex::shared_wait`] before the slice loop. A host can use it
    /// for a pre-wait observability peek at the shared word (HVF emits a
    /// carrick-trace `futex_route` probe here, which is why it previously kept its
    /// own `PlatformFutex` copy — this hook lets it fold onto the shared one).
    fn pre_wait(&self, _host_addr: usize, _val: u32) {}
}

/// The one `PlatformFutex` impl: a process-private [`FutexTable`] (the private
/// path, byte-identical across every backend) paired with a host
/// [`SharedFutexSyscall`] (the shared, cross-process path). Replaces the
/// per-backend `KvmFutex`/`BhyveFutex` copies.
pub struct FutexTableFutex<S: SharedFutexSyscall> {
    table: Arc<FutexTable>,
    shared: S,
}

impl<S: SharedFutexSyscall> FutexTableFutex<S> {
    /// Pair a process-private table with the host's shared-page syscall shim.
    pub fn new(table: Arc<FutexTable>, shared: S) -> Self {
        Self { table, shared }
    }
}

impl<S: SharedFutexSyscall> PlatformFutex for FutexTableFutex<S> {
    /// Park the calling thread on a private (anonymous) futex. The value-equality
    /// check already ran in the dispatcher before it returned `FutexWait`, so we
    /// do NOT re-check — `prepare_wait` captures the generation, then
    /// `wait_prepared_for_thread` parks under the thread's `ParkToken(tid)` so a
    /// thread-directed signal (tgkill) can wake exactly this parked thread.
    fn private_wait(
        &self,
        addr: u64,
        _val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome {
        let wait = self.table.prepare_wait(addr);
        match self
            .table
            .wait_prepared_for_thread(wait, timeout, tid, interrupted)
        {
            FutexWaitOutcome::Woken => FutexOutcome::Woken,
            FutexWaitOutcome::TimedOut => FutexOutcome::TimedOut,
            FutexWaitOutcome::Interrupted => FutexOutcome::Interrupted,
        }
    }

    fn private_wake(&self, addr: u64, n: u32) -> u32 {
        self.table.wake(addr, n)
    }

    /// Wait on a `MAP_SHARED` (cross-process) futex. The deadline/slice/interrupt
    /// loop is shared; only the single kernel wait slice + its host-errno
    /// classification is the host's (`SharedFutexSyscall::wait_one_slice`).
    fn shared_wait(
        &self,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64 {
        self.shared.pre_wait(host_addr, value);
        shared_wait_sliced(timeout, interrupted, &|slice_ns| {
            self.shared.wait_one_slice(host_addr, value, slice_ns)
        })
    }

    fn shared_wake(&self, host_addr: usize, n: u32) -> i64 {
        self.shared.wake(host_addr, n)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.table.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.table.notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.table.notify_signal_pending_for(tid);
    }
}
