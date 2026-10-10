//! bhyve vCPU kick: a `pthread_kill(SIGRTMIN)` makes an in-flight `vm_run`
//! return `EINTR` (handler installed WITHOUT `SA_RESTART`), which `run_x86`
//! maps to `X86Exit::Kicked` → `next_syscall` returns `Ok(None)`. Mirrors the
//! KVM kicker; the only host difference is FreeBSD's `SIGRTMIN` is a const.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// FreeBSD's fixed `SIGRTMIN` define in `<sys/signal.h>`.
pub const FREEBSD_SIGRTMIN: i32 = 65;

#[inline]
pub fn kick_signal() -> i32 {
    carrick_hal::posix_signal_kick::resolve_kick_signal::<FREEBSD_SIGRTMIN>()
}

/// Install the kick-signal handler (idempotent). NO `SA_RESTART`.
pub fn install_bhyve_kick_handler() {
    carrick_hal::posix_signal_kick::install_posix_kick_handler::<FREEBSD_SIGRTMIN>();
}

/// A `Send`/`Sync`/`Clone` handle to a vCPU thread, kickable from any thread.
#[derive(Clone)]
pub struct BhyveKickHandle(carrick_hal::PosixSignalKick<FREEBSD_SIGRTMIN>);

impl BhyveKickHandle {
    /// Build a handle for the CURRENT thread (call on the owning vCPU thread).
    /// `kick_pending` is the engine-owned flag the kick raises and that
    /// `next_syscall` clears on a requested-kick BOGUS exit.
    pub fn for_current_thread(kick_pending: Arc<AtomicBool>) -> Self {
        Self(carrick_hal::PosixSignalKick::for_current_thread_with_pending(kick_pending))
    }
}

impl carrick_hal::VcpuKick for BhyveKickHandle {
    fn kick(&self) {
        self.0.kick();
    }
}

/// The bhyve registry of live vCPUs is the platform-neutral GenericVcpuRegistry.
pub type BhyveKicker = carrick_hal::GenericVcpuRegistry;
