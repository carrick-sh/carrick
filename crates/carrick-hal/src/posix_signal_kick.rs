//! Cross-thread POSIX signal vCPU kick handle.
//!
//! Delivers a POSIX signal to a vCPU thread via `pthread_kill`, forcing an in-progress
//! hypervisor run ioctl (`KVM_RUN`, `vm_run`, `nvmm_vcpu_run`) to return `EINTR`
//! (or an AST-pending exit).
//! The signal handler is empty and installed with `sa_flags = 0` (NO `SA_RESTART`) so
//! that the kernel does not silently restart the interrupted ioctl.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

#[derive(Clone, Copy)]
struct IdleRunExitByte(*mut u8);

// SAFETY: the mapped KVM byte is installed and removed under the idle-kick
// mutex. Its owner does not recycle the vCPU until after removal.
unsafe impl Send for IdleRunExitByte {}

/// Resolves the signal number to use for `SIG`.
/// When `SIG == 0`, dynamically resolves `libc::SIGRTMIN()` on Linux.
#[inline]
pub fn resolve_kick_signal<const SIG: i32>() -> i32 {
    if SIG != 0 {
        SIG
    } else {
        #[cfg(target_os = "linux")]
        {
            libc::SIGRTMIN()
        }
        #[cfg(not(target_os = "linux"))]
        {
            34
        }
    }
}

extern "C" fn posix_kick_noop(_signum: libc::c_int) {}

static INSTALLED_SIGNALS: [AtomicBool; 128] = [const { AtomicBool::new(false) }; 128];

/// Process-wide idempotent installation of the POSIX kick signal handler.
/// Installed with `sa_flags = 0` (NO `SA_RESTART`).
pub fn install_posix_kick_handler<const SIG: i32>() {
    let sig = resolve_kick_signal::<SIG>();
    if sig >= 0
        && (sig as usize) < INSTALLED_SIGNALS.len()
        && INSTALLED_SIGNALS[sig as usize].swap(true, Ordering::SeqCst)
    {
        return;
    }
    // SAFETY: a zeroed sigaction is the documented "no flags, empty mask" form;
    // we set the handler fn, an empty mask, and sa_flags = 0 (NO SA_RESTART).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = posix_kick_noop as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0; // NO SA_RESTART
        libc::sigaction(sig, &action, std::ptr::null_mut());
    }
}

/// A `Send`/`Sync` handle to a guest thread's vCPU, usable from any thread to kick it
/// using POSIX signal `SIG`.
#[derive(Clone)]
pub struct PosixSignalKick<const SIG: i32> {
    tid: libc::pthread_t,
    idle_exit: Arc<Mutex<Option<IdleRunExitByte>>>,
    kick_pending: Option<Arc<AtomicBool>>,
}

impl<const SIG: i32> PosixSignalKick<SIG> {
    /// Build a handle for the CURRENT thread without an explicit pending flag.
    pub fn for_current_thread() -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            idle_exit: Arc::new(Mutex::new(None)),
            kick_pending: None,
        }
    }

    /// Build a handle for the CURRENT thread with an explicit pending flag (used by bhyve).
    pub fn for_current_thread_with_pending(kick_pending: Arc<AtomicBool>) -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            idle_exit: Arc::new(Mutex::new(None)),
            kick_pending: Some(kick_pending),
        }
    }

    /// Return the resolved kick signal number.
    #[inline]
    pub fn kick_signal() -> i32 {
        resolve_kick_signal::<SIG>()
    }

    /// Publish the KVM_RUN byte before the scheduler's last runnable check.
    /// A kick after this point survives even if its signal precedes KVM_RUN.
    pub fn arm_idle_run(&self, immediate_exit: &mut u8) {
        let mut armed = self
            .idle_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *immediate_exit = 0;
        *armed = Some(IdleRunExitByte(immediate_exit as *mut u8));
    }

    /// Revoke the mapped-byte publication after KVM_RUN returns or idle is cancelled.
    pub fn disarm_idle_run(&self) {
        let mut armed = self
            .idle_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(byte) = armed.take() {
            // SAFETY: the pointer was published from the live vCPU's mmap and
            // the owner disarms it before that mapping can be recycled.
            unsafe { AtomicU8::from_ptr(byte.0).store(0, Ordering::SeqCst) };
        }
    }
}

impl<const SIG: i32> crate::VcpuKick for PosixSignalKick<SIG> {
    fn kick(&self) {
        if let Some(ref pending) = self.kick_pending {
            pending.store(true, Ordering::SeqCst);
        }
        let armed = self
            .idle_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(byte) = *armed {
            // SAFETY: the arm holds the vCPU mapping alive through disarm;
            // the mutex serializes this write with disarm and recycling.
            unsafe { AtomicU8::from_ptr(byte.0).store(1, Ordering::SeqCst) };
        }
        // SAFETY: pthread_kill with a live pthread id + a valid signal. ESRCH is ignored.
        unsafe {
            libc::pthread_kill(self.tid, resolve_kick_signal::<SIG>());
        }
    }
}
