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
struct RunExitByte(*mut u8);

// SAFETY: the mapped KVM byte is installed and removed under the run-kick
// mutex. Its owner does not recycle the vCPU until after removal.
unsafe impl Send for RunExitByte {}

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

thread_local! {
    static CURRENT_THREAD_KICK_PENDING: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

/// Consume whether a [`PosixSignalKick`] targeted the current host thread.
///
/// External host stops (`ptrace` attach/interrupt, `SIGSTOP`/`SIGCONT`) and
/// unrelated signals (`SIGCHLD`, `SIGWINCH`) also make hypervisor run ioctls
/// return `EINTR`, without setting this flag.
#[inline]
pub fn take_current_thread_kick_pending() -> bool {
    CURRENT_THREAD_KICK_PENDING.with(|pending| pending.swap(false, Ordering::SeqCst))
}

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
    run_exit: Arc<Mutex<Option<RunExitByte>>>,
    thread_pending: Arc<AtomicBool>,
    kick_pending: Option<Arc<AtomicBool>>,
}

impl<const SIG: i32> PosixSignalKick<SIG> {
    /// Build a handle for the CURRENT thread without an explicit pending flag.
    pub fn for_current_thread() -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            run_exit: Arc::new(Mutex::new(None)),
            thread_pending: CURRENT_THREAD_KICK_PENDING.with(Arc::clone),
            kick_pending: None,
        }
    }

    /// Build a handle for the CURRENT thread with an explicit pending flag (used by bhyve).
    pub fn for_current_thread_with_pending(kick_pending: Arc<AtomicBool>) -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            run_exit: Arc::new(Mutex::new(None)),
            thread_pending: CURRENT_THREAD_KICK_PENDING.with(Arc::clone),
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
    pub fn arm_run(&self, immediate_exit: &mut u8) {
        let mut armed = self
            .run_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *immediate_exit = 0;
        *armed = Some(RunExitByte(immediate_exit as *mut u8));
    }

    /// Revoke the mapped-byte publication after KVM_RUN returns or entry is cancelled.
    pub fn disarm_run(&self) {
        let mut armed = self
            .run_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(byte) = armed.take() {
            // SAFETY: the pointer was published from the live vCPU's mmap and
            // the owner disarms it before that mapping can be recycled.
            unsafe { AtomicU8::from_ptr(byte.0).store(0, Ordering::SeqCst) };
        }
    }

    /// Observe the armed KVM byte from a deterministic pre-entry fixture.
    #[doc(hidden)]
    pub fn fixture_run_exit_byte(&self) -> Option<u8> {
        let armed = self
            .run_exit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        armed.map(|byte| {
            // SAFETY: the arm keeps this mapping alive while the mutex guard
            // prevents concurrent disarm.
            unsafe { AtomicU8::from_ptr(byte.0).load(Ordering::SeqCst) }
        })
    }
}

impl<const SIG: i32> crate::VcpuKick for PosixSignalKick<SIG> {
    fn kick(&self) {
        self.thread_pending.store(true, Ordering::SeqCst);
        if let Some(ref pending) = self.kick_pending {
            pending.store(true, Ordering::SeqCst);
        }
        let armed = self
            .run_exit
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::VcpuKick;

    #[test]
    fn unrequested_signal_leaves_current_thread_kick_pending_clear_while_kick_sets_only_target_thread()
     {
        let _ = take_current_thread_kick_pending();
        // SAFETY: SIGCONT's POSIX default action is ignore when not stopped.
        assert_eq!(unsafe { libc::raise(libc::SIGCONT) }, 0);
        assert!(
            !take_current_thread_kick_pending(),
            "an external signal must not manufacture a pending vCPU kick"
        );

        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (kicked_tx, kicked_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = take_current_thread_kick_pending();
            let handle = PosixSignalKick::<0>::for_current_thread();
            handle_tx.send(handle).unwrap();
            kicked_rx.recv().unwrap();
            let first = take_current_thread_kick_pending();
            let second = take_current_thread_kick_pending();
            (first, second)
        });
        let handle = handle_rx.recv().unwrap();
        handle.kick();
        assert!(
            !take_current_thread_kick_pending(),
            "kicking a target thread must not mark the sender thread kicked"
        );
        kicked_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), (true, false));
    }
}
