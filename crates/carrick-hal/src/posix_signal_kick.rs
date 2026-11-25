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
// mutex. Its owner revokes its publication before the mapping is recycled or
// unmapped (`arm_run`'s contract, upheld through `RunPublication`).
unsafe impl Send for RunExitByte {}

/// One run byte that [`PosixSignalKick::arm_run`] published into a thread's
/// kick window. The byte's owner keeps this beside the mapping and revokes it
/// before the mapping is recycled or unmapped, so a window can never hold a
/// byte that is gone, whatever path (error, unwind, recycle) ended the run.
#[must_use = "the owner of the byte must revoke the publication before the byte goes away"]
pub struct RunPublication {
    window: RunWindow,
    byte: RunExitByte,
}

impl RunPublication {
    /// Withdraw the byte from its window, and clear it, if the window still
    /// holds it. A window since disarmed, or re-armed with another run's
    /// byte, is left as it is.
    pub fn revoke(&self) {
        let mut armed = lock_window(&self.window);
        if armed.is_some_and(|byte| std::ptr::eq(byte.0, self.byte.0)) {
            *armed = None;
            // SAFETY: `arm_run`'s contract keeps the byte mapped until this
            // publication is revoked; the window lock excludes kicks.
            unsafe { AtomicU8::from_ptr(self.byte.0).store(0, Ordering::SeqCst) };
        }
    }
}

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

/// One host thread's run window: the mapped `immediate_exit` byte of the run
/// currently admitting kicks on that thread, or `None` between runs.
///
/// Every [`PosixSignalKick`] for a thread shares this one window, so a kick
/// through any handle reaches the run that is armed now. The byte is the only
/// request record: it is published when a run is armed, read atomically when
/// the run's ioctl is interrupted, and cleared and unpublished when the run is
/// disarmed. A kick that lands while no run is armed records nothing; its
/// sender published the state it wants observed (`need_resched`, shutdown,
/// pending host work) before kicking, and the target's next pre-entry check
/// reads that state. No request outlives the run it targeted (#2962).
type RunWindow = Arc<Mutex<Option<RunExitByte>>>;

thread_local! {
    static CURRENT_THREAD_RUN_WINDOW: RunWindow = Arc::new(Mutex::new(None));
}

fn lock_window(
    window: &Mutex<Option<RunExitByte>>,
) -> std::sync::MutexGuard<'_, Option<RunExitByte>> {
    window.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// The current thread's view of one hypervisor run's kick window.
///
/// [`CurrentThreadRun::open`] publishes the run's mapped `immediate_exit`
/// byte unless a caller already armed one ([`PosixSignalKick::arm_run`]), in
/// which case the caller keeps ownership and disarms it. A window this guard
/// opened is disarmed when the guard drops, when the run returns.
pub struct CurrentThreadRun {
    window: RunWindow,
    byte: RunExitByte,
    owned: bool,
}

impl CurrentThreadRun {
    /// Admit kicks into the run whose `immediate_exit` byte is `byte`.
    ///
    /// # Safety
    /// `byte` must point at the live run structure of the vCPU this thread
    /// is about to run, and stay mapped until the returned guard drops.
    pub unsafe fn open(byte: *mut u8) -> Self {
        let window = CURRENT_THREAD_RUN_WINDOW.with(Arc::clone);
        let owned = {
            let mut armed = lock_window(&window);
            if armed.is_some() {
                false
            } else {
                // Not zeroed: a stopped owner may already have requested this
                // run's immediate exit (pending I/O completion, fixtures).
                *armed = Some(RunExitByte(byte));
                true
            }
        };
        Self {
            window,
            byte: RunExitByte(byte),
            owned,
        }
    }

    /// Whether a kick, or the owner, requested this run's immediate exit.
    /// An interrupted run that reads `false` was stopped by something Carrick
    /// did not request (a ptrace stop, `SIGSTOP`/`SIGCONT`, an unrelated
    /// signal) and may re-enter.
    pub fn exit_requested(&self) -> bool {
        // SAFETY: `open`'s contract keeps the byte mapped for this guard's
        // life; kicks write it only with atomic stores under the window lock.
        unsafe { AtomicU8::from_ptr(self.byte.0).load(Ordering::SeqCst) != 0 }
    }
}

impl Drop for CurrentThreadRun {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        let mut armed = lock_window(&self.window);
        if armed.take().is_some() {
            // SAFETY: see `exit_requested`; the window lock excludes kicks.
            unsafe { AtomicU8::from_ptr(self.byte.0).store(0, Ordering::SeqCst) };
        }
    }
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
    run_exit: RunWindow,
    kick_pending: Option<Arc<AtomicBool>>,
}

impl<const SIG: i32> PosixSignalKick<SIG> {
    /// Build a handle for the CURRENT thread without an explicit pending flag.
    pub fn for_current_thread() -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            run_exit: CURRENT_THREAD_RUN_WINDOW.with(Arc::clone),
            kick_pending: None,
        }
    }

    /// Build a handle for the CURRENT thread with an explicit pending flag (used by bhyve).
    pub fn for_current_thread_with_pending(kick_pending: Arc<AtomicBool>) -> Self {
        install_posix_kick_handler::<SIG>();
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            run_exit: CURRENT_THREAD_RUN_WINDOW.with(Arc::clone),
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
    ///
    /// The byte is shared with kicks from other threads, so it is taken only
    /// as an atomic.
    ///
    /// # Safety
    /// `immediate_exit` must stay mapped until the returned publication is
    /// revoked ([`RunPublication::revoke`]); [`Self::disarm_run`] alone does
    /// not end that duty, because a failed or unwound run may never reach it.
    pub unsafe fn arm_run(&self, immediate_exit: &AtomicU8) -> RunPublication {
        let mut armed = lock_window(&self.run_exit);
        // The window lock excludes concurrent kicks while it is cleared.
        immediate_exit.store(0, Ordering::SeqCst);
        let byte = RunExitByte(immediate_exit.as_ptr());
        *armed = Some(byte);
        RunPublication {
            window: Arc::clone(&self.run_exit),
            byte,
        }
    }

    /// Revoke the mapped-byte publication after KVM_RUN returns or entry is cancelled.
    pub fn disarm_run(&self) {
        let mut armed = lock_window(&self.run_exit);
        if let Some(byte) = armed.take() {
            // SAFETY: the pointer was published from the live vCPU's mmap and
            // the owner disarms it before that mapping can be recycled.
            unsafe { AtomicU8::from_ptr(byte.0).store(0, Ordering::SeqCst) };
        }
    }

    /// Observe the armed KVM byte from a deterministic pre-entry fixture.
    #[doc(hidden)]
    pub fn fixture_run_exit_byte(&self) -> Option<u8> {
        let armed = lock_window(&self.run_exit);
        armed.map(|byte| {
            // SAFETY: the arm keeps this mapping alive while the mutex guard
            // prevents concurrent disarm.
            unsafe { AtomicU8::from_ptr(byte.0).load(Ordering::SeqCst) }
        })
    }
}

impl<const SIG: i32> crate::VcpuKick for PosixSignalKick<SIG> {
    fn kick(&self) {
        if let Some(ref pending) = self.kick_pending {
            pending.store(true, Ordering::SeqCst);
        }
        let armed = lock_window(&self.run_exit);
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

    /// A kick that lands while its target has no run armed (it raced a
    /// completed exit and the disarm) records nothing for the next run, and a
    /// kick through any handle of a thread reaches the run armed now.
    #[test]
    fn a_kick_reaches_only_the_run_armed_when_it_lands() {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (step_tx, step_rx) = std::sync::mpsc::channel::<()>();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let armed_handle = PosixSignalKick::<0>::for_current_thread();
            let other_handle = PosixSignalKick::<0>::for_current_thread();
            handle_tx.send(other_handle).unwrap();
            let first = AtomicU8::new(0);
            // SAFETY: `first` outlives the publication, revoked below.
            let publication = unsafe { armed_handle.arm_run(&first) };
            armed_handle.disarm_run();
            // The kick lands here, between runs.
            seen_tx.send(()).unwrap();
            step_rx.recv().unwrap();
            let mut second = 0_u8;
            // SAFETY: `second` outlives the guard.
            let run = unsafe { CurrentThreadRun::open(&mut second) };
            let stale = run.exit_requested();
            seen_tx.send(()).unwrap();
            // The kick through the other handle lands in this run.
            step_rx.recv().unwrap();
            let live = run.exit_requested();
            drop(run);
            publication.revoke();
            (first.into_inner(), stale, live, second)
        });
        let handle = handle_rx.recv().unwrap();
        seen_rx.recv().unwrap();
        handle.kick();
        step_tx.send(()).unwrap();
        seen_rx.recv().unwrap();
        handle.kick();
        step_tx.send(()).unwrap();
        assert_eq!(
            worker.join().unwrap(),
            (0, false, true, 0),
            "a between-runs kick must not request the next run; a live kick must, and the window clears on close"
        );
    }

    /// A caller-armed run stays the caller's: a nested run window neither
    /// re-zeroes nor disarms it.
    #[test]
    fn a_caller_armed_run_keeps_its_owner() {
        let handle = PosixSignalKick::<0>::for_current_thread();
        let byte = AtomicU8::new(0);
        // SAFETY: `byte` outlives the publication, revoked below.
        let publication = unsafe { handle.arm_run(&byte) };
        std::thread::scope(|scope| {
            scope.spawn(|| handle.kick()).join().unwrap();
        });
        // SAFETY: `byte` outlives the guard.
        let run = unsafe { CurrentThreadRun::open(byte.as_ptr()) };
        assert!(run.exit_requested());
        drop(run);
        assert_eq!(handle.fixture_run_exit_byte(), Some(1));
        handle.disarm_run();
        assert_eq!(handle.fixture_run_exit_byte(), None);
        publication.revoke();
        assert_eq!(byte.into_inner(), 0);
    }

    /// A run that ends without reaching `disarm_run` (an error or an
    /// unwind) leaves its byte published until its owner revokes it; the
    /// revocation withdraws it, so a later kick writes nothing.
    #[test]
    fn revoking_a_publication_withdraws_a_byte_left_armed() {
        let handle = PosixSignalKick::<0>::for_current_thread();
        let byte = AtomicU8::new(0);
        // SAFETY: `byte` outlives the publication, revoked below.
        let publication = unsafe { handle.arm_run(&byte) };
        assert_eq!(handle.fixture_run_exit_byte(), Some(0));
        publication.revoke();
        assert_eq!(handle.fixture_run_exit_byte(), None);
        // A window re-armed with another byte is not the revoker's to clear.
        let other = AtomicU8::new(0);
        // SAFETY: `other` outlives the publication, revoked below.
        let current = unsafe { handle.arm_run(&other) };
        publication.revoke();
        assert_eq!(handle.fixture_run_exit_byte(), Some(0));
        current.revoke();
        assert_eq!(handle.fixture_run_exit_byte(), None);
    }
}
