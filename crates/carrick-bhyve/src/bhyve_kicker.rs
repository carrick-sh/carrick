//! bhyve vCPU kick: a `pthread_kill(SIGRTMIN)` makes an in-flight `vm_run`
//! return `EINTR` (handler installed WITHOUT `SA_RESTART`), which `run_x86`
//! maps to `X86Exit::Kicked` → `next_syscall` returns `Ok(None)`. Mirrors the
//! KVM kicker; the only host difference is FreeBSD's `SIGRTMIN` is a const.

use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

static KICK_HANDLER_INSTALLED: Once = Once::new();

/// The kick signal. On FreeBSD `SIGRTMIN` is a fixed `#define` of 65 in
/// `<sys/signal.h>` (FreeBSD does NOT reserve real-time signals for the C
/// library's threading internals the way glibc does, so there is no runtime
/// `SIGRTMIN()` to call — unlike the KVM/Linux kicker). The `libc` crate does
/// not expose the constant for FreeBSD, so we mirror the system header value
/// directly. A real-time signal is chosen so it never collides with a signal
/// carrick routes to the guest.
const FREEBSD_SIGRTMIN: i32 = 65;

#[inline]
pub fn kick_signal() -> i32 {
    FREEBSD_SIGRTMIN
}

extern "C" fn bhyve_kick_noop(_signum: libc::c_int) {}

/// Install the kick-signal handler (idempotent). NO `SA_RESTART`.
pub fn install_bhyve_kick_handler() {
    KICK_HANDLER_INSTALLED.call_once(|| {
        // SAFETY: zeroed sigaction is the "no flags, empty mask" form; we set a
        // valid extern "C" handler, empty mask, sa_flags = 0.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = bhyve_kick_noop as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0; // NO SA_RESTART
            libc::sigaction(kick_signal(), &action, std::ptr::null_mut());
        }
    });
}

/// A `Send`/`Sync`/`Clone` handle to a vCPU thread, kickable from any thread.
#[derive(Clone)]
pub struct BhyveKickHandle {
    tid: libc::pthread_t,
    in_guest: Option<Arc<AtomicBool>>,
    /// Set by `kick()` BEFORE the `pthread_kill`. A pthread_kill makes the
    /// in-flight `vm_run` exit with `VM_EXITCODE_BOGUS` (a pending thread AST →
    /// `vm_exit_astpending`), NOT `EINTR`. This flag lets `next_syscall` tell
    /// OUR kick from a spurious VT-x BOGUS: if set on a BOGUS exit, return to
    /// the generic loop (Ok(None)); else re-enter the guest.
    kick_pending: Arc<AtomicBool>,
}

impl BhyveKickHandle {
    /// Build a handle for the CURRENT thread (call on the owning vCPU thread).
    /// `kick_pending` is the engine-owned flag the kick raises and that
    /// `next_syscall` clears on a requested-kick BOGUS exit.
    pub fn for_current_thread(kick_pending: Arc<AtomicBool>) -> Self {
        install_bhyve_kick_handler();
        // SAFETY: pthread_self is always safe.
        let tid = unsafe { libc::pthread_self() };
        Self {
            tid,
            in_guest: None,
            kick_pending,
        }
    }
}

impl carrick_hal::VcpuKick for BhyveKickHandle {
    fn kick(&self) {
        // A pthread_kill makes vm_run exit with VM_EXITCODE_BOGUS (astpending),
        // NOT EINTR; the flag lets next_syscall tell our kick from a spurious
        // VT-x BOGUS. Raise it BEFORE the signal so it is observable on the exit.
        self.kick_pending.store(true, Ordering::SeqCst);
        // SAFETY: pthread_kill with a live id + valid signal. ESRCH is ignored.
        unsafe {
            libc::pthread_kill(self.tid, kick_signal());
        }
    }

    fn target_in_guest(&self) -> bool {
        self.in_guest
            .as_ref()
            .map(|f| f.load(Ordering::SeqCst))
            .unwrap_or(false)
    }
}

/// The bhyve registry of live vCPUs is the platform-neutral GenericVcpuRegistry.
pub type BhyveKicker = carrick_hal::GenericVcpuRegistry;
