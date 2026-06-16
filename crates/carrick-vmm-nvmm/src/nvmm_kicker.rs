//! Cross-thread vCPU "kick" for the NVMM backend.
//!
//! The NetBSD/NVMM realisation of the "interrupt a running vCPU" primitive
//! (HVF has `hv_vcpus_exit`; KVM has `pthread_kill(tid, SIGRTMIN)` → `KVM_RUN`
//! EINTR). On NVMM the same vehicle applies: a signal delivered to a vCPU
//! thread makes the in-progress `nvmm_vcpu_run` return EINTR, which the
//! [`crate::nvmm_x86_engine`] run decode maps to [`carrick_x86::X86Exit::Kicked`].
//! The handler is empty and installed WITHOUT `SA_RESTART` so the kick is not
//! silently restarted.
//!
//! M1 (single-threaded hello) never issues a kick; this exists to satisfy the
//! [`carrick_x86::X86Vmm`] threaded-lifecycle surface. The bookkeeping registry
//! is the platform-neutral [`carrick_hal::GenericVcpuRegistry`] (same as KVM);
//! only [`NvmmKickHandle`] (the `pthread_kill` mechanism) is NVMM-specific.

use std::sync::Once;

/// NetBSD's `<sys/signal.h>` defines `SIGRTMIN` as 33. The Rust `libc` crate does
/// not expose that constant consistently, so keep the backend-local value here.
/// A real-time signal is reserved for carrick's own vCPU kick so it does not
/// collide with standard guest-routable signals like SIGUSR1/SIGUSR2.
const NETBSD_SIGRTMIN: i32 = 33;

/// The signal NVMM uses to force a vCPU out of `nvmm_vcpu_run`.
#[inline]
pub fn kick_signal() -> i32 {
    NETBSD_SIGRTMIN
}

/// Empty handler: its only purpose is to interrupt an in-progress
/// `nvmm_vcpu_run` (no `SA_RESTART`).
extern "C" fn nvmm_kick_noop(_signum: libc::c_int) {}

static KICK_HANDLER_INSTALLED: Once = Once::new();

pub fn install_nvmm_kick_handler() {
    KICK_HANDLER_INSTALLED.call_once(|| {
        // SAFETY: a zeroed sigaction is the documented "no flags, empty mask"
        // form; we set the handler fn, an empty mask, and sa_flags = 0 (NO
        // SA_RESTART). `nvmm_kick_noop` is a valid `extern "C"` handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = nvmm_kick_noop as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(kick_signal(), &action, std::ptr::null_mut());
        }
    });
}

/// A `Send`/`Sync` kick handle holding the owning vCPU thread's `pthread_t`.
#[derive(Clone)]
pub struct NvmmKickHandle {
    tid: libc::pthread_t,
}

impl NvmmKickHandle {
    /// Build a handle for the CURRENT thread (call on the owning vCPU thread).
    pub fn for_current_thread() -> Self {
        install_nvmm_kick_handler();
        // SAFETY: `pthread_self` is always safe; returns this thread's id.
        let tid = unsafe { libc::pthread_self() };
        Self { tid }
    }
}

impl carrick_hal::VcpuKick for NvmmKickHandle {
    fn kick(&self) {
        // SAFETY: pthread_kill with a live id + valid signal; ESRCH on a dead
        // thread is ignored (a missed kick is caught at the next trap boundary).
        unsafe {
            libc::pthread_kill(self.tid, kick_signal());
        }
    }

    fn target_in_guest(&self) -> bool {
        // The registry tracks in-guest state (set_in_guest / any_other_in_guest),
        // mirroring the KVM handle whose in-guest state lives in the registry.
        false
    }
}

/// The NVMM vCPU-kick registry — the platform-neutral
/// [`carrick_hal::GenericVcpuRegistry`] (no NVMM-specific registry logic).
pub type NvmmKicker = carrick_hal::GenericVcpuRegistry;
