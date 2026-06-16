//! NVMM glue for the shared cross-process explicit-signal ring.
//!
//! The neutral ring lives in `carrick_signal_core::xsig`; NVMM owns only the
//! NetBSD nudge signal and the async-safe handler that marks the ring dirty and
//! wakes the host-signal pump.

use std::os::raw::c_int;
use std::sync::Once;

use crate::nvmm_kicker::kick_signal;

#[inline]
pub fn nudge_signum() -> i32 {
    kick_signal() + 1
}

#[allow(dead_code)]
pub fn is_xsig_nudge(host_signum: i32) -> bool {
    host_signum == nudge_signum()
}

pub fn xsig_nudge(target_host_pid: i32) {
    // SAFETY: kill(2) with a pid and valid signal. ESRCH for a dead target is a
    // harmless lost wake; the target has already exited.
    unsafe {
        libc::kill(target_host_pid, nudge_signum());
    }
}

extern "C" fn xsig_nudge_handler(_sig: c_int) {
    carrick_signal_core::xsig::mark_xsig_dirty();
    crate::nvmm_signal_pump::poke();
}

static NUDGE_HANDLER_INSTALLED: Once = Once::new();

pub fn install_xsig_nudge_handler() {
    NUDGE_HANDLER_INSTALLED.call_once(|| {
        // SAFETY: zeroed sigaction is the documented empty action form. The
        // handler is async-signal-safe and installed without SA_RESTART so a
        // direct nudge can also interrupt `nvmm_vcpu_run`.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = xsig_nudge_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(nudge_signum(), &action, std::ptr::null_mut());
        }
    });
}

pub fn init_xsig() {
    carrick_signal_core::xsig::xsig_init();
    install_xsig_nudge_handler();
}
