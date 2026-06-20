//! NVMM glue for the cross-process xsignal ring — now a thin forwarder to the
//! SHARED [`carrick_signal_core::host_glue`], parameterized by [`crate::NvmmGlue`].
//! (The runtime calls the shared `host_glue::xsig_nudge` directly after the #6
//! cfg-flip.)

use carrick_signal_core::HostSignalGlue;
use carrick_signal_core::host_glue;

use crate::NvmmGlue;

/// The host signal carrick uses to NUDGE a sibling process (the kick signal + 1).
pub fn nudge_signum() -> i32 {
    NvmmGlue::nudge_signum()
}

/// Whether `host_signum` is the xsignal nudge.
#[allow(dead_code)]
pub fn is_xsig_nudge(host_signum: i32) -> bool {
    host_signum == NvmmGlue::nudge_signum()
}

/// Nudge `target_host_pid` to drain its xsignal entries.
pub fn xsig_nudge(target_host_pid: i32) {
    host_glue::xsig_nudge::<NvmmGlue>(target_host_pid);
}

/// Install the nudge handler (idempotent via the shared `Once`).
pub fn install_xsig_nudge_handler() {
    host_glue::install_xsig_nudge_handler::<NvmmGlue>();
}

/// Initialise the xsignal ring + install the nudge handler. MUST run pre-fork.
pub fn init_xsig() {
    host_glue::init_xsig::<NvmmGlue>();
}
