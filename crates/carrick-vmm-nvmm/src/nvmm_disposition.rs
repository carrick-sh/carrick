//! NVMM glue for mirroring guest signal dispositions onto NetBSD host handlers —
//! now a thin forwarder to the SHARED [`carrick_signal_core::host_glue`],
//! parameterized by [`crate::NvmmGlue`]. (The runtime calls
//! `host_glue::ensure_host_handler` etc. directly after the #6 cfg-flip.)

use carrick_signal_core::HostSignalGlue;
use carrick_signal_core::host_glue;

use crate::NvmmGlue;

/// Whether carrick has already CLAIMED `linux_signum` on NVMM. See
/// [`NvmmGlue::is_claimed`].
pub fn is_nvmm_claimed(linux_signum: i32) -> bool {
    NvmmGlue::is_claimed(linux_signum)
}

/// Install a host routed handler (on the translated host signum).
pub fn ensure_host_handler(linux_signum: i32) {
    host_glue::ensure_host_handler::<NvmmGlue>(linux_signum);
}

/// Mirror a guest `SIG_IGN` onto the host.
pub fn set_host_ignore(linux_signum: i32) {
    host_glue::set_host_ignore::<NvmmGlue>(linux_signum);
}

/// Reset a mirrored signal's host disposition to `SIG_DFL`.
pub fn set_host_default(linux_signum: i32) {
    host_glue::set_host_default::<NvmmGlue>(linux_signum);
}

/// Reset routed dispositions across a guest `execve`.
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    host_glue::reset_routed_handlers_after_execve::<NvmmGlue>(ignored_mask);
}
