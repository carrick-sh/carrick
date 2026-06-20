//! bhyve glue for mirroring guest signal DISPOSITIONS onto real HOST routed
//! handlers — now a thin forwarder to the SHARED [`carrick_signal_core::host_glue`],
//! parameterized by [`crate::BhyveGlue`]. The routed-handler body, the install
//! mask control flow, and the `sigaction` install (on the translated HOST signum)
//! are all shared; bhyve's only input is `BhyveGlue` (the FreeBSD signum table +
//! the claimed-signal set). (The runtime calls `host_glue::ensure_host_handler`
//! etc. directly after the #6 cfg-flip.)

use carrick_signal_core::HostSignalGlue;
use carrick_signal_core::host_glue;

use crate::BhyveGlue;

/// Whether carrick has already CLAIMED `linux_signum` on bhyve (pump/kick/nudge/
/// SIGCHLD/SIGPIPE). See [`BhyveGlue::is_claimed`].
pub fn is_bhyve_claimed(linux_signum: i32) -> bool {
    BhyveGlue::is_claimed(linux_signum)
}

/// Install a host routed handler (on the translated host signum) so a sibling's
/// host `kill` runs the guest handler. Idempotent; no-op for non-routable /
/// bhyve-claimed signals.
pub fn ensure_host_handler(linux_signum: i32) {
    host_glue::ensure_host_handler::<BhyveGlue>(linux_signum);
}

/// Mirror a guest `SIG_IGN` onto the host.
pub fn set_host_ignore(linux_signum: i32) {
    host_glue::set_host_ignore::<BhyveGlue>(linux_signum);
}

/// Reset a mirrored signal's host disposition to `SIG_DFL`.
pub fn set_host_default(linux_signum: i32) {
    host_glue::set_host_default::<BhyveGlue>(linux_signum);
}

/// Reset routed dispositions across a guest `execve`.
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    host_glue::reset_routed_handlers_after_execve::<BhyveGlue>(ignored_mask);
}
