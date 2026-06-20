//! KVM glue for mirroring guest signal DISPOSITIONS onto real HOST routed handlers
//! — now a thin forwarder to the SHARED [`carrick_signal_core::host_glue`],
//! parameterized by [`crate::KvmGlue`]. The routed-handler body, the install mask
//! control flow, and the `sigaction` install are all shared; KVM's only input is
//! `KvmGlue` (identity translation + the claimed-signal set). (The runtime calls
//! `host_glue::ensure_host_handler` etc. directly after the #6 cfg-flip.)

use carrick_signal_core::HostSignalGlue;
use carrick_signal_core::host_glue;

use crate::KvmGlue;

/// Whether carrick has already CLAIMED `signum` on KVM (pump/kick/nudge/SIGCHLD/
/// SIGPIPE) — the disposition mirror leaves it alone. See [`KvmGlue::is_claimed`].
pub fn is_kvm_claimed(signum: i32) -> bool {
    KvmGlue::is_claimed(signum)
}

/// Install a host routed handler for `signum` so a sibling's host `kill` runs the
/// guest handler instead of host-default terminating us. Idempotent; no-op for
/// non-routable / KVM-claimed signals.
pub fn ensure_host_handler(signum: i32) {
    host_glue::ensure_host_handler::<KvmGlue>(signum);
}

/// Mirror a guest `SIG_IGN` onto the host (a sibling's kill is dropped).
pub fn set_host_ignore(signum: i32) {
    host_glue::set_host_ignore::<KvmGlue>(signum);
}

/// Reset a mirrored signal's host disposition to `SIG_DFL`.
pub fn set_host_default(signum: i32) {
    host_glue::set_host_default::<KvmGlue>(signum);
}

/// Reset routed dispositions across a guest `execve` (caught -> default; the
/// `ignored_mask` ones preserved).
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    host_glue::reset_routed_handlers_after_execve::<KvmGlue>(ignored_mask);
}
