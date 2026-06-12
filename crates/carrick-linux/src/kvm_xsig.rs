//! KVM glue for the cross-process explicit-signal ring ("xsignal ring").
//!
//! ## Why a ring, not a native `rt_sigqueueinfo`
//!
//! A KVM guest `fork` is a real `libc::fork()`: parent and child are SEPARATE
//! host processes, each a hypervisor driving its own guest. A native
//! `rt_sigqueueinfo` of the *guest* signum to a sibling host process does NOT
//! deliver into that sibling's guest — the host process is carrick, not the
//! guest. Worse, it is actively harmful: `SIGRTMIN` collides with the vCPU kick
//! ([`crate::kvm_kicker::kick_signal`], whose no-op handler drops siginfo);
//! other numbers have no host handler (default action terminates the receiver);
//! and a fault signal (SIGSEGV/SIGBUS/…) would swallow a genuine carrick crash.
//!
//! So carrick uses the SAME shared-memory ring HVF uses. The neutral ring core
//! lives in [`carrick_signal_core::xsig`] (the `MAP_SHARED|MAP_ANON` ring,
//! inherited across `fork`, so every carrick process shares ONE ring). This
//! module owns only the KVM GLUE:
//!   * the nudge SIGNAL number ([`nudge_signum`]),
//!   * the `kill`-the-target nudge ([`xsig_nudge`]),
//!   * the async-signal-safe nudge handler ([`xsig_nudge_handler`]) that marks
//!     the ring dirty + wakes the signal pump, and
//!   * the idempotent init/install ([`init_xsig`]).
//!
//! The sender writes a ring slot and `kill`s the target with the NUDGE signal —
//! a pure wakeup that NEVER injects itself as a guest signal. The receiver's
//! nudge handler sets the ring dirty flag and pokes the pump (so every vCPU is
//! kicked out of `KVM_RUN`); the runtime then drains the ring in dispatch
//! context and re-injects each guest signal WITH the sender's siginfo
//! (preserving `si_value`).

use std::os::raw::c_int;
use std::sync::Once;

/// The host signal carrick uses to NUDGE a sibling process to drain its xsignal
/// ring. Must differ from:
///   * the vCPU kick ([`crate::kvm_kicker::kick_signal`] = `SIGRTMIN`): a nudge
///     landing on `SIGRTMIN` would fire the kick no-op, which does NOT mark the
///     ring dirty — so `xsig_has_pending()` would stay false and the drain be
///     skipped; and
///   * the pump's host signals (`SIGHUP`/`SIGINT`/`SIGQUIT`/`SIGTERM`, see
///     [`crate::kvm_signal_pump`]): the pump handler would mark THAT number as a
///     pending GUEST signal.
///
/// `SIGRTMIN+1` satisfies both. It is fine if the guest ALSO uses
/// guest-signal-`SIGRTMIN+1`: guest signals travel in the RING; the host nudge
/// signal is ONLY ever a wakeup — its handler never injects itself as a guest
/// signal.
#[inline]
pub fn nudge_signum() -> i32 {
    libc::SIGRTMIN() + 1
}

/// Whether the host signal `host_signum` is the xsignal nudge. Parity with HVF.
#[allow(dead_code)]
pub fn is_xsig_nudge(host_signum: i32) -> bool {
    host_signum == nudge_signum()
}

/// Nudge `target_host_pid` to drain its xsignal entries (host `SIGRTMIN+1`).
pub fn xsig_nudge(target_host_pid: i32) {
    // SAFETY: kill(2) with a pid and a valid signal. A nudge to a dead pid
    // returns ESRCH, which we ignore (the slot the sender wrote is simply never
    // drained — the same outcome as the receiver having already exited).
    unsafe {
        libc::kill(target_host_pid, nudge_signum());
    }
}

/// The xsignal nudge handler: a sibling carrick process queued a guest signal
/// for us in the shared ring. ASYNC-SIGNAL-SAFE ONLY — it does exactly two
/// things, both safe from a signal handler:
///   1. `mark_xsig_dirty()` — a single atomic store (sets the ring dirty flag),
///      so `xsig_has_pending()` becomes true and the dispatcher drains the ring.
///   2. `kvm_signal_pump::poke()` — one `write(2)` to the pump's self-pipe, so
///      the pump's `kick_all` fans every vCPU out of `KVM_RUN` and each re-checks
///      pending at its safe point (`deliver_pending_signal`).
///
/// NOTHING else (no locks, allocation, or `println!`).
extern "C" fn xsig_nudge_handler(_sig: c_int) {
    carrick_signal_core::xsig::mark_xsig_dirty();
    crate::kvm_signal_pump::poke();
}

/// Guards the one-time install of the nudge `sigaction`.
static NUDGE_HANDLER_INSTALLED: Once = Once::new();

/// Install the [`nudge_signum`] handler ONCE (idempotent). Installed with
/// `sa_flags = 0` — crucially WITHOUT `SA_RESTART`, like the kick — so a nudge
/// that lands DIRECTLY on a vCPU thread also EINTRs its in-progress `KVM_RUN`
/// (the pump poke covers the common case; the direct-EINTR is a belt-and-braces
/// fast path). The mask is empty.
pub fn install_xsig_nudge_handler() {
    NUDGE_HANDLER_INSTALLED.call_once(|| {
        // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask"
        // form; we set the handler fn, an empty mask, and sa_flags = 0 (NO
        // SA_RESTART). `xsig_nudge_handler` is a valid `extern "C"` handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = xsig_nudge_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0; // NO SA_RESTART — a direct nudge must EINTR KVM_RUN.
            libc::sigaction(nudge_signum(), &action, std::ptr::null_mut());
        }
    });
}

/// Initialise the xsignal ring + install the nudge handler. Idempotent. MUST run
/// pre-fork so the `MAP_SHARED` ring is created before `libc::fork` and inherited
/// by every child (see [`crate::kvm_fork_coord::KvmForkCoordinator`], which calls
/// this from `ensure_handler_installed`). `xsig_init` no-ops on an already-mapped
/// (e.g. inherited) ring, and the handler install is `Once`-guarded, so the
/// post-fork re-assert is free.
pub fn init_xsig() {
    carrick_signal_core::xsig::xsig_init();
    install_xsig_nudge_handler();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nudge signal must be DISTINCT from the vCPU kick (`SIGRTMIN`): a nudge
    /// landing on the kick number would fire the no-op kick handler, which never
    /// marks the ring dirty, so the drain would be skipped.
    #[test]
    fn nudge_distinct_from_kick() {
        assert_ne!(
            nudge_signum(),
            libc::SIGRTMIN(),
            "the xsig nudge must not collide with the vCPU kick signal"
        );
    }

    /// The nudge signal must be DISTINCT from every pumped host signal
    /// (SIGHUP/INT/QUIT/TERM): those numbers are marked as PENDING GUEST signals
    /// by the pump handler, which is wrong for a pure wakeup.
    #[test]
    fn nudge_distinct_from_pump_signals() {
        for &s in &[libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            assert_ne!(
                nudge_signum(),
                s,
                "the xsig nudge must not collide with a pumped host signal"
            );
        }
    }

    /// `is_xsig_nudge` recognises the nudge number and rejects the kick number.
    #[test]
    fn is_xsig_nudge_matches_only_the_nudge() {
        assert!(is_xsig_nudge(nudge_signum()));
        assert!(!is_xsig_nudge(libc::SIGRTMIN()));
    }
}
