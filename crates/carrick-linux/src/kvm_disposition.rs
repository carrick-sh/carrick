//! KVM glue for mirroring guest signal DISPOSITIONS onto real HOST routed
//! handlers (cross-process STANDARD-signal delivery — Task 6).
//!
//! ## The gap this closes
//!
//! When pid-namespacing is OFF (the DEFAULT — only OCI/`carrick run` containers
//! create one), a sibling guest process's `kill(target, sig)` of a STANDARD
//! catchable signal (SIGUSR1/SIGUSR2/SIGALRM/...) does NOT take the cross-process
//! xsignal ring — it falls through to a plain host `libc::kill` of the host
//! signum (`dispatch/signal.rs`). On a KVM guest a `fork` is a real `libc::fork`
//! (parent + child are SEPARATE host processes), so that host signal lands on the
//! receiver carrick process. With NO host disposition installed, the host DEFAULT
//! action runs — TERMINATING the receiver before its guest handler (or SIG_IGN
//! drop) ever runs. That is the CPython `test_interprocess_signal` / LTP kill02
//! bug.
//!
//! ## The fix (HVF-parallel)
//!
//! Mirror the guest's disposition onto a real HOST disposition:
//!   * guest installs a handler -> install a host routed handler ([`kvm_routed_handler`])
//!     that publishes the guest signal into PROC_PENDING + pokes the pump, so the
//!     generic loop runs the guest handler;
//!   * guest `SIG_IGN`  -> host `SIG_IGN`  (a sibling kill is dropped by the host);
//!   * guest `SIG_DFL`  -> host `SIG_DFL`  (clear an inherited host ignore/route);
//!   * guest `execve`   -> reset every mirrored disposition to default except the
//!     `ignored_mask` ones the new image keeps ignored.
//!
//! The disposition POLICY (the idempotency mask + WHICH signals are routable) is
//! the platform-NEUTRAL `carrick_signal_core::host_disposition`, shared with HVF.
//! This module owns only the KVM-specific GLUE: the routed handler body, the
//! `libc::sigaction` install, and the additional [`is_kvm_claimed`] exclusion for
//! signals KVM already delivers via another mechanism.
//!
//! ## What KVM must NOT clobber
//!
//! KVM already owns several host signals for its OWN mechanisms; host-routing one
//! of them here would BREAK that mechanism (e.g. installing a routed handler over
//! the pump's SIGTERM handler would stop the pump fanning SIGTERM to the guest).
//! [`is_kvm_claimed`] enumerates them; a claimed signal is a NO-OP here (the
//! existing mechanism already delivers it correctly). Faults are never routable
//! (the neutral `is_host_routable` excludes them) — they arrive as EL0-fault
//! vmexits, not host kills.

use std::os::raw::c_int;

use carrick_signal_core::host_disposition;

/// Whether KVM has already CLAIMED `signum` for one of its own mechanisms, so the
/// disposition mirror must leave it alone (the claiming mechanism already
/// delivers/handles it correctly):
///   * SIGHUP(1)/SIGINT(2)/SIGQUIT(3)/SIGTERM(15): the async host-signal PUMP
///     ([`crate::kvm_signal_pump`]) catches these, fans them into PROC_PENDING,
///     and kicks the vCPUs so the generic loop runs the guest handler. Installing
///     `kvm_routed_handler` over the pump's handler would break the pump.
///   * `libc::SIGRTMIN()`: the vCPU KICK ([`crate::kvm_kicker`]) — a no-op handler
///     that only EINTRs `KVM_RUN`.
///   * `libc::SIGRTMIN()+1`: the xsignal NUDGE ([`crate::kvm_xsig`]) — marks the
///     ring dirty + pokes the pump.
///   * SIGCHLD(17): the child-exit REAPER ([`crate::kvm_signal_pump`]) — its own
///     handler pokes the pump, whose thread `waitid`-peeks tracked children.
///
/// All four pump signals, the kick, the nudge, and SIGCHLD are therefore EXCLUDED
/// from disposition mirroring. (SIGINT additionally is not host-routed by HVF for
/// the same "carrick keeps its own" reason; here the pump owns it.)
pub fn is_kvm_claimed(signum: i32) -> bool {
    // The four pumped process-directed signals.
    if matches!(signum, libc::SIGHUP | libc::SIGINT | libc::SIGQUIT | libc::SIGTERM) {
        return true;
    }
    // SIGCHLD: the reaper owns it.
    if signum == libc::SIGCHLD {
        return true;
    }
    // The two RT signals carrick reserves: the kick (SIGRTMIN) and the xsignal
    // nudge (SIGRTMIN+1). `SIGRTMIN()` is a libc fn (the runtime base differs).
    let rtmin = libc::SIGRTMIN();
    signum == rtmin || signum == rtmin + 1
}

/// Whether `signum` is eligible for a mirrored host disposition on KVM: the
/// SHARED neutral base policy ANDed with `!is_kvm_claimed` (KVM's own additional
/// exclusions). The single gate every disposition fn below consults.
fn kvm_routable(signum: i32) -> bool {
    host_disposition::is_host_routable(signum) && !is_kvm_claimed(signum)
}

/// ASYNC-SIGNAL-SAFE host routed handler for a guest-caught STANDARD signal. A
/// sibling guest process `kill`ed us with `signum` (the host-kill path); publish
/// it as a pending guest signal and wake the pump so the generic loop delivers
/// the guest's handler at its next safe point. Does ONLY:
///   1. `proc_pending_fetch_or(pending_bit(signum))` — a lock-free atomic OR into
///      PROC_PENDING (so `has_process_pending()` becomes true).
///   2. `kvm_signal_pump::poke()` — one `write(2)` to the pump's self-pipe, so the
///      pump's `kick_all` fans every vCPU out of `KVM_RUN`.
/// This is the existing [`crate::kvm_signal_pump`] `pump_handler` GENERALIZED to
/// an arbitrary routable signum (on Linux host signum == guest signum, so no
/// translation). NOTHING else (no locks, allocation, or `println!`).
///
/// si_pid fidelity (the sender pid for the guest siginfo) is NOT captured here:
/// the SI_USER siginfo for a cross-process standard kill is best-effort and the
/// dispatcher's `kill` arm already records the local-send case; a future
/// SA_SIGINFO variant could `record_sender` for full fidelity, but the fixture
/// does not require it.
extern "C" fn kvm_routed_handler(signum: c_int) {
    if let Some(bit) = carrick_signal_core::pending_bit(signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    crate::kvm_signal_pump::poke();
}

/// Install a host routed handler for `signum` so a sibling guest process's host
/// `kill` runs THIS guest's registered handler rather than taking the host
/// default action (which would terminate the carrick process). Idempotent per
/// signal (the shared neutral install mask). No-op for signals that are not
/// routable or that KVM already claims for another mechanism.
pub fn ensure_host_handler(signum: i32) {
    if !kvm_routable(signum) {
        return;
    }
    // Idempotent: a second install of the same signum is a no-op.
    if host_disposition::mark_installed(signum) {
        return;
    }
    install_sigaction(signum, kvm_routed_handler as *const () as libc::sighandler_t);
}

/// Mirror a guest `SIG_IGN` onto the HOST disposition so a sibling guest
/// process's host `kill` is DROPPED at the host level (honoring the guest's
/// ignore) instead of taking the host default action. No-op for non-routable /
/// KVM-claimed signals.
pub fn set_host_ignore(signum: i32) {
    if !kvm_routable(signum) {
        return;
    }
    install_sigaction(signum, libc::SIG_IGN);
    // Mark installed so a later `set_host_default` knows to clear it (and so the
    // execve-reset visits it). A re-ignore is harmless.
    let _ = host_disposition::mark_installed(signum);
}

/// Reset a mirrored signal's HOST disposition back to `SIG_DFL` (the guest reset
/// it to default). Clears any host `SIG_IGN` / routed handler mirrored earlier
/// and possibly INHERITED across fork, so the host no longer swallows the signal.
/// No-op for non-routable / KVM-claimed signals.
pub fn set_host_default(signum: i32) {
    if !kvm_routable(signum) {
        return;
    }
    install_sigaction(signum, libc::SIG_DFL);
    host_disposition::clear_installed(signum);
}

/// Reset host dispositions installed only to route guest caught-signal handlers,
/// as a guest `execve` does (caught dispositions -> default; `SIG_IGN` preserved).
/// Because carrick does not host-exec, the host process would otherwise keep
/// catching/ignoring those signals after the emulated disposition was gone.
///
/// Walks the SHARED neutral install mask; for each installed signal NOT set in
/// `ignored_mask`, reset the host to `SIG_DFL` and clear the install bit; for the
/// `ignored_mask` ones leave the host disposition (the new image keeps them
/// ignored). `ignored_mask` is the dispatcher's caller ABI, indexed by bit
/// `signum` (NOT `signum-1`) — see `reset_signal_handlers_on_execve`.
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    let installed = host_disposition::installed_mask();
    // The neutral mask is bit `signum-1`; iterate signums and test that bit.
    for signum in 1..=64i32 {
        let install_bit = 1u64 << (signum - 1);
        if installed & install_bit == 0 {
            continue;
        }
        // KVM-claimed signals are never in the install mask (the disposition fns
        // skip them), but guard anyway so a future claim can't be clobbered.
        if is_kvm_claimed(signum) {
            continue;
        }
        let ignored_bit = 1u64 << signum;
        if ignored_mask & ignored_bit != 0 {
            // The new image keeps this signal ignored: leave the host SIG_IGN and
            // the install bit in place.
            continue;
        }
        install_sigaction(signum, libc::SIG_DFL);
        host_disposition::clear_installed(signum);
    }
}

/// Install `handler` (a routed handler fn, `SIG_IGN`, or `SIG_DFL`) as the host
/// disposition for `signum`. A routed handler gets `SA_RESTART` (so an
/// interrupted host syscall restarts across delivery); `SIG_IGN`/`SIG_DFL` get no
/// flags. On Linux host signum == guest signum, so no translation. Helper kept
/// private; the public fns above gate on `kvm_routable` first.
fn install_sigaction(signum: i32, handler: libc::sighandler_t) {
    let is_action = handler != libc::SIG_IGN && handler != libc::SIG_DFL;
    // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask" form;
    // we set the handler + flags before calling libc. `signum` is in 1..=64 (the
    // `kvm_routable` / install-mask gate guarantees it).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = if is_action { libc::SA_RESTART } else { 0 };
        libc::sigaction(signum, &action, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pump_kick_nudge_sigchld_are_kvm_claimed() {
        for s in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            assert!(is_kvm_claimed(s), "pumped signal {s} must be KVM-claimed");
        }
        assert!(is_kvm_claimed(libc::SIGCHLD), "SIGCHLD reaper is KVM-claimed");
        assert!(is_kvm_claimed(libc::SIGRTMIN()), "the kick is KVM-claimed");
        assert!(
            is_kvm_claimed(libc::SIGRTMIN() + 1),
            "the xsig nudge is KVM-claimed"
        );
    }

    #[test]
    fn standard_catchable_signals_are_not_kvm_claimed() {
        // SIGUSR1(10)/SIGUSR2(12)/SIGALRM(14): mirrorable, not claimed.
        for s in [10, 12, 14] {
            assert!(!is_kvm_claimed(s), "standard signal {s} must not be claimed");
        }
    }

    #[test]
    fn kvm_routable_excludes_claimed_and_faults() {
        // Routable: standard catchable, not claimed.
        assert!(kvm_routable(10), "SIGUSR1 is KVM-routable");
        assert!(kvm_routable(12), "SIGUSR2 is KVM-routable");
        // Not routable: KVM-claimed pump/kick/nudge/reaper.
        assert!(!kvm_routable(libc::SIGTERM));
        assert!(!kvm_routable(libc::SIGCHLD));
        assert!(!kvm_routable(libc::SIGRTMIN()));
        // Not routable: the synchronous-fault set (neutral base excludes it).
        for s in [4, 5, 6, 7, 8, 11] {
            assert!(!kvm_routable(s), "fault signum {s} must never be KVM-routable");
        }
        // Not routable: uncatchable.
        assert!(!kvm_routable(9)); // SIGKILL
        assert!(!kvm_routable(19)); // SIGSTOP
    }

    /// Install / ignore / default round-trip through the real `sigaction` host
    /// syscall on a signal carrick does not otherwise use here. Asserts the shared
    /// install mask tracks the disposition and `set_host_default` clears it, then
    /// restores the host default so the test is hermetic.
    #[test]
    fn install_ignore_default_roundtrip_tracks_mask() {
        // Use SIGURG (23): routable, not claimed, and not otherwise touched by
        // carrick on this test thread.
        const SIG: i32 = 23;
        assert!(kvm_routable(SIG));
        host_disposition::clear_installed(SIG);

        ensure_host_handler(SIG);
        assert!(host_disposition::is_installed(SIG), "handler marks installed");
        // Idempotent second install: still installed, no panic.
        ensure_host_handler(SIG);
        assert!(host_disposition::is_installed(SIG));

        set_host_ignore(SIG);
        assert!(host_disposition::is_installed(SIG), "ignore keeps it tracked");

        set_host_default(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "default clears the install bit"
        );

        // A claimed signal is a no-op (never marks installed).
        host_disposition::clear_installed(libc::SIGTERM);
        ensure_host_handler(libc::SIGTERM);
        assert!(
            !host_disposition::is_installed(libc::SIGTERM),
            "a KVM-claimed signal must not be mirrored"
        );
    }

    /// execve-reset clears the routed dispositions except the `ignored_mask` ones
    /// (indexed by bit `signum`, the dispatcher ABI).
    #[test]
    fn execve_reset_preserves_ignored_mask() {
        const SIG_KEEP: i32 = 10; // SIGUSR1 — kept ignored across execve
        const SIG_RESET: i32 = 12; // SIGUSR2 — reset to default
        host_disposition::clear_all();
        set_host_ignore(SIG_KEEP);
        set_host_ignore(SIG_RESET);
        assert!(host_disposition::is_installed(SIG_KEEP));
        assert!(host_disposition::is_installed(SIG_RESET));

        // ignored_mask keeps SIG_KEEP ignored (bit `signum`, NOT signum-1).
        let ignored_mask = 1u64 << SIG_KEEP;
        reset_routed_handlers_after_execve(ignored_mask);

        assert!(
            host_disposition::is_installed(SIG_KEEP),
            "an ignored-across-execve signal keeps its mirrored disposition"
        );
        assert!(
            !host_disposition::is_installed(SIG_RESET),
            "a non-ignored signal is reset to host default"
        );
        // Hermetic cleanup.
        set_host_default(SIG_KEEP);
        host_disposition::clear_all();
    }
}
