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

/// Whether carrick has already CLAIMED `signum` on KVM — either for one of KVM's
/// own delivery mechanisms OR as a process-wide runtime disposition carrick-cli
/// owns — so the disposition mirror must leave it alone (the claiming owner
/// already delivers/handles it correctly):
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
///   * SIGPIPE(13): carrick-cli installs a process-wide host `SIG_IGN` for it
///     (`carrick-cli/src/main.rs`, `configure_process_environment`) so carrick's
///     OWN internal `write(2)`s to a closed pipe return EPIPE silently instead of
///     killing the process; the guest's pipe-write SIGPIPE is synthesised on the
///     syscall path. Mirroring a guest disposition onto host SIGPIPE here would
///     either clobber that ignore with a routed handler (re-routing carrick's own
///     EPIPE writes into the guest as a spurious SIGPIPE) or, worse, restore
///     SIG_DFL so carrick's next internal closed-pipe write KILLS the process.
///     HVF excludes SIGPIPE in its `ensure_host_handler` for the same reason.
///
/// All four pump signals, the kick, the nudge, SIGCHLD, and SIGPIPE are therefore
/// EXCLUDED from disposition mirroring. (SIGINT additionally is not host-routed by
/// HVF for the same "carrick keeps its own" reason; here the pump owns it.)
pub fn is_kvm_claimed(signum: i32) -> bool {
    // The four pumped process-directed signals.
    if matches!(
        signum,
        libc::SIGHUP | libc::SIGINT | libc::SIGQUIT | libc::SIGTERM
    ) {
        return true;
    }
    // SIGCHLD: the reaper owns it.
    if signum == libc::SIGCHLD {
        return true;
    }
    // SIGPIPE: carrick-cli owns a process-wide SIG_IGN for its own internal
    // closed-pipe writes; never mirror a guest disposition onto it.
    if signum == libc::SIGPIPE {
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
///   1. `record_sender(signum, si_pid)` — one atomic store of the sender's host
///      pid, so the delivery path can stamp the guest siginfo's `si_pid`
///      (mirrors HVF's `handle_routed`; without it LTP kill10's SA_SIGINFO
///      handshake handlers saw `si_pid == 0` — "received unexpected signal 10
///      from 0" — and the manager→master ready/done acks looped forever).
///      SI_USER/SI_QUEUE/SI_TKILL carry the real sender; `record_sender`
///      ignores a non-positive si_pid, so a kernel-generated code is inert.
///   2. `proc_pending_fetch_or(pending_bit(signum))` — a lock-free atomic OR into
///      PROC_PENDING (so `has_process_pending()` becomes true).
///   3. `kvm_signal_pump::poke()` — one `write(2)` to the pump's self-pipe, so the
///      pump's `kick_all` fans every vCPU out of `KVM_RUN`.
///
/// This is the existing [`crate::kvm_signal_pump`] `pump_handler` GENERALIZED to
/// an arbitrary routable signum (on Linux host signum == guest signum, so no
/// translation). NOTHING else (no locks, allocation, or `println!`).
///
/// Unlike HVF's `handle_routed` there is no synchronous-fault guard: the neutral
/// `is_host_routable` base excludes the fault set (4/5/6/7/8/11) from routing on
/// KVM, so this handler is never installed for a signal a genuine carrick host
/// fault could raise.
extern "C" fn kvm_routed_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    if !info.is_null() {
        // SAFETY: the kernel hands a valid siginfo_t to an SA_SIGINFO handler;
        // `si_pid()` reads the POSIX-defined union member (libc marks the
        // accessor unsafe only because it reads a union). record_sender is one
        // atomic store — async-signal-safe.
        carrick_signal_core::record_sender(signum, unsafe { (*info).si_pid() });
    }
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
    install_sigaction(
        signum,
        kvm_routed_handler as *const () as libc::sighandler_t,
    );
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
    // The host no longer ROUTES this signal (it's ignored), so DROP the
    // routed-handler bookkeeping. The INSTALLED bit means "we have a routed
    // handler installed", NOT "any non-default disposition": if the guest later
    // transitions SIG_IGN -> a real handler, `ensure_host_handler` must RE-INSTALL
    // `kvm_routed_handler` rather than early-return via its idempotency guard.
    // (Leaving the bit set would make that transition silently drop cross-process
    // kills — the host would stay SIG_IGN. HVF's `set_host_ignore` clears it too.)
    //
    // SIG_IGN survives `execve` natively (POSIX) and via the `ignored_mask` the
    // dispatcher passes to `reset_routed_handlers_after_execve`, so NOT tracking
    // SIG_IGN in the INSTALLED (routed-handler) mask is correct.
    host_disposition::clear_installed(signum);
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
/// interrupted host syscall restarts across delivery) plus `SA_SIGINFO` (the
/// routed handler is the 3-arg form — it reads `si_pid` to record the sender);
/// `SIG_IGN`/`SIG_DFL` get no flags. On Linux host signum == guest signum, so no
/// translation. Helper kept private; the public fns above gate on `kvm_routable`
/// first.
fn install_sigaction(signum: i32, handler: libc::sighandler_t) {
    let is_action = handler != libc::SIG_IGN && handler != libc::SIG_DFL;
    // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask" form;
    // we set the handler + flags before calling libc. `signum` is in 1..=64 (the
    // `kvm_routable` / install-mask gate guarantees it).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = if is_action {
            libc::SA_RESTART | libc::SA_SIGINFO
        } else {
            0
        };
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
        assert!(
            is_kvm_claimed(libc::SIGCHLD),
            "SIGCHLD reaper is KVM-claimed"
        );
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
            assert!(
                !is_kvm_claimed(s),
                "standard signal {s} must not be claimed"
            );
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
            assert!(
                !kvm_routable(s),
                "fault signum {s} must never be KVM-routable"
            );
        }
        // Not routable: uncatchable.
        assert!(!kvm_routable(9)); // SIGKILL
        assert!(!kvm_routable(19)); // SIGSTOP
    }

    /// Install / ignore / default round-trip through the real `sigaction` host
    /// syscall on a signal carrick does not otherwise use here. The INSTALLED bit
    /// means "a ROUTED HANDLER is installed" — so a routed handler SETS it, while
    /// `set_host_ignore`/`set_host_default` CLEAR it (the host no longer routes the
    /// signal). Restores the host default at the end so the test is hermetic.
    #[test]
    fn install_ignore_default_roundtrip_tracks_mask() {
        // Use SIGURG (23): routable, not claimed, and not otherwise touched by
        // carrick on this test thread.
        const SIG: i32 = 23;
        assert!(kvm_routable(SIG));
        host_disposition::clear_installed(SIG);

        ensure_host_handler(SIG);
        assert!(
            host_disposition::is_installed(SIG),
            "handler marks installed"
        );
        // Idempotent second install: still installed, no panic.
        ensure_host_handler(SIG);
        assert!(host_disposition::is_installed(SIG));

        // SIG_IGN means we no longer have a ROUTED handler installed: the bit is
        // CLEARED (so a later ignore->handler transition re-installs the route).
        set_host_ignore(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "ignore drops the routed-handler bit (it's no longer routed)"
        );

        // Re-route then SIG_DFL: default also clears the install bit.
        ensure_host_handler(SIG);
        assert!(
            host_disposition::is_installed(SIG),
            "re-install marks installed"
        );
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

        // Hermetic cleanup: restore the host default for SIGURG.
        set_host_default(SIG);
        host_disposition::clear_installed(SIG);
    }

    /// DEFECT 1 regression: SIGPIPE(13) must NOT be host-routed on KVM, because
    /// carrick-cli owns a process-wide host `SIG_IGN` for its OWN internal
    /// closed-pipe writes (carrick-cli/src/main.rs). It must be KVM-claimed so all
    /// four disposition fns are no-ops for it (the process-wide ignore is
    /// preserved). KVM's effective skip set is then a SUPERSET of HVF's
    /// `9 | 13 | 17 | 19` guard: 9/19 are excluded by the neutral `is_host_routable`
    /// base, and 13/17 by `is_kvm_claimed`.
    #[test]
    fn sigpipe_is_not_host_routed() {
        assert!(
            is_kvm_claimed(libc::SIGPIPE),
            "SIGPIPE must be KVM-claimed (carrick-cli owns its process-wide SIG_IGN)"
        );
        // Therefore not routable, so every disposition fn no-ops.
        assert!(
            !kvm_routable(libc::SIGPIPE),
            "SIGPIPE must never be KVM-routable"
        );

        // Each of the four disposition fns must be a no-op: they must not mark the
        // install mask nor (since kvm_routable gates first) touch the host
        // disposition. The observable proxy is the mask staying clear.
        host_disposition::clear_installed(libc::SIGPIPE);
        ensure_host_handler(libc::SIGPIPE);
        assert!(
            !host_disposition::is_installed(libc::SIGPIPE),
            "ensure_host_handler must not mirror SIGPIPE"
        );
        set_host_ignore(libc::SIGPIPE);
        assert!(
            !host_disposition::is_installed(libc::SIGPIPE),
            "set_host_ignore must not touch SIGPIPE"
        );
        set_host_default(libc::SIGPIPE);
        assert!(
            !host_disposition::is_installed(libc::SIGPIPE),
            "set_host_default must not touch SIGPIPE"
        );

        // The HVF parity check: KVM's effective skip set ⊇ {9, 13, 17, 19}.
        assert!(!kvm_routable(9), "SIGKILL excluded by is_host_routable");
        assert!(!kvm_routable(13), "SIGPIPE excluded by is_kvm_claimed");
        assert!(!kvm_routable(17), "SIGCHLD excluded by is_kvm_claimed");
        assert!(!kvm_routable(19), "SIGSTOP excluded by is_host_routable");
    }

    /// DEFECT 2 regression: a guest SIG_IGN -> real-handler transition must
    /// RE-INSTALL the routed handler. `set_host_ignore` clears the INSTALLED bit
    /// (the host is no longer routing), so the subsequent `ensure_host_handler`
    /// does NOT early-return via its idempotency guard — it installs
    /// `kvm_routed_handler` and the bit ends up SET. (If `set_host_ignore` left the
    /// bit marked, the transition would be silently skipped and cross-process kills
    /// would be dropped while the host stayed SIG_IGN.)
    #[test]
    fn ignore_then_handler_installs_routed() {
        const SIG: i32 = 10; // SIGUSR1 — routable, not claimed.
        assert!(kvm_routable(SIG));
        host_disposition::clear_installed(SIG);

        // Guest sets SIG_IGN first.
        set_host_ignore(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "set_host_ignore must clear the routed-handler bit"
        );

        // Guest then installs a real handler: the routed handler MUST be installed
        // (the transition is not skipped), so the INSTALLED bit ends up SET.
        ensure_host_handler(SIG);
        assert!(
            host_disposition::is_installed(SIG),
            "ignore->handler must re-install the routed handler (not early-return)"
        );

        // Hermetic cleanup.
        set_host_default(SIG);
        host_disposition::clear_installed(SIG);
    }

    /// execve-reset clears the routed (INSTALLED) dispositions except the
    /// `ignored_mask` ones (indexed by bit `signum`, the dispatcher ABI). The walk
    /// is over the routed-handler mask: a signal the new image keeps ignored stays
    /// in place; an ordinary routed handler is reset to host default.
    #[test]
    fn execve_reset_preserves_ignored_mask() {
        const SIG_KEEP: i32 = 10; // SIGUSR1 — kept ignored across execve
        const SIG_RESET: i32 = 12; // SIGUSR2 — reset to default
        host_disposition::clear_all();
        // Both carry a ROUTED handler (the INSTALLED bit) before execve. (A pure
        // SIG_IGN no longer tracks in INSTALLED — see `set_host_ignore` — and
        // survives execve natively, so it is not part of this reset walk.)
        ensure_host_handler(SIG_KEEP);
        ensure_host_handler(SIG_RESET);
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

    /// A pure SIG_IGN (no routed handler) is NOT tracked in the INSTALLED mask, so
    /// `reset_routed_handlers_after_execve` does not visit it and leaves the host
    /// `SIG_IGN` in place — which is exactly correct: SIG_IGN survives execve
    /// natively (POSIX), so carrick's mirrored host ignore should too.
    #[test]
    fn execve_reset_leaves_pure_sig_ign_untracked() {
        const SIG: i32 = 14; // SIGALRM — routable, not claimed.
        host_disposition::clear_all();
        set_host_ignore(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "a pure SIG_IGN is not tracked as a routed handler"
        );
        // The reset walk is a no-op for it (nothing to reset); host SIG_IGN stays.
        reset_routed_handlers_after_execve(0);
        assert!(!host_disposition::is_installed(SIG));
        // Hermetic cleanup: restore the host default.
        set_host_default(SIG);
        host_disposition::clear_all();
    }
}
