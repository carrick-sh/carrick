//! bhyve glue for mirroring guest signal DISPOSITIONS onto real HOST routed
//! handlers — the FreeBSD mirror of [`carrick_linux::kvm_disposition`] (SP4.2).
//!
//! ## The gap this closes
//!
//! When pid-namespacing is OFF (the DEFAULT), a sibling guest process's
//! `kill(target, sig)` of a STANDARD catchable signal (SIGUSR1/SIGUSR2/SIGALRM/...)
//! does NOT take the cross-process xsignal ring — it falls through to a plain host
//! `libc::kill` (`dispatch/signal.rs`). On a bhyve guest a `fork` is a real
//! `libc::fork` (parent + child are SEPARATE host processes), so that host signal
//! lands on the receiver carrick process. With NO host disposition installed, the
//! host DEFAULT action runs — TERMINATING the receiver before its guest handler
//! (or SIG_IGN drop) ever runs.
//!
//! ## The fix (KVM/HVF-parallel)
//!
//! Mirror the guest's disposition onto a real HOST disposition:
//!   * guest handler -> host routed handler ([`bhyve_routed_handler`]) that
//!     publishes the guest signal into PROC_PENDING + pokes the pump;
//!   * guest `SIG_IGN` -> host `SIG_IGN`;
//!   * guest `SIG_DFL` -> host `SIG_DFL`;
//!   * guest `execve`  -> reset every mirrored disposition to default except the
//!     `ignored_mask` ones the new image keeps ignored.
//!
//! ## FreeBSD signum translation (the bhyve-specific difference)
//!
//! Unlike KVM (where host signum == guest signum), FreeBSD numbers several signals
//! differently from Linux. So the host `sigaction` is installed on the HOST signum
//! ([`bhyve_signum::linux_to_host_signum`]) while the routed handler — which fires
//! with the HOST signum — translates BACK to the Linux signum before touching the
//! neutral PROC_PENDING / record_sender state (keyed by Linux signum). The neutral
//! disposition POLICY (`carrick_signal_core::host_disposition`) is keyed by the
//! Linux signum throughout, shared with KVM/HVF.

use std::os::raw::c_int;

use carrick_signal_core::host_disposition;

use crate::bhyve_signum::{host_to_linux_signum, linux_to_host_signum};

/// Whether carrick has already CLAIMED `linux_signum` on bhyve — either for one of
/// bhyve's own delivery mechanisms OR as a process-wide runtime disposition — so
/// the disposition mirror must leave it alone:
///   * SIGHUP(1)/SIGINT(2)/SIGQUIT(3)/SIGTERM(15): the async host-signal PUMP
///     ([`crate::bhyve_signal_pump`]) catches these.
///   * SIGCHLD(17): the child-exit REAPER ([`crate::bhyve_signal_pump`]).
///   * SIGPIPE(13): carrick keeps a process-wide host `SIG_IGN` for its own
///     internal closed-pipe writes.
///   * the vCPU KICK (FreeBSD `SIGRTMIN` = 65) and the xsignal NUDGE (66): these
///     are HOST numbers above the Linux/guest range, so they can never be a guest
///     (Linux) signum here — but guard anyway for symmetry with KVM.
///
/// All are EXCLUDED from disposition mirroring. The argument is the GUEST (Linux)
/// signum (the dispatcher's ABI), matching the neutral policy's keying.
pub fn is_bhyve_claimed(linux_signum: i32) -> bool {
    // The four pumped process-directed signals (numbered identically on both).
    if matches!(linux_signum, 1 | 2 | 3 | 15) {
        return true;
    }
    // SIGCHLD (Linux 17): the reaper owns it.
    if linux_signum == carrick_abi::LINUX_SIGCHLD {
        return true;
    }
    // SIGPIPE (Linux 13): carrick owns a process-wide SIG_IGN for it.
    if linux_signum == carrick_abi::LINUX_SIGPIPE {
        return true;
    }
    // The reserved RT host numbers, defensively (they are above 31, so out of the
    // standard guest range that reaches disposition mirroring anyway).
    let kick = crate::bhyve_kicker::kick_signal();
    linux_signum == kick || linux_signum == kick + 1
}

/// Whether `linux_signum` is eligible for a mirrored host disposition on bhyve: the
/// SHARED neutral base policy ANDed with `!is_bhyve_claimed`.
fn bhyve_routable(linux_signum: i32) -> bool {
    host_disposition::is_host_routable(linux_signum) && !is_bhyve_claimed(linux_signum)
}

/// ASYNC-SIGNAL-SAFE host routed handler for a guest-caught STANDARD signal. A
/// sibling guest process `kill`ed us with the HOST signum; translate it back to the
/// guest (Linux) signum, then publish it as a pending guest signal + wake the pump.
/// Does ONLY:
///   1. translate host->Linux signum (pure arithmetic table lookup);
///   2. `record_sender(linux_signum, si_pid)` — one atomic store of the sender's
///      host pid (so the delivery path stamps the guest siginfo's `si_pid`);
///   3. `proc_pending_fetch_or(pending_bit(linux_signum))`;
///   4. `bhyve_signal_pump::poke()`.
///
/// NOTHING else (no locks, allocation, or `println!`).
extern "C" fn bhyve_routed_handler(
    host_signum: c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let linux_signum = host_to_linux_signum(host_signum);
    if !info.is_null() {
        // SAFETY: the kernel hands a valid siginfo_t to an SA_SIGINFO handler;
        // `si_pid()` reads the POSIX-defined union member. record_sender is one
        // atomic store — async-signal-safe.
        carrick_signal_core::record_sender(linux_signum, unsafe { (*info).si_pid() });
    }
    if let Some(bit) = carrick_signal_core::pending_bit(linux_signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    crate::bhyve_signal_pump::poke();
}

/// Install a host routed handler for `linux_signum` (translated to the host signum)
/// so a sibling guest process's host `kill` runs THIS guest's registered handler
/// rather than taking the host default action. Idempotent per signal; no-op for
/// non-routable / bhyve-claimed signals.
pub fn ensure_host_handler(linux_signum: i32) {
    if !bhyve_routable(linux_signum) {
        return;
    }
    if host_disposition::mark_installed(linux_signum) {
        return;
    }
    install_sigaction(
        linux_signum,
        bhyve_routed_handler as *const () as libc::sighandler_t,
    );
}

/// Mirror a guest `SIG_IGN` onto the HOST disposition so a sibling guest process's
/// host `kill` is DROPPED at the host level. No-op for non-routable / claimed signals.
pub fn set_host_ignore(linux_signum: i32) {
    if !bhyve_routable(linux_signum) {
        return;
    }
    install_sigaction(linux_signum, libc::SIG_IGN);
    // The host no longer ROUTES this signal; DROP the routed-handler bookkeeping so
    // a later SIG_IGN -> handler transition re-installs `bhyve_routed_handler`.
    host_disposition::clear_installed(linux_signum);
}

/// Reset a mirrored signal's HOST disposition back to `SIG_DFL`. Clears any host
/// `SIG_IGN` / routed handler mirrored earlier and possibly INHERITED across fork.
/// No-op for non-routable / claimed signals.
pub fn set_host_default(linux_signum: i32) {
    if !bhyve_routable(linux_signum) {
        return;
    }
    install_sigaction(linux_signum, libc::SIG_DFL);
    host_disposition::clear_installed(linux_signum);
}

/// Reset host dispositions installed only to route guest caught-signal handlers, as
/// a guest `execve` does (caught dispositions -> default; `SIG_IGN` preserved via
/// `ignored_mask`). `ignored_mask` is the dispatcher's caller ABI, indexed by bit
/// `signum` (NOT `signum-1`).
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    let installed = host_disposition::installed_mask();
    for linux_signum in 1..=64i32 {
        let install_bit = 1u64 << (linux_signum - 1);
        if installed & install_bit == 0 {
            continue;
        }
        if is_bhyve_claimed(linux_signum) {
            continue;
        }
        let ignored_bit = 1u64 << linux_signum;
        if ignored_mask & ignored_bit != 0 {
            continue;
        }
        install_sigaction(linux_signum, libc::SIG_DFL);
        host_disposition::clear_installed(linux_signum);
    }
}

/// Install `handler` (a routed handler fn, `SIG_IGN`, or `SIG_DFL`) as the host
/// disposition for the HOST signum derived from `linux_signum`. A routed handler
/// gets `SA_RESTART | SA_SIGINFO` (the 3-arg form — it reads `si_pid`);
/// `SIG_IGN`/`SIG_DFL` get no flags. The public fns above gate on `bhyve_routable`
/// (a Linux-signum predicate) first.
fn install_sigaction(linux_signum: i32, handler: libc::sighandler_t) {
    let host_signum = linux_to_host_signum(linux_signum);
    let is_action = handler != libc::SIG_IGN && handler != libc::SIG_DFL;
    // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask" form;
    // we set the handler + flags before calling libc. `host_signum` is a valid
    // FreeBSD signal number (the `bhyve_routable` gate guarantees the Linux source
    // is in 1..=64 and not claimed/uncatchable).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = if is_action {
            libc::SA_RESTART | libc::SA_SIGINFO
        } else {
            0
        };
        libc::sigaction(host_signum, &action, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pump_kick_nudge_sigchld_are_bhyve_claimed() {
        // Pumped (Linux numbers, identical to FreeBSD): HUP/INT/QUIT/TERM.
        for s in [1, 2, 3, 15] {
            assert!(is_bhyve_claimed(s), "pumped signal {s} must be claimed");
        }
        assert!(is_bhyve_claimed(17), "SIGCHLD (Linux 17) reaper is claimed");
        assert!(is_bhyve_claimed(13), "SIGPIPE (Linux 13) is claimed");
        let kick = crate::bhyve_kicker::kick_signal();
        assert!(is_bhyve_claimed(kick), "the kick (65) is claimed");
        assert!(is_bhyve_claimed(kick + 1), "the xsig nudge (66) is claimed");
    }

    #[test]
    fn standard_catchable_signals_are_routable() {
        // SIGUSR1(10)/SIGUSR2(12)/SIGALRM(14) Linux numbers: mirrorable, not claimed.
        for s in [10, 12, 14] {
            assert!(
                !is_bhyve_claimed(s),
                "standard signal {s} must not be claimed"
            );
            assert!(
                bhyve_routable(s),
                "standard signal {s} must be bhyve-routable"
            );
        }
    }

    #[test]
    fn bhyve_routable_excludes_claimed_and_faults() {
        // Not routable: the synchronous-fault set (neutral base excludes it).
        for s in [4, 5, 6, 7, 8, 11] {
            assert!(
                !bhyve_routable(s),
                "fault signum {s} must never be routable"
            );
        }
        // Not routable: uncatchable (Linux SIGKILL 9 / SIGSTOP 19).
        assert!(!bhyve_routable(9));
        assert!(!bhyve_routable(19));
        // Not routable: claimed.
        assert!(!bhyve_routable(15)); // SIGTERM (pump)
        assert!(!bhyve_routable(17)); // SIGCHLD (reaper)
        assert!(!bhyve_routable(13)); // SIGPIPE
    }

    /// The install path uses the HOST signum: a routable Linux SIGUSR1 (10) installs
    /// its host `sigaction` on FreeBSD 30, while the neutral install mask tracks the
    /// LINUX number (10). Round-trips install/ignore/default; restores host default.
    #[test]
    fn install_uses_host_signum_but_mask_tracks_linux() {
        const LINUX_USR1: i32 = 10;
        assert_eq!(linux_to_host_signum(LINUX_USR1), 30);
        assert!(bhyve_routable(LINUX_USR1));
        host_disposition::clear_installed(LINUX_USR1);

        ensure_host_handler(LINUX_USR1);
        assert!(
            host_disposition::is_installed(LINUX_USR1),
            "mask tracks the Linux signum"
        );
        // Idempotent second install.
        ensure_host_handler(LINUX_USR1);
        assert!(host_disposition::is_installed(LINUX_USR1));

        set_host_ignore(LINUX_USR1);
        assert!(
            !host_disposition::is_installed(LINUX_USR1),
            "ignore drops the routed-handler bit"
        );

        ensure_host_handler(LINUX_USR1);
        assert!(host_disposition::is_installed(LINUX_USR1));
        set_host_default(LINUX_USR1);
        assert!(
            !host_disposition::is_installed(LINUX_USR1),
            "default clears the install bit"
        );

        // Hermetic cleanup: restore the host default for FreeBSD 30 (SIGUSR1).
        set_host_default(LINUX_USR1);
        host_disposition::clear_installed(LINUX_USR1);
    }
}
