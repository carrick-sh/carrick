//! Platform-NEUTRAL host-disposition mirroring policy, shared by every backend.
//!
//! WHAT THIS IS FOR. When pid-namespacing is OFF (the DEFAULT — a namespace is
//! only created for OCI/`carrick run` containers), a sibling guest process's
//! `kill(target, sig)` of a STANDARD catchable signal does NOT take the
//! cross-process xsignal ring — it falls through to a plain host `libc::kill` of
//! the host signum. Since carrick's guest `fork` is a real `libc::fork` (parent
//! and child are SEPARATE host processes), that host signal lands on the receiver
//! carrick process. If the receiver installed NO host disposition for it, the
//! host DEFAULT action runs — which for most signals TERMINATES the receiver,
//! before the guest's own handler (or SIG_IGN drop) ever runs. That is the
//! CPython `test_interprocess_signal` / LTP kill02 bug.
//!
//! The fix (on both backends) is to MIRROR the guest's disposition onto a real
//! HOST routed handler / ignore / default, so a sibling's host `kill` runs the
//! guest handler (or is dropped, honoring SIG_IGN) instead of killing us. This
//! module owns the PLATFORM-NEUTRAL half of that policy so the HVF and KVM glue
//! cannot drift:
//!   * `INSTALLED_MASK` — the per-signum idempotency bitmask (so an install is a
//!     no-op if already installed), plus its `mark/clear/is/installed/clear_all`
//!     helpers.
//!   * [`is_host_routable`] — WHICH signals are eligible for a mirrored host
//!     disposition (the base policy). Each backend ANDs in its OWN additional
//!     exclusions (e.g. the KVM glue skips signals it has already claimed for the
//!     pump / kick / nudge / SIGCHLD reaper — see `is_kvm_claimed` in the KVM
//!     glue; HVF keeps its own per-signum skip set in its install code).
//!
//! The backend GLUE (the actual `libc::sigaction` install / ignore / default, the
//! routed handler body, and the number translation) stays per-backend: HVF needs
//! a Linux<->macOS `SIGNUM_XLATE`; KVM is identity (host Linux signum == guest
//! Linux signum). Only the policy CONSTANTS / mask logic are shared here.

use std::sync::atomic::{AtomicU64, Ordering};

/// Bitmask of Linux signums for which a host disposition has been mirrored, so an
/// install / ignore is idempotent per signal. Bit `n` (1..=64) = signum `n`. This
/// is the SHARED idempotency state both backends consult, so the two cannot drift
/// on which signals are considered "already routed". `fetch_or`/`fetch_and` are
/// used so a concurrent install never loses a bit.
static INSTALLED_MASK: AtomicU64 = AtomicU64::new(0);

/// Mark `signum` as having a mirrored host disposition. Returns `true` iff the bit
/// was ALREADY set (so the caller can early-return as an idempotent no-op). A
/// `signum` outside 1..=64 is ignored and reported as "already installed" so the
/// caller skips it.
pub fn mark_installed(signum: i32) -> bool {
    let Some(bit) = pending_bit(signum) else {
        return true;
    };
    INSTALLED_MASK.fetch_or(bit, Ordering::SeqCst) & bit != 0
}

/// Clear the installed bit for `signum` (the guest reset it to default, or an
/// execve reset dropped its routing). Out-of-range signums are ignored.
pub fn clear_installed(signum: i32) {
    if let Some(bit) = pending_bit(signum) {
        INSTALLED_MASK.fetch_and(!bit, Ordering::SeqCst);
    }
}

/// Whether `signum` currently has a mirrored host disposition installed.
pub fn is_installed(signum: i32) -> bool {
    match pending_bit(signum) {
        Some(bit) => INSTALLED_MASK.load(Ordering::SeqCst) & bit != 0,
        None => false,
    }
}

/// The full installed bitmask (bit `signum-1`). Used by the execve-reset walk to
/// visit exactly the installed signals.
pub fn installed_mask() -> u64 {
    INSTALLED_MASK.load(Ordering::SeqCst)
}

/// Clear ALL installed bits (fork / supervisor-fork reset, so a child does not
/// inherit the parent's mirrored-disposition bookkeeping).
pub fn clear_all() {
    INSTALLED_MASK.store(0, Ordering::SeqCst);
}

/// Bit for `signum` (`1 << (signum-1)`), or `None` if out of 1..=64. Local copy
/// so this leaf policy module has no cross-module dependency.
fn pending_bit(signum: i32) -> Option<u64> {
    (1..=64).contains(&signum).then(|| 1u64 << (signum - 1))
}

/// The BASE policy of WHICH signals get a mirrored host disposition. Returns
/// `true` for standard catchable signals that a sibling's host `kill` could
/// otherwise terminate us with (SIGUSR1/SIGUSR2/SIGALRM/SIGPIPE/the job-control
/// set/etc.). Returns `false` — SKIP, do not touch the host disposition — for
/// signals that are uncatchable or already owned by another mechanism:
///
///   * SIGKILL(9) / SIGSTOP(19): cannot be caught, blocked, or ignored.
///   * SIGCONT(18): job-control resume; carrick keeps the host default so a real
///     stop/cont still works (it is not an async kill we must route).
///   * The SYNCHRONOUS-FAULT set SIGILL(4)/SIGTRAP(5)/SIGABRT(6)/SIGBUS(7)/
///     SIGFPE(8)/SIGSEGV(11): these arrive as guest VMEXITS / carrick faults, NOT
///     host kills. Their host disposition is SHARED between a genuine carrick
///     fault and an async kill; host-routing one would make a real fault
///     re-execute forever (or swallow a genuine carrick crash). A cross-process
///     instance of these is dropped at the dispatch layer instead.
///   * Out of range (`<1 || >64`).
///
/// NOTE: this is the SHARED BASE policy only. Each backend layers its OWN
/// additional exclusions on top (the KVM glue ANDs in `!is_kvm_claimed(signum)`
/// to skip the pump/kick/nudge/SIGCHLD signals it already delivers correctly;
/// HVF keeps its own per-signum skip set — SIGINT/SIGPIPE/SIGCHLD — in its
/// install code). The base set here is the floor both agree on.
pub fn is_host_routable(signum: i32) -> bool {
    if !(1..=64).contains(&signum) {
        return false;
    }
    // 4/5/6/7/8/11 = synchronous-fault set; 9 = SIGKILL; 18 = SIGCONT;
    // 19 = SIGSTOP. All skipped (see the doc comment above).
    !matches!(signum, 4 | 5 | 6 | 7 | 8 | 9 | 11 | 18 | 19)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_catchable_signals_are_routable() {
        // The signals a sibling's host kill could otherwise terminate us with.
        for sig in [
            10, /*SIGUSR1*/
            12, /*SIGUSR2*/
            14, /*SIGALRM*/
            13, /*SIGPIPE*/
        ] {
            assert!(
                is_host_routable(sig),
                "signum {sig} should be host-routable"
            );
        }
        // Job-control SIGTSTP/SIGTTIN/SIGTTOU are routable (a guest may mirror an
        // ignore onto them, e.g. a job-control shell).
        for sig in [
            20, /*SIGTSTP*/
            21, /*SIGTTIN*/
            22, /*SIGTTOU*/
        ] {
            assert!(is_host_routable(sig), "job-control signum {sig} routable");
        }
    }

    #[test]
    fn uncatchable_and_claimed_signals_are_not_routable() {
        // Uncatchable / job-control-owned.
        assert!(!is_host_routable(9), "SIGKILL must never be host-routed");
        assert!(!is_host_routable(19), "SIGSTOP must never be host-routed");
        assert!(!is_host_routable(18), "SIGCONT keeps its host default");
        // The synchronous-fault set arrives as vmexits, never host kills.
        for sig in [
            4,  /*ILL*/
            5,  /*TRAP*/
            6,  /*ABRT*/
            7,  /*BUS*/
            8,  /*FPE*/
            11, /*SEGV*/
        ] {
            assert!(
                !is_host_routable(sig),
                "fault signum {sig} must never be host-routed"
            );
        }
    }

    #[test]
    fn out_of_range_signums_are_not_routable() {
        assert!(!is_host_routable(0));
        assert!(!is_host_routable(-1));
        assert!(!is_host_routable(65));
        assert!(!is_host_routable(1000));
    }

    #[test]
    fn installed_mask_mark_clear_roundtrip() {
        clear_all();
        assert!(!is_installed(10));
        assert_eq!(installed_mask(), 0);
        // First mark: not already installed.
        assert!(!mark_installed(10));
        assert!(is_installed(10));
        assert_eq!(installed_mask(), 1u64 << (10 - 1));
        // Second mark: already installed (idempotent no-op signal).
        assert!(mark_installed(10));
        // A different signum coexists.
        assert!(!mark_installed(12));
        assert!(is_installed(10) && is_installed(12));
        // Clear one; the other survives.
        clear_installed(10);
        assert!(!is_installed(10));
        assert!(is_installed(12));
        // clear_all wipes everything.
        clear_all();
        assert_eq!(installed_mask(), 0);
        assert!(!is_installed(12));
    }

    #[test]
    fn out_of_range_mark_is_inert_and_reports_installed() {
        clear_all();
        // Out-of-range marks report "already installed" (skip) and never set a bit.
        assert!(mark_installed(0));
        assert!(mark_installed(65));
        assert_eq!(installed_mask(), 0);
        assert!(!is_installed(0));
        clear_installed(0); // inert, must not panic
        clear_all();
    }
}
