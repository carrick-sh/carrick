//! The one BSD-family `linux <-> host` signal-number translation table.
//!
//! ## Why a table at all
//!
//! A guest signal number is a **Linux** signal number (the guest ABI carrick
//! emulates). When carrick must reach the real **host** kernel — `libc::kill` of
//! a sibling carrick process, `libc::raise` on a forked-child death, mirroring a
//! guest disposition onto a host `sigaction`, decoding a host `wait4` status — it
//! must use the **host** kernel's number. On Linux those are identical (the KVM
//! backend uses pure identity). **The BSDs use BSD signal numbering**, which
//! differs from Linux for several signals, so an identity map silently mis-targets
//! them (e.g. a guest SIGUSR1 = Linux 10 sent as host 10 = `SIGBUS` on a BSD).
//!
//! ## One table for the whole BSD family
//!
//! macOS, FreeBSD, NetBSD, OpenBSD and DragonFly all share the SAME BSD signal
//! numbering, so this is ONE table for the family — previously triplicated as
//! `carrick_hvf::host_signal::SIGNUM_XLATE` (macOS) and
//! `carrick_bhyve::bhyve_signum::SIGNUM_XLATE` (FreeBSD), entry-for-entry equal.
//! Derived clean-room from the BSD host header `<sys/signal.h>` (host-API side —
//! allowed) and the Linux numbers from `signal(7)` (already baked into carrick).
//! Only the divergent signals appear; every other signal (the 1..15 control set,
//! SIGKILL, SIGSEGV, SIGPIPE, SIGALRM, SIGTERM, the RT range 32..=64) is identity.
//!
//! | Signal   | Linux | BSD |
//! |----------|-------|-----|
//! | SIGBUS   | 7     | 10  |
//! | SIGUSR1  | 10    | 30  |
//! | SIGUSR2  | 12    | 31  |
//! | SIGCHLD  | 17    | 20  |
//! | SIGCONT  | 18    | 19  |
//! | SIGSTOP  | 19    | 17  |
//! | SIGTSTP  | 20    | 18  |
//! | SIGURG   | 23    | 16  |
//! | SIGIO    | 29    | 23  |
//! | SIGSYS   | 31    | 12  |

/// The divergent `(linux, bsd_host)` pairs. Every signal NOT listed maps
/// identically. Shared by every BSD host (macOS / FreeBSD / NetBSD / OpenBSD /
/// DragonFly) because they share BSD signal numbering.
pub const SIGNUM_XLATE: &[(i32, i32)] = &[
    (7, 10),  // SIGBUS
    (10, 30), // SIGUSR1
    (12, 31), // SIGUSR2
    (17, 20), // SIGCHLD
    (18, 19), // SIGCONT
    (19, 17), // SIGSTOP
    (20, 18), // SIGTSTP
    (23, 16), // SIGURG
    (29, 23), // SIGIO / SIGPOLL
    (31, 12), // SIGSYS
];

/// Translate a Linux (guest) signal number to the BSD host number. Identity for
/// any signal not in [`SIGNUM_XLATE`] (the control set, faults, SIGKILL,
/// SIGTERM, SIGALRM, the RT range 32..=64 — all numbered the same on both).
#[inline]
pub fn linux_to_host_signum(linux: i32) -> i32 {
    SIGNUM_XLATE
        .iter()
        .find(|&&(l, _)| l == linux)
        .map(|&(_, h)| h)
        .unwrap_or(linux)
}

/// Translate a BSD host signal number back to its Linux (guest) number. Identity
/// for any host number not in [`SIGNUM_XLATE`].
#[inline]
pub fn host_to_linux_signum(host: i32) -> i32 {
    SIGNUM_XLATE
        .iter()
        .find(|&&(_, h)| h == host)
        .map(|&(l, _)| l)
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The divergent set round-trips both directions through the table.
    #[test]
    fn divergent_signals_roundtrip() {
        for &(linux, bsd) in SIGNUM_XLATE {
            assert_eq!(
                linux_to_host_signum(linux),
                bsd,
                "linux {linux} -> bsd {bsd}"
            );
            assert_eq!(
                host_to_linux_signum(bsd),
                linux,
                "bsd {bsd} -> linux {linux}"
            );
        }
    }

    /// Spot-check the values that bite hardest (SIGUSR1/2, SIGCHLD): a guest
    /// SIGUSR1 (Linux 10) must NOT be sent as host 10 (= BSD SIGBUS).
    #[test]
    fn usr1_usr2_chld_match_bsd_header() {
        assert_eq!(linux_to_host_signum(10), 30, "Linux SIGUSR1 -> BSD 30");
        assert_eq!(linux_to_host_signum(12), 31, "Linux SIGUSR2 -> BSD 31");
        assert_eq!(linux_to_host_signum(17), 20, "Linux SIGCHLD -> BSD 20");
        // The headline footgun: identity would have sent SIGUSR1 as SIGBUS(10).
        assert_ne!(linux_to_host_signum(10), 10);
    }

    /// Signals numbered identically on both kernels stay identity (control set,
    /// faults, SIGKILL, SIGTERM, SIGALRM, the whole RT range).
    #[test]
    fn shared_numbering_stays_identity() {
        for s in [1, 2, 3, 4, 5, 6, 8, 9, 11, 13, 14, 15, 32, 33, 34, 40, 64] {
            assert_eq!(linux_to_host_signum(s), s, "signum {s} must be identity");
            assert_eq!(host_to_linux_signum(s), s, "signum {s} must be identity");
        }
    }
}
