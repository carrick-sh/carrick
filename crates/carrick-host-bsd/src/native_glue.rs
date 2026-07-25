//! The BSD **native (no-VMM) lane's** [`HostSignalGlue`].
//!
//! `carrick-runtime`'s non-macOS `host_signal` module resolves ONE
//! `ActiveGlue` type per build and every guest-facing signal operation
//! (`linux_to_host_signum`, `ensure_host_handler`, `set_host_default`,
//! `xsig_nudge`, …) is a generic call through it. On FreeBSD/x86_64 and
//! NetBSD/x86_64 that type is `carrick_vmm_bhyve::BhyveGlue` /
//! `carrick_vmm_nvmm::NvmmGlue` — which is fine there, because those builds
//! link the VMM crate anyway.
//!
//! On **FreeBSD/aarch64 and NetBSD/aarch64 there is no VMM crate at all**:
//! bhyve and NVMM virtualize the host ISA and are x86_64-only, so
//! `platform-freebsd` / `platform-netbsd` on arm64 select the native (DSR)
//! backend alone. `ActiveGlue` still has to resolve, and it has to resolve to
//! the REAL BSD signal policy — an identity-translating placeholder would
//! silently mis-target every divergent signal (a guest SIGUSR1 = Linux 10 sent
//! as host 10 = BSD `SIGBUS`).
//!
//! So this is that policy, sourced from the same single-source table
//! ([`crate::signum`]) the two VMM glues already delegate to, with no VMM
//! dependency. On the x86_64 BSD lanes both types are compiled and
//! `bhyve_signal_backend` / `nvmm_signal_backend` carry a test asserting they
//! agree on every signal number, so the two cannot drift.

#![cfg(any(target_os = "freebsd", target_os = "netbsd"))]

use carrick_signal_core::HostSignalGlue;

/// The native lane's kick signal: this OS's `SIGRTMIN`, used as a PAIR with
/// `+1` (kick, nudge).
///
/// FreeBSD's `SIGRTMIN` is 65 and NetBSD's is 33; neither libc reserves leading
/// real-time signals for pthread internals (a glibc-ism), so the pair is a
/// free, non-colliding channel. These are **OS** facts, not ISA facts, which is
/// why they are named here rather than in an amd64-gated module — and
/// `carrick-runtime` carries a `const` assertion tying this value to the native
/// host crate's `NATIVE_EXIT_KICK_SIGNAL` (the number the native run loop's
/// `pthread_kill` and kick redirect actually use) so the two cannot drift.
#[cfg(target_os = "freebsd")]
pub const NATIVE_KICK_SIGNAL: i32 = 65;
/// See the FreeBSD sibling above.
#[cfg(target_os = "netbsd")]
pub const NATIVE_KICK_SIGNAL: i32 = 33;

/// Zero-sized marker carrying the BSD native lane's host-signal policy.
pub struct BsdNativeGlue;

impl HostSignalGlue for BsdNativeGlue {
    fn kick_signal() -> i32 {
        NATIVE_KICK_SIGNAL
    }

    fn host_to_linux(host_signum: i32) -> i32 {
        crate::signum::host_to_linux_signum(host_signum)
    }

    fn linux_to_host(linux_signum: i32) -> i32 {
        crate::signum::linux_to_host_signum(linux_signum)
    }

    /// The same claimed set the bhyve and NVMM glues declare: signals with no
    /// BSD host carrier, the four pumped signals (1/2/3/15, numbered
    /// identically on both sides), the SIGCHLD reaper and SIGPIPE (by their
    /// LINUX numbers), and the reserved kick/nudge pair.
    fn is_claimed(linux_signum: i32) -> bool {
        if !crate::signum::linux_signum_has_host_carrier(linux_signum) {
            return true;
        }
        if matches!(linux_signum, 1 | 2 | 3 | 15) {
            return true;
        }
        if linux_signum == carrick_abi::LINUX_SIGCHLD {
            return true;
        }
        if linux_signum == carrick_abi::LINUX_SIGPIPE {
            return true;
        }
        linux_signum == NATIVE_KICK_SIGNAL || linux_signum == NATIVE_KICK_SIGNAL + 1
    }

    fn poke() {
        carrick_hal::signal_pump::poke();
    }

    /// Deliberately a no-op: on the native lane the kick signal's handler is
    /// the lane's OWN assembly redirect, installed by
    /// `carrick_native_{freebsd,netbsd}::fault::install_kick_redirect` at lane
    /// setup — a stub that resumes the interrupted JIT frame, not a plain
    /// `EINTR` no-op. The VMM glues install a bare no-op here because their
    /// kick only has to `EINTR` a `vm_run`/`nvmm_vcpu_run` ioctl; installing
    /// that bare handler on this lane would REPLACE the redirect stub and
    /// strand a kicked guest thread. Doing nothing cannot break the lane's own
    /// handler; installing one can.
    fn install_kick_handler() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kick and the nudge must be distinct, BOTH inside this OS's real-time
    /// range (`<sys/signal.h>`: FreeBSD `SIGRTMIN`=65/`SIGRTMAX`=126, NetBSD
    /// 33/63 — read off both guests), and both claimed, i.e. never mirrored onto
    /// a guest disposition. A nudge that fell off the end of the RT range would
    /// be an ordinary signal the glue silently reserves.
    #[test]
    fn the_kick_nudge_pair_is_distinct_claimed_and_real_time() {
        #[cfg(target_os = "freebsd")]
        let rt_range = 65..=126;
        #[cfg(target_os = "netbsd")]
        let rt_range = 33..=63;

        let kick = BsdNativeGlue::kick_signal();
        let nudge = BsdNativeGlue::nudge_signum();
        assert_ne!(kick, nudge);
        assert!(rt_range.contains(&kick), "kick {kick} outside {rt_range:?}");
        assert!(
            rt_range.contains(&nudge),
            "nudge {nudge} outside {rt_range:?}"
        );
        assert!(BsdNativeGlue::is_claimed(kick));
        assert!(BsdNativeGlue::is_claimed(nudge));
    }

    /// Translation is the shared BSD table, not identity: the divergent
    /// signals must actually diverge, or a guest SIGUSR1 lands on host SIGBUS.
    #[test]
    fn translation_is_the_shared_bsd_table_and_round_trips() {
        assert_eq!(BsdNativeGlue::linux_to_host(10), 30); // SIGUSR1
        assert_eq!(BsdNativeGlue::linux_to_host(17), 20); // SIGCHLD
        assert_eq!(BsdNativeGlue::host_to_linux(30), 10);
        assert_eq!(BsdNativeGlue::host_to_linux(20), 17);
        for linux in 1..=31 {
            if !crate::signum::linux_signum_has_host_carrier(linux) {
                continue;
            }
            let host = BsdNativeGlue::linux_to_host(linux);
            assert_eq!(
                BsdNativeGlue::host_to_linux(host),
                linux,
                "linux {linux} -> host {host} did not round-trip"
            );
        }
    }

    /// The pumped set, the reaper and SIGPIPE are claimed; an ordinary guest
    /// signal is not (or the disposition mirror would stop working).
    #[test]
    fn the_claimed_set_covers_the_pumped_signals_but_not_ordinary_ones() {
        for pumped in [1, 2, 3, 15] {
            assert!(BsdNativeGlue::is_claimed(pumped), "signal {pumped}");
        }
        assert!(BsdNativeGlue::is_claimed(carrick_abi::LINUX_SIGCHLD));
        assert!(BsdNativeGlue::is_claimed(carrick_abi::LINUX_SIGPIPE));
        assert!(!BsdNativeGlue::is_claimed(10)); // SIGUSR1
        assert!(!BsdNativeGlue::is_claimed(12)); // SIGUSR2
    }
}
