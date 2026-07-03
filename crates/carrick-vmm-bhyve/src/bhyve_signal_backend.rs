//! bhyve's [`HostSignalGlue`] — the ~15-line backend seam the shared host-signal
//! driver (`carrick_signal_core::host_glue` + `carrick_hal::signal_pump`) is
//! generic over. Unlike KVM, bhyve runs on FreeBSD, whose host signal numbers
//! differ from Linux for several signals, so the translation methods consult the
//! `bhyve_signum` table (the SAME shared code then services both the identity and
//! translated paths). The irreducible vCPU KICK lives in `crate::bhyve_kicker`
//! (FreeBSD `SIGRTMIN` = 65, with the `kick_pending`/`VM_EXITCODE_BOGUS`
//! disambiguation); only its signal NUMBER is named here.

use carrick_signal_core::HostSignalGlue;

/// Zero-sized marker carrying bhyve's host-signal policy.
pub struct BhyveGlue;

impl HostSignalGlue for BhyveGlue {
    fn kick_signal() -> i32 {
        crate::bhyve_kicker::kick_signal()
    }

    fn host_to_linux(host_signum: i32) -> i32 {
        crate::bhyve_signum::host_to_linux_signum(host_signum)
    }

    fn linux_to_host(linux_signum: i32) -> i32 {
        crate::bhyve_signum::linux_to_host_signum(linux_signum)
    }

    /// The old `bhyve_disposition::is_bhyve_claimed` body verbatim: the four pumped
    /// signals (1/2/3/15, numbered identically on both), the SIGCHLD reaper and
    /// SIGPIPE (by their LINUX numbers), and the reserved RT kick/nudge.
    fn is_claimed(linux_signum: i32) -> bool {
        if !carrick_host_bsd::signum::linux_signum_has_host_carrier(linux_signum) {
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
        let kick = crate::bhyve_kicker::kick_signal();
        linux_signum == kick || linux_signum == kick + 1
    }

    fn poke() {
        carrick_hal::signal_pump::poke();
    }

    fn install_kick_handler() {
        crate::install_bhyve_kick_handler();
    }
}
