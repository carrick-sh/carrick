//! The BSD-family [`HostSignalGlue`] implementation, parameterized by kick signal `SIG`.
//!
//! Used by bhyve (FreeBSD, SIG=65) and NVMM (NetBSD, SIG=33).

use carrick_signal_linux::HostSignalGlue;

/// Zero-sized marker carrying the BSD host-signal policy for kick signal `SIG`.
pub struct BsdSignalGlue<const SIG: i32>;

impl<const SIG: i32> HostSignalGlue for BsdSignalGlue<SIG> {
    fn kick_signal() -> i32 {
        SIG
    }

    fn host_to_linux(host_signum: i32) -> i32 {
        crate::signum::host_to_linux_signum(host_signum)
    }

    fn linux_to_host(linux_signum: i32) -> i32 {
        crate::signum::linux_to_host_signum(linux_signum)
    }

    /// The four pumped signals (1/2/3/15, numbered identically on both sides),
    /// the SIGCHLD reaper and SIGPIPE (by their LINUX numbers), and the reserved
    /// RT kick/nudge.
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
        linux_signum == SIG || linux_signum == SIG + 1
    }

    fn poke() {
        carrick_hal::signal_pump::poke();
    }

    fn install_kick_handler() {
        carrick_hal::posix_signal_kick::install_posix_kick_handler::<SIG>();
    }
}
