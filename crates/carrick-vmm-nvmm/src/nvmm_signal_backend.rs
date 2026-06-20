//! NVMM's [`HostSignalGlue`] — the ~15-line backend seam the shared host-signal
//! driver is generic over. NVMM runs on NetBSD; like bhyve its host signal numbers
//! differ from Linux, so the translation methods consult the `nvmm_signum` table.
//! The irreducible vCPU KICK lives in [`crate::nvmm_kicker`] (NetBSD `SIGRTMIN` =
//! 33); only its signal NUMBER is named here.

use carrick_signal_core::HostSignalGlue;

/// Zero-sized marker carrying NVMM's host-signal policy.
pub struct NvmmGlue;

impl HostSignalGlue for NvmmGlue {
    fn kick_signal() -> i32 {
        crate::nvmm_kicker::kick_signal()
    }

    fn host_to_linux(host_signum: i32) -> i32 {
        crate::nvmm_signum::host_to_linux_signum(host_signum)
    }

    fn linux_to_host(linux_signum: i32) -> i32 {
        crate::nvmm_signum::linux_to_host_signum(linux_signum)
    }

    /// The old `nvmm_disposition::is_nvmm_claimed` body: the four pumped signals,
    /// the SIGCHLD reaper + SIGPIPE (by LINUX number), and the kick/nudge.
    fn is_claimed(linux_signum: i32) -> bool {
        if matches!(linux_signum, 1 | 2 | 3 | 15) {
            return true;
        }
        if linux_signum == carrick_abi::LINUX_SIGCHLD {
            return true;
        }
        if linux_signum == carrick_abi::LINUX_SIGPIPE {
            return true;
        }
        let kick = crate::nvmm_kicker::kick_signal();
        linux_signum == kick || linux_signum == kick + 1
    }

    fn poke() {
        carrick_hal::signal_pump::poke();
    }

    fn install_kick_handler() {
        crate::nvmm_kicker::install_nvmm_kick_handler();
    }
}
