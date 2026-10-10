//! NVMM's [`HostSignalGlue`] — the ~15-line backend seam the shared host-signal
//! driver is generic over. NVMM runs on NetBSD; like bhyve its host signal numbers
//! differ from Linux, so the translation methods consult the `nvmm_signum` table.
//! The irreducible vCPU KICK lives in [`crate::nvmm_kicker`] (NetBSD `SIGRTMIN` =
//! 33); only its signal NUMBER is named here.

use crate::nvmm_kicker::NETBSD_SIGRTMIN;

/// Marker carrying NVMM's host-signal policy.
pub type NvmmGlue = carrick_host_bsd::signal_backend::BsdSignalGlue<NETBSD_SIGRTMIN>;

#[cfg(test)]
mod tests {
    use super::NvmmGlue;
    use carrick_host_bsd::native_glue::BsdNativeGlue;
    use carrick_signal_linux::HostSignalGlue;

    /// Drift guard for the aarch64 BSD lanes — the NetBSD twin of
    /// `carrick_vmm_bhyve::bhyve_signal_backend`'s test. On NetBSD/aarch64 there
    /// is no NVMM crate (NVMM is an x86-only NetBSD subsystem), so
    /// `carrick-runtime`'s `ActiveGlue` resolves to [`BsdNativeGlue`] instead of
    /// [`NvmmGlue`]; the two must express the SAME NetBSD signal policy. The only
    /// intended divergence is `install_kick_handler`.
    #[test]
    fn the_nvmm_glue_and_the_native_lane_glue_express_one_netbsd_policy() {
        assert_eq!(NvmmGlue::kick_signal(), BsdNativeGlue::kick_signal());
        assert_eq!(NvmmGlue::nudge_signum(), BsdNativeGlue::nudge_signum());
        for signum in 0..=64 {
            assert_eq!(
                NvmmGlue::host_to_linux(signum),
                BsdNativeGlue::host_to_linux(signum),
                "host_to_linux diverged at {signum}"
            );
            assert_eq!(
                NvmmGlue::linux_to_host(signum),
                BsdNativeGlue::linux_to_host(signum),
                "linux_to_host diverged at {signum}"
            );
            assert_eq!(
                NvmmGlue::is_claimed(signum),
                BsdNativeGlue::is_claimed(signum),
                "is_claimed diverged at {signum}"
            );
            assert_eq!(
                NvmmGlue::skip_install_routing(signum),
                BsdNativeGlue::skip_install_routing(signum),
                "skip_install_routing diverged at {signum}"
            );
        }
    }
}
