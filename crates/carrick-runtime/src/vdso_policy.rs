//! vDSO attach policy + the shared debug-env controls.
//!
//! Platform-NEUTRAL (moved out of the macOS-only `runtime.rs` arm): the native
//! backend and the VMM run paths on every host OS decide identically whether —
//! and with which debug variant — the Linux vDSO is attached to a guest image.
//! Both `runtime` arms re-export these under their original
//! `crate::runtime::…` paths so call sites are unchanged.

use carrick_mem::memory::{AddressSpace, AddressSpaceError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VdsoDebugMode {
    Full,
    Disabled,
    NoGetrandom,
    NoFastpaths,
    ClockSyscalls,
}

pub(crate) fn vdso_enabled_for_debug() -> bool {
    vdso_debug_mode() != VdsoDebugMode::Disabled
}

fn vdso_debug_mode() -> VdsoDebugMode {
    vdso_debug_mode_from_env(
        std::env::var("CARRICK_DISABLE_VDSO").ok().as_deref(),
        std::env::var("CARRICK_VDSO_MODE").ok().as_deref(),
    )
}

fn vdso_debug_mode_from_env(disable: Option<&str>, mode: Option<&str>) -> VdsoDebugMode {
    if debug_env_flag_enabled(disable) {
        return VdsoDebugMode::Disabled;
    }
    match mode {
        Some("no-getrandom" | "nogetrandom" | "without-getrandom") => VdsoDebugMode::NoGetrandom,
        Some("no-fastpaths" | "nofastpaths" | "minimal") => VdsoDebugMode::NoFastpaths,
        Some("clock-syscalls" | "clocksyscalls" | "clock-syscall") => VdsoDebugMode::ClockSyscalls,
        _ => VdsoDebugMode::Full,
    }
}

/// Shared truthy-string parse for the `CARRICK_DISABLE_*` debug env flags
/// (also used by the macOS arm's `hardware_tso_for_debug`).
pub(crate) fn debug_env_flag_enabled(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

pub(crate) fn with_optional_vdso<A: carrick_hal::GuestArch>(
    image: AddressSpace,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_at::<A>(
        image,
        carrick_mem::vdso::LINUX_VVAR_BASE,
        carrick_mem::vdso::LINUX_VDSO_BASE,
    )
}

/// [`with_optional_vdso`] with caller-chosen vvar/vdso guest VAs — the Darwin
/// native backend relocates both pages out of the Darwin-reserved host VA hole
/// the canonical bases sit in (see `AddressSpace::with_vdso_bytes_at`). The
/// same `CARRICK_DISABLE_VDSO` / `CARRICK_VDSO_MODE` debug controls apply.
pub(crate) fn with_optional_vdso_at<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    vvar_base: u64,
    vdso_base: u64,
) -> Result<AddressSpace, AddressSpaceError> {
    let vdso_bytes = match vdso_debug_mode() {
        VdsoDebugMode::Full => A::vdso_bytes(),
        VdsoDebugMode::Disabled => return Ok(image),
        // Debug variants are aarch64-only escape hatches; only the production
        // image routes through GuestArch.
        VdsoDebugMode::NoGetrandom => carrick_mem::vdso::vdso_image_bytes_without_getrandom(),
        VdsoDebugMode::NoFastpaths => carrick_mem::vdso::vdso_image_bytes_without_fastpaths(),
        VdsoDebugMode::ClockSyscalls => carrick_mem::vdso::vdso_image_bytes_with_clock_syscalls(),
    };
    image.with_vdso_bytes_at(vdso_bytes, vvar_base, vdso_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vdso_debug_control_is_opt_out() {
        assert_eq!(vdso_debug_mode_from_env(None, None), VdsoDebugMode::Full);
        assert_eq!(
            vdso_debug_mode_from_env(Some("0"), None),
            VdsoDebugMode::Full
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("false"), None),
            VdsoDebugMode::Full
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("no-getrandom")),
            VdsoDebugMode::NoGetrandom
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("no-fastpaths")),
            VdsoDebugMode::NoFastpaths
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("clock-syscalls")),
            VdsoDebugMode::ClockSyscalls
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("1"), Some("no-getrandom")),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("true"), None),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("yes"), None),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("on"), None),
            VdsoDebugMode::Disabled
        );
    }
}
