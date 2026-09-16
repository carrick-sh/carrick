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

// Callers: `runtime.rs` (`cfg(feature = "platform-macos")`).
#[cfg(any(
    feature = "platform-macos",
    all(target_os = "macos", target_arch = "aarch64")
))]
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

#[allow(dead_code)]
pub(crate) fn with_optional_vdso<A: carrick_hal::GuestArch>(
    image: AddressSpace,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_for_clock::<A>(image, &crate::kernel::container::ClockDomain::system())
}

pub(crate) fn with_optional_vdso_for_clock<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    clock: &crate::kernel::container::ClockDomain,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_for_clock_with_visibility::<A>(image, clock, false)
}

pub(crate) fn with_optional_vdso_for_clock_with_visibility<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    clock: &crate::kernel::container::ClockDomain,
    requires_syscall_traps: bool,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_for_clock_at::<A>(
        image,
        clock,
        carrick_mem::vdso::LINUX_VVAR_BASE,
        carrick_mem::vdso::LINUX_VDSO_BASE,
        requires_syscall_traps,
    )
}

/// [`with_optional_vdso`] with caller-chosen vvar/vdso guest VAs — the Darwin
/// native backend relocates both pages out of the Darwin-reserved host VA hole
/// the canonical bases sit in (see `AddressSpace::with_vdso_bytes_at`). The
/// same `CARRICK_DISABLE_VDSO` / `CARRICK_VDSO_MODE` debug controls apply.
#[allow(dead_code)]
pub(crate) fn with_optional_vdso_at<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    vvar_base: u64,
    vdso_base: u64,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_for_clock_at::<A>(
        image,
        &crate::kernel::container::ClockDomain::system(),
        vvar_base,
        vdso_base,
        false,
    )
}

/// [`with_optional_vdso_for_clock`] with caller-chosen vvar/vdso guest VAs and
/// container clock domain awareness. Under `Scaled`, `Deterministic`, or
/// `Frozen` modes, the vDSO is built with clock syscall stubs so monotonic and
/// controlled realtime reads route through the domain rather than bypassing it
/// via unscaled hardware counters.
pub(crate) fn with_optional_vdso_for_clock_at<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    clock: &crate::kernel::container::ClockDomain,
    vvar_base: u64,
    vdso_base: u64,
    requires_syscall_traps: bool,
) -> Result<AddressSpace, AddressSpaceError> {
    with_optional_vdso_for_clock_at_with_mode::<A>(
        image,
        clock,
        vvar_base,
        vdso_base,
        requires_syscall_traps,
        vdso_debug_mode(),
    )
}

pub(crate) fn with_optional_vdso_for_clock_at_with_mode<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    clock: &crate::kernel::container::ClockDomain,
    vvar_base: u64,
    vdso_base: u64,
    requires_syscall_traps: bool,
    mode: VdsoDebugMode,
) -> Result<AddressSpace, AddressSpaceError> {
    if mode == VdsoDebugMode::Disabled {
        return Ok(image.with_vdso_auxv(false));
    }
    let vdso_bytes = if requires_syscall_traps {
        carrick_mem::vdso::vdso_image_bytes_without_fastpaths()
    } else {
        match mode {
            VdsoDebugMode::NoGetrandom => carrick_mem::vdso::vdso_image_bytes_without_getrandom(),
            VdsoDebugMode::NoFastpaths => carrick_mem::vdso::vdso_image_bytes_without_fastpaths(),
            VdsoDebugMode::ClockSyscalls => {
                carrick_mem::vdso::vdso_image_bytes_with_clock_syscalls()
            }
            VdsoDebugMode::Full => {
                if clock.is_scaled() || clock.is_deterministic() || clock.is_frozen() {
                    carrick_mem::vdso::vdso_image_bytes_with_clock_syscalls()
                } else {
                    A::vdso_bytes()
                }
            }
            VdsoDebugMode::Disabled => unreachable!(),
        }
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

    #[test]
    fn vdso_clock_policy_selects_syscall_stubs_for_controlled_monotonic_or_frozen() {
        use crate::kernel::container::ClockDomain;
        use carrick_hal::aarch64_arch::Aarch64GuestArch;
        use std::time::{Duration, SystemTime};

        let sys = ClockDomain::system();
        let offset = ClockDomain::offset(Duration::from_secs(10).into());
        let frozen = ClockDomain::frozen(SystemTime::UNIX_EPOCH + Duration::from_secs(100));
        let scaled = ClockDomain::scaled(SystemTime::UNIX_EPOCH, 2, 1).unwrap();
        let det = ClockDomain::deterministic(SystemTime::UNIX_EPOCH);

        let space_sys = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &sys,
        )
        .unwrap();
        let space_offset = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &offset,
        )
        .unwrap();
        let space_frozen = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &frozen,
        )
        .unwrap();
        let space_scaled = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &scaled,
        )
        .unwrap();
        let space_det = with_optional_vdso_for_clock::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &det,
        )
        .unwrap();

        // System and Offset use standard full vDSO bytes
        let full_bytes = carrick_mem::vdso::vdso_image_bytes();
        let syscall_bytes = carrick_mem::vdso::vdso_image_bytes_with_clock_syscalls();

        let get_vdso = |space: &AddressSpace| {
            space
                .regions()
                .iter()
                .find(|r| r.start == carrick_mem::vdso::LINUX_VDSO_BASE)
                .unwrap()
                .bytes()
                .to_vec()
        };

        assert_eq!(
            &get_vdso(&space_sys)[..full_bytes.len()],
            full_bytes.as_slice()
        );
        assert_eq!(
            &get_vdso(&space_offset)[..full_bytes.len()],
            full_bytes.as_slice()
        );
        assert_eq!(
            &get_vdso(&space_frozen)[..syscall_bytes.len()],
            syscall_bytes.as_slice()
        );
        assert_eq!(
            &get_vdso(&space_scaled)[..syscall_bytes.len()],
            syscall_bytes.as_slice()
        );
        assert_eq!(
            &get_vdso(&space_det)[..syscall_bytes.len()],
            syscall_bytes.as_slice()
        );
    }

    #[test]
    fn interceptor_requires_syscall_vdso() {
        use crate::kernel::container::ClockDomain;
        use carrick_hal::aarch64_arch::Aarch64GuestArch;

        let space = with_optional_vdso_for_clock_with_visibility::<Aarch64GuestArch>(
            AddressSpace::from_regions(0, Vec::new()).unwrap(),
            &ClockDomain::system(),
            true,
        )
        .unwrap();
        let vdso = space
            .regions()
            .iter()
            .find(|region| region.start == carrick_mem::vdso::LINUX_VDSO_BASE)
            .expect("vDSO mapping")
            .bytes();
        let no_fastpaths = carrick_mem::vdso::vdso_image_bytes_without_fastpaths();

        assert_eq!(&vdso[..no_fastpaths.len()], no_fastpaths.as_slice());
    }
}
