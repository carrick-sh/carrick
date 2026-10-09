//! ARM ring-first flip opt-out hatch.
//!
//! Controlled by `CARRICK_ARM_RING_FIRST`:
//! - Default (unset or != "0"): strict ring-first forward allowlist is enforced.
//! - "0": opt-out hatch active; pre-flip host forwarding is restored.

use std::ffi::OsStr;

use carrick_el1_abi::ApertureControl;

/// Single owner of the ARM ring-first flip opt-out policy.
pub struct ArmRingFirstHatch;

impl ArmRingFirstHatch {
    /// Pure parser for the `CARRICK_ARM_RING_FIRST` value.
    ///
    /// - `None`: default (true, strict ring-first).
    /// - `Some("0")`: opt-out hatch active (false, pre-flip forwarding).
    /// - `Some(other)`: true (strict ring-first).
    #[inline]
    pub fn parse_strict(env_val: Option<&OsStr>) -> bool {
        match env_val {
            Some(val) => val != "0",
            None => true,
        }
    }

    /// Returns true if ARM EL1 enforces the strict forward allowlist (default: true).
    /// Disabled only when `CARRICK_ARM_RING_FIRST=0`.
    #[inline]
    pub fn is_strict() -> bool {
        Self::parse_strict(std::env::var_os("CARRICK_ARM_RING_FIRST").as_deref())
    }

    /// Configure the guest aperture control word based on the live environment hatch setting.
    #[inline]
    pub fn configure_aperture(aperture: &ApertureControl) {
        aperture.set_strict(Self::is_strict());
    }

    /// Configure the guest aperture control word with an explicit environment value (for pure testing).
    #[inline]
    pub fn configure_aperture_with(aperture: &ApertureControl, env_val: Option<&OsStr>) {
        aperture.set_strict(Self::parse_strict(env_val));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hatch_parse_semantics() {
        assert!(ArmRingFirstHatch::parse_strict(None));
        assert!(ArmRingFirstHatch::parse_strict(Some(OsStr::new("1"))));
        assert!(ArmRingFirstHatch::parse_strict(Some(OsStr::new("true"))));
        assert!(ArmRingFirstHatch::parse_strict(Some(OsStr::new("yes"))));
        assert!(!ArmRingFirstHatch::parse_strict(Some(OsStr::new("0"))));
    }

    #[test]
    fn test_aperture_control_honours_hatch_zero_and_default() {
        let aperture = ApertureControl::new();

        // Default (None): strict mode active
        ArmRingFirstHatch::configure_aperture_with(&aperture, None);
        assert!(aperture.is_strict());

        // Opt-out ("0"): strict mode disabled
        ArmRingFirstHatch::configure_aperture_with(&aperture, Some(OsStr::new("0")));
        assert!(!aperture.is_strict());

        // Explicit enable ("1"): strict mode active
        ArmRingFirstHatch::configure_aperture_with(&aperture, Some(OsStr::new("1")));
        assert!(aperture.is_strict());
    }

    #[test]
    fn test_host_aperture_control_honours_zero_and_default() {
        let total_size = carrick_el1_abi::EL1_APERTURE_CONTROL_OFFSET as usize
            + std::mem::size_of::<ApertureControl>();
        let mut region = vec![0u8; total_size];
        let ptr = region.as_mut_ptr() as usize;

        carrick_el1_abi::record_el1_region_host_ptr(ptr);

        let aperture = carrick_el1_abi::host_aperture_control()
            .expect("host_aperture_control must be accessible when region is recorded");

        // 1. With hatch = 0:
        ArmRingFirstHatch::configure_aperture_with(aperture, Some(OsStr::new("0")));
        assert!(!aperture.is_strict(), "hatch = 0 must clear strict mode");

        // 2. With default (None):
        ArmRingFirstHatch::configure_aperture_with(aperture, None);
        assert!(
            aperture.is_strict(),
            "default hatch must enable strict mode"
        );

        // Clean up global host pointer
        carrick_el1_abi::record_el1_region_host_ptr(0);
    }
}
