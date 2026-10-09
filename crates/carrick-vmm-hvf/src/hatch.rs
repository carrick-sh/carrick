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
    fn aperture_configuration_preserves_service_copy_slot_zero() {
        let region = carrick_test_support::TestEl1Region::zeroed();
        // SAFETY: TestEl1Region owns aligned, zero-valid shared ABI storage;
        // both offsets are checked disjoint by the ABI geometry assertions.
        let (aperture, service) = unsafe {
            (
                &*region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_APERTURE_CONTROL_OFFSET as usize)
                    .cast::<ApertureControl>(),
                &*region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_SERVICE_COPY_TABLE_OFFSET as usize)
                    .cast::<carrick_el1_abi::ServiceCopyTable>(),
            )
        };
        let slot = carrick_el1_abi::SlotId::from_index(0).expect("slot zero");
        drop(
            service
                .try_claim(slot)
                .expect("initialize idle descriptors"),
        );
        for setting in [None, Some(OsStr::new("0")), None] {
            ArmRingFirstHatch::configure_aperture_with(aperture, setting);
            assert_eq!(aperture.is_strict(), setting.is_none());
            // Reclaim asserts that the idle leaves still name exact slot bytes.
            drop(
                service
                    .try_claim(slot)
                    .expect("hatch must preserve the alias"),
            );
        }
    }
}
