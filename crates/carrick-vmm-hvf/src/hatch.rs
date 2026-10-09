//! ARM ring-first flip opt-out hatch.
//!
//! The frontend resolves `CARRICK_ARM_RING_FIRST` into typed run policy:
//! - Default (unset or != "0"): strict ring-first forward allowlist is enforced.
//! - "0": opt-out hatch active; pre-flip host forwarding is restored.

use carrick_el1_abi::ApertureControl;
use carrick_guest_mem::ArmRingFirst;

/// Writes the already-resolved run policy into the guest aperture.
pub struct ArmRingFirstHatch;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArmRingFirstPolicyConflict {
    held: ArmRingFirst,
    requested: ArmRingFirst,
}

impl core::fmt::Display for ArmRingFirstPolicyConflict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ARM ring policy conflict: carrier holds {:?}, root requests {:?}",
            self.held, self.requested
        )
    }
}

impl ArmRingFirstHatch {
    pub(crate) fn validate_carrier_policy(
        aperture: &ApertureControl,
        requested: ArmRingFirst,
    ) -> Result<(), ArmRingFirstPolicyConflict> {
        let held = if aperture.is_strict() {
            ArmRingFirst::Strict
        } else {
            ArmRingFirst::OptOut
        };
        if requested == held {
            Ok(())
        } else {
            Err(ArmRingFirstPolicyConflict { held, requested })
        }
    }

    pub fn configure_aperture(aperture: &ApertureControl, policy: ArmRingFirst) {
        aperture.set_strict(policy.is_strict());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_admission_rejects_conflicting_ring_policy_without_changing_it() {
        for held in [ArmRingFirst::Strict, ArmRingFirst::OptOut] {
            let aperture = ApertureControl::new();
            ArmRingFirstHatch::configure_aperture(&aperture, held);
            assert!(ArmRingFirstHatch::validate_carrier_policy(&aperture, held).is_ok());
            let requested = if held.is_strict() {
                ArmRingFirst::OptOut
            } else {
                ArmRingFirst::Strict
            };
            assert_eq!(
                ArmRingFirstHatch::validate_carrier_policy(&aperture, requested),
                Err(ArmRingFirstPolicyConflict { held, requested })
            );
            assert_eq!(aperture.is_strict(), held.is_strict());
        }
    }

    #[test]
    fn test_hatch_parse_semantics() {
        assert!(ArmRingFirst::from_setting(None).is_strict());
        assert!(ArmRingFirst::from_setting(Some("1")).is_strict());
        assert!(ArmRingFirst::from_setting(Some("true")).is_strict());
        assert!(ArmRingFirst::from_setting(Some("yes")).is_strict());
        assert!(!ArmRingFirst::from_setting(Some("0")).is_strict());
    }

    #[test]
    fn test_aperture_control_honours_hatch_zero_and_default() {
        let aperture = ApertureControl::new();

        // Default (None): strict mode active
        ArmRingFirstHatch::configure_aperture(&aperture, ArmRingFirst::Strict);
        assert!(aperture.is_strict());

        // Opt-out ("0"): strict mode disabled
        ArmRingFirstHatch::configure_aperture(&aperture, ArmRingFirst::OptOut);
        assert!(!aperture.is_strict());

        // Explicit enable ("1"): strict mode active
        ArmRingFirstHatch::configure_aperture(&aperture, ArmRingFirst::Strict);
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
        for setting in [
            ArmRingFirst::Strict,
            ArmRingFirst::OptOut,
            ArmRingFirst::Strict,
        ] {
            ArmRingFirstHatch::configure_aperture(aperture, setting);
            assert_eq!(aperture.is_strict(), setting.is_strict());
            // Reclaim asserts that the idle leaves still name exact slot bytes.
            drop(
                service
                    .try_claim(slot)
                    .expect("hatch must preserve the alias"),
            );
        }
    }
}
