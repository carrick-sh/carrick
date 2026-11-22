//! What one owner fault supply's outcome asks of the CPL0 #PF entry. Split
//! from the bare-metal entry so the mapping is host-testable, and shared by
//! the first supply and the rerun after a COW supply: both match it without
//! a wildcard, so a new outcome cannot fall into an unresolved fault.
use carrick_abi::{LINUX_SEGV_ACCERR, LINUX_SEGV_MAPERR, LINUX_SIGSEGV};
use carrick_el1::fault::OwnerFaultSupplyOutcome;

/// The entry's next step for an access the owner supply did not serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultAnswer {
    /// Linux refuses the access with this signal.
    Signal { signum: i32, code: i32 },
    /// Contention: park on the named release and retry the access.
    Wait(carrick_el1_abi::PortalOwnerWait),
    /// No owner could decide the access.
    Unresolved,
    /// The owner selected a COW replacement frame for the carrier to supply.
    CowSelected,
    /// The owner selected a first-touch window for the carrier to back.
    Selected,
}

/// Map `outcome` for a fault whose error code said the page was `present`.
/// A mapping that forbids the access is `SEGV_ACCERR` whether or not a leaf
/// is present; an address no mapping covers is `SEGV_MAPERR` unless a stale
/// present leaf answered first.
pub(crate) const fn answer(outcome: OwnerFaultSupplyOutcome, present: bool) -> FaultAnswer {
    match outcome {
        OwnerFaultSupplyOutcome::ProtectionDeclined => FaultAnswer::Signal {
            signum: LINUX_SIGSEGV,
            code: LINUX_SEGV_ACCERR,
        },
        OwnerFaultSupplyOutcome::PolicyDeclined => FaultAnswer::Signal {
            signum: LINUX_SIGSEGV,
            code: if present {
                LINUX_SEGV_ACCERR
            } else {
                LINUX_SEGV_MAPERR
            },
        },
        OwnerFaultSupplyOutcome::Wait(wait) => FaultAnswer::Wait(wait),
        OwnerFaultSupplyOutcome::Unavailable => FaultAnswer::Unresolved,
        OwnerFaultSupplyOutcome::CowSelected => FaultAnswer::CowSelected,
        OwnerFaultSupplyOutcome::Selected => FaultAnswer::Selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sibling's `mprotect(PROT_READ)` between a COW supply and its rerun
    /// makes the rerun's root decline the write: Linux answers
    /// SIGSEGV/SEGV_ACCERR, present leaf or not, never an unresolved fault.
    #[test]
    fn a_protection_decline_is_segv_accerr_for_a_present_or_absent_leaf() {
        for present in [false, true] {
            assert_eq!(
                answer(OwnerFaultSupplyOutcome::ProtectionDeclined, present),
                FaultAnswer::Signal {
                    signum: LINUX_SIGSEGV,
                    code: LINUX_SEGV_ACCERR,
                }
            );
        }
    }

    #[test]
    fn a_policy_decline_names_maperr_only_without_a_present_leaf() {
        assert_eq!(
            answer(OwnerFaultSupplyOutcome::PolicyDeclined, false),
            FaultAnswer::Signal {
                signum: LINUX_SIGSEGV,
                code: LINUX_SEGV_MAPERR,
            }
        );
        assert_eq!(
            answer(OwnerFaultSupplyOutcome::PolicyDeclined, true),
            FaultAnswer::Signal {
                signum: LINUX_SIGSEGV,
                code: LINUX_SEGV_ACCERR,
            }
        );
    }

    #[test]
    fn only_an_unavailable_owner_is_unresolved() {
        assert_eq!(
            answer(OwnerFaultSupplyOutcome::Unavailable, false),
            FaultAnswer::Unresolved
        );
        assert_eq!(
            answer(OwnerFaultSupplyOutcome::CowSelected, true),
            FaultAnswer::CowSelected
        );
        assert_eq!(
            answer(OwnerFaultSupplyOutcome::Selected, false),
            FaultAnswer::Selected
        );
    }
}
