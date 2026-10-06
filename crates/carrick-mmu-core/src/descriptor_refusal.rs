//! ISA-neutral descriptor transaction refusal codes.

/// Why a guest-owned descriptor transaction was not applied. Wire codes are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DescriptorRefusal {
    BadRange = 1,
    StaleRoot = 2,
    TableOutsidePrimary = 3,
    MissingTable = 4,
    NotPrivateAnonymous = 5,
    PermissionWidening = 6,
    CowArmed = 7,
    AlreadyValid = 8,
    Occupied = 9,
    Malformed = 10,
    NotPrepared = 11,
    WrongBacking = 12,
    PermissionDenied = 13,
    NotCowArmed = 14,
    TablesExhausted = 15,
    BadTableGrant = 16,
    JournalCapacity = 17,
    Contended = 18,
    BadEncoding = 19,
    WrongMm = 20,
    ExcludedOutput = 21,
    /// A reclaiming edit would empty more tables than its budget (or than
    /// one receipt carries): the host must split the span.
    ReclaimCapacity = 22,
    /// The MM's tables lack the two preallocated EL1 COW copy-alias leaves,
    /// so EL1 cannot copy the page without allocating (a provisioning
    /// defect of that image, distinct from exhausted table grants).
    CopyWindowAbsent = 23,
    /// The operation's span names the Carrick-owned EL1 COW copy window
    /// at its reserved copy-window address; only EL1's bounded copy may
    /// write those leaves.
    CarrickOwnedWindow = 24,
}

impl DescriptorRefusal {
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::BadRange,
            2 => Self::StaleRoot,
            3 => Self::TableOutsidePrimary,
            4 => Self::MissingTable,
            5 => Self::NotPrivateAnonymous,
            6 => Self::PermissionWidening,
            7 => Self::CowArmed,
            8 => Self::AlreadyValid,
            9 => Self::Occupied,
            10 => Self::Malformed,
            11 => Self::NotPrepared,
            12 => Self::WrongBacking,
            13 => Self::PermissionDenied,
            14 => Self::NotCowArmed,
            15 => Self::TablesExhausted,
            16 => Self::BadTableGrant,
            17 => Self::JournalCapacity,
            18 => Self::Contended,
            19 => Self::BadEncoding,
            20 => Self::WrongMm,
            21 => Self::ExcludedOutput,
            22 => Self::ReclaimCapacity,
            23 => Self::CopyWindowAbsent,
            24 => Self::CarrickOwnedWindow,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::DescriptorRefusal;

    #[test]
    fn both_isa_receipts_carry_the_same_stable_refusal() {
        let refusal = DescriptorRefusal::StaleRoot;
        let arm = crate::aarch64::descriptor_txn::DescriptorOutcome::Refused(refusal);
        let x86 = crate::x86::descriptor_txn::DescriptorOutcome::Refused(refusal);
        assert_eq!(
            arm,
            crate::aarch64::descriptor_txn::DescriptorOutcome::Refused(refusal)
        );
        assert_eq!(
            x86,
            crate::x86::descriptor_txn::DescriptorOutcome::Refused(refusal)
        );
        assert_eq!(DescriptorRefusal::from_code(refusal as u32), Some(refusal));
    }
}
