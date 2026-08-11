use std::num::NonZeroU16;
use std::time::Instant;

use carrick_guest_mem::{Gpa, GuestVa};
use carrick_hal::MappingId;

const AARCH64_STAGE1_ROOT_ALIGNMENT: u64 = 4096;
const AARCH64_TTBR0_ROOT_MASK: u64 = (1_u64 << 48) - 1;

/// Nonzero AArch64 stage-1 address-space identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Asid(NonZeroU16);

impl Asid {
    pub(crate) const fn from_registry_allocation(raw: NonZeroU16) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u16 {
        self.0.get()
    }
}

/// Validated AArch64 4 KiB-granule stage-1 root guest-physical address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Stage1Root(Gpa);

impl Stage1Root {
    pub fn for_aarch64_4k(gpa: Gpa) -> Result<Self, Stage1RootError> {
        if gpa.raw() & (AARCH64_STAGE1_ROOT_ALIGNMENT - 1) != 0 {
            return Err(Stage1RootError::Unaligned(gpa));
        }
        if gpa.raw() & !AARCH64_TTBR0_ROOT_MASK != 0 {
            return Err(Stage1RootError::OutOfRange(gpa));
        }
        Ok(Self(gpa))
    }

    pub const fn gpa(self) -> Gpa {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmBinding {
    pub asid: Asid,
    pub stage1_root: Stage1Root,
    pub ttbr0: Ttbr0,
}

impl MmBinding {
    pub const fn for_aarch64(asid: Asid, stage1_root: Stage1Root) -> Self {
        Self {
            asid,
            stage1_root,
            ttbr0: Ttbr0::for_aarch64(asid, stage1_root),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmaSummary {
    pub start: GuestVa,
    pub end: GuestVa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotTable {
    Mms,
    Vmas,
    Mappings,
}

/// One backend-generation observation. Implementations must copy all three
/// tables under one revision protocol; callers never compose independent
/// binding, VMA, and mapping reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmBackendSnapshot {
    pub revision: u64,
    pub binding: MmBinding,
    pub vmas: Vec<VmaSummary>,
    pub mapping_ids: Vec<MappingId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SnapshotError {
    #[error("{0:?} snapshot authority is not attached to this K1 backend adapter")]
    AuthorityUnavailable(SnapshotTable),
    #[error("backend snapshot changed while it was being observed")]
    ChangedDuringObservation,
    #[error("backend snapshot lock is busy")]
    Busy,
    #[error("backend snapshot deadline expired")]
    TimedOut,
}

pub trait MmBackend: Send + Sync {
    fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError>;
    fn revision(&self) -> u64;
}

/// A validated `TTBR0_EL1` value composed from typed ASID and root domains.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Ttbr0(u64);

impl Ttbr0 {
    pub const fn for_aarch64(asid: Asid, root: Stage1Root) -> Self {
        Self((asid.raw() as u64) << 48 | root.gpa().raw())
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Stage1RootError {
    #[error("stage-1 root GPA {0:?} is not 4 KiB aligned")]
    Unaligned(Gpa),
    #[error("stage-1 root GPA {0:?} does not fit TTBR0_EL1's 48-bit base field")]
    OutOfRange(Gpa),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asid(raw: u16) -> Asid {
        Asid::from_registry_allocation(NonZeroU16::new(raw).expect("nonzero test ASID"))
    }

    #[test]
    fn composes_validated_stage1_root_and_asid() {
        let root = Stage1Root::for_aarch64_4k(Gpa(0x1234_5000)).expect("aligned root");

        assert_eq!(
            Ttbr0::for_aarch64(asid(1), root).raw(),
            0x0001_0000_1234_5000
        );
        assert_eq!(
            MmBinding::for_aarch64(asid(1), root),
            MmBinding {
                asid: asid(1),
                stage1_root: root,
                ttbr0: Ttbr0::for_aarch64(asid(1), root),
            }
        );
    }

    #[test]
    fn rejects_unaligned_or_out_of_range_stage1_roots() {
        assert_eq!(
            Stage1Root::for_aarch64_4k(Gpa(0x1234_5001)),
            Err(Stage1RootError::Unaligned(Gpa(0x1234_5001)))
        );
        assert_eq!(
            Stage1Root::for_aarch64_4k(Gpa(0x0001_0000_0000_0000)),
            Err(Stage1RootError::OutOfRange(Gpa(0x0001_0000_0000_0000)))
        );
    }
}
