use std::fmt::Debug;
use std::num::NonZeroU16;
use std::sync::Arc;
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

/// Revision of the dispatcher-owned Linux VMA authority.
///
/// This is deliberately distinct from backend and frame-inventory revisions:
/// the three authorities publish independently and their counters must never be
/// compared as though they belonged to one domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct VmaRevision(u64);

impl VmaRevision {
    pub const INITIAL: Self = Self(1);

    pub(crate) const fn from_authority_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// One owned, coherent observation of the production VMA authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedVmaSnapshot {
    pub revision: VmaRevision,
    pub vmas: Vec<VmaSummary>,
}

/// Read-only K1 adapter over the runtime's sole production VMA authority.
pub trait VmaSnapshotSource: Debug + Send + Sync {
    fn snapshot(&self, deadline: Instant) -> Result<OwnedVmaSnapshot, SnapshotError>;
    fn revision(&self) -> VmaRevision;

    /// Run `publish` while this source's observable VMA revision cannot change.
    ///
    /// Historical-MM cutover uses this to validate the exact preparation
    /// generation and install its owned snapshot without a detach window.
    fn publish_if_revision(
        &self,
        expected: VmaRevision,
        deadline: Instant,
        publish: &mut dyn FnMut() -> Result<(), SnapshotError>,
    ) -> Result<(), SnapshotError>;
}

impl VmaSnapshotSource for OwnedVmaSnapshot {
    fn snapshot(&self, _deadline: Instant) -> Result<OwnedVmaSnapshot, SnapshotError> {
        Ok(self.clone())
    }

    fn revision(&self) -> VmaRevision {
        self.revision
    }

    fn publish_if_revision(
        &self,
        expected: VmaRevision,
        _deadline: Instant,
        publish: &mut dyn FnMut() -> Result<(), SnapshotError>,
    ) -> Result<(), SnapshotError> {
        if self.revision != expected {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        publish()
    }
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
    /// Revision of the independent VMA authority used for `vmas`.
    pub vma_revision: Option<VmaRevision>,
    pub mapping_ids: Vec<MappingId>,
    /// Revision of the global frame inventory from which `mapping_ids` were
    /// copied. Backends without frame inventory return `None`; HVPatch must
    /// return `Some` so the collector can classify concurrent churn as a retry
    /// rather than permanent corruption.
    pub frame_inventory_revision: Option<u64>,
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
    fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(None)
    }
}

pub type SharedVmaSnapshotSource = Arc<dyn VmaSnapshotSource>;

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
