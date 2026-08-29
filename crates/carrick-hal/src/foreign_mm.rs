//! Dependency-neutral transport values for carrier-owned foreign-MM reads.

use std::num::{NonZeroU16, NonZeroU64};

use carrick_guest_mem::{Gpa, GuestVa};

use crate::{ForeignBackendRevision, ForeignFrameInventoryRevision, ForeignVmaRevision, MappingId};

/// Never-reused kernel identity of one exact Linux MM incarnation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ForeignMmId(NonZeroU64);

impl ForeignMmId {
    pub const fn from_kernel_allocation(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw_for_probe(self) -> u64 {
        self.0.get()
    }
}

/// AArch64 address-space identifier carried as transport data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ForeignAsid(NonZeroU16);

impl ForeignAsid {
    pub const fn from_kernel_allocation(raw: NonZeroU16) -> Self {
        Self(raw)
    }

    pub const fn raw_for_probe(self) -> u16 {
        self.0.get()
    }
}

/// Coherent backend binding for one foreign-MM observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ForeignMmBinding {
    pub asid: ForeignAsid,
    pub stage1_root: Gpa,
}

impl ForeignMmBinding {
    pub const fn for_aarch64(asid: ForeignAsid, stage1_root: Gpa) -> Self {
        Self { asid, stage1_root }
    }
}

/// Exact incarnation of one live global-frame host owner.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ForeignOwnerGeneration(NonZeroU64);

impl ForeignOwnerGeneration {
    pub const fn from_backend_counter(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw_for_probe(self) -> u64 {
        self.0.get()
    }
}

/// Validated kernel observation projected into dependency-neutral transport data.
///
/// This is not authority: only the private runtime facade may construct it from
/// a retained kernel token, and the carrier reauthenticates every field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignMmSnapshot {
    pub mm: ForeignMmId,
    pub binding: ForeignMmBinding,
    pub backend_revision: ForeignBackendRevision,
    pub vma_revision: ForeignVmaRevision,
    pub frame_inventory_revision: ForeignFrameInventoryRevision,
    pub mapping_ids: Vec<MappingId>,
}

/// Authenticated outcome of one carrier-owned foreign read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignMmReadReceipt {
    pub mm: ForeignMmId,
    pub binding: ForeignMmBinding,
    pub backend_revision: ForeignBackendRevision,
    pub vma_revision: ForeignVmaRevision,
    pub frame_inventory_revision: ForeignFrameInventoryRevision,
    pub bytes_read: usize,
    pub owner_generations: Vec<ForeignOwnerGeneration>,
}

impl ForeignMmReadReceipt {
    /// Construct a receipt after the backend has reauthenticated the complete
    /// snapshot and every owner-pinned chunk.
    pub fn complete(
        snapshot: &ForeignMmSnapshot,
        bytes_read: usize,
        owner_generations: Vec<ForeignOwnerGeneration>,
    ) -> Self {
        Self {
            mm: snapshot.mm,
            binding: snapshot.binding,
            backend_revision: snapshot.backend_revision,
            vma_revision: snapshot.vma_revision,
            frame_inventory_revision: snapshot.frame_inventory_revision,
            bytes_read,
            owner_generations,
        }
    }
}

/// Backend-domain failure. Syscall-specific Linux errno lowering belongs to
/// the runtime consumer, not this transport layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForeignMmTransportError {
    #[error("foreign MM state changed during observation")]
    Retry,
    #[error("foreign MM global-frame owner is missing or stale")]
    OwnerStale,
    #[error("foreign MM stage-1 translation failed at {0:?}")]
    Translation(GuestVa),
    #[error("foreign MM binding is unavailable in this carrier")]
    MissingBinding,
}

/// Object-safe carrier transport over an already validated foreign-MM snapshot.
pub trait ForeignMmTransport: Send + Sync {
    fn read(
        &self,
        snapshot: &ForeignMmSnapshot,
        va: GuestVa,
        dst: &mut [u8],
    ) -> Result<ForeignMmReadReceipt, ForeignMmTransportError>;
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU16, NonZeroU64};

    use carrick_guest_mem::{Gpa, GuestVa};

    use super::*;

    #[derive(Debug)]
    struct MockTransport;

    impl ForeignMmTransport for MockTransport {
        fn read(
            &self,
            snapshot: &ForeignMmSnapshot,
            _va: GuestVa,
            dst: &mut [u8],
        ) -> Result<ForeignMmReadReceipt, ForeignMmTransportError> {
            dst.copy_from_slice(b"target");
            Ok(ForeignMmReadReceipt::complete(
                snapshot,
                dst.len(),
                vec![ForeignOwnerGeneration::from_backend_counter(
                    NonZeroU64::new(47).expect("nonzero owner generation"),
                )],
            ))
        }
    }

    #[test]
    fn foreign_mm_transport_round_trips_distinct_snapshot_domains() {
        let snapshot = ForeignMmSnapshot {
            mm: ForeignMmId::from_kernel_allocation(
                NonZeroU64::new(11).expect("nonzero MM identity"),
            ),
            binding: ForeignMmBinding::for_aarch64(
                ForeignAsid::from_kernel_allocation(NonZeroU16::new(13).expect("nonzero ASID")),
                Gpa(0x1234_5000),
            ),
            backend_revision: ForeignBackendRevision::from_authority_raw(17),
            vma_revision: ForeignVmaRevision::from_authority_raw(19),
            frame_inventory_revision: ForeignFrameInventoryRevision::from_authority_raw(23),
            mapping_ids: vec![MappingId::from_kernel_allocation(
                NonZeroU64::new(29).expect("nonzero mapping identity"),
            )],
        };
        let transport: &dyn ForeignMmTransport = &MockTransport;
        let mut bytes = [0_u8; 6];

        let receipt = transport
            .read(&snapshot, GuestVa(0x4000), &mut bytes)
            .expect("mock foreign read");

        assert_eq!(&bytes, b"target");
        assert_eq!(receipt.mm, snapshot.mm);
        assert_eq!(receipt.binding, snapshot.binding);
        assert_eq!(receipt.backend_revision, snapshot.backend_revision);
        assert_eq!(receipt.vma_revision, snapshot.vma_revision);
        assert_eq!(
            receipt.frame_inventory_revision,
            snapshot.frame_inventory_revision
        );
        assert_eq!(receipt.bytes_read, bytes.len());
        assert_eq!(
            receipt.owner_generations,
            [ForeignOwnerGeneration::from_backend_counter(
                NonZeroU64::new(47).expect("nonzero owner generation")
            )]
        );
        assert_eq!(snapshot.mapping_ids.len(), 1);
    }
}
