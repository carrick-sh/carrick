//! Dependency-neutral, object-safe contracts for carrier-owned foreign-MM reads.

use std::fmt::Debug;
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use std::time::Instant;

use carrick_guest_mem::{Gpa, GuestVa};

use crate::{ForeignBackendRevision, ForeignFrameInventoryRevision, ForeignVmaRevision, MappingId};

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ForeignMmBinding {
    asid: ForeignAsid,
    stage1_root: Gpa,
}

impl ForeignMmBinding {
    pub const fn for_aarch64(asid: ForeignAsid, stage1_root: Gpa) -> Self {
        Self { asid, stage1_root }
    }
    pub const fn asid(self) -> ForeignAsid {
        self.asid
    }
    pub const fn stage1_root(self) -> Gpa {
        self.stage1_root
    }
}

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

/// Coherent kernel projection of one exact Linux MM incarnation.
/// Implementations stay private to the kernel authority layer.
pub trait ForeignMmSnapshot: Debug + Send + Sync {
    fn mm(&self) -> ForeignMmId;
    fn binding(&self) -> ForeignMmBinding;
    fn backend_revision(&self) -> ForeignBackendRevision;
    fn vma_revision(&self) -> ForeignVmaRevision;
    fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision;
    fn mapping_ids(&self) -> &[MappingId];
}

/// Exact live backend used to re-observe real mutation authorities.
pub trait ForeignMmLiveAuthority: Send + Sync {
    fn snapshot(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmSnapshot>, ForeignMmTransportError>;
}

/// Authenticated completion. Concrete receipts stay private to transports.
pub trait ForeignMmReadReceipt: Debug + Send + Sync {
    fn bytes_read(&self) -> usize;
    fn owner_generations(&self) -> &[ForeignOwnerGeneration];
    fn authenticates(&self, snapshot: &dyn ForeignMmSnapshot) -> bool;
}

/// Strong lease for one exact carrier MM access state.
pub trait ForeignMmReadLease: Debug + Send + Sync {
    fn read(
        &self,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        dst: &mut [u8],
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError>;
}

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
    #[error("foreign MM read deadline expired")]
    TimedOut,
    #[error("foreign MM live authority is unavailable")]
    AuthorityUnavailable,
}

/// Object-safe endpoint privately installed by one exact carrier.
pub trait ForeignMmTransport: Debug + Send + Sync {
    fn retain(
        &self,
        snapshot: &dyn ForeignMmSnapshot,
        deadline: Instant,
    ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Snapshot(Vec<MappingId>);
    impl ForeignMmSnapshot for Snapshot {
        fn mm(&self) -> ForeignMmId {
            ForeignMmId::from_kernel_allocation(NonZeroU64::new(11).unwrap())
        }
        fn binding(&self) -> ForeignMmBinding {
            ForeignMmBinding::for_aarch64(
                ForeignAsid::from_kernel_allocation(NonZeroU16::new(13).unwrap()),
                Gpa(0x1234_5000),
            )
        }
        fn backend_revision(&self) -> ForeignBackendRevision {
            ForeignBackendRevision::from_authority_raw(17)
        }
        fn vma_revision(&self) -> ForeignVmaRevision {
            ForeignVmaRevision::from_authority_raw(19)
        }
        fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision {
            ForeignFrameInventoryRevision::from_authority_raw(23)
        }
        fn mapping_ids(&self) -> &[MappingId] {
            &self.0
        }
    }

    #[derive(Debug)]
    struct Receipt;
    impl ForeignMmReadReceipt for Receipt {
        fn bytes_read(&self) -> usize {
            6
        }
        fn owner_generations(&self) -> &[ForeignOwnerGeneration] {
            const OWNERS: [ForeignOwnerGeneration; 1] =
                [ForeignOwnerGeneration::from_backend_counter(
                    NonZeroU64::MIN,
                )];
            &OWNERS
        }
        fn authenticates(&self, snapshot: &dyn ForeignMmSnapshot) -> bool {
            snapshot.mm().raw_for_probe() == 11
                && snapshot.binding().asid().raw_for_probe() == 13
                && snapshot.binding().stage1_root() == Gpa(0x1234_5000)
                && snapshot.backend_revision().raw_for_probe() == 17
                && snapshot.vma_revision().raw_for_probe() == 19
                && snapshot.frame_inventory_revision().raw_for_probe() == 23
                && snapshot.mapping_ids().len() == 1
        }
    }

    #[derive(Debug)]
    struct Live;
    impl ForeignMmLiveAuthority for Live {
        fn snapshot(
            &self,
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignMmSnapshot>, ForeignMmTransportError> {
            Ok(Box::new(Snapshot(vec![MappingId::from_kernel_allocation(
                NonZeroU64::new(29).unwrap(),
            )])))
        }
    }

    #[derive(Debug)]
    struct Lease;
    impl ForeignMmReadLease for Lease {
        fn read(
            &self,
            _authority: &dyn ForeignMmLiveAuthority,
            _snapshot: &dyn ForeignMmSnapshot,
            _va: GuestVa,
            dst: &mut [u8],
            deadline: Instant,
        ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
            if Instant::now() >= deadline {
                return Err(ForeignMmTransportError::TimedOut);
            }
            dst.copy_from_slice(b"target");
            Ok(Box::new(Receipt))
        }
    }

    #[derive(Debug)]
    struct Transport;
    impl ForeignMmTransport for Transport {
        fn retain(
            &self,
            snapshot: &dyn ForeignMmSnapshot,
            deadline: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            assert!(Instant::now() < deadline);
            assert_eq!(snapshot.mm().raw_for_probe(), 11);
            Ok(Arc::new(Lease))
        }
    }

    #[test]
    fn object_safe_transport_retains_and_authenticates_distinct_domains() {
        let snapshot = Live.snapshot(Instant::now()).unwrap();
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(Transport);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let lease = transport.retain(snapshot.as_ref(), deadline).unwrap();
        let mut bytes = [0; 6];
        let receipt = lease
            .read(
                &Live,
                snapshot.as_ref(),
                GuestVa(0x4000),
                &mut bytes,
                deadline,
            )
            .unwrap();
        assert_eq!(&bytes, b"target");
        assert_eq!(receipt.bytes_read(), 6);
        assert_eq!(receipt.owner_generations().len(), 1);
        assert!(receipt.authenticates(snapshot.as_ref()));
    }
}
