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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    /// Boundary constructor for crates that intentionally depend only on HAL
    /// domain types rather than on `carrick-guest-mem` directly.
    pub const fn for_aarch64_root_raw(asid: ForeignAsid, stage1_root: u64) -> Self {
        Self::for_aarch64(asid, Gpa(stage1_root))
    }
}

/// Exact lifetime of one numeric target ASID. This is deliberately distinct
/// from both owner and COW publication generations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ForeignAsidGeneration {
    asid: ForeignAsid,
    generation: NonZeroU64,
}

impl ForeignAsidGeneration {
    pub const fn from_runtime_binding(asid: ForeignAsid, generation: NonZeroU64) -> Self {
        Self { asid, generation }
    }

    pub const fn asid(self) -> ForeignAsid {
        self.asid
    }

    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }
}

/// Exact MM + ASID lifetime + stage-1 root. Keeping the validated binding as
/// one field prevents a recycled numeric ASID from acknowledging work for an
/// older root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ForeignStage1Identity {
    mm: ForeignMmId,
    binding: ForeignMmBinding,
    asid_generation: ForeignAsidGeneration,
}

impl ForeignStage1Identity {
    pub const fn new(
        mm: ForeignMmId,
        binding: ForeignMmBinding,
        asid_generation: ForeignAsidGeneration,
    ) -> Option<Self> {
        if binding.asid().raw_for_probe() != asid_generation.asid().raw_for_probe() {
            return None;
        }
        Some(Self {
            mm,
            binding,
            asid_generation,
        })
    }

    pub const fn mm(self) -> ForeignMmId {
        self.mm
    }

    pub const fn binding(self) -> ForeignMmBinding {
        self.binding
    }

    pub const fn asid_generation(self) -> ForeignAsidGeneration {
        self.asid_generation
    }
}

/// Monotonic publication within one exact stage-1 identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ForeignCowInvalidationGeneration(NonZeroU64);

impl ForeignCowInvalidationGeneration {
    pub const fn from_runtime_publication(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw_for_probe(self) -> u64 {
        self.0.get()
    }
}

/// Complete typed identity of one target-MM COW invalidation publication.
///
/// ```compile_fail
/// # use carrick_hal::{ForeignAsidGeneration, ForeignCowInvalidationIdentity,
/// #     ForeignStage1Identity};
/// # fn swapped(stage1: ForeignStage1Identity, asid: ForeignAsidGeneration) {
/// let _ = ForeignCowInvalidationIdentity::new(stage1, asid);
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ForeignCowInvalidationIdentity {
    stage1: ForeignStage1Identity,
    generation: ForeignCowInvalidationGeneration,
}

impl ForeignCowInvalidationIdentity {
    pub const fn new(
        stage1: ForeignStage1Identity,
        generation: ForeignCowInvalidationGeneration,
    ) -> Self {
        Self { stage1, generation }
    }

    pub const fn stage1(self) -> ForeignStage1Identity {
        self.stage1
    }

    pub const fn generation(self) -> ForeignCowInvalidationGeneration {
        self.generation
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

/// Borrowed runtime-owned exact-target invalidation capability. Backends can
/// request publication at the transaction boundary but cannot retain or mint
/// the page-table authority behind it.
pub trait ForeignMmInvalidator {
    fn invalidate_exact_asid(
        &mut self,
        binding: ForeignMmBinding,
        deadline: Instant,
    ) -> Result<(), ForeignMmTransportError>;
}

/// Authenticated completion. Concrete receipts stay private to transports.
pub trait ForeignMmReadReceipt: Debug + Send + Sync {
    fn bytes_read(&self) -> usize;
    fn owner_generations(&self) -> &[ForeignOwnerGeneration];
    fn authenticates(&self, snapshot: &dyn ForeignMmSnapshot) -> bool;
}

/// Backend completion data for one exact post-COW compound. Implementations
/// are transport-private; the runtime may only inspect the values required to
/// validate them against its kernel-minted MM authority.
pub trait ForeignCowReceipt: Debug + Send + Sync {
    fn mm(&self) -> ForeignMmId;
    fn range_start(&self) -> GuestVa;
    fn range_len(&self) -> usize;
    fn backend_revision(&self) -> ForeignBackendRevision;
    fn vma_revision(&self) -> ForeignVmaRevision;
    fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision;
    fn mapping(&self) -> MappingId;
    fn frame(&self) -> crate::FrameId;
    fn physical_base(&self) -> Gpa;
    fn physical_len(&self) -> u64;
    fn owner_generation(&self) -> ForeignOwnerGeneration;
    fn kernel_proof(&self) -> &ForeignCowKernelProof;
}

/// Opaque carrier for a runtime-private kernel-authority proof. Transports can
/// retain and return the value but cannot construct the private payload type
/// that the runtime accepts when minting safe write authority.
pub struct ForeignCowKernelProof {
    payload: Box<dyn std::any::Any + Send + Sync>,
}

impl ForeignCowKernelProof {
    #[doc(hidden)]
    pub fn from_runtime_authority(payload: Box<dyn std::any::Any + Send + Sync>) -> Self {
        Self { payload }
    }

    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.payload.downcast_ref()
    }
}

impl Debug for ForeignCowKernelProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignCowKernelProof")
            .finish_non_exhaustive()
    }
}

/// Backend completion data for a copy through one authenticated post-COW
/// owner. Implementations are transport-private and confer no safe authority.
pub trait ForeignMmWriteReceipt: Debug + Send + Sync {
    fn mm(&self) -> ForeignMmId;
    fn range_start(&self) -> GuestVa;
    fn range_len(&self) -> usize;
    fn bytes_written(&self) -> usize;
    fn backend_revision(&self) -> ForeignBackendRevision;
    fn vma_revision(&self) -> ForeignVmaRevision;
    fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision;
    fn mapping(&self) -> MappingId;
    fn frame(&self) -> crate::FrameId;
    fn owner_generation(&self) -> ForeignOwnerGeneration;
}

/// Single-use transport witness for one prepared foreign copy. Commit consumes
/// the prepared state and performs the write infallibly.
pub trait ForeignMmPreparedWrite: Debug {
    fn commit(self: Box<Self>);
    fn receipt(&self) -> &dyn ForeignMmWriteReceipt;
}

/// Strong lease for one exact carrier MM access state.
pub trait ForeignMmReadLease: Debug + Send + Sync {
    fn read(
        &self,
        invocation: &ForeignMmInvocation,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        dst: &mut [u8],
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError>;

    #[allow(clippy::too_many_arguments)] // Object-safe transport carries exact mutation domains.
    fn break_cow(
        &self,
        invocation: &ForeignMmInvocation,
        invalidator: &mut dyn ForeignMmInvalidator,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        len: usize,
        deadline: Instant,
    ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
        let _ = (invocation, invalidator, snapshot, va, len, deadline);
        Err(ForeignMmTransportError::AuthorityUnavailable)
    }

    #[allow(clippy::too_many_arguments)] // Object-safe transport carries exact mutation domains.
    fn prepare_write<'a>(
        &self,
        invocation: &ForeignMmInvocation,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        cow: &dyn ForeignCowReceipt,
        va: GuestVa,
        src: &'a [u8],
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmPreparedWrite + 'a>, ForeignMmTransportError> {
        let _ = (invocation, authority, snapshot, cow, va, src, deadline);
        Err(ForeignMmTransportError::AuthorityUnavailable)
    }
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
    #[error("foreign MM mutation failed before commit")]
    MutationFailed,
}

/// Object-safe endpoint privately installed by one exact carrier.
pub trait ForeignMmTransport: Debug + Send + Sync {
    fn retain(
        &self,
        invocation: &ForeignMmInvocation,
        snapshot: &dyn ForeignMmSnapshot,
        deadline: Instant,
    ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError>;
}

/// Unforgeable call-site witness. Raw transport traits stay object-safe for
/// cross-crate backend implementations, but only an opaque endpoint can mint
/// the witness needed to invoke them.
///
/// ```compile_fail
/// let _ = carrick_hal::ForeignMmInvocation { _private: () };
/// ```
#[derive(Debug)]
pub struct ForeignMmInvocation {
    _private: (),
}

/// Cloneable capability for one exact carrier transport. Runtime stores this
/// only in the kernel MM object; raw backend observation never exposes it.
#[derive(Clone)]
pub struct ForeignMmEndpoint {
    transport: Arc<dyn ForeignMmTransport>,
}

impl Debug for ForeignMmEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForeignMmEndpoint")
            .finish_non_exhaustive()
    }
}

impl ForeignMmEndpoint {
    pub fn for_carrier(transport: Arc<dyn ForeignMmTransport>) -> Self {
        Self { transport }
    }

    pub fn retain(
        &self,
        snapshot: &dyn ForeignMmSnapshot,
        deadline: Instant,
    ) -> Result<ForeignMmLeaseEndpoint, ForeignMmTransportError> {
        let invocation = ForeignMmInvocation { _private: () };
        self.transport
            .retain(&invocation, snapshot, deadline)
            .map(|lease| ForeignMmLeaseEndpoint { lease })
    }
}

/// Token-held half of the carrier capability. Its raw lease is never exposed.
#[derive(Clone)]
pub struct ForeignMmLeaseEndpoint {
    lease: Arc<dyn ForeignMmReadLease>,
}

impl Debug for ForeignMmLeaseEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForeignMmLeaseEndpoint")
            .finish_non_exhaustive()
    }
}

impl ForeignMmLeaseEndpoint {
    pub fn read(
        &self,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        dst: &mut [u8],
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
        let invocation = ForeignMmInvocation { _private: () };
        self.lease
            .read(&invocation, authority, snapshot, va, dst, deadline)
    }

    pub fn break_cow(
        &self,
        invalidator: &mut dyn ForeignMmInvalidator,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        len: usize,
        deadline: Instant,
    ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
        let invocation = ForeignMmInvocation { _private: () };
        self.lease
            .break_cow(&invocation, invalidator, snapshot, va, len, deadline)
    }

    pub fn prepare_write<'a>(
        &self,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        cow: &dyn ForeignCowReceipt,
        va: GuestVa,
        src: &'a [u8],
        deadline: Instant,
    ) -> Result<Box<dyn ForeignMmPreparedWrite + 'a>, ForeignMmTransportError> {
        let invocation = ForeignMmInvocation { _private: () };
        self.lease
            .prepare_write(&invocation, authority, snapshot, cow, va, src, deadline)
    }
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
            _invocation: &ForeignMmInvocation,
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

        fn break_cow(
            &self,
            _invocation: &ForeignMmInvocation,
            _invalidator: &mut dyn ForeignMmInvalidator,
            snapshot: &dyn ForeignMmSnapshot,
            va: GuestVa,
            len: usize,
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
            Ok(Box::new(CowReceipt {
                mm: snapshot.mm(),
                start: va,
                len,
                backend_revision: snapshot.backend_revision(),
                vma_revision: snapshot.vma_revision(),
                frame_inventory_revision: snapshot.frame_inventory_revision(),
                mapping: MappingId::from_kernel_allocation(NonZeroU64::new(31).unwrap()),
                frame: crate::FrameId::from_kernel_allocation(NonZeroU64::new(37).unwrap()),
                physical_base: Gpa(0x9000),
                physical_len: 0x4000,
                owner_generation: ForeignOwnerGeneration::from_backend_counter(
                    NonZeroU64::new(41).unwrap(),
                ),
                kernel_proof: ForeignCowKernelProof::from_runtime_authority(Box::new(())),
            }))
        }

        fn prepare_write<'a>(
            &self,
            _invocation: &ForeignMmInvocation,
            _authority: &dyn ForeignMmLiveAuthority,
            snapshot: &dyn ForeignMmSnapshot,
            cow: &dyn ForeignCowReceipt,
            va: GuestVa,
            src: &'a [u8],
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignMmPreparedWrite + 'a>, ForeignMmTransportError> {
            assert_eq!(cow.mm(), snapshot.mm());
            assert!(va.raw() >= cow.range_start().raw());
            let va_end = va.raw().checked_add(src.len() as u64).unwrap();
            let cow_end = cow
                .range_start()
                .raw()
                .checked_add(cow.range_len() as u64)
                .unwrap();
            assert!(va_end <= cow_end);
            Ok(Box::new(PreparedWrite {
                receipt: Box::new(WriteReceipt {
                    mm: snapshot.mm(),
                    start: va,
                    len: src.len(),
                    backend_revision: snapshot.backend_revision(),
                    vma_revision: snapshot.vma_revision(),
                    frame_inventory_revision: snapshot.frame_inventory_revision(),
                    mapping: cow.mapping(),
                    frame: cow.frame(),
                    owner_generation: cow.owner_generation(),
                }),
            }))
        }
    }

    #[derive(Debug)]
    struct PreparedWrite {
        receipt: Box<WriteReceipt>,
    }

    impl ForeignMmPreparedWrite for PreparedWrite {
        fn commit(self: Box<Self>) {}

        fn receipt(&self) -> &dyn ForeignMmWriteReceipt {
            self.receipt.as_ref()
        }
    }

    #[derive(Debug)]
    struct CowReceipt {
        mm: ForeignMmId,
        start: GuestVa,
        len: usize,
        backend_revision: ForeignBackendRevision,
        vma_revision: ForeignVmaRevision,
        frame_inventory_revision: ForeignFrameInventoryRevision,
        mapping: MappingId,
        frame: crate::FrameId,
        physical_base: Gpa,
        physical_len: u64,
        owner_generation: ForeignOwnerGeneration,
        kernel_proof: ForeignCowKernelProof,
    }

    impl ForeignCowReceipt for CowReceipt {
        fn mm(&self) -> ForeignMmId {
            self.mm
        }
        fn range_start(&self) -> GuestVa {
            self.start
        }
        fn range_len(&self) -> usize {
            self.len
        }
        fn backend_revision(&self) -> ForeignBackendRevision {
            self.backend_revision
        }
        fn vma_revision(&self) -> ForeignVmaRevision {
            self.vma_revision
        }
        fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision {
            self.frame_inventory_revision
        }
        fn mapping(&self) -> MappingId {
            self.mapping
        }
        fn frame(&self) -> crate::FrameId {
            self.frame
        }
        fn physical_base(&self) -> Gpa {
            self.physical_base
        }
        fn physical_len(&self) -> u64 {
            self.physical_len
        }
        fn owner_generation(&self) -> ForeignOwnerGeneration {
            self.owner_generation
        }
        fn kernel_proof(&self) -> &ForeignCowKernelProof {
            &self.kernel_proof
        }
    }

    #[derive(Debug)]
    struct WriteReceipt {
        mm: ForeignMmId,
        start: GuestVa,
        len: usize,
        backend_revision: ForeignBackendRevision,
        vma_revision: ForeignVmaRevision,
        frame_inventory_revision: ForeignFrameInventoryRevision,
        mapping: MappingId,
        frame: crate::FrameId,
        owner_generation: ForeignOwnerGeneration,
    }

    impl ForeignMmWriteReceipt for WriteReceipt {
        fn mm(&self) -> ForeignMmId {
            self.mm
        }
        fn range_start(&self) -> GuestVa {
            self.start
        }
        fn range_len(&self) -> usize {
            self.len
        }
        fn bytes_written(&self) -> usize {
            self.len
        }
        fn backend_revision(&self) -> ForeignBackendRevision {
            self.backend_revision
        }
        fn vma_revision(&self) -> ForeignVmaRevision {
            self.vma_revision
        }
        fn frame_inventory_revision(&self) -> ForeignFrameInventoryRevision {
            self.frame_inventory_revision
        }
        fn mapping(&self) -> MappingId {
            self.mapping
        }
        fn frame(&self) -> crate::FrameId {
            self.frame
        }
        fn owner_generation(&self) -> ForeignOwnerGeneration {
            self.owner_generation
        }
    }

    #[derive(Debug)]
    struct Transport;
    impl ForeignMmTransport for Transport {
        fn retain(
            &self,
            _invocation: &ForeignMmInvocation,
            snapshot: &dyn ForeignMmSnapshot,
            deadline: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            assert!(Instant::now() < deadline);
            assert_eq!(snapshot.mm().raw_for_probe(), 11);
            Ok(Arc::new(Lease))
        }
    }

    struct Invalidator;
    impl ForeignMmInvalidator for Invalidator {
        fn invalidate_exact_asid(
            &mut self,
            binding: ForeignMmBinding,
            _deadline: Instant,
        ) -> Result<(), ForeignMmTransportError> {
            assert_eq!(binding, Snapshot(Vec::new()).binding());
            Ok(())
        }
    }

    #[test]
    fn object_safe_transport_retains_and_authenticates_distinct_domains() {
        let snapshot = Live.snapshot(Instant::now()).unwrap();
        let endpoint = ForeignMmEndpoint::for_carrier(Arc::new(Transport));
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let lease = endpoint.retain(snapshot.as_ref(), deadline).unwrap();
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

        let mut invalidator = Invalidator;
        let cow = lease
            .break_cow(
                &mut invalidator,
                snapshot.as_ref(),
                GuestVa(0x4000),
                bytes.len(),
                deadline,
            )
            .unwrap();
        assert_eq!(cow.mm(), snapshot.mm());
        assert_eq!(cow.range_start(), GuestVa(0x4000));
        assert_eq!(cow.range_len(), bytes.len());
        assert_eq!(cow.backend_revision(), snapshot.backend_revision());
        assert_eq!(cow.vma_revision(), snapshot.vma_revision());
        assert_eq!(
            cow.frame_inventory_revision(),
            snapshot.frame_inventory_revision()
        );
        assert_eq!(
            cow.mapping(),
            MappingId::from_kernel_allocation(NonZeroU64::new(31).unwrap())
        );
        assert_eq!(
            cow.frame(),
            crate::FrameId::from_kernel_allocation(NonZeroU64::new(37).unwrap())
        );
        assert_eq!(cow.physical_base(), Gpa(0x9000));
        assert_eq!(cow.physical_len(), 0x4000);
        assert_eq!(cow.owner_generation().raw_for_probe(), 41);

        let prepared = lease
            .prepare_write(
                &Live,
                snapshot.as_ref(),
                cow.as_ref(),
                GuestVa(0x4000),
                b"target",
                deadline,
            )
            .unwrap();
        assert_eq!(prepared.receipt().mm(), snapshot.mm());
        assert_eq!(prepared.receipt().range_start(), GuestVa(0x4000));
        assert_eq!(prepared.receipt().range_len(), 6);
        assert_eq!(prepared.receipt().bytes_written(), 6);
        assert_eq!(
            prepared.receipt().backend_revision(),
            snapshot.backend_revision()
        );
        assert_eq!(prepared.receipt().vma_revision(), snapshot.vma_revision());
        assert_eq!(
            prepared.receipt().frame_inventory_revision(),
            snapshot.frame_inventory_revision()
        );
        assert_eq!(prepared.receipt().mapping(), cow.mapping());
        assert_eq!(prepared.receipt().frame(), cow.frame());
        assert_eq!(
            prepared.receipt().owner_generation(),
            cow.owner_generation()
        );
        prepared.commit();
    }
}
