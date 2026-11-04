//! Exact logical inventory identities and receipt authentication.
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{fmt, num::NonZeroU64};

/// Exact owner of a frame-inventory receipt. The host and guest numeric MM
/// spaces overlap; a guest root incarnation is part of its custody identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameInventoryReceiptOwner {
    HostMm(NonZeroU64),
    GuestMm {
        native_mm: carrick_guest_arch::MmGeneration,
        root_generation: carrick_guest_arch::ContextGeneration,
    },
}

impl From<NonZeroU64> for FrameInventoryReceiptOwner {
    fn from(mm: NonZeroU64) -> Self {
        Self::HostMm(mm)
    }
}

impl FrameInventoryReceiptOwner {
    /// Scalar compatibility for ABI and diagnostic projections only.
    pub const fn wire_mm(self) -> NonZeroU64 {
        match self {
            Self::HostMm(mm) => mm,
            Self::GuestMm { native_mm, .. } => native_mm.raw(),
        }
    }
}

macro_rules! inventory_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Construct an ID from the kernel allocator's nonzero output.
            pub const fn from_kernel_allocation(raw: NonZeroU64) -> Self {
                Self(raw)
            }

            /// Export the scalar only at a wire, probe, or persistence boundary.
            pub const fn raw(self) -> u64 {
                self.0.get()
            }
        }
    };
}

inventory_id!(FrameId);
inventory_id!(MappingId);
inventory_id!(KernelTransactionId);

/// The allocator's physical owner identity, independent of mapping generations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrameBackingIdentity {
    ipa: carrick_guest_arch::FrameGpa,
    host_owner_generation: NonZeroU64,
    length: FrameLength,
}
impl FrameBackingIdentity {
    pub const fn from_allocator(
        ipa: carrick_guest_arch::FrameGpa,
        host_owner_generation: NonZeroU64,
        length: FrameLength,
    ) -> Self {
        Self {
            ipa,
            host_owner_generation,
            length,
        }
    }
    pub const fn ipa(self) -> carrick_guest_arch::FrameGpa {
        self.ipa
    }
    pub const fn host_owner_generation(self) -> NonZeroU64 {
        self.host_owner_generation
    }
    pub const fn length(self) -> FrameLength {
        self.length
    }
}

/// Inventory-side release of a physical publication exclusion. Backend callers
/// cannot invoke this through a permit; only terminal completion exposes it.
pub trait FrameRetirementCleanup: core::fmt::Debug + Send + Sync {
    fn complete(&self, frame: FrameId, backing: FrameBackingIdentity);
}

/// Linear permission to request retirement of one exact physical owner.
/// Dropping an unconsumed permit is safe but leaks retirement; the issuing
/// inventory counts it. A permit is returned only after its inventory unlocks.
/// ```compile_fail
/// fn duplicate(p: carrick_core_abi::FrameRetirementPermit) { let _ = p.clone(); }
/// ```
#[derive(Debug)]
#[must_use = "request physical retirement or retain the permit for retry"]
pub struct FrameRetirementPermit {
    origin: FrameInventoryOrigin,
    frame: FrameId,
    backing: FrameBackingIdentity,
    revision: u64,
    abandoned: Arc<core::sync::atomic::AtomicU64>,
    admission: Option<Arc<()>>,
    cleanup: Arc<dyn FrameRetirementCleanup>,
}
impl FrameRetirementPermit {
    /// # Safety
    /// Only the issuing inventory may call this, after irrevocably removing
    /// the last reference to `frame`, or atomically excluding publication of
    /// an unused allocator incarnation. `backing` must be its authenticated
    /// allocator identity, never the mapping generation or virtual address.
    pub unsafe fn from_inventory(
        origin: FrameInventoryOrigin,
        frame: FrameId,
        backing: FrameBackingIdentity,
        revision: u64,
        abandoned: Arc<core::sync::atomic::AtomicU64>,
        admission: Arc<()>,
        cleanup: Arc<dyn FrameRetirementCleanup>,
    ) -> Self {
        Self {
            origin,
            frame,
            backing,
            revision,
            abandoned,
            admission: Some(admission),
            cleanup,
        }
    }
    pub const fn frame(&self) -> FrameId {
        self.frame
    }
    pub const fn backing(&self) -> FrameBackingIdentity {
        self.backing
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn issued_by(&self, origin: &FrameInventoryOrigin) -> bool {
        self.origin == *origin
    }

    /// Consume only after the physical owner accepts the retirement request.
    /// A failed request returns the same linear permit for a later attempt.
    /// The consumer must check the allocator generation before touching storage;
    /// an already pending retirement is completion, not a stale successor.
    pub fn retire<E>(
        mut self,
        request: impl FnOnce(FrameBackingIdentity) -> Result<(), E>,
    ) -> Result<PendingFrameRetirement, (Self, E)> {
        match request(self.backing) {
            Ok(()) => Ok(PendingFrameRetirement {
                admission: self.admission.take(),
                abandoned: self.abandoned.clone(),
                cleanup: self.cleanup.clone(),
                frame: self.frame,
                backing: self.backing,
            }),
            Err(error) => Err((self, error)),
        }
    }
}
impl Drop for FrameRetirementPermit {
    fn drop(&mut self) {
        if let Some(admission) = self.admission.take() {
            self.abandoned
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            // Fail closed: an abandoned retirement must never reopen physical
            // publication. The inventory keeps only a weak admission index.
            core::mem::forget(admission);
        }
    }
}

/// Physical publication stays excluded after the retirement request, until
/// the backend proves the exact owner can no longer be reached or reissued.
#[derive(Debug)]
#[must_use = "retain through physical retirement completion"]
pub struct PendingFrameRetirement {
    admission: Option<Arc<()>>,
    abandoned: Arc<core::sync::atomic::AtomicU64>,
    cleanup: Arc<dyn FrameRetirementCleanup>,
    frame: FrameId,
    backing: FrameBackingIdentity,
}
impl PendingFrameRetirement {
    /// # Safety
    /// The backend must have completed retirement for the exact owner named
    /// by the issuing permit, including stage-2 removal and pin drain, or
    /// proved that the VM containing that owner was destroyed. All backend
    /// registry locks must be released: completion calls the inventory owner.
    pub unsafe fn complete(mut self) {
        self.cleanup.complete(self.frame, self.backing);
        self.admission.take();
    }
}
impl Drop for PendingFrameRetirement {
    fn drop(&mut self) {
        if let Some(admission) = self.admission.take() {
            self.abandoned
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            core::mem::forget(admission);
        }
    }
}

/// Unpredictable authority capability bound to one runtime reservation.
///
/// The bytes are deliberately not exported or printed. Public construction
/// lets a dependency-neutral HAL accept kernel entropy, while authentication
/// still requires matching the authority's independently retained capability.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrameInventoryProvenance([u8; 32]);

impl FrameInventoryProvenance {
    pub const fn from_kernel_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for FrameInventoryProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrameInventoryProvenance(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MappingGeneration(NonZeroU64);

impl MappingGeneration {
    pub const fn from_backend_counter(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct FrameLength(NonZeroU64);

impl FrameLength {
    pub const fn from_mapping_extent(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryReceiptChallenge {
    provenance: FrameInventoryProvenance,
    transaction: KernelTransactionId,
}

/// Exact incarnation of one inventory owner. Local transaction, frame,
/// mapping and MM numbers may repeat in another inventory.
#[derive(Clone, Debug, Default)]
pub struct FrameInventoryOrigin(Arc<()>);
impl PartialEq for FrameInventoryOrigin {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for FrameInventoryOrigin {}

#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryApplyReceipt {
    origin: FrameInventoryOrigin,
    provenance: FrameInventoryProvenance,
    transaction: KernelTransactionId,
    owner: FrameInventoryReceiptOwner,
    revision: u64,
    mappings: Vec<(MappingId, FrameId)>,
}

impl FrameInventoryApplyReceipt {
    /// Kernel-owner seam. Callers cannot authenticate a fabricated receipt
    /// without the reservation's opaque provenance retained by the Kernel.
    ///
    /// The mapping set is kept sorted, so [`Self::authorizes`] is a binary
    /// search: a process retirement authenticates every one of its n
    /// mappings against the receipt, and a linear `contains` made that
    /// O(n^2) (~0.7 ms of a 2511-mapping cpython teardown).
    #[doc(hidden)]
    pub fn from_kernel_authority(
        origin: FrameInventoryOrigin,
        provenance: FrameInventoryProvenance,
        transaction: KernelTransactionId,
        owner: impl Into<FrameInventoryReceiptOwner>,
        revision: u64,
        mut mappings: Vec<(MappingId, FrameId)>,
    ) -> Self {
        mappings.sort_unstable();
        Self {
            origin,
            provenance,
            transaction,
            owner: owner.into(),
            revision,
            mappings,
        }
    }

    pub fn issued_by(&self, origin: &FrameInventoryOrigin) -> bool {
        self.origin == *origin
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.transaction
    }

    pub const fn mm(&self) -> NonZeroU64 {
        self.owner.wire_mm()
    }

    pub const fn owner(&self) -> FrameInventoryReceiptOwner {
        self.owner
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn authorizes(&self, mapping: MappingId, frame: FrameId) -> bool {
        self.mappings.binary_search(&(mapping, frame)).is_ok()
    }

    /// The receipt's exact `(mapping, frame)` set, sorted.
    pub fn mapping_set(&self) -> &[(MappingId, FrameId)] {
        &self.mappings
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryRetirementReceipt {
    apply: FrameInventoryApplyReceipt,
    mm_empty_at_revision: bool,
}

impl FrameInventoryRetirementReceipt {
    #[doc(hidden)]
    pub fn from_kernel_authority(
        receipt: FrameInventoryApplyReceipt,
        mm_empty_at_revision: bool,
    ) -> Self {
        Self {
            apply: receipt,
            mm_empty_at_revision,
        }
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.apply.transaction()
    }

    pub const fn mm(&self) -> NonZeroU64 {
        self.apply.mm()
    }

    pub const fn owner(&self) -> FrameInventoryReceiptOwner {
        self.apply.owner()
    }

    pub const fn revision(&self) -> u64 {
        self.apply.revision()
    }

    pub fn authorizes(&self, mapping: MappingId, frame: FrameId) -> bool {
        self.apply.authorizes(mapping, frame)
    }

    pub fn mapping_set(&self) -> &[(MappingId, FrameId)] {
        self.apply.mapping_set()
    }

    pub const fn mm_empty_at_revision(&self) -> bool {
        self.mm_empty_at_revision
    }
}

/// Inventory half of whole-MM release. This retains the exact empty-MM
/// revision, but cannot authorize journal acknowledgement by itself.
#[derive(Debug)]
#[must_use = "retain the inventory half until backend custody is released"]
pub struct InventoryReleased {
    retirement: FrameInventoryRetirementReceipt,
    last_unmapped: Vec<FrameRetirementPermit>,
}
impl InventoryReleased {
    /// Attach the permits produced atomically with this retirement revision.
    /// A failed identity check preserves both the receipt and all permits.
    pub fn with_retirements(
        mut self,
        permits: Vec<FrameRetirementPermit>,
    ) -> Result<Self, Box<(Self, Vec<FrameRetirementPermit>)>> {
        let mut frames: Vec<_> = self
            .retirement
            .mapping_set()
            .iter()
            .map(|(_, frame)| *frame)
            .collect();
        frames.sort_unstable();
        frames.dedup();
        if !self.last_unmapped.is_empty()
            || permits.iter().any(|permit| {
                !permit.issued_by(&self.retirement.apply.origin)
                    || permit.revision() != self.revision()
                    || frames.binary_search(&permit.frame()).is_err()
            })
        {
            return Err(Box::new((self, permits)));
        }
        self.last_unmapped = permits;
        Ok(self)
    }
    pub fn pending_retirements(&self) -> usize {
        self.last_unmapped.len()
    }
    /// Transfer one linear permit to the backend's retirement owner.
    pub fn pop_retirement(&mut self) -> Option<FrameRetirementPermit> {
        self.last_unmapped.pop()
    }

    pub fn from_retirement(retirement: FrameInventoryRetirementReceipt) -> Option<Self> {
        retirement.mm_empty_at_revision().then_some(Self {
            retirement,
            last_unmapped: Vec::new(),
        })
    }
    pub fn issued_by(&self, origin: &FrameInventoryOrigin) -> bool {
        self.retirement.apply.issued_by(origin)
    }
    pub const fn owner(&self) -> FrameInventoryReceiptOwner {
        self.retirement.owner()
    }
    pub const fn revision(&self) -> u64 {
        self.retirement.revision()
    }
}

/// Backend half for one exact inventory release, including its transaction.
/// The unsafe constructor is the backend implementation boundary; settlement
/// cannot manufacture a backend release through a safe inventory operation.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "join with the exact inventory release"]
pub struct BackendCustodyReleased {
    origin: FrameInventoryOrigin,
    owner: FrameInventoryReceiptOwner,
    revision: u64,
    transaction: KernelTransactionId,
}
impl BackendCustodyReleased {
    /// # Safety
    /// Only the physical backend release owner may call this, after retiring
    /// residency and releasing the exact MM's backend custody. Every last-frame
    /// retirement must have been accepted by its physical owner, which retains
    /// the pending retirement until stage-2 removal and pin drain complete.
    /// Merely observing an empty inventory or dropping a receipt is insufficient.
    pub unsafe fn from_backend_release(inventory: &InventoryReleased) -> Self {
        Self {
            origin: inventory.retirement.apply.origin.clone(),
            owner: inventory.owner(),
            revision: inventory.revision(),
            transaction: inventory.retirement.transaction(),
        }
    }
}

/// Joined inventory and backend release. Pending physical retirement may
/// outlive this receipt; the physical owner must prevent frame reuse meanwhile.
/// Inventory emptiness alone cannot authorize whole-MM acknowledgement.
/// ```compile_fail
/// fn inventory_is_not_backend_release(
///     retired: carrick_core_abi::FrameInventoryRetirementReceipt,
/// ) -> Option<carrick_core_abi::MmReleaseReceipt> {
///     carrick_core_abi::MmReleaseReceipt::from_retirement(retired)
/// }
/// ```
/// ```compile_fail
/// fn inventory_half_is_not_a_receipt(
///     released: carrick_core_abi::InventoryReleased,
/// ) -> carrick_core_abi::MmReleaseReceipt {
///     released
/// }
/// ```
#[derive(Debug)]
#[must_use = "deliver the joined release to journal settlement"]
pub struct MmReleaseReceipt {
    inventory: InventoryReleased,
}
impl MmReleaseReceipt {
    /// A rejected join returns both halves, preserving retry custody.
    pub fn join(
        inventory: InventoryReleased,
        backend: BackendCustodyReleased,
    ) -> Result<Self, Box<(InventoryReleased, BackendCustodyReleased)>> {
        if inventory.last_unmapped.is_empty()
            && inventory.issued_by(&backend.origin)
            && inventory.owner() == backend.owner
            && inventory.revision() == backend.revision
            && inventory.retirement.transaction() == backend.transaction
        {
            Ok(Self { inventory })
        } else {
            Err(Box::new((inventory, backend)))
        }
    }
    pub fn issued_by(&self, origin: &FrameInventoryOrigin) -> bool {
        self.inventory.issued_by(origin)
    }
    pub const fn owner(&self) -> FrameInventoryReceiptOwner {
        self.inventory.owner()
    }
    pub const fn revision(&self) -> u64 {
        self.inventory.revision()
    }
}

impl FrameInventoryReceiptChallenge {
    #[doc(hidden)]
    pub const fn from_kernel_authority(
        provenance: FrameInventoryProvenance,
        transaction: KernelTransactionId,
    ) -> Self {
        Self {
            provenance,
            transaction,
        }
    }

    pub fn authenticate_apply(
        self,
        receipt: &FrameInventoryApplyReceipt,
        expected_mm: NonZeroU64,
    ) -> bool {
        self.provenance == receipt.provenance
            && self.transaction == receipt.transaction
            && receipt.mm() == expected_mm
            && receipt.revision != 0
    }

    pub fn authenticate_retirement(
        self,
        receipt: &FrameInventoryRetirementReceipt,
        expected_mm: NonZeroU64,
    ) -> bool {
        self.provenance == receipt.apply.provenance
            && self.transaction == receipt.apply.transaction
            && receipt.apply.mm() == expected_mm
            && receipt.apply.revision != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(raw: u64) -> NonZeroU64 {
        NonZeroU64::new(raw).expect("nonzero test ID")
    }
    #[test]
    fn mm_release_requires_empty_inventory_and_preserves_exact_owner() {
        let owner = FrameInventoryReceiptOwner::GuestMm {
            native_mm: carrick_guest_arch::MmGeneration::new(id(7)),
            root_generation: carrick_guest_arch::ContextGeneration::new(id(13)),
        };
        let make = |empty| {
            FrameInventoryRetirementReceipt::from_kernel_authority(
                FrameInventoryApplyReceipt::from_kernel_authority(
                    Default::default(),
                    FrameInventoryProvenance::from_kernel_entropy([2; 32]),
                    KernelTransactionId::from_kernel_allocation(id(8)),
                    owner,
                    27,
                    Vec::new(),
                ),
                empty,
            )
        };
        assert!(InventoryReleased::from_retirement(make(false)).is_none());
        let inventory = InventoryReleased::from_retirement(make(true)).expect("empty MM");
        // SAFETY: this ABI fixture has no physical custody or residency.
        let backend = unsafe { BackendCustodyReleased::from_backend_release(&inventory) };
        let release = MmReleaseReceipt::join(inventory, backend).unwrap();
        assert_eq!(release.owner(), owner);
        assert_eq!(release.revision(), 27);
    }
    #[test]
    fn mm_release_join_rejects_foreign_origin_owner_revision_and_transaction() {
        let origin = FrameInventoryOrigin::default();
        let make = |origin, owner, revision, transaction| {
            InventoryReleased::from_retirement(
                FrameInventoryRetirementReceipt::from_kernel_authority(
                    FrameInventoryApplyReceipt::from_kernel_authority(
                        origin,
                        FrameInventoryProvenance::from_kernel_entropy([2; 32]),
                        KernelTransactionId::from_kernel_allocation(id(transaction)),
                        FrameInventoryReceiptOwner::HostMm(id(owner)),
                        revision,
                        Vec::new(),
                    ),
                    true,
                ),
            )
            .unwrap()
        };
        for wrong in [
            make(FrameInventoryOrigin::default(), 7, 27, 8),
            make(origin.clone(), 9, 27, 8),
            make(origin.clone(), 7, 28, 8),
            make(origin.clone(), 7, 27, 9),
        ] {
            let expected = make(origin.clone(), 7, 27, 8);
            // SAFETY: these ABI fixtures hold no physical custody or residency.
            let backend = unsafe { BackendCustodyReleased::from_backend_release(&expected) };
            let (retained, backend) = *MmReleaseReceipt::join(wrong, backend).unwrap_err();
            // A refused join consumes neither half: the intended inventory can
            // still join, and the wrong inventory remains owned by the caller.
            assert_ne!(retained.retirement, expected.retirement);
            let receipt = MmReleaseReceipt::join(expected, backend).unwrap();
            assert!(receipt.issued_by(&origin));
            assert_eq!(receipt.owner(), FrameInventoryReceiptOwner::HostMm(id(7)));
            assert_eq!(receipt.revision(), 27);
        }
    }

    /// A receipt keeps its mapping set sorted however the Kernel listed it,
    /// so `authorizes` is a search, not a scan: process retirement asks it
    /// once per mapping, which made a linear scan O(n^2) in the process's
    /// mapping count.
    #[test]
    fn receipt_mapping_set_is_sorted_and_authorizes_exactly() {
        let n = 4096_u64;
        let mappings: Vec<_> = (1..=n)
            .rev()
            .map(|raw| {
                (
                    MappingId::from_kernel_allocation(id(raw)),
                    FrameId::from_kernel_allocation(id(raw % 97 + 1)),
                )
            })
            .collect();
        let receipt = FrameInventoryApplyReceipt::from_kernel_authority(
            Default::default(),
            FrameInventoryProvenance::from_kernel_entropy([7; 32]),
            KernelTransactionId::from_kernel_allocation(id(9)),
            id(3),
            1,
            mappings.clone(),
        );
        assert!(
            receipt
                .mapping_set()
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert_eq!(receipt.mapping_set().len(), mappings.len());
        for &(mapping, frame) in &mappings {
            assert!(receipt.authorizes(mapping, frame));
        }
        assert!(!receipt.authorizes(
            MappingId::from_kernel_allocation(id(1)),
            FrameId::from_kernel_allocation(id(97)),
        ));
        assert!(!receipt.authorizes(
            MappingId::from_kernel_allocation(id(n + 1)),
            FrameId::from_kernel_allocation(id(1)),
        ));
        let source = include_str!("inventory.rs");
        let authorizes = source
            .split("pub fn authorizes(&self, mapping: MappingId, frame: FrameId) -> bool {")
            .nth(1)
            .and_then(|tail| tail.split("\n    }").next())
            .expect("authorizes body");
        assert!(authorizes.contains("binary_search"));
        assert!(!authorizes.contains(".contains("));
    }
}
