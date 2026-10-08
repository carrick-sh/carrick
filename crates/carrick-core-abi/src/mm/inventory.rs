//! Exact logical inventory identities and receipt authentication.
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{fmt, num::NonZeroU64};

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
    mm: NonZeroU64,
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
        mm: NonZeroU64,
        revision: u64,
        mut mappings: Vec<(MappingId, FrameId)>,
    ) -> Self {
        mappings.sort_unstable();
        Self {
            origin,
            provenance,
            transaction,
            mm,
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
        self.mm
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
            && receipt.mm == expected_mm
            && receipt.revision != 0
    }

    pub fn authenticate_retirement(
        self,
        receipt: &FrameInventoryRetirementReceipt,
        expected_mm: NonZeroU64,
    ) -> bool {
        self.provenance == receipt.apply.provenance
            && self.transaction == receipt.apply.transaction
            && receipt.apply.mm == expected_mm
            && receipt.apply.revision != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(raw: u64) -> NonZeroU64 {
        NonZeroU64::new(raw).expect("nonzero test ID")
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
