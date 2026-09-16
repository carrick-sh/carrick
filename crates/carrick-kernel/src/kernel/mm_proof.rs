//! Kernel-minted proof that a foreign copy-on-write break was authorized.
//!
//! The proof names only kernel identities (the exact `Kernel`, the target
//! `MmId`, the semantic range, the frame-inventory revision, the `MappingId`
//! and `FrameId`, the physical extent and the owner generation). A transport
//! carries it opaquely through the HAL receipt and can only hand back a
//! proof this kernel minted; it never learns how to forge one.

use std::sync::Arc;

/// Runtime-private payload carried opaquely through the HAL receipt. A
/// transport can return only a proof that this exact Kernel authority minted;
/// an internally consistent transport-owned tuple has the wrong `TypeId` and
/// cannot authorize `CowBroken`.
#[derive(Clone, Debug)]
pub(crate) struct KernelForeignCowProof {
    kernel: Arc<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
    semantic_start: carrick_guest_mem::GuestVa,
    semantic_len: std::num::NonZeroUsize,
    inventory_revision: u64,
    mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    physical_base: carrick_guest_mem::Gpa,
    physical_len: carrick_hal::FrameLength,
    owner_generation: carrick_hal::ForeignOwnerGeneration,
}

impl KernelForeignCowProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel: Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: std::num::NonZeroUsize,
        inventory_revision: u64,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: carrick_guest_mem::Gpa,
        physical_len: carrick_hal::FrameLength,
        owner_generation: carrick_hal::ForeignOwnerGeneration,
    ) -> Self {
        Self {
            kernel,
            mm,
            semantic_start,
            semantic_len,
            inventory_revision,
            mapping,
            frame,
            physical_base,
            physical_len,
            owner_generation,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticates(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: usize,
        inventory_revision: u64,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: carrick_guest_mem::Gpa,
        physical_len: u64,
        owner_generation: carrick_hal::ForeignOwnerGeneration,
    ) -> bool {
        let Some(semantic_len) = std::num::NonZeroUsize::new(semantic_len) else {
            return false;
        };
        let Some(physical_len) = std::num::NonZeroU64::new(physical_len)
            .map(carrick_hal::FrameLength::from_mapping_extent)
        else {
            return false;
        };
        Arc::ptr_eq(&self.kernel, kernel)
            && self.mm == mm
            && self.semantic_start == semantic_start
            && self.semantic_len == semantic_len
            && self.inventory_revision == inventory_revision
            && self.mapping == mapping
            && self.frame == frame
            && self.physical_base == physical_base
            && self.physical_len == physical_len
            && self.owner_generation == owner_generation
            && kernel.frame_inventory().mapping_is_live_exact_at_revision(
                mm,
                inventory_revision,
                mapping,
                frame,
                physical_base,
                physical_len,
            )
    }
}
