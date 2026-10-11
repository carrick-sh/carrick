//! Physical custody projection for guest-only ARM process roots.
//! The canonical inventory issues every row. Root snapshots are read-only
//! indexes and every selected row is checked again before child publication.

use super::CarrierVmCustody;
use crate::fork_stock::{ForkStockHostCustody, ForkStockServiceError, GrantExecution};
use carrick_el1_abi::{ForkStockSettlement, PortalForkCustody};
use carrick_guest_arch::{AddressContext, FrameGpa, RootGpa};
use carrick_hal::{
    FrameCowAuthority, NativeRootFrameSnapshot, PhysicalMappingRow, UnpublishedFrameInventoryApply,
};
use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A borrowed, non-writing view of the carrier's retained physical table words.
pub(crate) struct NativeRootWords<'a> {
    pub(crate) custody: &'a CarrierVmCustody,
}
impl LiveDescriptorWords for NativeRootWords<'_> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        if !pa.is_multiple_of(8) {
            return Err(DescriptorRefusal::BadRange);
        }
        let identity = self
            .custody
            .stage2_record_covering(pa, 8)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        // The carrier state lock excludes physical record retirement through
        // the load; the exact record identity excludes recycled backing.
        let state = self.custody.state.lock();
        let record = state
            .stage2_records
            .get(&identity.record_id)
            .filter(|record| {
                CarrierVmCustody::stage2_identity_mismatch(record, identity).is_none()
                    && record.snapshot.mapped
                    && record.snapshot.host_addr != 0
            })
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        let offset = usize::try_from(
            pa.checked_sub(record.snapshot.ipa)
                .ok_or(DescriptorRefusal::BadRange)?,
        )
        .map_err(|_| DescriptorRefusal::BadRange)?;
        // SAFETY: the exact physical record is locked and covers this aligned
        // atomic descriptor throughout the load. This view never stores.
        let word = unsafe {
            &*((record.snapshot.host_addr as *const u8)
                .add(offset)
                .cast::<std::sync::atomic::AtomicU64>())
        };
        Ok(word.load(std::sync::atomic::Ordering::Acquire))
    }
    fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
        Err(DescriptorRefusal::PermissionDenied)
    }
    fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
        Err(DescriptorRefusal::PermissionDenied)
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

/// Resolve a selected retained output, including a prepared private terminal.
pub(crate) fn retained_leaf(
    words: &impl LiveDescriptorWords,
    root: RootGpa,
    va: u64,
) -> Result<(FrameGpa, u64), ForkStockServiceError> {
    let mut table = root.address().raw();
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let descriptor = words
            .load(table + ((va >> shift) & 511) * 8)
            .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        let valid = descriptor & 1 != 0;
        if level == 3 || (level > 0 && valid && descriptor & 3 == 1) {
            let retained =
                carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private(descriptor);
            if !valid && !retained {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            let mask = (1u64 << shift) - 1;
            let output = (descriptor & 0x0000_ffff_ffff_f000 & !mask) | (va & mask);
            return Ok((FrameGpa::new(output), descriptor));
        }
        if !valid || descriptor & 3 != 3 {
            return Err(ForkStockServiceError::MemoryAccessFailed);
        }
        table = descriptor & 0x0000_ffff_ffff_f000;
    }
    Err(ForkStockServiceError::MemoryAccessFailed)
}

pub(crate) fn selected_row(
    frames: &NativeRootFrameSnapshot,
    physical: FrameGpa,
    len: u64,
) -> Result<PhysicalMappingRow, ForkStockServiceError> {
    let index = frames
        .mappings
        .partition_point(|row| row.gpa.0 <= physical.raw());
    let row = *frames
        .mappings
        .get(
            index
                .checked_sub(1)
                .ok_or(ForkStockServiceError::MemoryAccessFailed)?,
        )
        .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
    if physical.raw().checked_add(len).is_none_or(|end| {
        row.gpa
            .0
            .checked_add(row.length.raw())
            .is_none_or(|limit| end > limit)
    }) {
        return Err(ForkStockServiceError::MemoryAccessFailed);
    }
    Ok(row)
}

pub(crate) struct NativeInheritedFramePublication {
    context: AddressContext<RootGpa>,
    frames: NativeRootFrameSnapshot,
    receipt: UnpublishedFrameInventoryApply<dyn FrameCowAuthority>,
}
impl NativeInheritedFramePublication {
    pub(crate) fn publish(
        self,
        stock: &mut ForkStockHostCustody,
    ) -> Result<(), ForkStockServiceError> {
        stock.publish_child_frame_snapshot(self.context, self.frames)
    }
    pub(crate) fn rollback(&mut self) -> Result<(), ForkStockServiceError> {
        self.receipt
            .rollback()
            .map_err(|_| ForkStockServiceError::MemoryAccessFailed)
    }
}

/// Stage aliases before accepting fork settlement. The stopped parent retains
/// its fork editor; no child can run before settlement returns to EL1.
pub(crate) fn stage_native_child_frames(
    custody: &CarrierVmCustody,
    stock: &ForkStockHostCustody,
    execution: GrantExecution,
    settlement: &ForkStockSettlement,
) -> Result<Option<NativeInheritedFramePublication>, ForkStockServiceError> {
    let pending = stock
        .pending_loans
        .get(execution.cpu.raw() as usize)
        .and_then(Option::as_ref)
        .ok_or(ForkStockServiceError::NoPendingLoan)?;
    if !pending.execution.matches(execution) {
        return Err(ForkStockServiceError::StaleExecution);
    }
    if settlement.abort_matches(pending.loan) {
        return Ok(None);
    }
    let (completion, records, count) = settlement
        .request(pending.loan)
        .ok_or(ForkStockServiceError::LoanMismatch)?;
    if count == 0 {
        return Ok(None);
    }
    let child = AddressContext {
        mm: carrick_guest_arch::MmGeneration::new(
            NonZeroU64::new(pending.loan.request.child_mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?,
        ),
        root: RootGpa::page_aligned(FrameGpa::new(pending.loan.request.child_tables.base))
            .ok_or(ForkStockServiceError::InvalidRecord)?,
        generation: carrick_guest_arch::ContextGeneration::new(completion.child.incarnation()),
    };
    if stock.root(child.mm.raw()).is_some() {
        return Err(ForkStockServiceError::StaleExecution);
    }
    let parent_frames = stock
        .root_frames(execution.context)
        .ok_or(ForkStockServiceError::StaleExecution)?;
    let source = custody
        .native_frame_inventory
        .lock()
        .as_ref()
        .map(|inventory| Arc::clone(&inventory.source))
        .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
    let parent_inventory = source.bind(execution.context.into());
    let child_inventory = source.bind(child.into());
    let words = NativeRootWords { custody };
    let mut rows = BTreeMap::new();
    let mut pages = BTreeSet::new();
    for index in 0..count {
        let va = records
            .raw()
            .checked_add(
                index
                    .checked_mul(32)
                    .ok_or(ForkStockServiceError::InvalidRecord)?,
            )
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        if !va.is_multiple_of(8) {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let mut wire = [0; 4];
        for (word, value) in wire.iter_mut().enumerate() {
            let (physical, _) =
                retained_leaf(&words, execution.context.root, va + word as u64 * 8)?;
            *value = words
                .load(physical.raw())
                .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        }
        let selected =
            PortalForkCustody::decode(wire).ok_or(ForkStockServiceError::InvalidRecord)?;
        let PortalForkCustody::Frame {
            va,
            ipa,
            len,
            shared,
        } = selected
        else {
            continue;
        };
        if !va.is_multiple_of(4096) || !ipa.is_multiple_of(4096) || !len.is_multiple_of(4096) {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        for offset in (0..len).step_by(4096) {
            if !pages.insert(va + offset) {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            let physical = FrameGpa::new(ipa + offset);
            let row = selected_row(parent_frames, physical, 4096)?;
            if parent_inventory.live_mapping_row(row.mapping) != Some(row) {
                return Err(ForkStockServiceError::StaleExecution);
            }
            let (parent_output, parent_leaf) =
                retained_leaf(&words, execution.context.root, va + offset)?;
            let (child_output, child_leaf) = retained_leaf(&words, child.root, va + offset)?;
            if parent_output != physical
                || child_output != physical
                || (!shared
                    && [parent_leaf, child_leaf].into_iter().any(|leaf| {
                        carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(
                            leaf,
                            carrick_mmu_core::aarch64::LeafAccess::Write,
                        )
                    }))
            {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            rows.insert(row.mapping, row);
        }
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let events = rows
        .len()
        .checked_mul(2)
        .ok_or(ForkStockServiceError::InvalidRecord)?;
    let mut reservation = child_inventory
        .reserve(0, rows.len(), events)
        .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
    let transaction = reservation.transaction();
    let generation = carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::MIN);
    let mut child_rows = Vec::with_capacity(rows.len());
    for row in rows.into_values() {
        let mapping = reservation
            .claim_mapping()
            .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame: row.frame,
                mapping,
                generation,
                gpa: row.gpa,
                length: row.length,
                permissions: row.permissions,
            })
            .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        child_rows.push(PhysicalMappingRow {
            mapping,
            generation,
            ..row
        });
    }
    let receipt = UnpublishedFrameInventoryApply::apply(child_inventory, reservation.commit(()))
        .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
    let revision =
        NonZeroU64::new(receipt.revision()).ok_or(ForkStockServiceError::InvalidRecord)?;
    Ok(Some(NativeInheritedFramePublication {
        context: child,
        frames: NativeRootFrameSnapshot {
            owner: child.into(),
            revision,
            mappings: child_rows,
        },
        receipt,
    }))
}
