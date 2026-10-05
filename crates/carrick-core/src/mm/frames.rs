//! One lazy grant authentication, logical residency publication and settlement.
use crate::mm::reservation::{ReservationFaultPlan, ReservationGeometry, ReservationPolicy};
use crate::mm::transaction::{MmError, MmPortal, OwnerVenue};
use carrick_core_abi::*;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::{OwnerGrantMmu, OwnerMmu};
use carrick_sched_core::SpaceEditor;

/// An editor retained from target admission through descriptor completion.
pub struct GrantTarget<'a> {
    window: carrick_core_abi::PortalGrantWindow,
    grant: carrick_sched_core::SpaceGrant,
    _editor: SpaceEditor<'a>,
    authenticated: bool,
}

impl<'a> GrantTarget<'a> {
    pub fn grant(&self) -> carrick_sched_core::SpaceGrant {
        self.grant
    }
    fn into_parts(
        self,
    ) -> (
        PortalGrantWindow,
        carrick_sched_core::SpaceGrant,
        SpaceEditor<'a>,
        bool,
    ) {
        (self.window, self.grant, self._editor, self.authenticated)
    }
}

pub fn grant_target<
    'a,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue,
    B: OwnerMmu,
>(
    portal: &'a MmPortal<'_, P, Policy, Geometry, Venue, B>,
    window: carrick_core_abi::PortalGrantWindow,
    worker: u32,
) -> Result<GrantTarget<'a>, MmError> {
    if window.operation.carrier != portal.carrier {
        return Err(MmError::Stale);
    }
    // SAFETY: this is only a candidate identity. editor_for authenticates its
    // exact notification source before admitting it; root_for and the fault
    // plan below validate incarnation, generation, range, protection and source.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            window.operation.carrier,
            window.operation.mm,
            window.operation.incarnation,
        )
    };
    let gate = portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Gate)?;
    let editor = portal.editor_for(handle, worker)?;
    let index = portal
        .spaces
        .find(window.operation.mm.raw())
        .ok_or(MmError::Stale)?;
    // A host can raise the gate after admission, then wait for this editor.
    // Observe before probing and release the editor before parking that wait.
    let grant = portal
        .spaces
        .grant(index, window.operation.mm.raw())
        .ok_or_else(|| gate.map_or(MmError::Busy, MmError::Wait))?;
    let mut root = portal.root_for(handle, worker)?;
    let authenticated = root.authenticate_fork_transfer_fault(
        ReservationFaultPlan {
            mm: window.operation.mm,
            generation: window.generation,
            range: window.range,
            protection: window.protection,
            fault_page: window.fault_page,
        },
        window.host_backing,
        window.fork_sequence,
    );
    Ok(GrantTarget {
        window,
        grant,
        _editor: editor,
        authenticated,
    })
}

/// Revalidate an owner-selected lazy window and apply its isolated submission
/// through the existing descriptor executor. Normal descriptor drains cannot
/// see the submission before this exact-generation check.
pub fn serve_grant<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue,
    B: OwnerGrantMmu,
    W: LiveDescriptorWords + ?Sized,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B>,
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    worker: u32,
    invalidate: impl FnOnce(),
) -> Result<Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt>, MmError> {
    let Some(window) = slot.window() else {
        return Ok(None);
    };
    let target = grant_target(portal, window, worker)?;
    Ok(apply_grant::<B, _>(
        slot, words, residency, target, invalidate,
    ))
}

pub fn apply_grant<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    target: GrantTarget<'_>,
    invalidate: impl FnOnce(),
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt> {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, DescriptorRefusal,
    };
    let (window, grant, editor, authenticated) = target.into_parts();
    let mm = window.operation.mm;
    let claimed = slot.descriptor().claim_for_mm(mm.raw())?;
    let outcome = (|| {
        let Ok(txn) = claimed.txn() else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        if !authenticated {
            return DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot);
        }
        let DescriptorOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        if publication.va != window.range.start()
            || publication.len != window.range.len()
            || publication.writable != (window.protection.bits() & 2 != 0)
            || publication.executable != (window.protection.bits() & 4 != 0)
            || resident.va != window.fault_page
            || resident.len != 4096
        {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        }
        // The authenticated remapped root may replace a core-typed retired
        // terminal with fresh backing. Never revive its output, or replace a
        // prepared/live predecessor. The window is at most 512 pages.
        for va in (publication.va..publication.va + publication.len).step_by(4096) {
            let Ok(root) = B::root(grant.ttbr0) else {
                return DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot);
            };
            let mut table = root.address().raw();
            for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
                let Ok(word) = words.load(table + ((va >> shift) & 511) * 8) else {
                    return DescriptorOutcome::Refused(DescriptorRefusal::TableOutsidePrimary);
                };
                if word == 0 {
                    break;
                }
                if !B::is_table(word, level) {
                    if level != 0 && B::is_retired(word) {
                        break;
                    }
                    return DescriptorOutcome::Refused(DescriptorRefusal::Occupied);
                }
                table = word & B::ADDRESS_MASK;
            }
        }
        let identity = carrick_core_abi::FrameGrantResidencyIdentity {
            mm_key: mm.raw(),
            semantic_base: publication.va,
            physical_ipa: publication.ipa,
            len: publication.len,
            mapping_id: backing.mapping_id.get(),
            frame_id: backing.frame_id.get(),
            owner_generation: backing.owner_generation.get(),
            inventory_revision: backing.inventory_revision.get(),
        };
        let Some(residency_slot) = residency.publish(identity) else {
            return DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity);
        };
        let outcome = B::execute_grant(words, grant.ttbr0, txn);
        if let DescriptorOutcome::Applied(_) = outcome {
            if let Some(page) = residency.lookup(mm.raw(), window.fault_page) {
                residency.record_commit(page);
            }
        } else {
            residency.retire(residency_slot, identity);
        }
        outcome
    })();
    let receipt = claimed.complete(outcome, invalidate);
    drop(editor);
    Some(receipt)
}

/// Logical leaf references for one physical backing. The backend owns storage
/// and the inventory's one journal; this value is the journaled logical state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameReferences {
    mapping_count: u32,
    retire_on_last_unmap: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    Exhausted,
    Underflow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRetirement {
    Ready,
    AlreadyPending,
    Deferred,
}
impl FrameReferences {
    pub const fn count(self) -> u32 {
        self.mapping_count
    }
    pub fn retain(&mut self) -> Result<(), ReferenceError> {
        self.mapping_count = self
            .mapping_count
            .checked_add(1)
            .ok_or(ReferenceError::Exhausted)?;
        // A new holder takes responsibility for retirement.
        self.retire_on_last_unmap = false;
        Ok(())
    }
    pub fn unmap(&mut self) -> Result<bool, ReferenceError> {
        self.mapping_count = self
            .mapping_count
            .checked_sub(1)
            .ok_or(ReferenceError::Underflow)?;
        Ok(self.mapping_count == 0 && self.retire_on_last_unmap)
    }
    pub fn request_retirement(&mut self) -> ReferenceRetirement {
        if self.mapping_count == 0 {
            ReferenceRetirement::Ready
        } else if self.retire_on_last_unmap {
            ReferenceRetirement::AlreadyPending
        } else {
            self.retire_on_last_unmap = true;
            ReferenceRetirement::Deferred
        }
    }
}
