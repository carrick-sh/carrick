//! Pending heap retirement owns its scrub independently of ordinary user copy.
use super::{MmError, MmPortal};
use crate::cow::GuestCowVenue;
use crate::memory::reservations::Reservations;
use carrick_el1_abi::{CowGrantCompletion, PinnedMetadataExtent, PortalBackingMaintenance};
use carrick_mmu_core::aarch64::SubstrateGpa;
use carrick_mmu_core::aarch64::descriptor_txn::{
    CowRepointAccess, DescriptorOp, DescriptorOutcome, InlineJournal, LiveDescriptorWords,
    TableGrants, execute_descriptor_op, plan_descriptor_op,
};
use carrick_sched_core::SpaceEditor;
use core::num::NonZeroU64;

const PA: u64 = 0x0000_ffff_ffff_f000;

/// Exact pending-root and editor custody. No physical supply or scheduler wait
/// may run while this borrow exists. Ordinary transfers cannot obtain it.
pub struct BackingMaintenance<'a> {
    _root: Reservations<'a>,
    _editor: SpaceEditor<'a>,
    request: PortalBackingMaintenance,
    ttbr0: u64,
}

impl<P: PinnedMetadataExtent> MmPortal<'_, P> {
    pub fn begin_backing_maintenance(
        &self,
        request: PortalBackingMaintenance,
        slot: u32,
    ) -> Result<BackingMaintenance<'_>, MmError> {
        let handle = request.handle();
        if handle.carrier() != self.carrier {
            return Err(MmError::Stale);
        }
        let index = self.spaces.find(handle.mm().raw()).ok_or(MmError::Stale)?;
        let access = self.space_access(slot)?;
        let editor = self
            .spaces
            .try_begin_maintenance_edit(
                index,
                handle.mm().raw(),
                NonZeroU64::new(u64::from(slot) + 1).ok_or(MmError::Invalid)?,
                access.venue(),
            )
            .map_err(|_| MmError::Busy)?;
        let ttbr0 = self
            .spaces
            .paused_root_identity(index, handle.mm().raw())
            .ok_or(MmError::Stale)?;
        let root = self.root(handle.mm(), slot)?;
        if root.incarnation().raw() != handle.incarnation().get()
            || !root.authenticates_brk_maintenance(request.pending())
        {
            return Err(MmError::Stale);
        }
        Ok(BackingMaintenance {
            _root: root,
            _editor: editor,
            request,
            ttbr0,
        })
    }
}

/// Supply is an exact physical dependency, never a wait for the pending gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackingMaintenanceProgress {
    Complete { next: u64 },
    Supply,
}

impl BackingMaintenance<'_> {
    pub fn ttbr0(&self) -> u64 {
        self.ttbr0
    }

    /// Replace one retired page with private zero backing. A pool record owns
    /// the physical generation until host settlement; the old frame is never
    /// written, including when another live MM retains it. Invalidation already
    /// happened and the replacement descriptor remains invalid throughout.
    pub fn scrub<W: LiveDescriptorWords + ?Sized>(
        self,
        venue: &GuestCowVenue<'_, W>,
        mut zero_page: impl FnMut(u64, u64),
    ) -> Result<BackingMaintenanceProgress, MmError> {
        if venue.root.raw() != self.ttbr0 & PA {
            return Err(MmError::Stale);
        }
        let va = self.request.page();
        let (backing, next) = retired_page(
            venue.words,
            venue.root,
            va,
            self.request.pending().range.end(),
        )?;
        let Some(old_ipa) = backing else {
            return Ok(BackingMaintenanceProgress::Complete { next });
        };
        let mm = self.request.handle().mm().raw();
        let Some(grant) = venue.pool.claim(mm) else {
            return Ok(BackingMaintenanceProgress::Supply);
        };
        // Keep the old compound offset for the existing exact COW settlement.
        let new_ipa = grant.physical_ipa + (old_ipa & (carrick_el1_abi::COW_GRANT_SIZE - 1));
        let op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::Retired,
            va,
            len: 4096,
            old_ipa: SubstrateGpa(old_ipa),
            new_ipa: SubstrateGpa(new_ipa),
            backing: grant.backing,
        };
        let refuse = || {
            assert!(
                venue.pool.abandon(&grant),
                "maintenance lost physical grant"
            );
            Err(MmError::Core)
        };
        if grant.physical_ipa == old_ipa & !(carrick_el1_abi::COW_GRANT_SIZE - 1) {
            return refuse();
        }
        if !matches!(plan_descriptor_op(venue.words, venue.root, op), Ok(plan) if plan.table_grants == 0)
            || !venue.residency.retire_small_span(mm, va, 4096)
        {
            return refuse();
        }
        match venue
            .copy_window
            .with_page(old_ipa, new_ipa, &mut zero_page)
        {
            Ok(()) => {}
            Err(DescriptorOutcome::Indeterminate(reason)) => {
                panic!("maintenance copy alias rollback failed: {reason:?}")
            }
            Err(_) => return refuse(),
        }
        match execute_descriptor_op(
            venue.words,
            venue.root,
            op,
            &TableGrants::NONE,
            &mut InlineJournal::new(),
        ) {
            DescriptorOutcome::Applied(applied) => {
                // Both old and new leaves are invalid. A valid predecessor is
                // rejected before zeroing and can never require a deferred TLBI.
                assert!(
                    !applied.flush_required,
                    "maintenance revalidated a retired page"
                );
                assert!(
                    venue.pool.complete(&CowGrantCompletion {
                        purpose: carrick_el1_abi::CowGrantPurpose::RetiredBacking,
                        grant,
                        span_va: va,
                        span_len: 4096,
                        old_ipa,
                        new_ipa,
                    }),
                    "maintenance lost exact physical completion"
                );
                Ok(BackingMaintenanceProgress::Complete { next })
            }
            DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_) => refuse(),
            DescriptorOutcome::Indeterminate(reason) => {
                panic!("maintenance repoint rollback failed: {reason:?}")
            }
        }
    }
}

/// At most four live words, independent of VMA or carrier populations.
fn retired_page<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: SubstrateGpa,
    va: u64,
    end: u64,
) -> Result<(Option<u64>, u64), MmError> {
    let mut table = root.raw();
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let word = words
            .load(table + ((va >> shift) & 511) * 8)
            .map_err(|_| MmError::Core)?;
        if level == 3 {
            if word & 1 != 0 {
                return Err(MmError::Fault);
            }
            return Ok(((word & PA != 0).then_some(word & PA), va + 4096));
        }
        if word == 0 {
            let span = 1u64 << shift;
            return Ok((None, ((va & !(span - 1)) + span).min(end)));
        }
        if word & 3 != 3 {
            return Err(MmError::Fault);
        }
        table = word & PA;
    }
    Err(MmError::Core)
}

#[cfg(target_os = "none")]
pub fn serve_backing_maintenance_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let run = |frame: &carrick_el1_abi::TrapFrame| -> Result<BackingMaintenanceProgress, MmError> {
        let slot = carrick_el1_abi::service_slot_from_stack(
            crate::substrate::sched::hw::read_current_sp(),
            frame.slot,
        )
        .ok_or(MmError::Stale)?;
        let request = PortalBackingMaintenance::decode(
            frame.x[1..9].try_into().map_err(|_| MmError::Invalid)?,
        )
        .ok_or(MmError::Invalid)?;
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        if slots.carrier() != Some(request.handle().carrier()) {
            return Err(MmError::Stale);
        }
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<super::production::GuestMetadataPin> {
            carrier: request.handle().carrier(),
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        let operation = portal.begin_backing_maintenance(request, frame.slot as u32)?;
        crate::fault::with_hardware_cow_venue(operation.ttbr0(), Some(slot), None, |venue| {
            operation.scrub(venue, |_, destination| {
                // SAFETY: the existing copy window maps one retained private
                // grant page RW; the owner authenticated the invalid predecessor.
                unsafe { core::ptr::write_bytes(destination as *mut u8, 0, 4096) };
            })
        })
        .map_err(|_| MmError::Core)?
    };
    frame.x[0] = match run(frame) {
        Ok(BackingMaintenanceProgress::Complete { next }) => {
            frame.x[9] = next;
            0
        }
        Ok(BackingMaintenanceProgress::Supply) => 11,
        Err(error) => u64::from(error.errno()),
    };
}
