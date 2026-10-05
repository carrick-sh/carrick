//! Native table-window, register and delivery bindings to the sole core owner.
#[cfg(target_os = "none")]
use super::{El1MmHandle, GuestVa, TransferIntent};
use super::{MmError, MmErrorLinux};
use crate::memory::reservations::NativeReservationGeometry;
pub use carrick_core::mm::transaction::{
    GrantTarget, TRANSFER_CHUNK_BYTES, TransferStep, admit_service_root, bind_service_root,
    grant_target, prepare_transfer, serve_transfer, settle_prepared_service,
};
#[cfg(any(test, target_os = "none"))]
use carrick_el1_abi::ReservationMm;
use carrick_el1_abi::{FrameGrantResidencyTable, PinnedMetadataExtent};
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_personality_linux::mm::LinuxReservationPolicy;
#[cfg(target_os = "none")]
use core::num::NonZeroU64;

pub struct NativeOwnerVenue;
impl carrick_core::mm::transaction::OwnerVenue for NativeOwnerVenue {
    fn space_access(
        zone: &carrick_sched_core::ZoneTables,
        slot: carrick_sched_core::SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_> {
        crate::substrate::sched::object_wait::space_access(zone, slot)
    }
    fn deliver_completion(
        zone: &carrick_sched_core::ZoneTables,
        slot: carrick_sched_core::SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        crate::substrate::sched::object_wait::deliver_completion(zone, slot, effects)
    }
    fn encode_error(error: MmError) -> u32 {
        error.errno()
    }
    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}
pub type MmPortal<'a, P, B = Aarch64Mmu> = carrick_core::mm::transaction::MmPortal<
    'a,
    P,
    LinuxReservationPolicy,
    NativeReservationGeometry,
    NativeOwnerVenue,
    B,
>;
const PA: u64 = 0x0000_ffff_ffff_f000;

#[cfg(target_os = "none")]
pub enum GuestMetadataPin {}
#[cfg(target_os = "none")]
// SAFETY: uninhabited; guest identity banks never construct a host pin.
unsafe impl PinnedMetadataExtent for GuestMetadataPin {
    fn extent(&self) -> carrick_el1_abi::MetadataExtent {
        match *self {}
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        match *self {}
    }
}

#[cfg(target_os = "none")]
pub fn serve_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(service) = slots
        .slot(frame.slot as usize)
        .and_then(|slot| slot.claim())
    else {
        return;
    };
    let request = service.request();
    if slots.carrier() != Some(request.operation.carrier) {
        service.complete(0, 3);
        return;
    }
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    let portal = MmPortal::<GuestMetadataPin> {
        backend: core::marker::PhantomData,
        carrier: request.operation.carrier,
        roots: crate::memory::reservations::shared_guest(),
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
    };
    if matches!(
        service.phase(),
        carrick_el1_abi::PortalTransferPhase::Commit | carrick_el1_abi::PortalTransferPhase::Cancel
    ) {
        let Some(permit) = service.permit() else {
            service.complete(0, 3);
            return;
        };
        let _ = settle_prepared_service(
            &portal,
            service,
            permit,
            frame.slot as u32,
            yield_host_effect,
        );
        return;
    }
    let Some((service, grant)) = admit_service_root(&portal, service) else {
        return;
    };
    let live_ttbr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) live_ttbr, options(nomem, nostack));
    }
    let Some(table) = carrick_el1_abi::service_target_table_window(live_ttbr, grant.ttbr0) else {
        service.complete(0, 3);
        return;
    };
    let maintenance = CallerInvalidatesAsid;
    let words = unsafe {
        PrimaryTableWords::new(
            table.words,
            table.physical_base,
            carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
            &maintenance,
        )
        .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
    };
    let Ok(words) = words else {
        service.complete(0, 5);
        return;
    };
    let _ = serve_transfer(&portal, service, &words, frame.slot as u32, || {
        // The host resumes this exact stack after copy OR cancellation. The
        // permit cannot be abandoned by resetting service-call registers.
        yield_host_effect();
    });
}

/// Suspend the current portal service stack for an authenticated host effect.
/// The host must resume this exact stack after servicing or cancelling the
/// effect; the portal keeps its operation and semantic permit across the yield.
#[cfg(target_os = "none")]
pub(super) fn yield_host_effect() {
    unsafe {
        core::arch::asm!("hvc #1", clobber_abi("C"));
    }
}

/// Selection entry for a borrowed target root. Input x1..x7 is carrier, MM,
/// admitted incarnation, VA, chunk length, intent, and completed host prefix.
/// Output x0 is errno; x8..x10 is sequence, policy generation, selected IPA.
#[cfg(target_os = "none")]
pub fn select_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let run = |frame: &mut carrick_el1_abi::TrapFrame| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let carrier = slots.carrier().ok_or(MmError::Stale)?;
        if frame.x[1] != carrier.get() {
            return Err(MmError::Stale);
        }
        let mm = ReservationMm::new(frame.x[2]).ok_or(MmError::Stale)?;
        let intent = TransferIntent::decode(frame.x[6]).ok_or(MmError::Invalid)?;
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        // SAFETY: source and root authentication below validate this exact request.
        let handle = unsafe {
            El1MmHandle::from_admitted_owner(
                carrier,
                mm,
                NonZeroU64::new(frame.x[3]).ok_or(MmError::Stale)?,
            )
        };
        let gate = portal.observe_wait(handle, carrick_el1_abi::PortalWaitCause::Gate)?;
        let index = zone.spaces.find(mm.raw()).ok_or(MmError::Stale)?;
        let grant = zone
            .spaces
            .grant(index, mm.raw())
            .ok_or_else(|| gate.map_or(MmError::Busy, MmError::Wait))?;
        let live_ttbr: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) live_ttbr, options(nomem, nostack));
        }
        let table = carrick_el1_abi::service_target_table_window(live_ttbr, grant.ttbr0)
            .ok_or(MmError::Stale)?;
        let range = carrick_el1_abi::PortalByteRange::new(frame.x[4], frame.x[5])
            .ok_or(MmError::Invalid)?;
        if range.is_empty() || range.len() > 4096 - (range.address() & 4095) {
            return Err(MmError::Invalid);
        }
        let continuation = if let Some(sequence) = NonZeroU64::new(frame.x[19]) {
            super::fork::authenticate_pending_parent_write(frame.slot as usize, handle, sequence)?;
            portal.begin_fork_parent_write(
                handle,
                GuestVa::new(range.address()),
                range.len(),
                intent,
                sequence,
                frame.slot as u32,
            )?
        } else {
            portal.begin(
                handle,
                GuestVa::new(range.address()),
                range.len(),
                intent,
                frame.slot as u32,
            )?
        };
        let maintenance = CallerInvalidatesAsid;
        let words = unsafe {
            PrimaryTableWords::new(
                table.words,
                table.physical_base,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &maintenance,
            )
            .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
        }
        .map_err(|_| MmError::Core)?;
        match portal.select(
            &continuation,
            &words,
            &mut crate::fault::HardwarePreparedResolver,
            &mut crate::fault::HardwareCowResolver {
                publication: slots.executable(frame.slot as usize),
                completion: None,
                service_slot: Some(executor_slot),
            },
            carrick_el1_abi::frame_grant_residency_guest(),
            frame.slot as u32,
        )? {
            TransferStep::Selected(selected) => {
                frame.x[8] = selected.sequence().get();
                frame.x[9] = selected.generation();
                frame.x[10] = selected.ipa;
                frame.x[15] = u64::from(selected.executable);
                let retry = selected.retry().ok_or(MmError::Stale)?;
                frame.x[16] = retry.cause().encode();
                frame.x[17] = retry.revision();
                Ok(())
            }
            step @ (TransferStep::Supply(_) | TransferStep::CowSupply(_)) => {
                let cow = matches!(step, TransferStep::CowSupply(_));
                let (TransferStep::Supply(window) | TransferStep::CowSupply(window)) = step else {
                    unreachable!()
                };
                frame.x[8] = window.operation.sequence.get();
                frame.x[9] = window.generation.raw();
                frame.x[10] = window.range.start();
                frame.x[11] = window.range.end();
                frame.x[12] = window.protection.bits();
                frame.x[13] = window.fault_page;
                frame.x[14] = if cow { 2 } else { 1 };
                frame.x[16] = window
                    .host_backing
                    .map_or(0, |source| source.handle().get());
                frame.x[17] = window
                    .host_backing
                    .map_or(0, |source| source.generation().get());
                frame.x[18] = window.host_backing.map_or(0, |source| source.offset());
                Err(MmError::Busy)
            }
            TransferStep::Suspended => Err(MmError::Busy),
            TransferStep::Complete => Err(MmError::Invalid),
        }
    };
    frame.x[0] = match run(frame) {
        Ok(()) => 0,
        Err(MmError::Busy) => 11,
        Err(MmError::Wait(wait)) => {
            frame.x[14] = 3;
            frame.x[16] = wait.cause().encode();
            frame.x[17] = wait.revision();
            11
        }
        Err(error) => u64::from(error.errno()),
    };
}

/// Revalidate an owner-selected lazy window and apply its isolated submission
/// through the existing descriptor executor. Normal descriptor drains cannot
/// see the submission before this exact-generation check.
pub fn serve_grant<P: PinnedMetadataExtent, W: LiveDescriptorWords + ?Sized>(
    portal: &MmPortal<'_, P>,
    slot: &carrick_el1_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    worker: u32,
    invalidate: impl FnOnce(),
) -> Result<Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt>, MmError> {
    let Some(window) = slot.window() else {
        return Ok(None);
    };
    let target = grant_target(portal, window, worker)?;
    Ok(apply_grant(slot, words, residency, target, invalidate))
}

fn apply_grant<W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_el1_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    target: GrantTarget<'_>,
    invalidate: impl FnOnce(),
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt> {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, DescriptorRefusal, InlineJournal, execute_descriptor_txn,
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
            let mut table = grant.ttbr0 & PA;
            for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
                let Ok(word) = words.load(table + ((va >> shift) & 511) * 8) else {
                    return DescriptorOutcome::Refused(DescriptorRefusal::TableOutsidePrimary);
                };
                if word == 0 {
                    break;
                }
                if word & 3 != 3 || level == 3 {
                    if level != 0
                        && carrick_mmu_core::aarch64::el1_private_leaf_state(word)
                            == carrick_mmu_core::aarch64::El1PrivateLeafState::Retired
                    {
                        break;
                    }
                    return DescriptorOutcome::Refused(DescriptorRefusal::Occupied);
                }
                table = word & PA;
            }
        }
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
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
        let outcome = execute_descriptor_txn(
            words,
            carrick_mmu_core::aarch64::SubstrateGpa(grant.ttbr0 & PA),
            txn,
            &mut InlineJournal::new(),
        )
        .outcome;
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

#[cfg(target_os = "none")]
pub fn serve_grant_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    use carrick_mmu_core::aarch64::descriptor_txn::PrimaryTableWords;
    // Every pre-claim failure is explicit; only a typed owner wait suspends.
    frame.x[0] = 22;
    frame.x[14] = 0;
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        return;
    };
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(slot) = slots.grant(frame.slot as usize) else {
        return;
    };
    let Some(window) = slot.window() else {
        return;
    };
    let Some(carrier) = slots.carrier() else {
        return;
    };
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    let portal = MmPortal::<GuestMetadataPin> {
        backend: core::marker::PhantomData,
        carrier,
        roots: crate::memory::reservations::shared_guest(),
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
    };
    let target = match grant_target(&portal, window, u32::from(executor_slot.raw())) {
        Ok(target) => target,
        Err(MmError::Wait(wait)) => {
            frame.x[0] = 11;
            frame.x[14] = 3;
            frame.x[16] = wait.cause().encode();
            frame.x[17] = wait.revision();
            return;
        }
        Err(error) => {
            frame.x[0] = u64::from(error.errno());
            return;
        }
    };
    let ttbr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1",out(reg)ttbr,options(nomem,nostack));
    }
    let Some(table) = carrick_el1_abi::service_target_table_window(ttbr, target.grant().ttbr0)
    else {
        return;
    };
    let maintenance = crate::fault::El1TableMaintenance {
        ttbr0: target.grant().ttbr0,
    };
    let Ok(words) = (unsafe {
        PrimaryTableWords::new(
            table.words,
            table.physical_base,
            carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
            &maintenance,
        )
        .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
    }) else {
        return;
    };
    let root = target.grant().ttbr0;
    if apply_grant(
        slot,
        &words,
        carrick_el1_abi::frame_grant_residency_guest(),
        target,
        || {
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, root);
        },
    )
    .is_some()
    {
        frame.x[0] = 0;
    }
}

#[cfg(target_os = "none")]
pub fn bind_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    let result = (|| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let carrier = slots.carrier().ok_or(MmError::Stale)?;
        if frame.x[1] != carrier.get() {
            return Err(MmError::Stale);
        }
        let mm = ReservationMm::new(frame.x[2]).ok_or(MmError::Stale)?;
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        // The normal BIND still requires an open grant. The first-load BIND
        // carries a publication-issued closed-root token and must recheck
        // that this exact entry has never opened. No transfer service uses
        // the closed identity observation.
        let root = match frame.x[6] {
            0 => bind_service_root(&zone.spaces, mm, false, 0)?,
            1 => bind_service_root(&zone.spaces, mm, true, frame.x[7])?,
            _ => return Err(MmError::Stale),
        };
        let live: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1",out(reg)live,options(nomem,nostack));
        }
        if carrick_el1_abi::service_target_table_window(live, root).is_none() {
            return Err(MmError::Stale);
        }
        let portal = MmPortal::<GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        frame.x[3] = portal
            .admitted_handle(mm, frame.slot as u32)?
            .incarnation()
            .get();
        frame.x[4] = portal.root(mm, frame.slot as u32)?.generation().raw();
        frame.x[5] = portal
            .root(mm, frame.slot as u32)?
            .next_transfer_sequence()?
            .get();
        Ok(())
    })();
    frame.x[0] = result.err().map_or(0, |error| u64::from(error.errno()));
}

#[cfg(test)]
mod closed_bind_tests {
    use super::*;

    #[test]
    fn closed_bind_cannot_escape_its_initial_mm_or_gate() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let first = ReservationMm::new(81).unwrap();
        let second = ReservationMm::new(82).unwrap();
        let first_index = spaces
            .publish_closed(first.raw(), 0x81_000, 0x81_000)
            .unwrap();
        spaces
            .publish_closed(second.raw(), 0x82_000, 0x82_000)
            .unwrap();
        assert!(bind_service_root(&spaces, first, false, 0).is_err());
        assert!(bind_service_root(&spaces, first, true, 0x81_000).is_err());
        assert!(spaces.mark_initial_bindable(first_index));
        assert_eq!(
            bind_service_root(&spaces, first, true, 0x81_000),
            Ok(0x81_000)
        );
        assert!(bind_service_root(&spaces, first, true, 0x82_000).is_err());
        assert!(bind_service_root(&spaces, second, true, 0x81_000).is_err());
        spaces.open(first_index);
        assert!(bind_service_root(&spaces, first, true, 0x81_000).is_err());
        assert_eq!(bind_service_root(&spaces, first, false, 0), Ok(0x81_000));
        spaces.close(first_index);
        assert!(bind_service_root(&spaces, first, true, 0x81_000).is_err());
    }

    #[test]
    fn fixed_boot_primary_requires_exact_closed_mm_generation() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let boot = ReservationMm::new(81).unwrap();
        let successor = ReservationMm::new(82).unwrap();
        let root = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE | (1 << 48);
        let index = spaces.publish_closed(boot.raw(), root, root).unwrap();
        assert!(spaces.mark_initial_bindable(index));
        assert_eq!(bind_service_root(&spaces, boot, true, root), Ok(root));
        assert_eq!(
            bind_service_root(&spaces, successor, true, root),
            Err(MmError::Stale)
        );
        assert_eq!(
            bind_service_root(&spaces, boot, true, root + 4096),
            Err(MmError::Stale)
        );
        spaces.open(index);
        assert_eq!(
            bind_service_root(&spaces, boot, true, root),
            Err(MmError::Stale)
        );
    }
}
