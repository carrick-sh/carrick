//! Native table-window, register and delivery bindings to the sole core owner.
#[cfg(target_os = "none")]
use super::{El1MmHandle, GuestVa, TransferIntent};
use super::{MmError, MmErrorLinux};
use crate::memory::reservations::NativeReservationGeometry;
pub use carrick_core::mm::transaction::{
    SelectionVenues, TRANSFER_CHUNK_BYTES, TransferServiceAdmission, TransferStep,
    admit_service_root, admit_transfer_service, bind_service_root, grant_target, prepare_transfer,
    serve_transfer, settle_prepared_service,
};
#[cfg(any(test, target_os = "none"))]
use carrick_el1_abi::ReservationMm;
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
#[cfg(target_os = "none")]
use carrick_core::mm::frames::apply_grant;
pub use carrick_core::mm::frames::{GrantTarget, serve_grant};

pub use carrick_el1_abi::GuestMetadataPin;

/// Production ARM slot facade, before table views or native HVC effects.
pub fn admit_transfer_hw<'a>(
    slots: &'a carrick_el1_abi::MmPortalSlots,
    zone: &'a carrick_sched_core::ZoneTables,
    roots: &'a crate::memory::reservations::SharedReservations,
    slot: &'a carrick_el1_abi::PortalTransferSlot,
) -> Result<Option<(MmPortal<'a, GuestMetadataPin>, TransferServiceAdmission<'a>)>, MmError> {
    carrick_core::mm::transaction::admit_transfer_slot(
        slots.carrier(),
        roots,
        zone,
        slot,
        Aarch64Mmu,
    )
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
    let Some(slot) = slots.slot(frame.slot as usize) else {
        return;
    };
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    let Ok(Some((portal, admission))) = admit_transfer_hw(
        slots,
        zone,
        crate::memory::reservations::shared_guest(),
        slot,
    ) else {
        return;
    };
    let (service, grant) = match admission {
        TransferServiceAdmission::Settle { service, permit } => {
            let _ = settle_prepared_service(
                &portal,
                service,
                permit,
                frame.slot as u32,
                yield_host_effect,
            );
            return;
        }
        TransferServiceAdmission::NeedsWords { service, grant } => (service, grant),
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
            carrick_core::mm::transaction::SelectionVenues {
                prepared: &mut crate::fault::HardwarePreparedResolver,
                cow: &mut crate::fault::HardwareCowResolver {
                    publication: slots.executable(frame.slot as usize),
                    completion: None,
                    service_slot: Some(executor_slot),
                },
                residency: carrick_el1_abi::frame_grant_residency_guest(),
                slot: frame.slot as u32,
            },
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
    if apply_grant::<Aarch64Mmu, _>(
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
