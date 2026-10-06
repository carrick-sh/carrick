//! CPL0 x86 adapter hooks for the shared carrick-core MM owner.
//!
//! Provides direct-mapped descriptor words, owner venue, and grant serving
//! dispatch using the shared `X86Mmu` and `carrick-core::mm::frames::serve_grant`.
#![cfg_attr(not(test), allow(dead_code))]

use carrick_core::mm::frames::serve_grant;
use carrick_core::mm::transaction::MmError;
use carrick_core_abi::FrameGrantResidencyTable;
use carrick_el1_abi::{MmPortalSlots, PinnedMetadataExtent};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOutcome, DescriptorRefusal, LiveDescriptorWords,
};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::mm::LinuxReservationPolicy;
use carrick_sched_core::ZoneTables;
use core::sync::atomic::{AtomicU64, Ordering};

pub const PROGRESS_RESERVATIONS: u64 = 0x160_0000;
pub const PROGRESS_RESIDENCY: u64 = 0x170_0000;
pub const PROGRESS_PORTAL: u64 = 0x180_0000;

/// Uninhabited pinned metadata extent for guest execution.
#[derive(Clone, Copy, Debug)]
pub enum GuestMetadataPin {}
unsafe impl PinnedMetadataExtent for GuestMetadataPin {
    fn extent(&self) -> carrick_core_abi::MetadataExtent {
        match *self {}
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        match *self {}
    }
}

/// Direct supervisor physical descriptor words. In CPL0, page tables
/// are identity-mapped in the supervisor page table range.
pub struct Cpl0DirectWords {
    start: u64,
    end: u64,
}

impl Cpl0DirectWords {
    /// Construct a descriptor view over an identity-mapped supervisor range.
    ///
    /// # Safety
    ///
    /// Every byte in `start..end` must remain mapped, writable, naturally
    /// aligned table memory for the lifetime of the returned view. No host
    /// caller may construct this from guest physical addresses.
    pub unsafe fn from_identity_mapped_range(start: u64, end: u64) -> Option<Self> {
        (start != 0 && start < end && start.is_multiple_of(4096) && end.is_multiple_of(4096))
            .then_some(Self { start, end })
    }

    fn word(&self, pa: u64) -> Result<*const AtomicU64, DescriptorRefusal> {
        if !pa.is_multiple_of(8)
            || pa < self.start
            || pa.checked_add(8).is_none_or(|end| end > self.end)
        {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        Ok(pa as *const AtomicU64)
    }

    pub fn invalidate_range(&self, va: u64, len: u64) {
        for page in (va..va.saturating_add(len)).step_by(4096) {
            #[cfg(target_os = "none")]
            unsafe {
                core::arch::asm!("invlpg [{}]", in(reg) page, options(nostack, preserves_flags));
            }
            #[cfg(not(target_os = "none"))]
            let _ = page;
        }
    }
}

impl LiveDescriptorWords for Cpl0DirectWords {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        Ok(unsafe { (*ptr).load(Ordering::Acquire) })
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        Ok(unsafe {
            (*ptr)
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        unsafe { (*ptr).store(value, Ordering::Release) };
        Ok(())
    }

    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        Cpl0DirectWords::invalidate_range(self, va, len);
    }
}

use carrick_personality_linux::mm::MmErrorLinux;

pub struct X86OwnerVenue;

fn request_owner_boundary(
    zone: &ZoneTables,
    slot: carrick_sched_core::SlotId,
    current: bool,
) -> bool {
    let target = zone.slot(slot).sgi_target();
    if target == 0 || !target.is_multiple_of(core::mem::align_of::<CpuBinding>() as u64) {
        return false;
    }
    // SAFETY: x86 slot publication authenticates `sgi_target` as the retained
    // CpuBinding for that exact executor. The binding outlives the ZoneTables
    // publication and all owner callbacks.
    let binding = unsafe { &*(target as *const CpuBinding) };
    if current {
        binding.return_kick.store(1, Ordering::Release);
    } else {
        binding.entry_kick.store(1, Ordering::Release);
    }
    true
}

fn deliver_owner_effects(
    zone: &ZoneTables,
    venue: carrick_sched_core::SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
) {
    let (waker, effects, deferred) = owned.defer_handbacks();
    let own = match waker {
        carrick_sched_core::Waker::El1 { slot } => Some(slot),
        carrick_sched_core::Waker::Host => None,
    };
    let mut undelivered = false;
    for slot in effects
        .sgi_slots()
        .chain(own.filter(|slot| effects.queued_own && *slot != venue))
    {
        undelivered |= !request_owner_boundary(zone, slot, slot == venue);
    }
    if deferred || effects.misplaced || (effects.queued_own && own == Some(venue)) || undelivered {
        let _ = request_owner_boundary(zone, venue, true);
    }
}

impl carrick_core::mm::transaction::OwnerVenue for X86OwnerVenue {
    fn space_access(
        zone: &ZoneTables,
        slot: carrick_sched_core::SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_> {
        fn deliver(
            zone: &ZoneTables,
            waker: carrick_sched_core::Waker,
            effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
        ) {
            if let carrick_sched_core::Waker::El1 { slot } = waker {
                deliver_owner_effects(zone, slot, effects);
            } else {
                let _ = effects.defer_handbacks();
            }
        }
        carrick_sched_core::spaces::notification::SpaceAccess::notified(
            carrick_sched_core::spaces::notification::SpaceReleaseVenue {
                zone,
                waker: carrick_sched_core::Waker::El1 { slot },
                deliver,
            },
        )
    }

    fn deliver_completion(
        zone: &ZoneTables,
        slot: carrick_sched_core::SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        deliver_owner_effects(zone, slot, effects);
    }

    fn encode_error(error: MmError) -> u32 {
        error.errno()
    }

    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NativeReservationGeometry;
impl carrick_core::mm::reservation::ReservationGeometry for NativeReservationGeometry {
    const RESERVATIONS_OFFSET: usize = 0x60_0000;
    const ZONE_OFFSET: usize = 0;
    const REGION_BASE: u64 = 0x100_0000;
    const BOOTSTRAP_BASE: u64 = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE;
    const BOOTSTRAP_SIZE: u64 = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE;
    fn authorizes_internal_read(address: u64, len: u64) -> bool {
        carrick_el1_abi::CarrickInternalReadRange::authorizes(address, len)
    }
}
pub type SharedReservations = carrick_core::mm::reservation::SharedReservations<
    LinuxReservationPolicy,
    NativeReservationGeometry,
>;

pub type X86MmPortal<'a, P> = carrick_core::mm::transaction::MmPortal<
    'a,
    P,
    LinuxReservationPolicy,
    NativeReservationGeometry,
    X86OwnerVenue,
    X86Mmu,
>;

#[cfg(target_os = "none")]
use super::adapter::CpuBinding;
#[cfg(not(target_os = "none"))]
use crate::cpl0_entry::CpuBinding;

/// Execute a grant submission in CPL0, calling the shared `serve_grant` owner.
/// Returns 0 on success, or Linux errno (e.g. 22 = EINVAL) on refusal/error.
pub fn serve_cpl0_grant(binding: &CpuBinding, slot_index: usize) -> u32 {
    binding.entries.fetch_add(1, Ordering::Relaxed);
    if binding.zone_address == 0
        || binding.reservations_address == 0
        || binding.residency_address == 0
        || binding.portal_address == 0
    {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return 22;
    }

    let zone_ptr = binding.zone_address as *const ZoneTables;
    let reservations_addr = binding.reservations_address;
    let residency_addr = binding.residency_address;
    let portal_addr = binding.portal_address;

    // SAFETY: the carrier retains these published supervisor records for the
    // vCPU lifetime and binds their exact mapped addresses before entry.
    let zone = unsafe { &*zone_ptr };
    // SAFETY: checked nonzero above; the carrier publishes and retains the
    // correctly aligned shared reservation record at this address.
    let reservations = unsafe { &*(reservations_addr as *const SharedReservations) };
    // SAFETY: checked nonzero above; the carrier publishes and retains the
    // correctly aligned residency record at this address.
    let residency = unsafe { &*(residency_addr as *const FrameGrantResidencyTable) };
    // SAFETY: checked nonzero above; the carrier publishes and retains the
    // correctly aligned portal slots at this address.
    let portal_slots = unsafe { &*(portal_addr as *const MmPortalSlots) };

    let Some(grant_slot) = portal_slots.grant(slot_index) else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return 22;
    };

    let Some(carrier) = portal_slots.carrier() else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return MmError::Invalid.errno();
    };

    let portal = carrick_core::mm::transaction::MmPortal::<
        GuestMetadataPin,
        LinuxReservationPolicy,
        NativeReservationGeometry,
        X86OwnerVenue,
    >::for_zone(carrier, reservations, zone)
    .with_mmu(X86Mmu);

    // SAFETY: the CPL0 carrier binds only the retained identity-mapped table
    // arena; host builds never call this entry over guest physical addresses.
    let Some(words) = (unsafe {
        Cpl0DirectWords::from_identity_mapped_range(
            binding.table_memory_start,
            binding.table_memory_end,
        )
    }) else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return MmError::Invalid.errno();
    };
    let window_opt = grant_slot.window();
    let result = serve_grant(&portal, grant_slot, &words, residency, binding.slot, || {
        if let Some(w) = window_opt {
            words.invalidate_range(w.range.start(), w.range.len());
        }
    });

    match result {
        Ok(Some(receipt)) => {
            if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) {
                binding.publications.fetch_add(1, Ordering::Relaxed);
                binding.completions.fetch_add(1, Ordering::Relaxed);
                0
            } else {
                binding.completions.fetch_add(1, Ordering::Relaxed);
                22
            }
        }
        Ok(None) => {
            binding.completions.fetch_add(1, Ordering::Relaxed);
            300
        }
        Err(err) => {
            binding.completions.fetch_add(1, Ordering::Relaxed);
            err.errno()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};
    use carrick_sched_core::{BoundedSpin, ThreadIdentity};
    use std::sync::OnceLock;

    static WAKE_ZONE: OnceLock<usize> = OnceLock::new();

    fn complete_owner_wake(owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>) {
        let address = *WAKE_ZONE.get().unwrap();
        // SAFETY: the witness leaks this exact ZoneTables through the process
        // lifetime before registering the completion function.
        let zone = unsafe { &*(address as *const ZoneTables) };
        deliver_owner_effects(zone, carrick_sched_core::SlotId::new(0), owned);
    }

    #[test]
    fn direct_words_refuse_every_address_outside_the_qualified_view() {
        // SAFETY: the test never accesses the declared fake range; every
        // attempted word is deliberately outside it and must be refused.
        let words = unsafe { Cpl0DirectWords::from_identity_mapped_range(0x2000, 0x3000) }.unwrap();
        for address in [0, 0x1ff8, 0x3000, 0x4000] {
            assert_eq!(
                words.load(address),
                Err(DescriptorRefusal::TableOutsidePrimary)
            );
        }
    }

    #[test]
    fn cpl0_owner_refusals_use_the_linux_personality_encoding() {
        assert_eq!(MmError::Stale.errno(), 3);
        assert_eq!(MmError::Busy.errno(), 16);
        assert_eq!(MmError::MetadataRequired.errno(), 11);
    }

    #[test]
    fn contended_owner_completion_kicks_the_other_executor_after_unlock() {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        // SAFETY: ZoneTables documents the all-zero empty representation; the
        // allocation is uniquely owned for the duration of the witness.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let zone = Box::leak(zone);
        WAKE_ZONE.set(zone as *const ZoneTables as usize).unwrap();
        // SAFETY: CpuBinding consists only of integers and atomics whose zero
        // bit patterns are valid. These fixture bindings never enter CPL0.
        let bindings: Box<[CpuBinding; 2]> = unsafe { Box::new(core::mem::zeroed()) };
        let owner = carrick_sched_core::SlotId::new(0);
        let waiter = carrick_sched_core::SlotId::new(1);
        let space = zone.spaces.publish_closed(11, 0x600000, 0).unwrap();
        zone.spaces.open(space);
        for slot in [owner, waiter] {
            zone.drive(slot, 1);
            zone.publish_slot(slot, 11, Some(u32::from(slot.raw())), 0);
            zone.slot(slot)
                .set_sgi_target((&bindings[usize::from(slot.raw())] as *const CpuBinding) as u64);
            zone.enter_guest(slot);
        }
        assert!(zone.enter_idle(waiter, true));

        let key = ObjectWaitKey::new(3, 1).unwrap();
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &complete_owner_wake)
            .unwrap();
        let ticket = zone
            .admit_object_notification(key, &BoundedSpin(0), &complete_owner_wake)
            .unwrap();
        let record = zone
            .alloc_record(ThreadIdentity {
                mm: 11,
                tid: 41,
                serial: 1,
                generation: 1,
                affinity: 1 << waiter.raw(),
                ..Default::default()
            })
            .unwrap();
        let guard = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &complete_owner_wake)
            .unwrap();
        guard
            .park(guard.snapshot(), record, OperationToken::new(1, 1).unwrap())
            .unwrap();
        drop(guard);

        let held = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &complete_owner_wake)
            .unwrap();
        ticket.publish(
            carrick_sched_core::Waker::El1 { slot: owner },
            &complete_owner_wake,
        );
        assert_eq!(bindings[1].entry_kick.load(Ordering::Acquire), 0);
        drop(held);
        assert_eq!(zone.slot(waiter).queued(), 1, "waiter must queue remotely");
        assert_eq!(
            bindings[1].entry_kick.load(Ordering::Acquire),
            1,
            "unlock completion must preserve and deliver the remote wake"
        );
    }
}
