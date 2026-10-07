//! Shared lazy-supply generations and exact reservation fault admission.
use carrick_core_abi::{EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantMailbox, FrameGrantRequest};
use carrick_mmu_core::aarch64::LeafAccess;
use carrick_sched_core::spaces::notification::SpaceAccess;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_FRAME_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);
/// Zero is permanent exhaustion and cannot publish a mailbox or grant slot.
pub fn next_frame_grant_generation() -> u64 {
    frame_grant_generation(&NEXT_FRAME_GRANT_GENERATION)
}
fn frame_grant_generation(counter: &AtomicU64) -> u64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .unwrap_or(0)
}

/// The one lazy-supply protocol, shared by faults and stopped-target transfers.
/// Failed mailbox admission leaves the caller's owned continuation resumable.
pub fn request_lazy_frames(mailbox: &FrameGrantMailbox, mm_key: u64, va: u64, access: u64) -> bool {
    mailbox.try_publish_request(FrameGrantRequest {
        mm_key,
        request_generation: next_frame_grant_generation(),
        fault_va: va,
        requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
        access,
    })
}

/// Whether a delegated MM's root lets this prepared page be committed:
/// NotDelegated when the MM has no admitted root (its host arming decided), else
/// whether a node covers `page` and, for plain anonymous memory, permits
/// `access`. A busy root is Unavailable, never a Linux protection decline.
pub fn root_fault_admission<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    roots: Option<&crate::mm::reservation::SharedReservations<Policy, Geometry>>,
    spaces: SpaceAccess<'_, Context>,
    slot: u32,
    mm_key: u64,
    page: u64,
    access: LeafAccess,
) -> RootFaultAdmission {
    let Some(roots) = roots else {
        return RootFaultAdmission::NotDelegated;
    };
    let Some(mm) = carrick_core_abi::ReservationMm::new(mm_key) else {
        return RootFaultAdmission::Unavailable;
    };
    let Some(index) = spaces.find(mm_key).map(|index| index.index()) else {
        return RootFaultAdmission::Unavailable;
    };
    if !roots.admitted(index, mm) {
        return RootFaultAdmission::NotDelegated;
    }
    let Ok(mut model) = roots.lock_in(spaces, index, mm, slot) else {
        return RootFaultAdmission::Unavailable;
    };
    let bits = match access {
        LeafAccess::Read => 1,
        LeafAccess::Write => 2,
        LeafAccess::Execute => 4,
    };
    if model.mapping(page).is_some_and(|mapping| {
        !mapping.anonymous
            || carrick_core_abi::ReservationProtection::from_bits(bits)
                .is_some_and(|access| mapping.protection.permits(access))
    }) {
        RootFaultAdmission::Allowed
    } else {
        RootFaultAdmission::Declined
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootFaultAdmission {
    NotDelegated,
    Allowed,
    Declined,
    Unavailable,
}

use core::num::NonZeroU64;

/// Select physical supply from the exact reservation owner. The selected
/// window carries no descriptor authority; its generation is revalidated by
/// the shared grant target before any terminal becomes visible.
pub fn select_fault_window<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    root: &mut crate::mm::reservation::Reservations<'_, Policy, Geometry, Context>,
    carrier: NonZeroU64,
    va: carrick_guest_arch::UserVa,
    max_len: carrick_guest_arch::GuestLen,
    protection: carrick_core_abi::ReservationProtection,
) -> Result<carrick_core_abi::PortalGrantWindow, crate::mm::reservation::Refusal> {
    use crate::mm::reservation::Refusal;
    let plan = root.transfer_fault_plan(va.raw() & !4095, max_len.raw(), protection)?;
    let mapping = root.mapping(plan.range.start()).ok_or(Refusal::Stale)?;
    let host_backing = match mapping.host_backing {
        Some(source) => Some(
            source
                .advance(
                    plan.range
                        .start()
                        .checked_sub(mapping.range.start())
                        .ok_or(Refusal::Stale)?,
                )
                .ok_or(Refusal::Stale)?,
        ),
        None => None,
    };
    let sequence = root.next_transfer_sequence()?;
    Ok(carrick_core_abi::PortalGrantWindow {
        operation: carrick_core_abi::PortalOperation {
            carrier,
            mm: root.mm(),
            incarnation: NonZeroU64::new(root.incarnation().raw()).ok_or(Refusal::Stale)?,
            sequence,
        },
        generation: plan.generation,
        range: plan.range,
        protection: plan.protection,
        fault_page: plan.fault_page,
        host_backing,
        fork_sequence: None,
    })
}

pub struct FileFaultVenue<
    'a,
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
    Context: Copy + Send + Sync + zerocopy::FromZeros = carrick_sched_core::ThreadCtx,
> {
    pub roots: &'a crate::mm::reservation::SharedReservations<Policy, Geometry>,
    pub spaces: SpaceAccess<'a, Context>,
    pub slots: &'a Slots,
    pub worker: u32,
    pub mailbox: &'a FrameGrantMailbox,
}
impl<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
> FileFaultVenue<'_, Policy, Geometry, Slots, Context>
{
    pub fn publish(&self, mm_key: u64, va: u64, access: u64) -> bool {
        let owner_source = core::cell::Cell::new(false);
        let run = || -> Option<bool> {
            let mm = carrick_core_abi::ReservationMm::new(mm_key)?;
            let index = self.spaces.find(mm_key)?;
            if !self.roots.admitted(index.index(), mm) {
                return None;
            }
            let mut root = self
                .roots
                .lock_in(self.spaces, index.index(), mm, self.worker)
                .ok()?;
            root.mapping(va)?.host_backing?;
            owner_source.set(true);
            let window = select_fault_window(
                &mut root,
                self.slots.carrier()?,
                carrick_guest_arch::UserVa::new(va),
                carrick_guest_arch::GuestLen::new(4096),
                carrick_core_abi::ReservationProtection::from_bits(access)?,
            )
            .ok()?;
            drop(root);
            let slot = self.slots.grant(self.worker as usize)?;
            let generation = next_frame_grant_generation();
            if !slot.publish_fault_selection(generation, window) {
                return Some(true);
            }
            if !self.mailbox.try_publish_request(FrameGrantRequest {
                mm_key,
                request_generation: generation,
                fault_va: va,
                requested_len: window.range.len(),
                access,
            }) {
                slot.cancel_fault_selection(window, generation);
            }
            Some(true)
        };
        run().unwrap_or(owner_source.get())
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;
    #[test]
    fn exhausted_frame_request_generation_refuses_without_reusing_one() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let last = frame_grant_generation(&counter);
        let exhausted = frame_grant_generation(&counter);
        let repeated = frame_grant_generation(&counter);
        assert_ne!(repeated, 1, "exhaustion reused request incarnation one");
        assert_eq!(last, u64::MAX - 1);
        assert_eq!(exhausted, 0);
        assert_eq!(repeated, 0);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
