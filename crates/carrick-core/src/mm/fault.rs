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
/// `None` when the MM has no admitted root (its host arming decided), else
/// whether a node covers `page` and, for plain anonymous memory, permits
/// `access`. A busy root answers `Some(false)`: the host decides.
pub fn root_admits_commit<
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
) -> Option<bool> {
    let roots = roots?;
    let mm = carrick_core_abi::ReservationMm::new(mm_key)?;
    let index = spaces.find(mm_key)?.index();
    if !roots.admitted(index, mm) {
        return None;
    }
    let Ok(mut model) = roots.lock_in(spaces, index, mm, slot) else {
        return Some(false);
    };
    let bits = match access {
        LeafAccess::Read => 1,
        LeafAccess::Write => 2,
        LeafAccess::Execute => 4,
    };
    Some(model.mapping(page).is_some_and(|mapping| {
        !mapping.anonymous
            || carrick_core_abi::ReservationProtection::from_bits(bits)
                .is_some_and(|access| mapping.protection.permits(access))
    }))
}

use core::num::NonZeroU64;

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
            let protection = carrick_core_abi::ReservationProtection::from_bits(access)?;
            let plan = root
                .transfer_fault_plan(va & !4095, 4096, protection)
                .ok()?;
            let mapping = root.mapping(plan.range.start())?;
            let source = mapping
                .host_backing?
                .advance(plan.range.start().checked_sub(mapping.range.start())?)?;
            let sequence = root.next_transfer_sequence().ok()?;
            let carrier = self.slots.carrier()?;
            let operation = carrick_core_abi::PortalOperation {
                carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())?,
                sequence,
            };
            let window = carrick_core_abi::PortalGrantWindow {
                operation,
                generation: plan.generation,
                range: plan.range,
                protection: plan.protection,
                fault_page: plan.fault_page,
                host_backing: Some(source),
                fork_sequence: None,
            };
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
                requested_len: plan.range.len(),
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
