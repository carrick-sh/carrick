//! One retirement queue for fork children's address-space entries, shared
//! by every guest ISA's native process service.
//!
//! A fork child's final exit closes its space gate, crosses to the carrier
//! (child retire), leaves its root and releases its slot. Its closed
//! `AddressSpaces` entry and reservation root are then queued here and
//! retired once no zone slot still has the MM installed. A failed retirement
//! never drops a queued entry: it and every entry after it stay queued.

extern crate alloc;

use alloc::vec::Vec;
use carrick_core::mm::reservation::{ReservationGeometry, ReservationPolicy};
use carrick_core::mm::transaction::{MmPortal, OwnerVenue};

use carrick_el1_abi::{PinnedMetadataExtent, ReservationMm};
use carrick_mmu_core::owner_mmu::OwnerMmu;
use carrick_sched_core::{SlotId, ZoneTables};
use core::num::NonZeroU64;

use super::native_process_runtime::NativeProcessError;
use crate::lock::SpinLock;

/// A closed child space awaiting retirement, keyed by the exact carrier,
/// zone and reservation table it was published in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredSpace {
    pub carrier: NonZeroU64,
    pub zone: usize,
    pub roots: usize,
    pub mm: ReservationMm,
}

/// The pending queue. Each ISA owns one static instance.
pub struct RetiredSpaces {
    pending: SpinLock<Vec<RetiredSpace>>,
}

impl RetiredSpaces {
    pub const fn new() -> Self {
        Self {
            pending: SpinLock::new(Vec::new()),
        }
    }

    pub fn push(&self, space: RetiredSpace) {
        self.pending.lock().push(space);
    }

    pub fn len(&self) -> usize {
        self.pending.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retire every queued space `ready` admits; keep the rest queued. On
    /// the first `retire` error, that entry and every later one go back to
    /// the queue with the deferred ones, and the error is returned.
    pub fn drain<E>(
        &self,
        mut ready: impl FnMut(&RetiredSpace) -> bool,
        mut retire: impl FnMut(&RetiredSpace) -> Result<(), E>,
    ) -> Result<(), E> {
        let pending = core::mem::take(&mut *self.pending.lock());
        let mut keep = Vec::new();
        let mut result = Ok(());
        let mut entries = pending.into_iter();
        for space in entries.by_ref() {
            if !ready(&space) {
                keep.push(space);
                continue;
            }
            if let Err(error) = retire(&space) {
                keep.push(space);
                result = Err(error);
                break;
            }
        }
        keep.extend(entries);
        self.pending.lock().extend(keep);
        result
    }

    /// The production drain for one ISA's portal and zone: entries from
    /// another carrier, zone or table, and MMs still installed on a slot of
    /// the zone's first `slots` slots, stay queued.
    pub fn drain_portal<
        P: PinnedMetadataExtent,
        Policy: ReservationPolicy,
        Geometry: ReservationGeometry,
        Venue: OwnerVenue<Context>,
        B: OwnerMmu,
        Context: Copy + Send + Sync + zerocopy::FromZeros,
    >(
        &self,
        owner: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
        zone: &ZoneTables<Context>,
        slots: usize,
        worker: u32,
    ) -> Result<(), NativeProcessError> {
        let zone_address = core::ptr::from_ref(zone).addr();
        let roots_address = core::ptr::from_ref(owner.roots).addr();
        self.drain(
            |space| {
                space.carrier == owner.carrier
                    && space.zone == zone_address
                    && space.roots == roots_address
                    && !space_has_resident_slot(zone, slots, space.mm)
            },
            |space| retire_closed_space(owner, space.mm, worker),
        )
    }
}

impl Default for RetiredSpaces {
    fn default() -> Self {
        Self::new()
    }
}

/// True when any of the zone's first `slots` slots has `mm` installed.
pub fn space_has_resident_slot<C: Copy + Send + Sync + zerocopy::FromZeros>(
    zone: &ZoneTables<C>,
    slots: usize,
    mm: ReservationMm,
) -> bool {
    (0..slots).any(|slot| {
        SlotId::from_index(slot).is_some_and(|slot| zone.installed_space(slot) == mm.raw())
    })
}

/// Retire a closed child's reservation root (tree nodes, notifications) and
/// free its exact space entry so both indices can be reused.
pub fn retire_closed_space<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    owner: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    mm: ReservationMm,
    worker: u32,
) -> Result<(), NativeProcessError> {
    let index = owner
        .spaces
        .find(mm.raw())
        .ok_or(NativeProcessError::Stale)?;
    owner.spaces.close(index);
    owner
        .root_any(mm, worker)
        .map_err(|_| NativeProcessError::Stale)?
        .retire()
        .map_err(|_| NativeProcessError::Busy)?;
    owner.spaces.free(index);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space(mm: u64) -> RetiredSpace {
        RetiredSpace {
            carrier: NonZeroU64::MIN,
            zone: 1,
            roots: 2,
            mm: ReservationMm::new(mm).unwrap(),
        }
    }

    #[test]
    fn busy_retire_mid_list_loses_nothing_and_a_later_drain_completes_it() {
        let queue = RetiredSpaces::new();
        for mm in [10, 11, 12, 13] {
            queue.push(space(mm));
        }
        let retired = core::cell::RefCell::new(Vec::new());
        // 11 is still installed (deferred); 12 refuses Busy mid-list.
        let result = queue.drain(
            |space| space.mm.raw() != 11,
            |space| {
                if space.mm.raw() == 12 {
                    Err(NativeProcessError::Busy)
                } else {
                    retired.borrow_mut().push(space.mm.raw());
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(NativeProcessError::Busy));
        assert_eq!(*retired.borrow(), vec![10]);
        // 11 (deferred), 12 (failed) and 13 (never reached) are all kept.
        assert_eq!(queue.len(), 3);
        let result = queue.drain(
            |_| true,
            |space| {
                retired.borrow_mut().push(space.mm.raw());
                Ok::<(), NativeProcessError>(())
            },
        );
        assert_eq!(result, Ok(()));
        let mut done = retired.borrow().clone();
        done.sort_unstable();
        assert_eq!(done, vec![10, 11, 12, 13]);
        assert!(queue.is_empty());
    }
}
