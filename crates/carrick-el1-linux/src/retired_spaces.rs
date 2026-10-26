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
use carrick_el1::lock::SpinLock;

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

    /// Retire every queued space `ready` admits; keep the rest queued.
    ///
    /// When `retire` returns `NativeProcessError::Busy`, that space is
    /// kept to retry at the next drain, and remaining entries stay queued.
    /// Stale or unretireable entries are dropped/diagnosed so they do not
    /// block the queue head forever, allowing subsequent entries to drain.
    pub fn drain(
        &self,
        mut ready: impl FnMut(&RetiredSpace) -> bool,
        mut retire: impl FnMut(&RetiredSpace) -> Result<(), NativeProcessError>,
    ) -> Result<(), NativeProcessError> {
        // Take only the entries this drain admits. Entries for another
        // carrier, zone or still-resident MM stay in the shared queue, so a
        // concurrent drain never sees its own pending retirement as absent.
        let admitted = {
            let mut pending = self.pending.lock();
            let mut admitted = Vec::new();
            pending.retain(|space| {
                if ready(space) {
                    admitted.push(*space);
                    false
                } else {
                    true
                }
            });
            admitted
        };
        let mut keep = Vec::new();
        let mut result = Ok(());
        let mut entries = admitted.into_iter();
        for space in entries.by_ref() {
            match retire(&space) {
                Ok(()) => {}
                Err(NativeProcessError::Busy) => {
                    keep.push(space);
                    result = Err(NativeProcessError::Busy);
                    break;
                }
                Err(error) => {
                    // Stale or unretireable entries are dropped from the queue
                    // so they do not block the queue head forever.
                    result = Err(error);
                }
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
/// free its exact space entry so both indices can be reused. The carrier
/// quarantines physical stock before this call and releases the whole MM's
/// inventory only after entry removal; deferred returns retire with that MM.
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
        .retire_final()
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
    fn concurrent_drains_cannot_hide_another_carriers_retirement() {
        use std::sync::mpsc;
        use std::time::Duration;
        let queue = RetiredSpaces::new();
        let a = space(10);
        let b = space(11);
        queue.push(a);
        queue.push(b);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let queue_ref = &queue;
        let retired_b = std::thread::scope(|scope| {
            let first = scope.spawn(move || {
                queue_ref.drain(
                    |space| space.mm == a.mm,
                    |_| {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(())
                    },
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut retired = 0;
            queue
                .drain(
                    |space| space.mm == b.mm,
                    |_| {
                        retired += 1;
                        Ok(())
                    },
                )
                .unwrap();
            release_tx.send(()).unwrap();
            first.join().unwrap().unwrap();
            retired
        });
        assert_eq!(
            retired_b, 1,
            "foreign drain hid this carrier's owned retirement"
        );
        assert!(queue.is_empty());
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

    #[test]
    fn stale_entry_at_head_is_dropped_and_does_not_block_later_entries() {
        let queue = RetiredSpaces::new();
        queue.push(space(10));
        queue.push(space(11));
        let retired = core::cell::RefCell::new(Vec::new());
        // 10 is Stale; 11 succeeds.
        let result = queue.drain(
            |_| true,
            |space| {
                if space.mm.raw() == 10 {
                    Err(NativeProcessError::Stale)
                } else {
                    retired.borrow_mut().push(space.mm.raw());
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(NativeProcessError::Stale));
        assert_eq!(*retired.borrow(), vec![11]);
        // 10 is dropped (does not sit at head forever); 11 was retired.
        assert!(queue.is_empty());
    }
}
