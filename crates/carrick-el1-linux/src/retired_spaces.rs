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
use core::sync::atomic::{AtomicU64, Ordering};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedSpace {
    id: u64,
    space: RetiredSpace,
    in_flight: bool,
}

/// The pending queue. Each ISA owns one static instance.
pub struct RetiredSpaces {
    next_id: AtomicU64,
    pending: SpinLock<Vec<QueuedSpace>>,
}

struct InFlightGuard<'a> {
    queue: &'a RetiredSpaces,
    id: u64,
    armed: bool,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut pending = self.queue.pending.lock();
            if let Some(entry) = pending.iter_mut().find(|entry| entry.id == self.id) {
                entry.in_flight = false;
            }
        }
    }
}

impl RetiredSpaces {
    pub const fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            pending: SpinLock::new(Vec::new()),
        }
    }

    pub fn push(&self, space: RetiredSpace) {
        let mut pending = self.pending.lock();
        if pending.iter().any(|entry| entry.space == space) {
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        pending.push(QueuedSpace {
            id,
            space,
            in_flight: false,
        });
    }

    pub fn len(&self) -> usize {
        self.pending.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn has_portal_in_flight(&self, carrier: NonZeroU64, zone: usize, roots: usize) -> bool {
        let pending = self.pending.lock();
        pending.iter().any(|entry| {
            entry.in_flight
                && entry.space.carrier == carrier
                && entry.space.zone == zone
                && entry.space.roots == roots
        })
    }

    fn wait_portal_in_flight(&self, carrier: NonZeroU64, zone: usize, roots: usize) {
        while self.has_portal_in_flight(carrier, zone, roots) {
            core::hint::spin_loop();
        }
    }

    fn next_candidate(&self, next_min_id: u64) -> Option<(u64, RetiredSpace)> {
        let pending = self.pending.lock();
        pending
            .iter()
            .find(|entry| entry.id >= next_min_id && !entry.in_flight)
            .map(|entry| (entry.id, entry.space))
    }

    /// Retire every queued space `ready` admits; keep the rest queued.
    ///
    /// Entries remain in `self.pending` until their retirement completes, so a
    /// concurrent caller never observes a temporarily emptied queue. The queue
    /// spin lock is held only for short slice lookups/removals and is never
    /// held across `ready` or `retire`.
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
        let mut next_min_id = 0u64;
        let mut result = Ok(());
        while let Some((id, space)) = self.next_candidate(next_min_id) {
            next_min_id = id.saturating_add(1);
            if !ready(&space) {
                continue;
            }
            let claimed = {
                let mut pending = self.pending.lock();
                if let Some(entry) = pending
                    .iter_mut()
                    .find(|entry| entry.id == id && !entry.in_flight)
                {
                    entry.in_flight = true;
                    true
                } else {
                    false
                }
            };
            if !claimed {
                continue;
            }
            let mut guard = InFlightGuard {
                queue: self,
                id,
                armed: true,
            };
            let outcome = retire(&space);
            guard.armed = false;
            let mut pending = self.pending.lock();
            match outcome {
                Ok(()) => {
                    if let Some(pos) = pending.iter().position(|entry| entry.id == id) {
                        pending.remove(pos);
                    }
                }
                Err(NativeProcessError::Busy) => {
                    if let Some(entry) = pending.iter_mut().find(|entry| entry.id == id) {
                        entry.in_flight = false;
                    }
                    return Err(NativeProcessError::Busy);
                }
                Err(error) => {
                    // Stale or unretireable entries are dropped from the queue
                    // so they do not block the queue head forever.
                    if let Some(pos) = pending.iter().position(|entry| entry.id == id) {
                        pending.remove(pos);
                    }
                    result = Err(error);
                }
            }
        }
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
        let result = self.drain(
            |space| {
                space.carrier == owner.carrier
                    && space.zone == zone_address
                    && space.roots == roots_address
                    && !space_has_resident_slot(zone, slots, space.mm)
            },
            |space| retire_closed_space(owner, space.mm, worker),
        );
        self.wait_portal_in_flight(owner.carrier, zone_address, roots_address);
        result
    }

    /// Retire `mm` synchronously when no zone slot has it installed and its
    /// root is free, after opportunistically draining any older entries for
    /// this portal. If `mm` still has a resident slot or its root is busy,
    /// queue it so a later drain completes retirement.
    pub fn retire_or_queue_portal<
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
        mm: ReservationMm,
    ) -> Result<(), NativeProcessError> {
        let _ = self.drain_portal(owner, zone, slots, worker);
        if !space_has_resident_slot(zone, slots, mm) {
            match retire_closed_space(owner, mm, worker) {
                Ok(()) => return Ok(()),
                Err(NativeProcessError::Busy) => {}
                Err(error) => {
                    return if owner.spaces.find(mm.raw()).is_none() {
                        Ok(())
                    } else {
                        Err(error)
                    };
                }
            }
        }
        let zone_address = core::ptr::from_ref(zone).addr();
        let roots_address = core::ptr::from_ref(owner.roots).addr();
        let target = RetiredSpace {
            carrier: owner.carrier,
            zone: zone_address,
            roots: roots_address,
            mm,
        };
        self.push(target);
        let _ = self.drain(
            |space| *space == target && !space_has_resident_slot(zone, slots, space.mm),
            |space| retire_closed_space(owner, space.mm, worker),
        );
        self.wait_portal_in_flight(owner.carrier, zone_address, roots_address);
        if owner.spaces.find(mm.raw()).is_none() {
            Ok(())
        } else {
            Err(NativeProcessError::Busy)
        }
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
        .map_err(|error| match error {
            carrick_core::mm::transaction::MmError::Busy
            | carrick_core::mm::transaction::MmError::Wait(_) => NativeProcessError::Busy,
            _ => NativeProcessError::Stale,
        })?
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

    struct BoundedBarrier {
        parties: usize,
        state: std::sync::Mutex<(usize, u64)>,
        cvar: std::sync::Condvar,
    }

    impl BoundedBarrier {
        fn new(parties: usize) -> Self {
            Self {
                parties,
                state: std::sync::Mutex::new((0, 0)),
                cvar: std::sync::Condvar::new(),
            }
        }

        fn wait(&self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut state = self.state.lock().unwrap();
            let generation = state.1;
            state.0 += 1;
            if state.0 == self.parties {
                state.0 = 0;
                state.1 += 1;
                self.cvar.notify_all();
                return;
            }
            while state.1 == generation {
                let now = std::time::Instant::now();
                assert!(now < deadline, "bounded barrier timed out after 5s");
                let (next, result) = self.cvar.wait_timeout(state, deadline - now).unwrap();
                state = next;
                assert!(
                    !result.timed_out() || state.1 != generation,
                    "bounded barrier timed out after 5s"
                );
            }
        }
    }

    #[test]
    fn concurrent_drain_does_not_hide_second_callers_space() {
        let queue = RetiredSpaces::new();
        let first_carrier = NonZeroU64::new(1).unwrap();
        let second_carrier = NonZeroU64::new(2).unwrap();
        let first_space = RetiredSpace {
            carrier: first_carrier,
            zone: 10,
            roots: 20,
            mm: ReservationMm::new(10).unwrap(),
        };
        let second_space = RetiredSpace {
            carrier: second_carrier,
            zone: 30,
            roots: 40,
            mm: ReservationMm::new(20).unwrap(),
        };
        queue.push(first_space);

        let pushed = BoundedBarrier::new(2);
        let in_first_retire = BoundedBarrier::new(2);
        let second_finished = BoundedBarrier::new(2);

        let (second_outcome, second_retired, visible_to_second) = std::thread::scope(|s| {
            let first = s.spawn(|| {
                pushed.wait();
                let mut retired = Vec::new();
                let outcome = queue.drain(
                    |space| space.carrier == first_carrier,
                    |space| {
                        in_first_retire.wait();
                        second_finished.wait();
                        retired.push(space.mm.raw());
                        Ok(())
                    },
                );
                assert_eq!(outcome, Ok(()));
                assert_eq!(retired, vec![10]);
            });

            let second = s.spawn(|| {
                queue.push(second_space);
                pushed.wait();
                in_first_retire.wait();

                let mut retired = Vec::new();
                let outcome = queue.drain(
                    |space| space.carrier == second_carrier,
                    |space| {
                        retired.push(space.mm.raw());
                        Ok(())
                    },
                );
                let visible = !queue.is_empty();
                second_finished.wait();
                (outcome, retired, visible)
            });

            first.join().unwrap();
            second.join().unwrap()
        });

        assert_eq!(second_outcome, Ok(()));
        assert!(
            !second_retired.is_empty() || visible_to_second,
            "second caller's space was neither retired nor visible in queue"
        );
        assert_eq!(
            second_retired,
            vec![20],
            "second caller's ready space must retire during its own drain"
        );
        assert!(queue.is_empty());
    }
}
