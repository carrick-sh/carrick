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
use carrick_core::mm::transaction::{MmError, MmPortal, OwnerVenue};

use carrick_el1_abi::{PinnedMetadataExtent, ReservationMm};
use carrick_mmu_core::owner_mmu::OwnerMmu;
use carrick_sched_core::{SlotId, ZoneTables};
use core::num::NonZeroU64;

use carrick_core::mm::reservation::{RootHolder, RootWait};
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

/// Why one queued space did not retire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceRetireRefusal {
    /// A host thread held the space's reservation root: "not now". The
    /// carrier's own release ends it; a drain with a
    /// [`SpaceRetiredCrossing`] enrols on that release by crossing, then
    /// reruns ([`RetiredSpaces::drain_portal_crossing`]).
    HostHeld,
    /// Otherwise not now (a guest holder of the root, a pending edit): the
    /// entry stays queued for the next drain (#3031).
    Busy,
    /// The entry is gone or cannot retire: it is dropped.
    Stale,
}

/// What one [`RetiredSpaces::drain`] did: how many queued spaces it
/// retired (their entries are unpublished, so carrier custody waiting for
/// that, a retired fork child's quarantined tables, is now reclaimable),
/// and the first refusal, if any (the refused entries stay queued).
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredDrain {
    pub retired: usize,
    pub result: Result<(), SpaceRetireRefusal>,
}

/// The carrier crossing a retired-space drain owes (x86: the recordless
/// [`carrick_el1_abi::NATIVE_SPACE_RETIRED_PORT`]).
///
/// The contract a crossing must keep: it returns only after every host
/// thread's hold of a reservation root that was live when it began has
/// ended. The carrier holds a guest MM's root only inside the custody a
/// crossing must take, so the crossing is the enrolment on that holder's
/// release. It also tells the carrier that entries were unpublished, so it
/// reclaims what waited for that (a retired fork child's quarantine).
pub trait SpaceRetiredCrossing {
    fn cross(&mut self);
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
    /// Holds `self.pending`'s lock across `ready` and `retire` while
    /// compacting entries in place, so a concurrent `push` or `drain` waits on
    /// bounded owner work and never sees a queue emptied by another drain.
    /// Lock order: the queue lock is taken before owner and root locks, and
    /// nothing calls `push` or `drain` while holding those.
    ///
    /// When `retire` answers "not now" ([`SpaceRetireRefusal::HostHeld`] or
    /// [`SpaceRetireRefusal::Busy`]), that space and every later entry stay
    /// queued to retry at the next drain. Stale or unretireable entries are
    /// dropped so they do not block the queue head forever, allowing
    /// subsequent entries to drain.
    pub fn drain(
        &self,
        mut ready: impl FnMut(&RetiredSpace) -> bool,
        mut retire: impl FnMut(&RetiredSpace) -> Result<(), SpaceRetireRefusal>,
    ) -> RetiredDrain {
        let mut pending = self.pending.lock();
        let len = pending.len();
        let mut write = 0;
        let mut busy = false;
        let mut retired = 0;
        let mut result = Ok(());
        for read in 0..len {
            let Some(space) = pending.get(read).copied() else {
                break;
            };
            if busy || !ready(&space) {
                if write != read
                    && let Some(slot) = pending.get_mut(write)
                {
                    *slot = space;
                }
                write += 1;
                continue;
            }
            match retire(&space) {
                Ok(()) => retired += 1,
                Err(refusal @ (SpaceRetireRefusal::HostHeld | SpaceRetireRefusal::Busy)) => {
                    if write != read
                        && let Some(slot) = pending.get_mut(write)
                    {
                        *slot = space;
                    }
                    write += 1;
                    busy = true;
                    result = Err(refusal);
                }
                Err(error) => {
                    // Stale or unretireable entries are dropped from the queue
                    // so they do not block the queue head forever.
                    result = Err(error);
                }
            }
        }
        pending.truncate(write);
        RetiredDrain { retired, result }
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
    ) -> RetiredDrain {
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

    /// [`Self::drain_portal`] for a carrier that parks waiters on what a
    /// retirement returns: cross whenever the drain retired an entry, so
    /// the carrier reclaims it now, or found a root the host held. A host
    /// hold is "not now": the crossing waits for its release
    /// ([`SpaceRetiredCrossing`]'s contract), and the drain reruns. Every
    /// rerun follows a host hold that began after the previous crossing, so
    /// none spins. Any other refusal stays queued and is returned.
    pub fn drain_portal_crossing<
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
        crossing: &mut dyn SpaceRetiredCrossing,
    ) -> Result<(), SpaceRetireRefusal> {
        self.drain_crossing(|| self.drain_portal(owner, zone, slots, worker), crossing)
    }

    fn drain_crossing(
        &self,
        mut drain: impl FnMut() -> RetiredDrain,
        crossing: &mut dyn SpaceRetiredCrossing,
    ) -> Result<(), SpaceRetireRefusal> {
        loop {
            let drained = drain();
            let host_held = drained.result == Err(SpaceRetireRefusal::HostHeld);
            if drained.retired != 0 || host_held {
                crossing.cross();
            }
            if !host_held {
                return drained.result;
            }
        }
    }

    /// Carriers with at least one queued entry for `(zone, roots)`.
    #[cfg(any(test, feature = "host-test"))]
    pub fn carriers_in_scope(&self, zone: usize, roots: usize) -> Vec<NonZeroU64> {
        let pending = self.pending.lock();
        let mut carriers = Vec::new();
        for space in pending.iter() {
            if space.zone == zone && space.roots == roots && !carriers.contains(&space.carrier) {
                carriers.push(space.carrier);
            }
        }
        carriers
    }

    /// Remove every queued entry for `(zone, roots)`, returning how many
    /// entries remained unretired in that scope.
    #[cfg(any(test, feature = "host-test"))]
    pub fn purge_scope(&self, zone: usize, roots: usize) -> usize {
        let mut pending = self.pending.lock();
        let before = pending.len();
        pending.retain(|space| !(space.zone == zone && space.roots == roots));
        before - pending.len()
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
) -> Result<(), SpaceRetireRefusal> {
    let index = owner
        .spaces
        .find(mm.raw())
        .ok_or(SpaceRetireRefusal::Stale)?;
    owner.spaces.close(index);
    let holder = HolderProbe::default();
    owner
        .root_any_observing(mm, worker, &holder)
        .map_err(|error| match (error, holder.0.get()) {
            (MmError::Busy, Some(RootHolder::Host)) => SpaceRetireRefusal::HostHeld,
            (MmError::Busy, _) => SpaceRetireRefusal::Busy,
            _ => SpaceRetireRefusal::Stale,
        })?
        .retire_final()
        .map_err(|_| SpaceRetireRefusal::Busy)?;
    owner
        .space_access(worker)
        .map_err(|_| SpaceRetireRefusal::Stale)?
        .retire_entry(index)
        .map_err(|_| SpaceRetireRefusal::Stale)?;
    Ok(())
}

/// Observes the holder of a held root for [`retire_closed_space`]; never
/// waits (EL1 gives up at once).
#[derive(Default)]
struct HolderProbe(core::cell::Cell<Option<RootHolder>>);
impl RootWait for HolderProbe {
    fn wait(&self, _attempt: u32, holder: RootHolder) -> bool {
        self.0.set(Some(holder));
        false
    }
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
                    Err(SpaceRetireRefusal::Busy)
                } else {
                    retired.borrow_mut().push(space.mm.raw());
                    Ok(())
                }
            },
        );
        assert_eq!(
            result,
            RetiredDrain {
                retired: 1,
                result: Err(SpaceRetireRefusal::Busy)
            }
        );
        assert_eq!(*retired.borrow(), vec![10]);
        // 11 (deferred), 12 (failed) and 13 (never reached) are all kept.
        assert_eq!(queue.len(), 3);
        let result = queue.drain(
            |_| true,
            |space| {
                retired.borrow_mut().push(space.mm.raw());
                Ok::<(), SpaceRetireRefusal>(())
            },
        );
        assert_eq!(
            result,
            RetiredDrain {
                retired: 3,
                result: Ok(())
            }
        );
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
                    Err(SpaceRetireRefusal::Stale)
                } else {
                    retired.borrow_mut().push(space.mm.raw());
                    Ok(())
                }
            },
        );
        assert_eq!(
            result,
            RetiredDrain {
                retired: 1,
                result: Err(SpaceRetireRefusal::Stale)
            }
        );
        assert_eq!(*retired.borrow(), vec![11]);
        // 10 is dropped (does not sit at head forever); 11 was retired.
        assert!(queue.is_empty());
    }

    struct CountingCrossing(usize);
    impl SpaceRetiredCrossing for CountingCrossing {
        fn cross(&mut self) {
            self.0 += 1;
        }
    }

    /// #3030 (rev3022c P0-1): a host thread holding a retiring space's root
    /// is "not now", never a strand. The drain crosses (the crossing waits
    /// out the carrier's hold), reruns, retires the entry and crosses again
    /// for it. "Host-held once, then success."
    #[test]
    fn a_host_held_root_crosses_and_reruns_until_the_space_retires() {
        let queue = RetiredSpaces::new();
        queue.push(space(10));
        let attempts = core::cell::Cell::new(0);
        let mut crossing = CountingCrossing(0);
        let result = queue.drain_crossing(
            || {
                queue.drain(
                    |_| true,
                    |_| {
                        attempts.set(attempts.get() + 1);
                        if attempts.get() == 1 {
                            Err(SpaceRetireRefusal::HostHeld)
                        } else {
                            Ok(())
                        }
                    },
                )
            },
            &mut crossing,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(attempts.get(), 2, "held once, then retired");
        assert_eq!(
            crossing.0, 2,
            "one crossing for the hold, one for the retirement"
        );
        assert!(queue.is_empty());
    }

    /// A guest holder is not the carrier's to release: the entry stays
    /// queued, nothing crosses, and the drain does not spin (#3031).
    #[test]
    fn a_guest_held_root_stays_queued_without_crossing() {
        let queue = RetiredSpaces::new();
        queue.push(space(10));
        let mut crossing = CountingCrossing(0);
        let result = queue.drain_crossing(
            || queue.drain(|_| true, |_| Err(SpaceRetireRefusal::Busy)),
            &mut crossing,
        );
        assert_eq!(result, Err(SpaceRetireRefusal::Busy));
        assert_eq!(crossing.0, 0);
        assert_eq!(queue.len(), 1);
    }
}
