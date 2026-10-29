//! Per-carrier retirement queues for closed address-space entries, shared by
//! every guest ISA's native process service.
//!
//! A fork child's final exit (or an `exec` predecessor switch) closes its
//! space gate and releases its slot. When no slot still has the MM installed
//! and its reservation root has no active borrows, the space retires
//! immediately; otherwise its closed `AddressSpaces` entry and reservation
//! root are queued under that exact `(carrier, zone, roots)` scope and retried
//! by later drains in the same scope.
//!
//! Two scopes never share a queue or lock, so concurrent carriers or host-test
//! fixtures cannot detach or delay each other's spaces. Within one scope, each
//! drain compacts in place under that scope's lock so a concurrent drain on
//! another vCPU never observes a transiently empty queue while a retirement is
//! still in flight.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use carrick_core::mm::reservation::{ReservationGeometry, ReservationPolicy};
use carrick_core::mm::transaction::{MmPortal, OwnerVenue};

use carrick_el1_abi::{PinnedMetadataExtent, ReservationMm};
use carrick_mmu_core::owner_mmu::OwnerMmu;
use carrick_sched_core::{SlotId, ZoneTables};
use core::num::NonZeroU64;

use super::native_process_runtime::NativeProcessError;
use carrick_el1::lock::SpinLock;

/// The exact `(carrier, zone, reservation-table)` authority that owns a
/// queued space's indices.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetiredScope {
    pub carrier: NonZeroU64,
    pub zone: usize,
    pub roots: usize,
}

impl RetiredScope {
    pub fn for_portal<
        P: PinnedMetadataExtent,
        Policy: ReservationPolicy,
        Geometry: ReservationGeometry,
        Venue: OwnerVenue<Context>,
        B: OwnerMmu,
        Context: Copy + Send + Sync + zerocopy::FromZeros,
    >(
        owner: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
        zone: &ZoneTables<Context>,
    ) -> Self {
        Self {
            carrier: owner.carrier,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(owner.roots).addr(),
        }
    }
}

/// A closed space awaiting retirement, keyed by the exact carrier, zone and
/// reservation table it was published in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredSpace {
    pub carrier: NonZeroU64,
    pub zone: usize,
    pub roots: usize,
    pub mm: ReservationMm,
}

impl RetiredSpace {
    pub const fn scope(&self) -> RetiredScope {
        RetiredScope {
            carrier: self.carrier,
            zone: self.zone,
            roots: self.roots,
        }
    }
}

struct ScopeQueue {
    pending: SpinLock<Vec<ReservationMm>>,
}

impl ScopeQueue {
    const fn new() -> Self {
        Self {
            pending: SpinLock::new(Vec::new()),
        }
    }
}

/// Scope-partitioned pending queues. Each ISA owns one static instance.
pub struct RetiredSpaces {
    scopes: SpinLock<BTreeMap<RetiredScope, Arc<ScopeQueue>>>,
}

impl RetiredSpaces {
    pub const fn new() -> Self {
        Self {
            scopes: SpinLock::new(BTreeMap::new()),
        }
    }

    pub fn push(&self, space: RetiredSpace) {
        let queue = {
            let mut scopes = self.scopes.lock();
            Arc::clone(
                scopes
                    .entry(space.scope())
                    .or_insert_with(|| Arc::new(ScopeQueue::new())),
            )
        };
        let mut pending = queue.pending.lock();
        if !pending.contains(&space.mm) {
            pending.push(space.mm);
        }
    }

    pub fn len(&self) -> usize {
        let queues: Vec<Arc<ScopeQueue>> = self.scopes.lock().values().cloned().collect();
        queues.iter().map(|queue| queue.pending.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn prune_if_empty(&self, scope: RetiredScope) {
        let mut scopes = self.scopes.lock();
        let removable = scopes
            .get_mut(&scope)
            .and_then(Arc::get_mut)
            .is_some_and(|exclusive| exclusive.pending.lock().is_empty());
        if removable {
            scopes.remove(&scope);
        }
    }

    /// Retire every queued space in `scope` that `ready` admits; keep the rest
    /// queued in `scope` without touching any other scope.
    ///
    /// When `retire` returns `NativeProcessError::Busy`, that space and all
    /// remaining spaces in `scope` stay queued in FIFO order for the next
    /// drain. Stale or unretireable entries are dropped so they cannot block
    /// the queue head forever.
    pub fn drain_scope(
        &self,
        scope: RetiredScope,
        mut ready: impl FnMut(&RetiredSpace) -> bool,
        mut retire: impl FnMut(&RetiredSpace) -> Result<(), NativeProcessError>,
    ) -> Result<(), NativeProcessError> {
        let Some(queue) = self.scopes.lock().get(&scope).cloned() else {
            return Ok(());
        };
        let (result, empty) = {
            let mut pending = queue.pending.lock();
            let result = drain_vec(scope, &mut pending, &mut ready, &mut retire);
            (result, pending.is_empty())
        };
        drop(queue);
        if empty {
            self.prune_if_empty(scope);
        }
        result
    }

    /// Retire every queued space across all scopes that `ready` admits; keep
    /// the rest queued.
    pub fn drain(
        &self,
        mut ready: impl FnMut(&RetiredSpace) -> bool,
        mut retire: impl FnMut(&RetiredSpace) -> Result<(), NativeProcessError>,
    ) -> Result<(), NativeProcessError> {
        let scopes: Vec<(RetiredScope, Arc<ScopeQueue>)> = self
            .scopes
            .lock()
            .iter()
            .map(|(scope, queue)| (*scope, Arc::clone(queue)))
            .collect();
        let mut result = Ok(());
        let mut empty_scopes = Vec::new();
        for (scope, queue) in scopes {
            let (scope_result, empty) = {
                let mut pending = queue.pending.lock();
                let outcome = drain_vec(scope, &mut pending, &mut ready, &mut retire);
                (outcome, pending.is_empty())
            };
            drop(queue);
            if empty {
                empty_scopes.push(scope);
            }
            match scope_result {
                Ok(()) => {}
                Err(NativeProcessError::Busy) => {
                    result = Err(NativeProcessError::Busy);
                    break;
                }
                Err(error) => {
                    result = Err(error);
                }
            }
        }
        for scope in empty_scopes {
            self.prune_if_empty(scope);
        }
        result
    }

    /// Drain queued spaces belonging to this exact `(owner, zone)` scope whose
    /// MM is no longer installed on any of the zone's first `slots` slots.
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
        let scope = RetiredScope::for_portal(owner, zone);
        self.drain_scope(
            scope,
            |space| !space_has_resident_slot(zone, slots, space.mm),
            |space| retire_closed_space(owner, space.mm, worker),
        )
    }

    /// Retire `mm` now when no slot in `zone` has it installed, queuing `mm`
    /// in this portal's scope only if a slot still holds `mm` or its root is
    /// `Busy`. Earlier queued spaces in the same scope are drained best-effort
    /// without letting an unrelated space's error mask `mm`'s outcome.
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
        let scope = RetiredScope::for_portal(owner, zone);
        let _earlier_drain = self.drain_portal(owner, zone, slots, worker);
        if space_has_resident_slot(zone, slots, mm) {
            self.push(RetiredSpace {
                carrier: scope.carrier,
                zone: scope.zone,
                roots: scope.roots,
                mm,
            });
            let _recheck = self.drain_portal(owner, zone, slots, worker);
            return if owner.spaces.find(mm.raw()).is_none() {
                Ok(())
            } else {
                Err(NativeProcessError::Busy)
            };
        }
        match retire_closed_space(owner, mm, worker) {
            Ok(()) => Ok(()),
            Err(NativeProcessError::Busy) => {
                self.push(RetiredSpace {
                    carrier: scope.carrier,
                    zone: scope.zone,
                    roots: scope.roots,
                    mm,
                });
                let _recheck = self.drain_portal(owner, zone, slots, worker);
                if owner.spaces.find(mm.raw()).is_none() {
                    Ok(())
                } else {
                    Err(NativeProcessError::Busy)
                }
            }
            Err(error) => Err(error),
        }
    }
}

fn drain_vec(
    scope: RetiredScope,
    pending: &mut Vec<ReservationMm>,
    ready: &mut impl FnMut(&RetiredSpace) -> bool,
    retire: &mut impl FnMut(&RetiredSpace) -> Result<(), NativeProcessError>,
) -> Result<(), NativeProcessError> {
    let mut result = Ok(());
    let mut write = 0;
    for read in 0..pending.len() {
        let mm = pending[read];
        let space = RetiredSpace {
            carrier: scope.carrier,
            zone: scope.zone,
            roots: scope.roots,
            mm,
        };
        if !ready(&space) {
            pending[write] = mm;
            write += 1;
            continue;
        }
        match retire(&space) {
            Ok(()) => {}
            Err(NativeProcessError::Busy) => {
                pending.copy_within(read.., write);
                write += pending.len() - read;
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
    pending.truncate(write);
    result
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

    #[test]
    fn foreign_scope_drain_does_not_steal_or_block_other_scopes() {
        use std::sync::{Barrier, mpsc};
        use std::time::Duration;

        let queue = RetiredSpaces::new();
        // Order `scope_b < scope_a` so `BTreeMap` order cannot hide blocking.
        let scope_b = RetiredScope {
            carrier: NonZeroU64::new(1).unwrap(),
            zone: 10,
            roots: 20,
        };
        let scope_a = RetiredScope {
            carrier: NonZeroU64::new(2).unwrap(),
            zone: 30,
            roots: 40,
        };
        queue.push(RetiredSpace {
            carrier: scope_b.carrier,
            zone: scope_b.zone,
            roots: scope_b.roots,
            mm: ReservationMm::new(20).unwrap(),
        });
        queue.push(RetiredSpace {
            carrier: scope_a.carrier,
            zone: scope_a.zone,
            roots: scope_a.roots,
            mm: ReservationMm::new(10).unwrap(),
        });

        let entered = Barrier::new(2);
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let early = std::thread::scope(|s| {
            let worker_b = s.spawn(|| {
                queue.drain_scope(
                    scope_b,
                    |_| true,
                    |_| {
                        entered.wait();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                )
            });

            entered.wait();

            let worker_a = s.spawn(|| {
                let mut retired_a = Vec::new();
                let outcome = queue.drain_scope(
                    scope_a,
                    |_| true,
                    |space| {
                        retired_a.push(space.mm.raw());
                        Ok(())
                    },
                );
                done_tx.send((outcome, retired_a)).unwrap();
            });

            let early = done_rx.recv_timeout(Duration::from_millis(200));
            release_tx.send(()).unwrap();
            assert_eq!(worker_b.join().unwrap(), Ok(()));
            worker_a.join().unwrap();
            early
        });

        let (outcome_a, retired_a) =
            early.expect("scope A drain must complete without waiting on scope B");
        assert_eq!(outcome_a, Ok(()));
        assert_eq!(
            retired_a,
            vec![10],
            "foreign scope B drain must not steal scope A's queued space"
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn same_scope_concurrent_drain_waits_for_inflight_retirement() {
        use std::sync::{Barrier, Mutex, mpsc};
        use std::time::Duration;

        let queue = RetiredSpaces::new();
        queue.push(space(10));

        let retired = Mutex::new(Vec::new());
        let entered = Barrier::new(2);
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let premature = std::thread::scope(|s| {
            let worker_1 = s.spawn(|| {
                queue.drain(
                    |_| true,
                    |space| {
                        entered.wait();
                        release_rx.recv().unwrap();
                        retired.lock().unwrap().push(space.mm.raw());
                        Ok(())
                    },
                )
            });

            entered.wait();

            let worker_2 = s.spawn(|| {
                let outcome = queue.drain(
                    |_| true,
                    |space| {
                        retired.lock().unwrap().push(space.mm.raw());
                        Ok(())
                    },
                );
                let snapshot = retired.lock().unwrap().clone();
                done_tx.send((outcome, snapshot)).unwrap();
            });

            let premature = done_rx.recv_timeout(Duration::from_millis(50));
            release_tx.send(()).unwrap();
            assert_eq!(worker_1.join().unwrap(), Ok(()));
            worker_2.join().unwrap();
            premature
        });

        assert!(
            premature.is_err(),
            "same-scope concurrent drain returned before in-flight retirement finished: {premature:?}"
        );
        let (outcome_2, snapshot_at_return) = done_rx.recv().unwrap();
        assert_eq!(outcome_2, Ok(()));
        assert_eq!(snapshot_at_return, vec![10]);
        assert!(queue.is_empty());
    }
}
