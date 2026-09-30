//! Neutral object readiness waits. No private-futex address or numeric fd is
//! an object identity. T1 assigns a queue index per readiness class, binds its
//! strictly increasing object generation, and owns the pinned operation arena.
//! T3 saves an adapter-selected resumption entry and consumes the operation
//! token there BEFORE resolving any numeric fd. T5 does the same at handback,
//! including signal/control/cancellation; `Handback::Resumed` means registers
//! are preserved, not that a pending operation has completed.
//!
//! Lock order: object state, this queue, one execution slot. Observe readiness
//! under object state after taking a snapshot; release object state before
//! parking. Every readiness mutation must call `notify_object` before releasing
//! object state. Epoch validation then closes check/enroll/park races even when
//! the notification found no waiters. No lock crosses a switch or SGI delivery.

use super::*;

/// Admission capacity, independent of the number of execution slots. Queue
/// storage is provisioned once with the zone; transfers allocate no entries.
pub const OBJECT_WAIT_QUEUES: usize = ZONE_RECORDS;

/// Direct queue index plus the exact object incarnation. Different readiness
/// classes of one object have different indices, assigned by its authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ObjectWaitKey {
    index: u32,
    generation: u64,
}

impl ObjectWaitKey {
    pub const fn new(index: u32, generation: u64) -> Option<Self> {
        if index == 0 || index as usize >= OBJECT_WAIT_QUEUES || generation == 0 {
            None
        } else {
            Some(Self { index, generation })
        }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Owned locator of a pinned operation in the object authority's shared arena.
/// The authority, not this scheduler, defines its payload (endpoint, buffer,
/// length, progress and operation kind). No host pointer or fd is stored here.
/// Construct only when transferring an admitted operation to the scheduler;
/// consuming it transfers responsibility for completion/cancellation back.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "an operation token must be resumed, reparked, or cancelled by its authority"]
#[repr(C)]
pub struct OperationToken {
    index: u64,
    generation: u64,
}

impl OperationToken {
    pub const fn new(index: u64, generation: u64) -> Option<Self> {
        if index == 0 || generation == 0 {
            None
        } else {
            Some(Self { index, generation })
        }
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Readiness version sampled before the object predicate is checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectWaitSnapshot {
    key: ObjectWaitKey,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectWaitError {
    Busy,
    Stale,
    Changed,
    Occupied,
    Exhausted,
}

/// Exact work receipt: each visit is to a member of this object's queue;
/// unrelated records, objects and futex buckets are never visited.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObjectWakeReport {
    pub visited: u32,
    pub queued: u32,
    /// A home slot stopped or address-space admission prevented placement.
    /// The registration stays live; its mutation must be settled by the
    /// boundary adapter, never silently treated as a delivered wake.
    pub deferred: u32,
}

/// Host notification receipt. Every claimed waiter is either queued through
/// the host placement boundary or transferred to the caller for handback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostObjectWakeReport {
    pub visited: u32,
    pub queued: u32,
    pub handed: u32,
}

#[repr(C)]
pub(super) struct ObjectQueue {
    lock: AtomicU32,
    head: AtomicU32,
    tail: AtomicU32,
    generation: AtomicU64,
    epoch: AtomicU64,
}

#[repr(C)]
pub(super) struct ObjectRecord {
    queue: AtomicU32,
    prev: AtomicU32,
    next: AtomicU32,
    generation: AtomicU64,
    operation: AtomicU64,
    operation_generation: AtomicU64,
}

/// The queue guard also authenticates its zone, index and incarnation. It
/// cannot be used with a different zone's queue by accident.
pub struct ObjectWaitGuard<'a> {
    zone: &'a ZoneTables,
    key: ObjectWaitKey,
}

impl Drop for ObjectWaitGuard<'_> {
    fn drop(&mut self) {
        self.queue().lock.store(0, Ordering::Release);
    }
}

impl ObjectWaitGuard<'_> {
    fn queue(&self) -> &ObjectQueue {
        &self.zone.object_waits[self.key.index as usize]
    }

    pub fn snapshot(&self) -> ObjectWaitSnapshot {
        ObjectWaitSnapshot {
            key: self.key,
            epoch: self.queue().epoch.load(Ordering::Relaxed),
        }
    }

    /// Host-side readiness publication, under object state and this queue.
    /// Uses the same host placement transaction as host futex wakes, without
    /// pretending the caller is a running guest slot. A waiter resumes its
    /// saved operation; readiness never completes a syscall with zero bytes.
    ///
    /// Callbacks only collect ownership/effects into preallocated storage.
    /// Release this guard and object state before handback or reschedule
    /// delivery. If no guest slot admits a waiter, `handed` owns its exact
    /// detached record and pending operation, which must be resumed or settled.
    pub fn notify_object_host(
        &self,
        handed: &mut impl FnMut(RecordRef),
        placed: &mut impl FnMut(HostPlacement),
    ) -> Result<HostObjectWakeReport, ObjectWaitError> {
        let epoch = self.queue().epoch.load(Ordering::Relaxed);
        let next_epoch = epoch.checked_add(1).ok_or(ObjectWaitError::Exhausted)?;
        self.queue().epoch.store(next_epoch, Ordering::Relaxed);
        let mut report = HostObjectWakeReport::default();
        let mut cursor = self.queue().head.load(Ordering::Relaxed);
        while let Some(record) = RecordId::from_raw(cursor) {
            let rec = self.zone.record(record);
            cursor = rec.object.next.load(Ordering::Relaxed);
            report.visited += 1;
            let from @ Claim::Parked { .. } = rec.claim() else {
                continue;
            };
            match self.zone.place_in_guest(record, from, None, |rec| {
                self.unlink(record);
                self.zone.mark_woken(rec, 0);
            }) {
                Placement::Placed(placement) => {
                    report.queued += 1;
                    placed(placement);
                }
                Placement::NoSlot => {
                    if let Some(transfer) = self
                        .zone
                        .begin_host_transfer(self.zone.record_ref(record), from)
                    {
                        self.unlink(record);
                        self.zone.mark_woken(rec, 0);
                        self.zone
                            .counters
                            .host_wakes
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(ready) = transfer.publish() {
                            report.handed += 1;
                            handed(ready);
                        }
                    }
                }
                Placement::Lost => {}
            }
        }
        Ok(report)
    }

    /// Enroll and publish one owned record atomically with respect to object
    /// notifications. On refusal ownership of `operation` stays with caller.
    /// Caller owns the record/context and has released every object lock.
    pub fn park(
        &self,
        snapshot: ObjectWaitSnapshot,
        record: RecordId,
        operation: OperationToken,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        if snapshot.key != self.key {
            return Err((ObjectWaitError::Stale, operation));
        }
        if snapshot.epoch != self.queue().epoch.load(Ordering::Relaxed) {
            return Err((ObjectWaitError::Changed, operation));
        }
        let rec = self.zone.record(record);
        if rec.has_object_operation()
            || rec.object.queue.load(Ordering::Relaxed) != 0
            || rec.entry_count() != 0
            || !matches!(rec.claim(), Claim::Free | Claim::OnCpu { .. })
        {
            return Err((ObjectWaitError::Occupied, operation));
        }
        rec.object
            .operation_generation
            .store(operation.generation, Ordering::Relaxed);
        rec.object
            .operation
            .store(operation.index, Ordering::Release);
        rec.object
            .generation
            .store(self.key.generation, Ordering::Relaxed);
        let tail = self.queue().tail.load(Ordering::Relaxed);
        rec.object.prev.store(tail, Ordering::Relaxed);
        rec.object.next.store(NIL, Ordering::Relaxed);
        rec.object.queue.store(self.key.index, Ordering::Release);
        if let Some(tail) = RecordId::from_raw(tail) {
            self.zone
                .record(tail)
                .object
                .next
                .store(record.raw(), Ordering::Relaxed);
        } else {
            self.queue().head.store(record.raw(), Ordering::Relaxed);
        }
        self.queue().tail.store(record.raw(), Ordering::Relaxed);
        self.zone.set_deadline(record, 0);
        self.zone.publish_park(record, self.zone.next_seq(record));
        Ok(())
    }

    fn unlink(&self, record: RecordId) {
        let rec = self.zone.record(record);
        let prev = rec.object.prev.load(Ordering::Relaxed);
        let next = rec.object.next.load(Ordering::Relaxed);
        if let Some(prev) = RecordId::from_raw(prev) {
            self.zone
                .record(prev)
                .object
                .next
                .store(next, Ordering::Relaxed);
        } else {
            self.queue().head.store(next, Ordering::Relaxed);
        }
        if let Some(next) = RecordId::from_raw(next) {
            self.zone
                .record(next)
                .object
                .prev
                .store(prev, Ordering::Relaxed);
        } else {
            self.queue().tail.store(prev, Ordering::Relaxed);
        }
        rec.object.queue.store(0, Ordering::Release);
    }

    /// Publish a readiness change, even with no waiters. Called by a running
    /// guest slot while holding object state (host venue integration must use
    /// its own placement boundary, never impersonate a running guest slot).
    /// Release this guard AND object state before delivering the returned SGIs.
    pub fn notify_object(
        &self,
        waker: SlotId,
        effects: &mut WakeEffects,
    ) -> Result<ObjectWakeReport, ObjectWaitError> {
        let epoch = self.queue().epoch.load(Ordering::Relaxed);
        let next_epoch = epoch.checked_add(1).ok_or(ObjectWaitError::Exhausted)?;
        self.queue().epoch.store(next_epoch, Ordering::Relaxed);
        let mut report = ObjectWakeReport::default();
        let mut cursor = self.queue().head.load(Ordering::Relaxed);
        while let Some(record) = RecordId::from_raw(cursor) {
            let rec = self.zone.record(record);
            cursor = rec.object.next.load(Ordering::Relaxed);
            report.visited += 1;
            if let Claim::Parked { seq } = rec.claim() {
                // Readiness is already committed by the object. Even when no
                // slot admits this MM now, queue the owned operation on the
                // waker and request host handback via WakeEffects::misplaced.
                // A generic pending-host flag alone cannot find this waiter.
                if self
                    .zone
                    .claim_for_el1(record, seq, 0, waker, effects, || self.unlink(record))
                {
                    report.queued += 1;
                }
            }
            // A host claimant removes its own registration after dropping
            // the claim CAS. Never touch an operation that it now owns.
        }
        Ok(report)
    }
}

/// Read-only view of one record's object-wait registration (census only;
/// each word is read once, values may be torn across fields).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectWaitCensus {
    /// The queue index it is linked on (0: not linked).
    pub queue: u32,
    /// The object incarnation it enrolled for.
    pub generation: u64,
    /// The owned operation token's index and generation (0: none).
    pub operation: u64,
    pub operation_generation: u64,
}

/// Read-only view of one object wait queue (census only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectQueueCensus {
    pub generation: u64,
    pub epoch: u64,
    pub head: u32,
    pub tail: u32,
    /// Records reached from `head` (bounded by the record count).
    pub waiters: u32,
    pub locked: bool,
}

impl ZoneRecord {
    /// This record's object-wait registration, if it has one or owns a
    /// pending object operation.
    pub fn object_wait_census(&self) -> Option<ObjectWaitCensus> {
        let census = ObjectWaitCensus {
            queue: self.object.queue.load(Ordering::Acquire),
            generation: self.object.generation.load(Ordering::Relaxed),
            operation: self.object.operation.load(Ordering::Acquire),
            operation_generation: self.object.operation_generation.load(Ordering::Relaxed),
        };
        (census.queue != 0 || census.operation != 0).then_some(census)
    }

    pub fn has_object_operation(&self) -> bool {
        self.object.operation.load(Ordering::Acquire) != 0
    }

    /// Transfer a pending operation to its adapter exactly once.
    ///
    /// # Safety
    /// Caller exclusively owns the record's context under the claim protocol,
    /// and all registrations have been unlinked. In guest it must have loaded
    /// the record's exact MM and task identity before touching user memory.
    pub unsafe fn take_object_operation(&self) -> Option<OperationToken> {
        let index = self.object.operation.swap(0, Ordering::AcqRel);
        OperationToken::new(
            index,
            self.object.operation_generation.load(Ordering::Relaxed),
        )
    }
}

impl ZoneTables {
    fn lock_object_index(
        &self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
    ) -> Option<ObjectWaitGuard<'_>> {
        let queue = &self.object_waits[key.index as usize];
        let mut attempt = 0;
        loop {
            if queue
                .lock
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(ObjectWaitGuard { zone: self, key });
            }
            if !wait.wait(attempt) {
                return None;
            }
            attempt = attempt.saturating_add(1);
        }
    }

    /// Admission only: bind a previously unused index or advance a quiescent
    /// index to a strictly newer object generation. T1 must retain the old
    /// object while any operation pin exists, even if this queue is empty.
    pub fn bind_object_wait(
        &self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
    ) -> Result<(), ObjectWaitError> {
        let guard = self
            .lock_object_index(key, wait)
            .ok_or(ObjectWaitError::Busy)?;
        let queue = guard.queue();
        if queue.generation.load(Ordering::Relaxed) >= key.generation {
            return Err(ObjectWaitError::Stale);
        }
        if queue.head.load(Ordering::Relaxed) != NIL {
            return Err(ObjectWaitError::Occupied);
        }
        queue.generation.store(key.generation, Ordering::Relaxed);
        queue.epoch.store(1, Ordering::Relaxed);
        Ok(())
    }

    /// Lock-free census of queue `index` (never takes its lock).
    pub fn object_queue_census(&self, index: u32) -> Option<ObjectQueueCensus> {
        let queue = self.object_waits.get(index as usize)?;
        let head = queue.head.load(Ordering::Acquire);
        let mut waiters = 0u32;
        let mut cursor = head;
        while let Some(record) = RecordId::from_raw(cursor) {
            if waiters as usize >= ZONE_RECORDS {
                break;
            }
            waiters += 1;
            cursor = self.record(record).object.next.load(Ordering::Relaxed);
        }
        Some(ObjectQueueCensus {
            generation: queue.generation.load(Ordering::Relaxed),
            epoch: queue.epoch.load(Ordering::Relaxed),
            head,
            tail: queue.tail.load(Ordering::Relaxed),
            waiters,
            locked: queue.lock.load(Ordering::Relaxed) != 0,
        })
    }

    pub fn object_wait(
        &self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
    ) -> Result<ObjectWaitGuard<'_>, ObjectWaitError> {
        let guard = self
            .lock_object_index(key, wait)
            .ok_or(ObjectWaitError::Busy)?;
        if guard.queue().generation.load(Ordering::Relaxed) != key.generation {
            return Err(ObjectWaitError::Stale);
        }
        Ok(guard)
    }

    /// The claim owner removes at most one object registration, by direct
    /// index and intrusive links, before consuming the operation token.
    pub(super) fn unlink_object(&self, record: RecordId, wait: &impl LockWait) {
        let rec = self.record(record);
        loop {
            let index = rec.object.queue.load(Ordering::Acquire);
            if index == 0 {
                return;
            }
            let Some(key) =
                ObjectWaitKey::new(index, rec.object.generation.load(Ordering::Relaxed))
            else {
                return;
            };
            let Ok(guard) = self.object_wait(key, wait) else {
                continue;
            };
            if rec.object.queue.load(Ordering::Acquire) == index {
                guard.unlink(record);
            }
            return;
        }
    }
}

#[cfg(test)]
mod host_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::{boxed::Box, sync::Barrier, vec::Vec};

    const SLOT: SlotId = SlotId::new(3);
    const MM: u64 = 7;

    fn fixture(running: bool) -> Box<ZoneTables> {
        let zone = unsafe {
            // SAFETY: the shared zone ABI's empty state is all-zero.
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!ptr.is_null());
            Box::from_raw(ptr.cast::<ZoneTables>())
        };
        if running {
            zone.drive(SLOT, u64::from(SLOT.raw()) + 1);
            zone.publish_slot(SLOT, MM, None, 0);
            assert!(zone.occupancy.replace(ExecutionSlot::zone(SLOT), 0, MM));
            zone.enter_guest(SLOT);
        }
        zone.bind_object_wait(key(1), &SpinForever).unwrap();
        zone.bind_object_wait(key(2), &SpinForever).unwrap();
        zone
    }

    fn key(index: u32) -> ObjectWaitKey {
        ObjectWaitKey::new(index, 1).unwrap()
    }

    fn allocate(zone: &ZoneTables, tid: u64) -> RecordId {
        zone.alloc_record(ThreadIdentity {
            tid,
            serial: tid,
            mm: MM,
            file_table: 99,
            generation: 1,
            affinity: 0,
        })
        .unwrap()
    }

    fn park(zone: &ZoneTables, index: u32, tid: u64) -> RecordId {
        let record = allocate(zone, tid);
        let guard = zone.object_wait(key(index), &SpinForever).unwrap();
        guard
            .park(
                guard.snapshot(),
                record,
                OperationToken::new(tid, 1).unwrap(),
            )
            .unwrap();
        record
    }

    fn notify(zone: &ZoneTables, index: u32) -> (HostObjectWakeReport, Vec<RecordId>) {
        let mut handed = Vec::with_capacity(64);
        let guard = zone.object_wait(key(index), &SpinForever).unwrap();
        let report = guard
            .notify_object_host(&mut |r| handed.push(r.id), &mut |_| {})
            .unwrap();
        (report, handed)
    }

    #[test]
    fn el1_ipc_wait_unplaceable_wake_keeps_owned_operation_runnable() {
        let zone = fixture(true);
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 202,
                serial: 202,
                mm: MM + 1, // No open address space or other admissible slot.
                file_table: 202,
                generation: 1,
                affinity: 0,
            })
            .unwrap();
        let guard = zone.object_wait(key(1), &SpinForever).unwrap();
        guard
            .park(
                guard.snapshot(),
                record,
                OperationToken::new(202, 1).unwrap(),
            )
            .unwrap();
        assert_eq!(zone.placement(record, SLOT), None);
        let mut effects = WakeEffects::default();
        let report = guard.notify_object(SLOT, &mut effects).unwrap();
        assert_eq!(report.queued, 1, "readiness must retain runnable ownership");
        assert_eq!(report.deferred, 0);
        assert!(effects.queued_own && effects.misplaced);
        assert!(matches!(zone.record(record).claim(), Claim::Queued { slot, .. } if slot == SLOT));
        assert!(zone.record(record).has_object_operation());
        assert_eq!(zone.record(record).object.queue.load(Ordering::Acquire), 0);
    }

    #[test]
    fn el1_ipc_wait_host_wake_scales_and_preserves_operation() {
        for n in [1, 8, 64] {
            let zone = fixture(true);
            for tid in 1..=128 {
                park(&zone, 2, tid);
            }
            for tid in 129..129 + n {
                park(&zone, 1, tid);
            }
            let (report, handed) = notify(&zone, 1);
            assert_eq!(report.visited, n as u32);
            assert_eq!(report.queued, n as u32);
            assert_eq!(report.handed, 0);
            assert!(handed.is_empty());
            assert_eq!(
                zone.counters
                    .host_service_placements
                    .load(Ordering::Relaxed),
                0
            );
            for _ in 0..n {
                let switched = zone.switch_in_full(SLOT).unwrap();
                assert_eq!(switched.result, None);
                let rec = zone.record(switched.record);
                // SAFETY: the test owns the switched-in context.
                assert_eq!(
                    unsafe { rec.take_object_operation() }.unwrap().index(),
                    rec.identity().tid
                );
                zone.release_current(SLOT, switched.record);
            }
            assert_eq!(notify(&zone, 1).0.visited, 0);
        }
    }

    #[test]
    fn el1_ipc_wait_host_wake_closes_concurrent_enroll_gap() {
        let zone = fixture(true);
        let snapshot = zone.object_wait(key(1), &SpinForever).unwrap().snapshot();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                notify(&zone, 1);
                barrier.wait();
            });
            barrier.wait();
            let record = allocate(&zone, 1);
            let guard = zone.object_wait(key(1), &SpinForever).unwrap();
            let (error, operation) = guard
                .park(snapshot, record, OperationToken::new(1, 1).unwrap())
                .unwrap_err();
            assert_eq!(error, ObjectWaitError::Changed);
            guard.park(guard.snapshot(), record, operation).unwrap();
        });
        assert_eq!(notify(&zone, 1).0.queued, 1);
    }

    #[test]
    fn el1_ipc_wait_host_wake_races_signal_control_once() {
        for kind in [Handback::Signal, Handback::Control, Handback::Cancelled] {
            let zone = fixture(true);
            let records: Vec<_> = (1..=64).map(|tid| park(&zone, 1, tid)).collect();
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    notify(&zone, 1);
                });
                barrier.wait();
                for record in records {
                    assert_eq!(
                        zone.claim_for_host(zone.record_ref(record), None, kind, &SpinForever),
                        HostClaim::Claimed
                    );
                    let rec = zone.record(record);
                    assert_eq!(rec.handback(), Some(kind));
                    // SAFETY: host claim detached all wait and run registrations.
                    unsafe {
                        assert_eq!(
                            rec.take_object_operation().unwrap().index(),
                            rec.identity().tid
                        );
                        assert!(rec.take_object_operation().is_none());
                    }
                    zone.free_record(record);
                }
            });
            assert_eq!(notify(&zone, 1).0.visited, 0);
            assert_eq!(zone.slot(SLOT).queued(), 0);
        }
    }

    #[test]
    fn el1_ipc_wait_host_wake_without_slot_hands_back_exact_operation() {
        let zone = fixture(false);
        let record = park(&zone, 1, 1);
        let (report, handed) = notify(&zone, 1);
        assert_eq!(report.handed, 1);
        assert_eq!(report.queued, 0);
        assert_eq!(handed, [record]);
        let rec = zone.record(record);
        assert!(matches!(rec.claim(), Claim::Host { .. }));
        assert_eq!(rec.handback(), Some(Handback::Resumed));
        // SAFETY: the caller owns the detached host handback.
        assert!(unsafe { rec.take_object_operation() }.is_some());
        assert_eq!(notify(&zone, 1).0.visited, 0);
    }
}
