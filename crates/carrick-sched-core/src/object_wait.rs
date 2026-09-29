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
                if self.zone.placement(record, waker).is_none() {
                    report.deferred += 1;
                    continue;
                }
                if self
                    .zone
                    .claim_for_el1_with(record, seq, 0, waker, effects, || self.unlink(record))
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

impl ZoneRecord {
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
