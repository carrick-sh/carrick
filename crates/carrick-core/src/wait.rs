//! Neutral wait mechanisms: queue observation, one-winner wake/cancel,
//! release-before-enrollment edit coordination, and owned park continuations.

pub use carrick_core_abi::wait::*;
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport, OperationToken,
    OwnedObjectWakeEffects,
};
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{
    BoundedSpin, Claim, RecordId, SlotId, ThreadIdentity, WakeEffects, Waker, ZoneTables,
};
use core::sync::atomic::Ordering;

/// Snapshot before checking the object predicate.
pub fn observe_object(
    zone: &ZoneTables,
    slot: SlotId,
    key: ObjectWaitKey,
    completion: &dyn Fn(OwnedObjectWakeEffects<'_>),
) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
    let _ = slot;
    let guard = if zone.completion_enabled(key) {
        zone.object_wait_with_completion(key, &BoundedSpin(1024), completion)?
    } else {
        zone.object_wait(key, &BoundedSpin(1024))?
    };
    Ok(guard.snapshot())
}

/// Whether a park of the running thread on `slot` may carry a deadline:
/// the slot's timer has no other live owner.
pub fn may_time_park(zone: &ZoneTables, slot: SlotId) -> bool {
    zone.timer_free(slot)
}

/// Whether the switched-in record's last object park ended at its deadline.
pub fn object_wait_expired(zone: &ZoneTables, slot: SlotId) -> bool {
    zone.slot(slot)
        .current()
        .is_some_and(|record| zone.record(record).object_wait_expired())
}

/// Save and park a pending operation record without switching while caller locks
/// might still be live. On Changed the caller rechecks the predicate.
pub fn park_object_record<'a, S>(
    zone: &'a ZoneTables,
    slot: SlotId,
    request: ObjectParkRequest,
    spins: u32,
    completion: &dyn Fn(OwnedObjectWakeEffects<'_>),
    save_context: S,
) -> Result<ObjectParked<'a>, (ObjectWaitError, OperationToken)>
where
    S: FnOnce() -> Result<(RecordId, bool), ObjectWaitError>,
{
    if request.deadline.is_some() && !may_time_park(zone, slot) {
        return Err((ObjectWaitError::Occupied, request.operation));
    }
    let result = if zone.completion_enabled(request.key) {
        zone.object_wait_with_completion(request.key, &BoundedSpin(spins), completion)
    } else {
        zone.object_wait(request.key, &BoundedSpin(spins))
    };
    let guard = match result {
        Ok(guard) => guard,
        Err(error) => return Err((error, request.operation)),
    };
    let (record, fresh) = match save_context() {
        Ok(pair) => pair,
        Err(err) => {
            drop(guard);
            return Err((err, request.operation));
        }
    };
    let seq = zone.next_seq(record);
    if request.deadline.is_some() && zone.arm_timer(slot, record, seq).is_err() {
        drop(guard);
        if fresh {
            zone.discard_unpublished(slot, record);
        }
        return Err((ObjectWaitError::Occupied, request.operation));
    }
    let deadline_ticks = request.deadline.unwrap_or_default();
    if let Err(error) =
        guard.park_until(request.snapshot, record, request.operation, deadline_ticks)
    {
        drop(guard);
        if fresh {
            zone.discard_unpublished(slot, record);
        }
        return Err(error);
    }
    drop(guard);
    zone.clear_current(slot);
    zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
    Ok(ObjectParked::new(zone, slot))
}

/// Authenticate exact record ownership, identity and address space, then take the operation token.
pub fn take_object_operation(
    zone: &ZoneTables,
    slot: SlotId,
    expected: ThreadIdentity,
) -> Result<Option<OperationToken>, ObjectWaitError> {
    let Some(record): Option<RecordId> = zone.slot(slot).current() else {
        return Ok(None);
    };
    let rec = zone.record(record);
    let id = rec.identity();
    if !matches!(rec.claim(), Claim::OnCpu { slot: s, .. } if s == slot)
        || id != expected
        || zone.installed_space(slot) != id.mm
    {
        return Err(ObjectWaitError::Stale);
    }
    // SAFETY: this slot owns the OnCpu record, load restored its exact
    // MM/task, and the waker detached its registration before queueing.
    Ok(unsafe { rec.take_object_operation() })
}

/// Notify under the caller's object lock.
pub fn notify_object(
    zone: &ZoneTables,
    slot: SlotId,
    key: ObjectWaitKey,
    spins: u32,
) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
    let guard = zone.object_wait(key, &BoundedSpin(spins))?;
    let mut effects = WakeEffects::default();
    let report = guard.notify_object(slot, &mut effects)?;
    Ok((report, effects))
}

/// Bind space release notification authority for zone and execution slot.
pub fn space_access<'a>(
    zone: &'a ZoneTables,
    slot: SlotId,
    deliver: fn(&ZoneTables, Waker, OwnedObjectWakeEffects<'_>),
) -> SpaceAccess<'a> {
    SpaceAccess::notified(SpaceReleaseVenue {
        zone,
        waker: Waker::El1 { slot },
        deliver,
    })
}

/// Coordinate a conflicting reservation edit wait: validates active wait key,
/// detects overlap against prepared proposals, releases root lock before enrollment,
/// and retries if the predicate changed before the park was published.
pub fn coordinate_prepared_edit_wait<P, G, O, C, F, T>(
    table: &crate::mm::reservation::SharedReservations<P, G>,
    target: EditWaitTarget<'_>,
    resumed: Option<OperationToken>,
    mut observe: O,
    mut check_conflict: C,
    mut park: F,
) -> EditWaitOutcome<T>
where
    P: carrick_core_abi::ReservationPolicy,
    G: carrick_core_abi::ReservationGeometry,
    O: FnMut(ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError>,
    C: FnMut(&mut crate::mm::reservation::Reservations<'_, P, G>) -> Option<bool>,
    F: FnMut(
        ObjectWaitKey,
        ObjectWaitSnapshot,
        OperationToken,
    ) -> Result<T, (ObjectWaitError, OperationToken)>,
{
    loop {
        let Ok(mut root) = table.lock_in(
            target.space_access,
            target.space_index,
            target.mm,
            target.slot.raw() as u32,
        ) else {
            return EditWaitOutcome::Refused;
        };
        let Some(key) = root.prepared_wait_key() else {
            return EditWaitOutcome::Refused;
        };
        if resumed.as_ref().is_some_and(|token| {
            token.index() != u64::from(key.index()) || token.generation() != key.generation()
        }) {
            return EditWaitOutcome::StaleToken;
        }

        // Source custody is established at root admission. Contention here
        // must never try to bind a queue while retaining this root guard.
        let snapshot = match observe(key) {
            Ok(s) => s,
            Err(_) => return EditWaitOutcome::Refused,
        };
        let conflict = match check_conflict(&mut root) {
            Some(c) => c,
            None => return EditWaitOutcome::Refused,
        };
        drop(root);
        if !conflict {
            return EditWaitOutcome::NoConflict;
        }
        let Some(token) = OperationToken::new(u64::from(key.index()), key.generation()) else {
            return EditWaitOutcome::Refused;
        };
        match park(key, snapshot, token) {
            Ok(parked) => return EditWaitOutcome::Parked(parked),
            Err((ObjectWaitError::Changed, _)) => continue,
            Err(_) => return EditWaitOutcome::Refused,
        }
    }
}
