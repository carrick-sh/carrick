//! Neutral wait records and enrollment authority.

use crate::ReservationMm;
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, OperationToken, OwnedObjectWakeEffects,
};
use carrick_sched_core::spaces::notification::{
    SpaceAccess, SpaceNotificationLease, SpaceWaitCause,
};
use carrick_sched_core::{RecordId, SlotId, ZoneTables};

/// Adapter-selected guest re-entry PC, distinct from a syscall return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationResumePc(u64);

impl OperationResumePc {
    pub const fn new(pc: u64) -> Option<Self> {
        if pc == 0 || !pc.is_multiple_of(4) {
            None
        } else {
            Some(Self(pc))
        }
    }

    pub const fn from_raw(pc: u64) -> Option<Self> {
        if pc == 0 { None } else { Some(Self(pc)) }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A published park. Consuming this ticket switches only after all object
/// and queue guards have been released by the caller.
#[must_use = "a published park must be followed by scheduling another thread"]
pub struct ObjectParked<'a> {
    zone: &'a ZoneTables,
    slot: SlotId,
}

impl<'a> ObjectParked<'a> {
    pub const fn new(zone: &'a ZoneTables, slot: SlotId) -> Self {
        Self { zone, slot }
    }

    pub const fn zone(&self) -> &'a ZoneTables {
        self.zone
    }

    pub const fn slot(&self) -> SlotId {
        self.slot
    }

    pub fn matches(&self, zone: &ZoneTables, slot: SlotId) -> bool {
        self.slot == slot && core::ptr::eq(self.zone, zone)
    }
}

/// Enrollment authority joined from one retained carrier region and its exact
/// live MM source. It cannot be paired with another zone or recycled MM.
pub struct PortalWaitEnrollment<'a> {
    source: SpaceNotificationLease<'a>,
    cause: SpaceWaitCause,
    revision: u64,
}

impl<'a> PortalWaitEnrollment<'a> {
    pub const fn new(
        source: SpaceNotificationLease<'a>,
        cause: SpaceWaitCause,
        revision: u64,
    ) -> Self {
        Self {
            source,
            cause,
            revision,
        }
    }

    pub const fn cause(&self) -> SpaceWaitCause {
        self.cause
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn park_host(
        self,
        record: RecordId,
        operation: OperationToken,
        completion: &dyn Fn(OwnedObjectWakeEffects<'_>),
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        self.source.reserve(self.cause).park_host_rechecked(
            self.source.observed_revision(self.cause, self.revision),
            record,
            operation,
            completion,
            || {
                self.source.is_live()
                    && (self.cause != SpaceWaitCause::Editor || self.source.editor_held())
            },
        )
    }
}

/// Outcome of coordinating a prepared reservation edit wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditWaitOutcome<T> {
    /// No conflicting prepared edit overlaps the requested range; proceed with edit.
    NoConflict,
    /// Resumed operation token does not match the active root wait key generation.
    StaleToken,
    /// Wait was enrolled and the thread was parked.
    Parked(T),
    /// Root admission or lock failed, or park was refused.
    Refused,
}

/// Request parameters for parking an object wait record.
#[derive(Debug)]
pub struct ObjectParkRequest {
    pub key: ObjectWaitKey,
    pub snapshot: ObjectWaitSnapshot,
    pub operation: OperationToken,
    pub deadline: Option<u64>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use carrick_sched_core::spaces::notification::SpaceReleaseVenue;
    use carrick_sched_core::{BoundedSpin, ThreadIdentity, Waker};
    use core::{alloc::Layout, num::NonZeroU64};

    fn deliver(_: &ZoneTables, _: Waker, effects: OwnedObjectWakeEffects<'_>) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }

    #[test]
    fn editor_wait_refuses_after_release_at_same_observed_revision() {
        let ptr = unsafe { alloc::alloc::alloc_zeroed(Layout::new::<ZoneTables>()) };
        assert!(!ptr.is_null());
        let zone = unsafe { alloc::boxed::Box::from_raw(ptr.cast::<ZoneTables>()) };
        let index = zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        entry
            .admit_notifications(NonZeroU64::new(1).unwrap(), &BoundedSpin(0), &complete)
            .unwrap();
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver,
        });
        access.open(index);
        let editor = access
            .try_begin_edit(index, 77, NonZeroU64::new(1).unwrap())
            .unwrap();
        drop(editor);
        let source = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let revision = source.observe(SpaceWaitCause::Editor).revision();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 77,
                serial: 1,
                mm: 77,
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let operation = OperationToken::new(77, 1).unwrap();
        let enrollment = PortalWaitEnrollment::new(source, SpaceWaitCause::Editor, revision);
        assert!(
            matches!(
                enrollment.park_host(record, operation, &complete),
                Err((ObjectWaitError::Changed, _))
            ),
            "the revision can advance while the editor is held; a later park must recheck the editor"
        );
    }
}

impl ObjectParkRequest {
    pub const fn new(
        key: ObjectWaitKey,
        snapshot: ObjectWaitSnapshot,
        operation: OperationToken,
        deadline: Option<u64>,
    ) -> Self {
        Self {
            key,
            snapshot,
            operation,
            deadline,
        }
    }
}

/// Target venue for coordinating an edit wait against the reservation table.
#[derive(Clone, Copy)]
pub struct EditWaitTarget<'a> {
    pub space_access: SpaceAccess<'a>,
    pub space_index: usize,
    pub mm: ReservationMm,
    pub slot: SlotId,
}

impl<'a> EditWaitTarget<'a> {
    pub const fn new(
        space_access: SpaceAccess<'a>,
        space_index: usize,
        mm: ReservationMm,
        slot: SlotId,
    ) -> Self {
        Self {
            space_access,
            space_index,
            mm,
            slot,
        }
    }
}
