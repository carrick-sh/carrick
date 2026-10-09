//! Neutral wait records and enrollment authority.

use crate::{EntryContext, ReservationMm};
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, OperationToken, OwnedObjectWakeEffects,
};
use carrick_sched_core::spaces::notification::{
    SpaceAccess, SpaceNotificationLease, SpaceWaitCause,
};
use carrick_sched_core::{RecordId, SlotId, ThreadCtx, ZoneTables};

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
pub struct ObjectParked<'a, C: crate::EntryContext = ThreadCtx> {
    zone: &'a ZoneTables<C>,
    slot: SlotId,
    receipt: Option<crate::EntryHandoffReceipt<C>>,
}

impl<'a, C: crate::EntryContext> ObjectParked<'a, C> {
    pub const fn new(
        zone: &'a ZoneTables<C>,
        slot: SlotId,
        receipt: Option<crate::EntryHandoffReceipt<C>>,
    ) -> Self {
        Self {
            zone,
            slot,
            receipt,
        }
    }

    pub fn take_receipt(&mut self) -> Option<crate::EntryHandoffReceipt<C>> {
        self.receipt.take()
    }

    pub const fn zone(&self) -> &'a ZoneTables<C> {
        self.zone
    }

    pub const fn slot(&self) -> SlotId {
        self.slot
    }

    pub fn matches(&self, zone: &ZoneTables<C>, slot: SlotId) -> bool {
        self.slot == slot && core::ptr::eq(self.zone, zone)
    }
}

/// Enrollment authority joined from one retained carrier region and its exact
/// live MM source. It cannot be paired with another zone or recycled MM.
pub struct PortalWaitEnrollment<'a, C: EntryContext = ThreadCtx> {
    source: SpaceNotificationLease<'a, C>,
    cause: SpaceWaitCause,
    revision: u64,
}

impl<'a, C: EntryContext> PortalWaitEnrollment<'a, C> {
    pub const fn new(
        source: SpaceNotificationLease<'a, C>,
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
        completion: &dyn Fn(OwnedObjectWakeEffects<'_, C>),
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        self.source.reserve(self.cause).park_host_rechecked(
            self.source.observed_revision(self.cause, self.revision),
            record,
            operation,
            completion,
            || self.source.is_live(),
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
pub struct EditWaitTarget<'a, C: crate::EntryContext = ThreadCtx> {
    pub space_access: SpaceAccess<'a, C>,
    pub space_index: usize,
    pub mm: ReservationMm,
    pub slot: SlotId,
}

impl<'a, C: crate::EntryContext> EditWaitTarget<'a, C> {
    pub const fn new(
        space_access: SpaceAccess<'a, C>,
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
