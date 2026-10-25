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

    /// Current revision of the exact notification source named by this
    /// enrollment. Consumers use this to distinguish completed producer work
    /// from a current receipt that has no live producer.
    pub fn current_revision(&self) -> u64 {
        self.source.observe(self.cause).revision()
    }

    /// Authenticate a ring-owned continuation against its retained birth MM.
    pub fn for_owner(
        zone: &'a ZoneTables<C>,
        expected: crate::El1MmHandle,
        receipt: crate::PortalOwnerWait,
    ) -> Result<Self, ObjectWaitError> {
        if receipt.handle() != expected {
            return Err(ObjectWaitError::Stale);
        }
        use crate::PortalWaitCause;
        let cause = match receipt.cause() {
            PortalWaitCause::Editor => SpaceWaitCause::Editor,
            PortalWaitCause::Reservations => SpaceWaitCause::Reservations,
            PortalWaitCause::PendingEdit => SpaceWaitCause::PendingEdit,
            PortalWaitCause::Gate => SpaceWaitCause::Gate,
            PortalWaitCause::Metadata => SpaceWaitCause::Metadata,
            PortalWaitCause::ReservationPool => return Err(ObjectWaitError::Stale),
        };
        let entry = zone
            .space_entry(
                core::num::NonZeroU64::new(expected.mm().raw()).ok_or(ObjectWaitError::Stale)?,
            )
            .ok_or(ObjectWaitError::Stale)?;
        Ok(Self::new(
            entry.notifications(expected.incarnation())?,
            cause,
            receipt.revision(),
        ))
    }
    pub fn owner_request(&self, operation: OperationToken) -> ObjectParkRequest {
        let mut request = ObjectParkRequest::owner(
            self.source.key(self.cause),
            operation,
            carrick_sched_core::object_wait::OwnerEntry::Exception,
        );
        request.snapshot = Some(self.source.observed_revision(self.cause, self.revision));
        request
    }
    pub fn is_live(&self) -> bool {
        self.source.is_live()
    }
    pub fn key(&self) -> ObjectWaitKey {
        self.source.key(self.cause)
    }

    /// Link the host operation, then recheck the exact resource predicate as
    /// well as the source lifetime and producer revision. A receipt identifies
    /// the release stream; it does not prove that a producer still holds the
    /// resource at enrollment time.
    pub fn park_host_rechecked(
        self,
        record: RecordId,
        operation: OperationToken,
        completion: &dyn Fn(OwnedObjectWakeEffects<'_, C>),
        still_blocked: impl FnOnce() -> bool,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        self.source.reserve(self.cause).park_host_rechecked(
            self.source.observed_revision(self.cause, self.revision),
            record,
            operation,
            completion,
            || self.source.is_live() && still_blocked(),
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
    snapshot: Option<ObjectWaitSnapshot>,
    owner_entry: Option<carrick_sched_core::object_wait::OwnerEntry>,
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
            snapshot: Some(snapshot),
            owner_entry: None,
            operation,
            deadline,
        }
    }
    /// The owner checks readiness from save_context while the object guard is
    /// held. The request and its native entry remain one scheduler operation.
    pub const fn owner(
        key: ObjectWaitKey,
        operation: OperationToken,
        entry: carrick_sched_core::object_wait::OwnerEntry,
    ) -> Self {
        Self {
            key,
            snapshot: None,
            owner_entry: Some(entry),
            operation,
            deadline: None,
        }
    }
    pub const fn observed(&self) -> Option<ObjectWaitSnapshot> {
        self.snapshot
    }
    pub const fn owner_entry(&self) -> Option<carrick_sched_core::object_wait::OwnerEntry> {
        self.owner_entry
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
