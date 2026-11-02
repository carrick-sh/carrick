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

/// Authenticated carrier/zone pairing retained at an execution entry boundary.
/// A safe caller cannot relabel a ticket using an unrelated carrier handle.
pub struct PortalWaitAuthority<'z, C: Copy + Send + Sync + zerocopy::FromZeros = ThreadCtx> {
    zone: &'z ZoneTables<C>,
    owner: crate::El1MmHandle,
}
impl<'z, C: Copy + Send + Sync + zerocopy::FromZeros> PortalWaitAuthority<'z, C> {
    /// # Safety
    /// The retained carrier region must own `zone` and match `owner.carrier()`.
    /// The caller authenticates that pairing before entering this boundary.
    pub unsafe fn from_retained_zone(zone: &'z ZoneTables<C>, owner: crate::El1MmHandle) -> Self {
        Self { zone, owner }
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
    pub fn from_ticket(
        authority: &PortalWaitAuthority<'a, C>,
        operation: OperationToken,
        ticket: carrick_sched_core::refusal::ReleaseTicket<'a, C>,
    ) -> carrick_sched_core::refusal::Rerun<(Self, OperationToken), OperationToken> {
        let zone = authority.zone;
        let expected = authority.owner;
        use carrick_sched_core::refusal::{ReleaseCause, Rerun};
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe {
            ticket.park_and_rerun(operation, |operation, enrollment| {
                if !enrollment.belongs_to(zone) || !enrollment.unchanged() {
                    return Rerun::Now(operation);
                }
                let Some(identity) = enrollment.identity() else {
                    return Rerun::Now(operation);
                };
                if identity.mm.get() != expected.mm().raw()
                    || identity.incarnation != expected.incarnation()
                {
                    return Rerun::Now(operation);
                }
                let ReleaseCause::Space(cause) = enrollment.cause() else {
                    return Rerun::Now(operation);
                };
                let Some(source) = zone
                    .space_entry(identity.mm)
                    .and_then(|entry| entry.notifications(identity.incarnation).ok())
                else {
                    return Rerun::Now(operation);
                };
                Rerun::Park((
                    Self::new(source, cause, enrollment.observed().revision()),
                    operation,
                ))
            })
        }
    }

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
    pub fn observed_snapshot(&self) -> ObjectWaitSnapshot {
        self.source.observed_revision(self.cause, self.revision)
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
    snapshot: Option<ObjectWaitSnapshot>,
    owner_entry: Option<carrick_sched_core::object_wait::OwnerEntry>,
    pub operation: OperationToken,
    pub deadline: Option<u64>,
}

impl ObjectParkRequest {
    /// Ticket front door. No raw post-probe revision can be supplied here.
    /// ```compile_fail
    /// use carrick_core_abi::wait::ObjectParkRequest;
    /// use carrick_sched_core::{ZoneTables, object_wait::OperationToken, refusal::ReleaseTicket};
    /// fn escape(zone: &ZoneTables, op: OperationToken, ticket: ReleaseTicket<'_>) {
    ///     let _ = ObjectParkRequest::from_ticket(zone, op, ticket);
    /// }
    /// ```
    /// # Safety
    /// A returned request must be enrolled only against `zone`, before its
    /// retained entry authority is released. Use carrick_core::wait::park_and_rerun
    /// for the safe end-to-end adapter; a raw request cannot retain zone custody.
    pub unsafe fn from_ticket<C: EntryContext>(
        zone: &ZoneTables<C>,
        operation: OperationToken,
        ticket: carrick_sched_core::refusal::ReleaseTicket<'_, C>,
    ) -> carrick_sched_core::refusal::Rerun<Self, OperationToken> {
        use carrick_sched_core::refusal::Rerun;
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe {
            ticket.park_and_rerun(operation, |operation, enrollment| {
                if !enrollment.belongs_to(zone) || !enrollment.unchanged() {
                    return Rerun::Now(operation);
                }
                Rerun::Park(Self::new(
                    enrollment.key(),
                    enrollment.observed(),
                    operation,
                    None,
                ))
            })
        }
    }

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

/// MM-wire adapter; the ticket remains the only source of new wait receipts.
/// The existing wire consumer authenticates the carrier and exact owner handle.
pub trait ReleaseTicketPortalExt<C: Copy + Send + Sync + zerocopy::FromZeros = ThreadCtx> {
    fn into_portal_wait(
        self,
        authority: &PortalWaitAuthority<'_, C>,
    ) -> Result<crate::PortalOwnerWait, carrick_sched_core::refusal::InvariantKind>;
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> ReleaseTicketPortalExt<C>
    for carrick_sched_core::refusal::ReleaseTicket<'_, C>
{
    fn into_portal_wait(
        self,
        authority: &PortalWaitAuthority<'_, C>,
    ) -> Result<crate::PortalOwnerWait, carrick_sched_core::refusal::InvariantKind> {
        let expected = authority.owner;
        use carrick_sched_core::refusal::{InvariantKind, ReleaseCause};
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe {
            self.park_and_rerun((), |(), enrollment| {
                let bad = || InvariantKind {
                    domain: "portal_ticket_owner",
                    code: 1,
                };
                if !enrollment.belongs_to(authority.zone) {
                    return Err(bad());
                }
                let identity = enrollment.identity().ok_or_else(bad)?;
                if identity.mm.get() != expected.mm().raw()
                    || identity.incarnation != expected.incarnation()
                {
                    return Err(bad());
                }
                let ReleaseCause::Space(cause) = enrollment.cause() else {
                    return Err(bad());
                };
                let cause = match cause {
                    SpaceWaitCause::Editor => crate::PortalWaitCause::Editor,
                    SpaceWaitCause::Reservations => crate::PortalWaitCause::Reservations,
                    SpaceWaitCause::PendingEdit => crate::PortalWaitCause::PendingEdit,
                    SpaceWaitCause::Gate => crate::PortalWaitCause::Gate,
                    SpaceWaitCause::Metadata => crate::PortalWaitCause::Metadata,
                    SpaceWaitCause::PreparedOverlap => return Err(bad()),
                };
                // SAFETY: the sealed probe retained this exact admitted source and
                // observed its cause before the failed probe. The wire keeps the
                // expected carrier identity for the existing authenticated decoder.
                Ok(crate::PortalOwnerWait::from_owner(
                    expected,
                    cause,
                    enrollment.observed().revision(),
                ))
            })
        }
    }
}

#[cfg(test)]
mod ticket_tests {
    extern crate std;
    use super::*;
    use carrick_sched_core::refusal::{Attempt, ContentionSource, Refusal, ReleaseCause, Rerun};
    use carrick_sched_core::{ShortLockSpin, Waker};
    use core::num::NonZeroU64;
    use std::boxed::Box;

    fn zone() -> Box<ZoneTables> {
        // SAFETY: allocate the all-zero initial shared ABI directly off-stack.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!ptr.is_null());
            Box::from_raw(ptr.cast())
        }
    }
    fn complete(effects: OwnedObjectWakeEffects<'_>) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    fn source(zone: &ZoneTables) -> SpaceNotificationLease<'_> {
        zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
        entry
            .admit_notifications(NonZeroU64::MIN, &ShortLockSpin, &complete)
            .unwrap();
        entry.notifications(NonZeroU64::MIN).unwrap()
    }
    fn ticket<'z>(
        source: &SpaceNotificationLease<'z>,
    ) -> carrick_sched_core::refusal::ReleaseTicket<'z> {
        let Err(Refusal::Contended(ticket)) = source.contend(|| {
            Err::<(), _>(Attempt::<()>::Contended(ReleaseCause::Space(
                SpaceWaitCause::Editor,
            )))
        }) else {
            panic!("ticket");
        };
        ticket
    }
    fn handle() -> crate::El1MmHandle {
        // SAFETY: fixture owns the admitted exact MM and incarnation.
        unsafe {
            crate::El1MmHandle::from_admitted_owner(
                NonZeroU64::MIN,
                crate::ReservationMm::new(77).unwrap(),
                NonZeroU64::MIN,
            )
        }
    }
    fn authority(zone: &ZoneTables, owner: crate::El1MmHandle) -> PortalWaitAuthority<'_> {
        // SAFETY: this fixture allocates and retains each carrier's own zone.
        unsafe { PortalWaitAuthority::from_retained_zone(zone, owner) }
    }
    #[test]
    fn object_front_door_preserves_operation_on_release_race() {
        let zone = zone();
        let source = source(&zone);
        let ticket = ticket(&source);
        source
            .reserve(SpaceWaitCause::Editor)
            .publish(Waker::Host, &complete);
        let operation = OperationToken::new(19, 3).unwrap();
        let Rerun::Now(operation) =
            (unsafe { ObjectParkRequest::from_ticket(&zone, operation, ticket) })
        else {
            panic!("must rerun");
        };
        assert_eq!((operation.index(), operation.generation()), (19, 3));
    }
    #[test]
    fn portal_front_door_authenticates_source_and_owns_one_enrollment() {
        let zone = zone();
        let source = source(&zone);
        let record = zone
            .alloc_record(carrick_sched_core::ThreadIdentity {
                tid: 77,
                serial: 1,
                mm: 77,
                file_table: 1,
                generation: 1,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let Rerun::Park((enrollment, operation)) = PortalWaitEnrollment::from_ticket(
            &authority(&zone, handle()),
            OperationToken::new(19, 3).unwrap(),
            ticket(&source),
        ) else {
            panic!("must enroll");
        };
        assert_eq!(enrollment.cause(), SpaceWaitCause::Editor);
        // Operation ownership is transferred exactly once through the existing
        // host enrollment path; the source publishes completion afterwards.
        enrollment.park_host(record, operation, &complete).unwrap();
        let mut handed = 0;
        let guard = zone
            .object_wait_with_completion(
                source.key(SpaceWaitCause::Editor),
                &ShortLockSpin,
                &complete,
            )
            .unwrap();
        assert_eq!(
            guard
                .notify_object_host(&mut |_| handed += 1, &mut |_| {})
                .unwrap()
                .visited,
            1
        );
        assert_eq!(
            guard
                .notify_object_host(&mut |_| handed += 1, &mut |_| {})
                .unwrap()
                .visited,
            0
        );
        assert_eq!(handed, 1);
    }
    #[test]
    fn wire_preserves_exact_owner_and_rejects_foreign_mm() {
        let zone = zone();
        let source = source(&zone);
        let wire = ticket(&source)
            .into_portal_wait(&authority(&zone, handle()))
            .unwrap();
        assert_eq!(wire.handle(), handle());
        assert_eq!(wire.cause(), crate::PortalWaitCause::Editor);
        let foreign = unsafe {
            crate::El1MmHandle::from_admitted_owner(
                NonZeroU64::MIN,
                crate::ReservationMm::new(78).unwrap(),
                NonZeroU64::MIN,
            )
        };
        assert!(
            ticket(&source)
                .into_portal_wait(&authority(&zone, foreign))
                .is_err()
        );
    }
    #[test]
    fn wire_rejects_foreign_carrier_region() {
        let zone = zone();
        let source = source(&zone);
        // SAFETY: independently admitted fixture carrier, same numeric MM/incarnation.
        let other_handle = unsafe {
            crate::El1MmHandle::from_admitted_owner(
                NonZeroU64::new(2).unwrap(),
                crate::ReservationMm::new(77).unwrap(),
                NonZeroU64::MIN,
            )
        };
        let other_zone = self::zone();
        let _other_source = self::source(&other_zone);
        assert!(
            ticket(&source)
                .into_portal_wait(&authority(&other_zone, other_handle))
                .is_err()
        );
    }
    #[test]
    fn dropped_tickets_fail_in_production_dependency() {
        let zone = zone();
        let source = source(&zone);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket(&source))))
                .is_err()
        );
        assert_eq!(
            zone.counters
                .contention_tickets_dropped
                .load(core::sync::atomic::Ordering::Relaxed),
            1
        );
    }
    #[test]
    fn foreign_zone_cannot_enroll_a_ticket() {
        let zone = zone();
        let other = self::zone();
        let source = source(&zone);
        assert!(matches!(
            unsafe {
                ObjectParkRequest::from_ticket(
                    &other,
                    OperationToken::new(19, 3).unwrap(),
                    ticket(&source),
                )
            },
            Rerun::Now(_)
        ));
    }
}
