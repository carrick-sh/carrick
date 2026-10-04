//! Exact live-MM notification custody. No shared record contains a host pointer.
use super::SpaceIndex;
use crate::object_wait::{
    BorrowedObjectNotificationSource, ObjectNotificationTicket, ObjectWaitError, ObjectWaitKey,
    ObjectWaitSnapshot, OwnedObjectWakeEffects,
};
use crate::{LockWait, Waker, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Independent producers: a root reader cannot wake a pending edit waiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SpaceWaitCause {
    PreparedOverlap,
    Editor,
    Reservations,
    PendingEdit,
    Gate,
    Metadata,
}
impl SpaceWaitCause {
    pub const ALL: [Self; 6] = [
        Self::PreparedOverlap,
        Self::Editor,
        Self::Reservations,
        Self::PendingEdit,
        Self::Gate,
        Self::Metadata,
    ];
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceNotificationIdentity {
    pub mm: NonZeroU64,
    pub incarnation: NonZeroU64,
}
#[derive(Clone, Copy)]
pub struct SpaceReleaseVenue<'a> {
    pub zone: &'a ZoneTables,
    pub waker: Waker,
    pub deliver: for<'z> fn(&'z ZoneTables, Waker, OwnedObjectWakeEffects<'z>),
}
impl SpaceReleaseVenue<'_> {
    pub fn publish(self, ticket: ObjectNotificationTicket<'_>) {
        ticket.publish(self.waker, &|effects| {
            (self.deliver)(self.zone, self.waker, effects)
        });
    }
}
/// Lock-word state after releasing a resource. The high flag requires the
/// next root holder to carry authenticated notification authority.
#[derive(Clone, Copy)]
pub enum ResourceUnlocked {
    Plain,
    NotificationRoot,
}
pub const ROOT_NOTIFICATION_REQUIRED: u64 = 1 << 63;
impl ResourceUnlocked {
    pub fn word(self) -> u64 {
        match self {
            Self::Plain => 0,
            Self::NotificationRoot => ROOT_NOTIFICATION_REQUIRED,
        }
    }
}
const ACTIVE: u64 = 1 << 63;
const CLOSING: u64 = 1 << 62;
const BINDING: u64 = 1 << 61;
const FINISHING: u64 = 1 << 60;
const COUNT: u64 = FINISHING - 1;
/// Appended to a SpaceEntry. One base publisher per cause, one live admission
/// count around derivation. Counted tickets independently exclude queue rebind.
#[repr(C)]
pub(super) struct NotificationSource {
    state: AtomicU64,
    mm: AtomicU64,
    incarnation: AtomicU64,
    retirement: AtomicU64,
}
impl NotificationSource {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            mm: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            retirement: AtomicU64::new(0),
        }
    }
    pub fn empty(&self) -> bool {
        self.state.load(Ordering::Acquire) == 0
    }
    pub fn attached(&self) -> bool {
        self.state.load(Ordering::Acquire) & ACTIVE != 0
    }
    pub(super) fn claim_entry_retirement(&self) {
        assert!(
            self.retirement
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "entry retirement is unique"
        );
    }
    pub(super) fn reusable(&self) -> bool {
        self.empty() && matches!(self.retirement.load(Ordering::Acquire), 0 | 3)
    }
    pub(super) fn prepare_entry(&self) {
        self.retirement.store(0, Ordering::Release);
    }
    pub(super) fn finish_entry_retirement(&self, spaces: &super::AddressSpaces, index: SpaceIndex) {
        if self.empty()
            && self
                .retirement
                .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            spaces.clear_retired_entry(index);
            self.retirement.store(3, Ordering::Release);
        }
    }
    fn identity(&self) -> Option<SpaceNotificationIdentity> {
        Some(SpaceNotificationIdentity {
            mm: NonZeroU64::new(self.mm.load(Ordering::Acquire))?,
            incarnation: NonZeroU64::new(self.incarnation.load(Ordering::Acquire))?,
        })
    }
    fn release(&self, zone: &ZoneTables, index: SpaceIndex) {
        let previous = self.state.fetch_sub(1, Ordering::AcqRel);
        assert!(previous & COUNT != 0, "notification admission underflow");
        if previous & COUNT == 1 {
            self.finish(zone, index);
            self.finish_entry_retirement(&zone.spaces, index);
        }
    }
    fn finish(&self, zone: &ZoneTables, index: SpaceIndex) {
        let state = self.state.load(Ordering::Acquire);
        if state & COUNT != 0 || state & (BINDING | FINISHING) != 0 || state & CLOSING == 0 {
            return;
        }
        if self
            .state
            .compare_exchange(state, FINISHING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let incarnation = self.incarnation.load(Ordering::Acquire);
        if state & ACTIVE != 0 {
            for cause in SpaceWaitCause::ALL {
                let key = notification_key(index, incarnation, cause);
                // SAFETY: FINISHING uniquely owns the detached durable base pins;
                // every borrower that could derive from them has released admission.
                drop(unsafe { zone.retained_object_notification(key) });
            }
        }
        // Failed/inactive admissions may have incremented the low count during
        // destruction. Preserve it; rebinding requires the exact empty word.
        self.state
            .fetch_and(!(FINISHING | CLOSING), Ordering::Release);
        self.finish_entry_retirement(&zone.spaces, index);
    }
}
fn notification_key(index: SpaceIndex, incarnation: u64, cause: SpaceWaitCause) -> ObjectWaitKey {
    ObjectWaitKey::live_space_cause(index.index(), incarnation, cause)
}
/// Zone-bound membership. The index is discovered from the exact live MM;
/// callers cannot transplant an index or pair it with another zone.
#[derive(Clone, Copy)]
pub struct SpaceEntryHandle<'a> {
    zone: &'a ZoneTables,
    index: SpaceIndex,
    mm: NonZeroU64,
}
impl<'a> SpaceEntryHandle<'a> {
    pub fn index(self) -> SpaceIndex {
        self.index
    }
    fn identity(self, incarnation: NonZeroU64) -> SpaceNotificationIdentity {
        SpaceNotificationIdentity {
            mm: self.mm,
            incarnation,
        }
    }
    pub fn notification_key(
        self,
        incarnation: NonZeroU64,
        cause: SpaceWaitCause,
    ) -> Result<ObjectWaitKey, ObjectWaitError> {
        if self.zone.spaces.key(self.index) != self.mm.get() {
            return Err(ObjectWaitError::Stale);
        }
        Ok(notification_key(self.index, incarnation.get(), cause))
    }
    pub fn admit_notifications(
        self,
        incarnation: NonZeroU64,
        wait: &impl LockWait,
        completion: &dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<(), ObjectWaitError> {
        self.zone.admit_space_notifications(
            self.index,
            self.identity(incarnation),
            wait,
            completion,
        )
    }
    pub fn notifications(
        self,
        incarnation: NonZeroU64,
    ) -> Result<SpaceNotificationLease<'a>, ObjectWaitError> {
        self.zone
            .borrow_space_notifications(self.index, self.identity(incarnation))
    }
    /// Retire a closed entry without waiting for already admitted source
    /// borrowers. The last borrower owns cleanup; publication skips it until
    /// that unique cleanup finishes.
    pub fn retire_entry(self, venue: SpaceReleaseVenue<'_>) {
        assert!(
            core::ptr::eq(venue.zone, self.zone),
            "retirement source zone"
        );
        assert!(self.zone.spaces.gate(self.index) & super::GATE_CLOSED != 0);
        assert!(self.zone.spaces.active_editor(self.index).is_none());
        assert_eq!(self.zone.spaces.key(self.index), self.mm.get());
        let source = &self.zone.spaces.entry(self.index).notifications;
        // Pin before claiming retirement, so a concurrent last borrower cannot
        // finish/recycle the entry underneath this terminal publisher. Inspect
        // ACTIVE only after excluding new admissions: a binder may have become
        // live between the pin and retirement claim.
        let previous = source.state.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous & COUNT != COUNT,
            "notification admission exhaustion"
        );
        source.claim_entry_retirement();
        let closing = source.state.fetch_or(CLOSING, Ordering::SeqCst);
        if closing & !COUNT == ACTIVE {
            let Some(identity) = source.identity() else {
                unreachable!("active source identity");
            };
            assert_eq!(identity.mm, self.mm);
            SpaceNotificationLease {
                zone: self.zone,
                index: self.index,
                source,
                identity,
            }
            .publish_terminal(venue);
        } else {
            source.release(self.zone, self.index);
        }
        source.finish(self.zone, self.index);
    }
    pub fn close_notifications(
        self,
        incarnation: NonZeroU64,
        venue: SpaceReleaseVenue<'_>,
    ) -> Result<(), ObjectWaitError> {
        assert!(core::ptr::eq(venue.zone, self.zone), "closing source zone");
        self.zone
            .close_space_notifications(self.index, self.identity(incarnation), venue)
    }
}
/// Private release custody: even unwinding while constructing several
/// publications unlocks the protected resource before any receipt is dropped.
struct ResourceRelease<'a, 'z, 'c> {
    word: &'a AtomicU64,
    unlocked: ResourceUnlocked,
    publications: [Option<crate::object_wait::ObjectNotificationPublication<'z, 'c>>; 6],
}
impl Drop for ResourceRelease<'_, '_, '_> {
    fn drop(&mut self) {
        self.word.store(self.unlocked.word(), Ordering::SeqCst);
        for publication in &mut self.publications {
            if let Some(publication) = publication.take() {
                publication.publish();
            }
        }
    }
}
/// Non-owning view licensed by a counted live-source admission. Its Drop can
/// complete retirement but never reconstructs or decrements a base pin twice.
pub struct SpaceNotificationLease<'a> {
    zone: &'a ZoneTables,
    index: SpaceIndex,
    source: &'a NotificationSource,
    identity: SpaceNotificationIdentity,
}
impl<'a> SpaceNotificationLease<'a> {
    fn publish_terminal(self, venue: SpaceReleaseVenue<'_>) {
        // CLOSING is already visible: this edge means the exact source is
        // unavailable, not that a resource is ready for another attempt.
        // Retain all receipts before the first callback can run.
        let complete =
            |effects: OwnedObjectWakeEffects<'_>| (venue.deliver)(venue.zone, venue.waker, effects);
        let publications = SpaceWaitCause::ALL
            .map(|cause| self.reserve(cause).advance_revision(venue.waker, &complete));
        for publication in publications {
            publication.publish();
        }
    }

    /// Closing admission is visible to a waiter before it publishes a park.
    pub fn is_live(&self) -> bool {
        let state = self.source.state.load(Ordering::Acquire);
        state & (ACTIVE | CLOSING) == ACTIVE
            && self.source.retirement.load(Ordering::Acquire) == 0
            && self.zone.spaces.key(self.index) == self.identity.mm.get()
    }
    pub fn identity(&self) -> SpaceNotificationIdentity {
        self.identity
    }
    pub fn key(&self, cause: SpaceWaitCause) -> ObjectWaitKey {
        notification_key(self.index, self.identity.incarnation.get(), cause)
    }
    pub fn reserve(&self, cause: SpaceWaitCause) -> ObjectNotificationTicket<'a> {
        // This view's lifetime is bounded by the live admission below. No
        // owning source reconstruction, queue admission or lock acquisition.
        BorrowedObjectNotificationSource::from_live_admission(self.zone, self.key(cause), self)
            .reserve()
    }
    /// Close an exact source and release its final protected resource before
    /// delivering terminal edges. The counted lease keeps all cause pins live.
    ///
    /// # Safety
    /// The caller owns `word` exclusively for this exact MM and has finished
    /// all protected mutation. It must not unlock or access that resource again.
    pub unsafe fn release_retiring_resource(
        &self,
        venue: SpaceReleaseVenue<'_>,
        word: &AtomicU64,
        unlocked: ResourceUnlocked,
    ) {
        assert!(core::ptr::eq(venue.zone, self.zone), "retiring source zone");
        assert!(self.zone.spaces.gate(self.index) & super::GATE_CLOSED != 0);
        assert!(self.zone.spaces.active_editor(self.index).is_none());
        self.source.state.fetch_or(CLOSING, Ordering::SeqCst);
        // SAFETY: the caller supplies the same exact exclusive resource custody.
        unsafe { self.release_resource(venue, word, unlocked, &SpaceWaitCause::ALL) };
    }
    /// Unlock and publish as one release authority. No advanced receipt can
    /// escape to a caller or be destroyed before its resource unlock.
    ///
    /// # Safety
    /// The caller owns the exact MM resource represented by `word`, exclusively
    /// until this method stores the typed unlocked state. It must cease using
    /// protected data before calling and must not unlock a second time.
    pub unsafe fn release_resource(
        &self,
        venue: SpaceReleaseVenue<'_>,
        word: &AtomicU64,
        unlocked: ResourceUnlocked,
        causes: &[SpaceWaitCause],
    ) {
        assert!(
            core::ptr::eq(venue.zone, self.zone),
            "release belongs to exact source zone"
        );
        let completion = |effects: crate::object_wait::OwnedObjectWakeEffects<'_>| {
            (venue.deliver)(venue.zone, venue.waker, effects)
        };
        let mut release = ResourceRelease {
            word,
            unlocked,
            publications: core::array::from_fn(|_| None),
        };
        for (i, cause) in SpaceWaitCause::ALL.into_iter().enumerate() {
            if causes.contains(&cause) {
                release.publications[i] = Some(
                    self.reserve(cause)
                        .advance_revision(venue.waker, &completion),
                );
            }
        }
        drop(release);
    }

    /// Reattach an owner-service revision to this still-live exact source.
    /// Enrollment checks that revision again after linking the saved operation.
    pub fn observed_revision(&self, cause: SpaceWaitCause, revision: u64) -> ObjectWaitSnapshot {
        ObjectWaitSnapshot::at_revision(self.key(cause), revision)
    }

    pub fn observe(&self, cause: SpaceWaitCause) -> ObjectWaitSnapshot {
        self.zone.notification_snapshot(self.key(cause))
    }
}
impl Drop for SpaceNotificationLease<'_> {
    fn drop(&mut self) {
        self.source.release(self.zone, self.index);
    }
}
impl ZoneTables {
    pub fn space_entry(&self, mm: NonZeroU64) -> Option<SpaceEntryHandle<'_>> {
        self.spaces.find(mm.get()).map(|index| SpaceEntryHandle {
            zone: self,
            index,
            mm,
        })
    }

    /// Bind while the root's admission guard excludes publication/retirement.
    /// All cause pins are acquired before ACTIVE publication; refusal unwinds
    /// every acquired pin, leaving no admitted source.
    pub(crate) fn admit_space_notifications(
        &self,
        index: SpaceIndex,
        identity: SpaceNotificationIdentity,
        wait: &impl LockWait,
        completion: &dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<(), ObjectWaitError> {
        let entry = self.spaces.entry(index);
        if self.spaces.key(index) != identity.mm.get() {
            return Err(ObjectWaitError::Stale);
        }
        let source = &entry.notifications;
        source
            .state
            .compare_exchange(0, BINDING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ObjectWaitError::Occupied)?;
        let result = (|| {
            if self.spaces.key(index) != identity.mm.get()
                || source.retirement.load(Ordering::Acquire) != 0
            {
                return Err(ObjectWaitError::Stale);
            }
            let mut pins: [Option<crate::object_wait::ObjectNotificationSource<'_>>; 6] =
                core::array::from_fn(|_| None);
            for (at, cause) in SpaceWaitCause::ALL.into_iter().enumerate() {
                let key = notification_key(index, identity.incarnation.get(), cause);
                if self.notification_generation(key) != key.generation() {
                    self.bind_object_wait_with_completion(key, wait, completion)?;
                }
                pins[at] = Some(
                    self.admit_object_notification(key, wait, completion)?
                        .into_source(),
                );
            }
            source.mm.store(identity.mm.get(), Ordering::Relaxed);
            source
                .incarnation
                .store(identity.incarnation.get(), Ordering::Relaxed);
            for pin in pins.into_iter().flatten() {
                let _ = pin.detach();
            }
            Ok(())
        })();
        if result.is_ok() {
            source.state.fetch_xor(BINDING | ACTIVE, Ordering::Release);
        } else {
            source.state.fetch_and(!BINDING, Ordering::Release);
        }
        if source.retirement.load(Ordering::Acquire) != 0 {
            source.state.fetch_or(CLOSING, Ordering::AcqRel);
            source.finish(self, index);
            return Err(ObjectWaitError::Stale);
        }
        source.finish(self, index);
        result
    }
    pub(crate) fn borrow_space_notifications(
        &self,
        index: SpaceIndex,
        identity: SpaceNotificationIdentity,
    ) -> Result<SpaceNotificationLease<'_>, ObjectWaitError> {
        let source = &self.spaces.entry(index).notifications;
        if source.retirement.load(Ordering::Acquire) != 0 {
            return Err(ObjectWaitError::Stale);
        }
        let previous = source.state.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous & COUNT != COUNT,
            "notification admission exhaustion"
        );
        if previous & !COUNT != ACTIVE
            || source.identity() != Some(identity)
            || self.spaces.key(index) != identity.mm.get()
        {
            source.release(self, index);
            return Err(ObjectWaitError::Stale);
        }
        Ok(SpaceNotificationLease {
            zone: self,
            index,
            source,
            identity,
        })
    }
    pub(crate) fn close_space_notifications(
        &self,
        index: SpaceIndex,
        identity: SpaceNotificationIdentity,
        venue: SpaceReleaseVenue<'_>,
    ) -> Result<(), ObjectWaitError> {
        if self.spaces.gate(index) & super::GATE_CLOSED == 0
            || self.spaces.active_editor(index).is_some()
        {
            return Err(ObjectWaitError::Occupied);
        }
        let lease = self.borrow_space_notifications(index, identity)?;
        lease.source.state.fetch_or(CLOSING, Ordering::SeqCst);
        lease.publish_terminal(venue);
        Ok(())
    }
    pub(super) fn editor_notification(
        &self,
        index: SpaceIndex,
        mm: u64,
    ) -> Option<SpaceNotificationLease<'_>> {
        let source = &self.spaces.entry(index).notifications;
        if !source.attached() {
            return None;
        }
        let identity = source.identity()?;
        if identity.mm.get() != mm {
            return None;
        }
        self.borrow_space_notifications(index, identity).ok()
    }
}

/// A space table paired with its release venue at the owning entrypoint.
/// Source-free construction is explicit and available only to model fixtures.
#[derive(Clone, Copy)]
pub struct SpaceAccess<'a> {
    spaces: &'a super::AddressSpaces,
    venue: Option<SpaceReleaseVenue<'a>>,
}
impl<'a> SpaceAccess<'a> {
    pub fn notified(venue: SpaceReleaseVenue<'a>) -> Self {
        Self {
            spaces: &venue.zone.spaces,
            venue: Some(venue),
        }
    }
    #[cfg(any(test, feature = "host-test"))]
    pub fn source_free(spaces: &'a super::AddressSpaces) -> Self {
        Self {
            spaces,
            venue: None,
        }
    }
    pub fn venue(self) -> Option<SpaceReleaseVenue<'a>> {
        self.venue
    }
    pub fn table(self) -> &'a super::AddressSpaces {
        self.spaces
    }
    /// Preserve the nested host pause count; the release revision precedes
    /// the atomic decrement, and delivery follows it.
    pub fn lower(self, index: SpaceIndex) {
        self.release_gate(index, false);
    }
    pub fn open(self, index: SpaceIndex) {
        self.release_gate(index, true);
    }
    fn release_gate(self, index: SpaceIndex, opening: bool) {
        let entry = self.spaces.entry(index);
        let release = if entry.notifications.attached() {
            let Some(venue) = self.venue else {
                unreachable!("admitted gate release requires its venue");
            };
            let Some(lease) = venue
                .zone
                .editor_notification(index, self.spaces.key(index))
            else {
                unreachable!("live gate release admission");
            };
            Some((venue, lease))
        } else {
            None
        };
        if let Some((venue, lease)) = release {
            let completion = |effects: OwnedObjectWakeEffects<'_>| {
                (venue.deliver)(venue.zone, venue.waker, effects)
            };
            let publication = lease
                .reserve(SpaceWaitCause::Gate)
                .advance_revision(venue.waker, &completion);
            if opening {
                entry.gate.fetch_and(
                    !(super::GATE_CLOSED | super::GATE_INITIAL_BIND),
                    Ordering::SeqCst,
                );
            } else {
                entry.gate.fetch_sub(1, Ordering::SeqCst);
            }
            publication.publish();
        } else if opening {
            self.spaces.open(index);
        } else {
            self.spaces.lower(index);
        }
    }
    pub fn try_begin_edit(
        self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
    ) -> Option<super::SpaceEditor<'a>> {
        self.spaces
            .try_begin_edit_with_venue(index, key, owner, self.venue)
    }
    pub fn try_begin_closed_child_edit(
        self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
    ) -> Option<super::ClosedChildEditor<'a>> {
        self.spaces
            .try_begin_closed_child_edit_with_venue(index, key, owner, self.venue)
    }
    pub fn try_begin_edit_bounded(
        self,
        index: SpaceIndex,
        key: u64,
        owner: NonZeroU64,
        spins: u32,
    ) -> Option<super::SpaceEditor<'a>> {
        for _ in 0..spins.max(1) {
            if let Some(editor) = self.try_begin_edit(index, key, owner) {
                return Some(editor);
            }
            if self.spaces.gate(index) != 0 || self.spaces.key(index) != key {
                return None;
            }
            core::hint::spin_loop();
        }
        None
    }
}
impl core::ops::Deref for SpaceAccess<'_> {
    type Target = super::AddressSpaces;
    fn deref(&self) -> &Self::Target {
        self.spaces
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::BoundedSpin;
    fn zone() -> std::boxed::Box<ZoneTables> {
        let ptr = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>()) };
        assert!(!ptr.is_null());
        unsafe { std::boxed::Box::from_raw(ptr.cast()) }
    }
    fn deliver(_: &ZoneTables, _: Waker, effects: OwnedObjectWakeEffects<'_>) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    fn access(zone: &ZoneTables) -> SpaceAccess<'_> {
        SpaceAccess::notified(SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver,
        })
    }
    fn admitted(zone: &ZoneTables) -> SpaceEntryHandle<'_> {
        zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
        entry
            .admit_notifications(NonZeroU64::new(1).unwrap(), &BoundedSpin(0), &|effects| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            })
            .unwrap();
        entry
    }
    #[test]
    fn source_retirement_completes_already_parked_gate_operation() {
        let zone = zone();
        let entry = admitted(&zone);
        let incarnation = NonZeroU64::new(1).unwrap();
        let lease = entry.notifications(incarnation).unwrap();
        let record = zone
            .alloc_record(crate::ThreadIdentity {
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
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        lease
            .reserve(SpaceWaitCause::Gate)
            .park_host_rechecked(
                lease.observe(SpaceWaitCause::Gate),
                record,
                crate::object_wait::OperationToken::new(77, 1).unwrap(),
                &complete,
                || true,
            )
            .unwrap();
        drop(lease);
        entry
            .close_notifications(incarnation, access(&zone).venue().unwrap())
            .unwrap();
        entry.retire_entry(access(&zone).venue().unwrap());
        assert!(
            matches!(zone.record(record).claim(), crate::Claim::Host { .. }),
            "terminal source closure must return the owned operation"
        );
        assert_eq!(
            unsafe { zone.record(record).take_object_operation() }
                .unwrap()
                .index(),
            77
        );
    }

    #[test]
    fn source_close_after_predicate_observation_refuses_park_publication() {
        let zone = zone();
        let entry = admitted(&zone);
        let incarnation = NonZeroU64::new(1).unwrap();
        let lease = entry.notifications(incarnation).unwrap();
        let record = zone
            .alloc_record(crate::ThreadIdentity {
                tid: 78,
                serial: 1,
                mm: 77,
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        let result = lease.reserve(SpaceWaitCause::Gate).park_host_rechecked(
            lease.observe(SpaceWaitCause::Gate),
            record,
            crate::object_wait::OperationToken::new(78, 1).unwrap(),
            &complete,
            || {
                let observed = lease.is_live();
                entry
                    .close_notifications(incarnation, access(&zone).venue().unwrap())
                    .unwrap();
                observed
            },
        );
        assert_eq!(
            result,
            Err((
                ObjectWaitError::Changed,
                crate::object_wait::OperationToken::new(78, 1).unwrap()
            ))
        );
        assert!(!zone.record(record).has_object_operation());
        entry.retire_entry(access(&zone).venue().unwrap());
    }

    #[test]
    fn direct_entry_retirement_returns_every_enrolled_cause() {
        let zone = zone();
        let entry = admitted(&zone);
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        let records = SpaceWaitCause::ALL.map(|cause| {
            let record = zone
                .alloc_record(crate::ThreadIdentity {
                    tid: 90 + cause as u64,
                    serial: 1,
                    mm: 77,
                    file_table: 1,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            lease
                .reserve(cause)
                .park_host_rechecked(
                    lease.observe(cause),
                    record,
                    crate::object_wait::OperationToken::new(90 + cause as u64, 1).unwrap(),
                    &complete,
                    || true,
                )
                .unwrap();
            record
        });
        drop(lease);
        entry.retire_entry(access(&zone).venue().unwrap());
        for record in records {
            assert!(matches!(
                zone.record(record).claim(),
                crate::Claim::Host { .. }
            ));
            assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
        }
    }

    #[test]
    fn nested_gate_release_keeps_count_and_publishes_final_edge() {
        let zone = zone();
        let entry = admitted(&zone);
        let spaces = access(&zone);
        spaces.open(entry.index());
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let key = lease.key(SpaceWaitCause::Gate);
        spaces.raise(entry.index());
        spaces.raise(entry.index());
        spaces.lower(entry.index());
        assert_eq!(spaces.gate(entry.index()), 1);
        assert!(
            spaces
                .try_begin_edit(entry.index(), 77, NonZeroU64::new(1).unwrap())
                .is_none()
        );
        let before = zone.object_queue_census(key.index()).unwrap().epoch;
        spaces.lower(entry.index());
        assert_eq!(spaces.gate(entry.index()), 0);
        assert!(
            zone.object_queue_census(key.index()).unwrap().epoch > before,
            "final nested gate release must publish its actual producer edge"
        );
        assert!(
            spaces
                .try_begin_edit(entry.index(), 77, NonZeroU64::new(1).unwrap())
                .is_some()
        );
        spaces.close(entry.index());
        entry
            .close_notifications(NonZeroU64::new(1).unwrap(), access(&zone).venue().unwrap())
            .unwrap();
    }
    #[test]
    fn close_with_live_borrow_defers_entry_reuse_until_last_release() {
        let zone = zone();
        let entry = admitted(&zone);
        let index = entry.index();
        let incarnation = NonZeroU64::new(1).unwrap();
        let lease = entry.notifications(incarnation).unwrap();
        let ticket = lease.reserve(SpaceWaitCause::Editor);
        entry.retire_entry(access(&zone).venue().unwrap());
        assert!(entry.notifications(incarnation).is_err());
        assert_eq!(
            zone.spaces.key(index),
            77,
            "borrow retains old entry custody"
        );
        assert!(!zone.spaces.entry(index).notifications.reusable());
        drop(lease);
        assert_eq!(zone.spaces.key(index), super::super::FREED);
        let replacement_mm = 77 + super::super::ADDRESS_SPACES as u64;
        let replacement = zone
            .spaces
            .publish_closed(replacement_mm, 0x50000, 0x50000)
            .unwrap();
        assert_eq!(replacement, index);
        let next = zone
            .space_entry(NonZeroU64::new(replacement_mm).unwrap())
            .unwrap();
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        assert_eq!(
            next.admit_notifications(NonZeroU64::new(2).unwrap(), &BoundedSpin(0), &complete),
            Err(ObjectWaitError::Occupied),
            "outstanding old ticket prevents cause queue rebind"
        );
        ticket.publish(Waker::Host, &complete);
        next.admit_notifications(NonZeroU64::new(2).unwrap(), &BoundedSpin(0), &complete)
            .unwrap();
        assert!(entry.notifications(incarnation).is_err());
        next.retire_entry(access(&zone).venue().unwrap());
    }
    #[test]
    fn source_binding_loses_to_entry_retirement_without_resurrection() {
        let zone = zone();
        let index = zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
        let source = &zone.spaces.entry(index).notifications;
        // Exact admission gap: the binder has won shared exclusion, but has
        // not validated the key or published any base pin yet.
        source.state.store(BINDING, Ordering::Release);
        entry.retire_entry(access(&zone).venue().unwrap());
        assert_eq!(zone.spaces.key(index), 77);
        assert!(!source.reusable());
        source.state.fetch_and(!BINDING, Ordering::Release);
        source.finish(&zone, index);
        assert_eq!(zone.spaces.key(index), super::super::FREED);
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        assert_eq!(
            entry.admit_notifications(NonZeroU64::new(1).unwrap(), &BoundedSpin(0), &complete),
            Err(ObjectWaitError::Stale)
        );
        assert!(source.reusable());
    }
    #[test]
    fn cause_identity_and_appended_geometry_are_exact() {
        let zone = zone();
        let entry = admitted(&zone);
        for cause in SpaceWaitCause::ALL {
            let key = entry
                .notification_key(NonZeroU64::new(1).unwrap(), cause)
                .unwrap();
            assert_eq!(
                key,
                ObjectWaitKey::address_space_cause(entry.index().index(), 1, cause).unwrap()
            );
            for other in SpaceWaitCause::ALL {
                if other != cause {
                    assert_ne!(
                        key.index(),
                        entry
                            .notification_key(NonZeroU64::new(1).unwrap(), other)
                            .unwrap()
                            .index()
                    );
                }
            }
        }
        assert_eq!(
            core::mem::size_of_val(&zone.space_cause_waits),
            5 * super::super::ADDRESS_SPACES
                * core::mem::size_of::<crate::object_wait::ObjectQueue>()
        );
        assert_eq!(core::mem::size_of::<super::super::SpaceEntry>(), 384);
        assert_eq!(
            core::mem::offset_of!(super::super::SpaceEntry, notifications),
            344
        );
        entry.retire_entry(access(&zone).venue().unwrap());
    }
    #[test]
    fn every_cause_refuses_release_before_enrollment_and_ignores_other_causes() {
        use crate::object_wait::OperationToken;
        for cause in SpaceWaitCause::ALL {
            let zone = zone();
            let entry = admitted(&zone);
            let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
            let snapshot = lease.observe(cause);
            let other = if cause == SpaceWaitCause::Editor {
                SpaceWaitCause::Reservations
            } else {
                SpaceWaitCause::Editor
            };
            access(&zone).venue().unwrap().publish(lease.reserve(other));
            assert_eq!(
                lease.observe(cause),
                snapshot,
                "unrelated producer cannot reschedule this cause"
            );
            access(&zone).venue().unwrap().publish(lease.reserve(cause));
            let complete = |effects: OwnedObjectWakeEffects<'_>| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            };
            let queue = zone
                .object_wait_with_completion(lease.key(cause), &BoundedSpin(0), &complete)
                .unwrap();
            let record = zone
                .alloc_record(crate::ThreadIdentity {
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
            assert!(matches!(
                queue.park(snapshot, record, OperationToken::new(77, 1).unwrap()),
                Err((ObjectWaitError::Changed, _))
            ));
            assert!(!zone.record(record).has_object_operation());
            drop(queue);
            entry.retire_entry(access(&zone).venue().unwrap());
        }
    }

    #[test]
    fn abandoned_release_unlocks_before_delivering_advanced_receipt() {
        let zone = zone();
        let entry = admitted(&zone);
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let word = AtomicU64::new(17);
        let delivered = core::cell::Cell::new(0);
        let completion = |effects: OwnedObjectWakeEffects<'_>| {
            assert_eq!(
                word.load(Ordering::SeqCst),
                0,
                "unlock must precede unwind delivery"
            );
            delivered.set(delivered.get() + 1);
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut release = ResourceRelease {
                word: &word,
                unlocked: ResourceUnlocked::Plain,
                publications: core::array::from_fn(|_| None),
            };
            release.publications[0] = Some(
                lease
                    .reserve(SpaceWaitCause::Editor)
                    .advance_revision(Waker::Host, &completion),
            );
            panic!("abandon release custody after advancing revision");
        }));
        assert!(result.is_err());
        assert_eq!(word.load(Ordering::SeqCst), 0);
        assert_eq!(delivered.get(), 1);
        entry.retire_entry(access(&zone).venue().unwrap());
    }

    #[test]
    fn release_after_enrollment_reprobes_before_park_for_every_cause() {
        use crate::object_wait::OperationToken;
        for cause in SpaceWaitCause::ALL {
            let zone = zone();
            let entry = admitted(&zone);
            let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
            let snapshot = lease.observe(cause);
            let complete = |effects: OwnedObjectWakeEffects<'_>| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            };
            let queue = zone
                .object_wait_with_completion(lease.key(cause), &BoundedSpin(0), &complete)
                .unwrap();
            let record = zone
                .alloc_record(crate::ThreadIdentity {
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
            let refused = queue.park_rechecked(snapshot, record, operation, || {
                assert_eq!(
                    zone.object_queue_census(lease.key(cause).index())
                        .unwrap()
                        .waiters,
                    1
                );
                // A real producer may advance without taking this held queue.
                lease.reserve(cause).publish(Waker::Host, &complete);
                true
            });
            assert_eq!(
                refused,
                Err((
                    ObjectWaitError::Changed,
                    OperationToken::new(77, 1).unwrap()
                ))
            );
            assert!(!zone.record(record).has_object_operation());
            assert_eq!(
                zone.object_queue_census(lease.key(cause).index())
                    .unwrap()
                    .waiters,
                0
            );
            drop(queue);
            entry.retire_entry(access(&zone).venue().unwrap());
        }
    }
    #[test]
    fn failed_editor_admission_releases_the_claimed_editor_with_notification() {
        let zone = zone();
        let entry = admitted(&zone);
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let before = lease.observe(SpaceWaitCause::Editor);
        assert!(
            access(&zone)
                .try_begin_edit(entry.index(), 77, NonZeroU64::new(1).unwrap())
                .is_none()
        );
        assert_ne!(lease.observe(SpaceWaitCause::Editor), before);
        assert!(zone.spaces.active_editor(entry.index()).is_none());
        entry
            .close_notifications(NonZeroU64::new(1).unwrap(), access(&zone).venue().unwrap())
            .unwrap();
        let before = lease.observe(SpaceWaitCause::Editor);
        assert!(
            access(&zone)
                .try_begin_edit(entry.index(), 77, NonZeroU64::new(1).unwrap())
                .is_none()
        );
        assert_eq!(
            lease.observe(SpaceWaitCause::Editor),
            before,
            "closing source refuses before claiming editor"
        );
    }
    #[test]
    fn actual_editor_release_under_held_queue_delivers_only_after_unlock() {
        use crate::object_wait::OperationToken;
        let zone = zone();
        let entry = admitted(&zone);
        let spaces = access(&zone);
        spaces.open(entry.index());
        let editor = spaces
            .try_begin_edit(entry.index(), 77, NonZeroU64::new(1).unwrap())
            .unwrap();
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let delivered = core::cell::Cell::new(0);
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            assert!(zone.spaces.active_editor(entry.index()).is_none());
            let _ = effects.deliver_handbacks(&mut |_| delivered.set(delivered.get() + 1));
        };
        let queue = zone
            .object_wait_with_completion(
                lease.key(SpaceWaitCause::Editor),
                &BoundedSpin(0),
                &complete,
            )
            .unwrap();
        let record = zone
            .alloc_record(crate::ThreadIdentity {
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
        queue
            .park(
                queue.snapshot(),
                record,
                OperationToken::new(77, 1).unwrap(),
            )
            .unwrap();
        // Derivation and the actual release never admit this held queue again.
        drop(editor);
        assert_eq!(delivered.get(), 0);
        drop(queue);
        assert_eq!(delivered.get(), 1);
        spaces.close(entry.index());
        entry.retire_entry(access(&zone).venue().unwrap());
    }
    #[test]
    fn enrollment_predicate_unwind_removes_unparked_registration() {
        use crate::object_wait::OperationToken;
        let zone = zone();
        let entry = admitted(&zone);
        let lease = entry.notifications(NonZeroU64::new(1).unwrap()).unwrap();
        let complete = |effects: OwnedObjectWakeEffects<'_>| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        let queue = zone
            .object_wait_with_completion(
                lease.key(SpaceWaitCause::Editor),
                &BoundedSpin(0),
                &complete,
            )
            .unwrap();
        let record = zone
            .alloc_record(crate::ThreadIdentity {
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
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = queue.park_rechecked(
                queue.snapshot(),
                record,
                OperationToken::new(77, 1).unwrap(),
                || panic!("predicate unwind"),
            );
        }));
        assert!(result.is_err());
        assert_eq!(
            zone.object_queue_census(lease.key(SpaceWaitCause::Editor).index())
                .unwrap()
                .waiters,
            0
        );
        assert!(!zone.record(record).has_object_operation());
        drop(queue);
        entry.retire_entry(access(&zone).venue().unwrap());
    }
}
