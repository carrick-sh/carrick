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
mod delegated;
pub use delegated::{
    DELEGATED_FILE_WAIT_QUEUES, DelegatedFileWaitIndex, DelegatedLockRelease, DelegatedReleaseVenue,
};

/// Admission capacity, independent of the number of execution slots. Queue
/// storage is provisioned once with the zone; transfers allocate no entries.
/// IPC retains the original queue domain. Carrier metadata uses the next
/// queue; MM permit waits use the following disjoint domain. Round the total
/// for the queue census bitmap.
pub const ADDRESS_SPACE_WAIT_BASE: usize = ZONE_RECORDS;
pub const ORIGINAL_OBJECT_WAIT_QUEUES: usize =
    (ADDRESS_SPACE_WAIT_BASE + 1 + spaces::ADDRESS_SPACES).div_ceil(64) * 64;
/// A dedicated carrier metadata queue in the rounded, otherwise unused tail.
const METADATA_WAIT_INDEX: usize = ADDRESS_SPACE_WAIT_BASE + 1 + spaces::ADDRESS_SPACES;
const _: () = assert!(METADATA_WAIT_INDEX < ORIGINAL_OBJECT_WAIT_QUEUES);
pub const EXTRA_CAUSE_QUEUES: usize = 5 * spaces::ADDRESS_SPACES;
const DELEGATED_FILE_WAIT_BASE: usize = ORIGINAL_OBJECT_WAIT_QUEUES + EXTRA_CAUSE_QUEUES;
pub const OBJECT_WAIT_QUEUES: usize = DELEGATED_FILE_WAIT_BASE + DELEGATED_FILE_WAIT_QUEUES;

const fn cause_queue_index(index: usize, cause: spaces::notification::SpaceWaitCause) -> usize {
    if cause as usize == 0 {
        ADDRESS_SPACE_WAIT_BASE + 1 + index
    } else {
        ORIGINAL_OBJECT_WAIT_QUEUES + (cause as usize - 1) * spaces::ADDRESS_SPACES + index
    }
}
pub const OBJECT_WAIT_PROTOCOL: u64 = 6;
pub const OBJECT_WAIT_LAYOUT_HASH: u64 = {
    let words = [
        OBJECT_WAIT_PROTOCOL,
        OBJECT_WAIT_QUEUES as u64,
        ORIGINAL_OBJECT_WAIT_QUEUES as u64,
        METADATA_WAIT_INDEX as u64,
        DELEGATED_FILE_WAIT_BASE as u64,
        DELEGATED_FILE_WAIT_QUEUES as u64,
        core::mem::offset_of!(crate::ZoneTables, delegated_file_waits) as u64,
        core::mem::offset_of!(crate::ZoneTables, space_cause_waits) as u64,
        crate::spaces::SPACE_NOTIFICATION_LAYOUT_HASH,
        core::mem::size_of::<ObjectQueue>() as u64,
        core::mem::offset_of!(ObjectQueue, generation) as u64,
        core::mem::offset_of!(ObjectQueue, epoch) as u64,
        core::mem::offset_of!(ObjectQueue, completion_mode) as u64,
        core::mem::offset_of!(ObjectQueue, publishers) as u64,
        core::mem::size_of::<crate::completion_queue::CompletionQueue>() as u64,
    ];
    let mut hash = 0xcbf29ce484222325u64;
    let mut i = 0;
    while i < words.len() {
        hash = (hash ^ words[i]).wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
};

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
        if index == 0 || index as usize >= ORIGINAL_OBJECT_WAIT_QUEUES || generation == 0 {
            None
        } else {
            Some(Self { index, generation })
        }
    }

    /// Carrier metadata has its own queue, outside IPC's admitted indices.
    pub const fn metadata_request(generation: u64) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self {
                index: METADATA_WAIT_INDEX as u32,
                generation,
            })
        }
    }

    pub const fn delegated_file(
        index: DelegatedFileWaitIndex,
        generation: core::num::NonZeroU64,
    ) -> Self {
        Self {
            index: (DELEGATED_FILE_WAIT_BASE + index.index()) as u32,
            generation: generation.get(),
        }
    }
    /// Carrier reservation-pool progress uses the original reserved queue,
    /// disjoint from metadata, IPC objects and exact-MM prepared-overlap queues.
    pub const fn reservation_pool(generation: core::num::NonZeroU64) -> Self {
        Self {
            index: ADDRESS_SPACE_WAIT_BASE as u32,
            generation: generation.get(),
        }
    }

    /// Exact admitted MM incarnation, independent of its mutable policy
    /// generation. No IPC readiness lane can name this index domain.
    pub const fn address_space(index: usize, incarnation: u64) -> Option<Self> {
        if index >= spaces::ADDRESS_SPACES {
            None
        } else {
            Self::new((ADDRESS_SPACE_WAIT_BASE + 1 + index) as u32, incarnation)
        }
    }

    #[cfg(test)]
    pub(crate) const fn address_space_cause(
        index: usize,
        incarnation: u64,
        cause: spaces::notification::SpaceWaitCause,
    ) -> Option<Self> {
        if index >= spaces::ADDRESS_SPACES {
            None
        } else {
            if incarnation == 0 {
                None
            } else {
                Some(Self {
                    index: cause_queue_index(index, cause) as u32,
                    generation: incarnation,
                })
            }
        }
    }

    pub(crate) fn live_space_cause(
        index: usize,
        incarnation: u64,
        cause: spaces::notification::SpaceWaitCause,
    ) -> Self {
        assert!(index < spaces::ADDRESS_SPACES && incarnation != 0);
        Self {
            index: cause_queue_index(index, cause) as u32,
            generation: incarnation,
        }
    }
    fn from_retained_registration(index: u32, generation: u64) -> Option<Self> {
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
        if index == 0 || index == u64::MAX || generation == 0 {
            None
        } else {
            Some(Self { index, generation })
        }
    }

    /// An owned metadata request wait; no IPC operation arena owns this token.
    pub const fn metadata_request(generation: u64) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self {
                index: u64::MAX,
                generation,
            })
        }
    }

    pub const fn metadata_generation(&self) -> Option<u64> {
        if self.index == u64::MAX {
            Some(self.generation)
        } else {
            None
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

/// Linear effect custody passed from a queue holder after unlocking. The
/// delivery venue owns SGIs and any required host handback.
#[must_use = "queue completion effects must be delivered after unlock"]
pub struct OwnedObjectWakeEffects<'a> {
    zone: &'a ZoneTables,
    key: ObjectWaitKey,
    waker: Waker,
    effects: WakeEffects,
    handed: u32,
}
impl OwnedObjectWakeEffects<'_> {
    pub(crate) fn missing_venue(self) {
        assert_eq!(
            self.zone
                .object_queue(self.key.index as usize)
                .completion_mode
                .load(Ordering::Acquire),
            0,
            "completion-enabled queue requires an effect delivery venue"
        );
    }

    pub fn into_parts(mut self) -> (Waker, WakeEffects) {
        assert_eq!(self.handed, 0, "owned handbacks require delivery");
        (self.waker, core::mem::take(&mut self.effects))
    }
    /// Host venue consumes exact detached claims after queue unlock.
    pub fn deliver_handbacks(mut self, handed: &mut impl FnMut(RecordRef)) -> (Waker, WakeEffects) {
        let zone = self.zone;
        while let Some(id) = RecordId::from_raw(self.handed) {
            let rec = zone.record(id);
            self.handed = rec.object.next.load(Ordering::Relaxed);
            let transfer = zone.completion_transfer(id);
            if let Some(record) = transfer.publish() {
                handed(record);
            }
        }
        (self.waker, core::mem::take(&mut self.effects))
    }
    /// Guest venue moves detached claims to the existing carrier handback
    /// boundary. The caller must force that boundary after publication.
    pub fn defer_handbacks(mut self) -> (Waker, WakeEffects, bool) {
        let zone = self.zone;
        let deferred = self.handed != 0;
        if deferred {
            let mut tail = self.handed;
            loop {
                let next = zone
                    .record(RecordId(tail))
                    .object
                    .next
                    .load(Ordering::Relaxed);
                if next == 0 {
                    break;
                }
                tail = next;
            }
            zone.completion_handbacks
                .push(self.handed, tail, |previous, next| {
                    zone.record(RecordId(previous))
                        .object
                        .next
                        .store(next, Ordering::Release)
                });
            self.handed = 0;
        }
        (self.waker, core::mem::take(&mut self.effects), deferred)
    }
}
impl Drop for OwnedObjectWakeEffects<'_> {
    fn drop(&mut self) {
        assert!(
            self.handed == 0 && self.effects == WakeEffects::default(),
            "owned queue completion effects were not delivered"
        );
    }
}

/// Durable exact-incarnation publication custody. A source is admitted once
/// while its object is published and lends queue-lock-free counted tickets.
/// Its Rust borrow excludes source retirement during derivation; a detached
/// source requires the same exclusion from its owning shared object guard.
#[must_use = "retain publication custody until object retirement"]
pub struct ObjectNotificationSource<'a> {
    ticket: ObjectNotificationTicket<'a>,
}
impl<'a> ObjectNotificationSource<'a> {
    pub fn key(&self) -> ObjectWaitKey {
        self.ticket.key
    }
    pub fn borrow(&self) -> BorrowedObjectNotificationSource<'_, 'a> {
        BorrowedObjectNotificationSource {
            zone: self.ticket.zone,
            key: self.ticket.key,
            _source: core::marker::PhantomData,
        }
    }
    pub fn reserve(&self) -> ObjectNotificationTicket<'a> {
        self.borrow().reserve()
    }
    /// Move this source's one admission into its owner-protected record.
    pub fn detach(self) -> ObjectWaitKey {
        self.ticket.detach()
    }
}

/// Borrowed derivation authority. Dropping a view never releases the durable
/// source's admission. The scope borrow excludes retirement during reserve;
/// each derived ticket thereafter owns its own independently counted custody.
pub struct BorrowedObjectNotificationSource<'scope, 'zone> {
    zone: &'zone ZoneTables,
    key: ObjectWaitKey,
    _source: core::marker::PhantomData<&'scope ()>,
}
impl<'scope, 'zone> BorrowedObjectNotificationSource<'scope, 'zone> {
    pub(crate) fn from_live_admission(
        zone: &'zone ZoneTables,
        key: ObjectWaitKey,
        _admission: &'scope crate::spaces::notification::SpaceNotificationLease<'zone>,
    ) -> Self {
        Self {
            zone,
            key,
            _source: core::marker::PhantomData,
        }
    }

    pub fn reserve(&self) -> ObjectNotificationTicket<'zone> {
        let queue = self.zone.object_queue(self.key.index as usize);
        // The borrowed source retains a publisher, excluding rebind while
        // deriving. No queue lock, retry loop, or owning source reconstruction.
        assert_eq!(
            queue.generation.load(Ordering::Acquire),
            self.key.generation,
            "retained source incarnation"
        );
        let previous = queue.publishers.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous != 0 && previous != u64::MAX,
            "source publisher exhaustion"
        );
        ObjectNotificationTicket {
            zone: self.zone,
            key: self.key,
            retained: true,
        }
    }
}

/// Linear notification custody; no source may be consumed before admission.
#[must_use = "notification admission must be published, detached, or cancelled"]
pub struct ObjectNotificationTicket<'a> {
    zone: &'a ZoneTables,
    key: ObjectWaitKey,
    retained: bool,
}
impl<'a> ObjectNotificationTicket<'a> {
    pub fn into_source(self) -> ObjectNotificationSource<'a> {
        ObjectNotificationSource { ticket: self }
    }
    pub fn key(&self) -> ObjectWaitKey {
        self.key
    }
    /// Move custody into an authority's exact-generation durable record.
    pub fn detach(mut self) -> ObjectWaitKey {
        self.retained = false;
        self.key
    }
    /// Never waits or retries. A current holder or this publisher owns delivery.
    pub fn publish(self, waker: Waker, completion: &dyn Fn(OwnedObjectWakeEffects)) {
        let revision = self.advance_revision(waker, completion);
        revision.publish();
    }
    /// Advance the producer revision while its resource is still excluded.
    /// The returned receipt must publish after that resource is unlocked.
    pub(crate) fn advance_revision<'c>(
        self,
        waker: Waker,
        completion: &'c dyn Fn(OwnedObjectWakeEffects),
    ) -> ObjectNotificationPublication<'a, 'c> {
        let queue = self.zone.object_queue(self.key.index as usize);
        assert_eq!(
            queue.generation.load(Ordering::Acquire),
            self.key.generation,
            "admitted notification incarnation"
        );
        let previous = queue.epoch.fetch_add(1, Ordering::SeqCst);
        assert!(previous != u64::MAX, "notification epoch exhaustion");
        ObjectNotificationPublication {
            ticket: self,
            waker,
            completion,
        }
    }
}
#[must_use = "publish the advanced producer revision after resource unlock"]
pub(crate) struct ObjectNotificationPublication<'a, 'c> {
    ticket: ObjectNotificationTicket<'a>,
    waker: Waker,
    completion: &'c dyn Fn(OwnedObjectWakeEffects),
}
impl ObjectNotificationPublication<'_, '_> {
    pub fn publish(mut self) {
        self.publish_inner();
    }
    fn publish_inner(&mut self) {
        if !self.ticket.retained {
            return;
        }
        let waker = self.waker;
        let completion = self.completion;
        let key = self.ticket.key;
        self.ticket.retained = false;
        let queue = self.ticket.zone.object_queue(key.index as usize);
        queue
            .notification_waker
            .store(encode_notification_waker(waker), Ordering::Release);
        let state = queue.lock.fetch_or(NOTIFY_PENDING, Ordering::SeqCst);
        // The pending bit/queue holder now owns notification delivery. Release
        // publisher custody before calling a host callback that may unwind.
        queue.publishers.fetch_sub(1, Ordering::AcqRel);
        if state == 0
            && queue
                .lock
                .compare_exchange(
                    NOTIFY_PENDING,
                    OWNED_LOCK | NOTIFY_PENDING,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        {
            drop(ObjectWaitGuard {
                zone: self.ticket.zone,
                key,
                completion: Some(completion),
            });
        }
    }
}
impl Drop for ObjectNotificationPublication<'_, '_> {
    fn drop(&mut self) {
        self.publish_inner();
    }
}
impl Drop for ObjectNotificationTicket<'_> {
    fn drop(&mut self) {
        if self.retained {
            self.zone
                .object_queue(self.key.index as usize)
                .publishers
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}
// This tag participates in OBJECT_WAIT_PROTOCOL even though the stored
// word has not changed size. A host publisher owns no EL1 execution slot.
const HOST_NOTIFICATION_WAKER: u32 = ZONE_SLOTS as u32;
fn encode_notification_waker(waker: Waker) -> u32 {
    match waker {
        Waker::El1 { slot } => u32::from(slot.raw()),
        Waker::Host => HOST_NOTIFICATION_WAKER,
    }
}
fn decode_notification_waker(word: u32) -> Waker {
    if word == HOST_NOTIFICATION_WAKER {
        return Waker::Host;
    }
    assert!(word < HOST_NOTIFICATION_WAKER, "valid notification waker");
    Waker::El1 {
        slot: SlotId::new(word as u8),
    }
}
const OWNED_LOCK: u32 = 2;
const NOTIFY_PENDING: u32 = 4;

#[repr(C)]
pub(super) struct ObjectQueue {
    lock: AtomicU32,
    head: AtomicU32,
    tail: AtomicU32,
    generation: AtomicU64,
    epoch: AtomicU64,
    /// Appended mode: completion-enabled queues require a delivery hook.
    completion_mode: AtomicU32,
    notification_waker: AtomicU32,
    publishers: AtomicU64,
}

#[repr(C)]
pub(super) struct ObjectRecord {
    queue: AtomicU32,
    prev: AtomicU32,
    next: AtomicU32,
    /// 1: the park's deadline ended it ([`ZoneTables::expire_timer`]), not
    /// a readiness notification. Cleared by every park; read by the adapter
    /// after it takes the operation token.
    expired: AtomicU32,
    generation: AtomicU64,
    operation: AtomicU64,
    operation_generation: AtomicU64,
}

/// The queue guard also authenticates its zone, index and incarnation. It
/// cannot be used with a different zone's queue by accident.
pub struct ObjectWaitGuard<'a> {
    zone: &'a ZoneTables,
    key: ObjectWaitKey,
    completion: Option<&'a dyn Fn(OwnedObjectWakeEffects)>,
}

// A host predicate may unwind before the record is parked. Keep the newly
// linked operation private until both rechecks pass, and undo it on any exit.
struct EnrollmentRollback<'g, 'z> {
    queue: &'g ObjectWaitGuard<'z>,
    record: RecordId,
    armed: bool,
}
impl Drop for EnrollmentRollback<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            self.queue.unlink(self.record);
            self.queue
                .zone
                .record(self.record)
                .object
                .operation
                .store(0, Ordering::Release);
        }
    }
}

impl Drop for ObjectWaitGuard<'_> {
    fn drop(&mut self) {
        let queue = self.queue();
        let Some(completion) = self.completion else {
            queue.lock.store(0, Ordering::Release);
            return;
        };
        // Atomic unlock either wins before publication (the publisher takes
        // the unlocked pending queue), or observes the publisher's bit and
        // owns its notification. No retry, spin, bitmap scan, or parked worker.
        if queue
            .lock
            .compare_exchange(OWNED_LOCK, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return;
        }
        let waker = decode_notification_waker(queue.notification_waker.load(Ordering::Acquire));
        let mut effects = WakeEffects::default();
        let handed = self.drain_completion(waker, &mut effects);
        // Publishers coalesce while this holder drains. No new enrollment can
        // occur under this lock; every publication still advances the epoch.
        queue.lock.store(0, Ordering::SeqCst);
        completion(OwnedObjectWakeEffects {
            zone: self.zone,
            key: self.key,
            waker,
            effects,
            handed,
        });
    }
}

impl ObjectWaitGuard<'_> {
    fn drain_completion(&self, waker: Waker, effects: &mut WakeEffects) -> u32 {
        let mut handed = 0;
        let mut cursor = self.queue().head.load(Ordering::Relaxed);
        while let Some(record) = RecordId::from_raw(cursor) {
            let rec = self.zone.record(record);
            cursor = rec.object.next.load(Ordering::Relaxed);
            let from @ Claim::Parked { seq } = rec.claim() else {
                continue;
            };
            let placed = match waker {
                Waker::El1 { slot } => self.zone.claim_for_el1_with_wait(
                    (record, seq, 0),
                    slot,
                    effects,
                    || self.unlink(record),
                    true,
                ),
                Waker::Host => {
                    match self
                        .zone
                        .place_in_guest(record, from, None, &BoundedSpin(0), |rec| {
                            self.unlink(record);
                            self.zone.mark_woken(rec, 0);
                        }) {
                        Placement::Placed(placement) => {
                            if placement.resched {
                                effects.push_sgi(placement.slot);
                            }
                            true
                        }
                        Placement::Lost => true,
                        Placement::NoSlot => false,
                    }
                }
            };
            if placed {
                continue;
            }
            if let Some(transfer) = self
                .zone
                .begin_host_transfer(self.zone.record_ref(record), from)
            {
                if waker == Waker::Host {
                    self.zone
                        .counters
                        .host_wakes
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.unlink(record);
                self.zone.mark_woken(rec, 0);
                rec.object.next.store(handed, Ordering::Relaxed);
                handed = record.raw();
                // The intrusive receipt exclusively owns this transfer.
                let _ = transfer;
            }
        }
        handed
    }
    fn queue(&self) -> &ObjectQueue {
        self.zone.object_queue(self.key.index as usize)
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
        self.queue()
            .epoch
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| ObjectWaitError::Exhausted)?;
        let mut report = HostObjectWakeReport::default();
        let mut cursor = self.queue().head.load(Ordering::Relaxed);
        while let Some(record) = RecordId::from_raw(cursor) {
            let rec = self.zone.record(record);
            cursor = rec.object.next.load(Ordering::Relaxed);
            report.visited += 1;
            let from @ Claim::Parked { .. } = rec.claim() else {
                continue;
            };
            match self
                .zone
                .place_in_guest(record, from, None, &SpinForever, |rec| {
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
        self.park_until(snapshot, record, operation, 0)
    }

    /// [`Self::park`] bounded by `deadline` (a `CNTVCT` value; 0: untimed).
    /// A timed park is ended by whichever comes first: a notification, or
    /// the timer of the record's home slot ([`ZoneTables::arm_timer`], armed
    /// by the parker after this returns), which queues the record with its
    /// operation and [`ZoneRecord::object_wait_expired`] set. Both claim the
    /// record under this queue's lock, so exactly one wins.
    pub fn park_until(
        &self,
        snapshot: ObjectWaitSnapshot,
        record: RecordId,
        operation: OperationToken,
        deadline: u64,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        self.park_until_rechecked(snapshot, record, operation, deadline, || true)
    }

    /// Recheck a nonblocking resource predicate after linking, before parking.
    /// The producer's revision is also checked after this predicate. A false
    /// result returns the same operation to its current execution owner.
    pub fn park_rechecked(
        &self,
        snapshot: ObjectWaitSnapshot,
        record: RecordId,
        operation: OperationToken,
        still_blocked: impl FnOnce() -> bool,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        self.park_until_rechecked(snapshot, record, operation, 0, still_blocked)
    }
    fn park_until_rechecked(
        &self,
        snapshot: ObjectWaitSnapshot,
        record: RecordId,
        operation: OperationToken,
        deadline: u64,
        still_blocked: impl FnOnce() -> bool,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        if deadline != 0 && self.completion.is_some() {
            return Err((ObjectWaitError::Occupied, operation));
        }
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
        let mut rollback = EnrollmentRollback {
            queue: self,
            record,
            armed: true,
        };
        if !still_blocked() || snapshot.epoch != self.queue().epoch.load(Ordering::SeqCst) {
            return Err((ObjectWaitError::Changed, operation));
        }
        rollback.armed = false;
        rec.object.expired.store(0, Ordering::Relaxed);
        self.zone.set_deadline(record, deadline);
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
        self.queue()
            .epoch
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| ObjectWaitError::Exhausted)?;
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

    /// Whether this record's last object park ended at its deadline rather
    /// than by a notification. Meaningful to the owner of the record's
    /// context once the record was claimed off its park.
    pub fn object_wait_expired(&self) -> bool {
        self.object.expired.load(Ordering::Acquire) != 0
    }

    /// Transfer a pending operation to its adapter exactly once.
    ///
    /// # Safety
    /// Caller exclusively owns the record's context under the claim protocol,
    /// and all registrations have been unlinked. In guest it must have loaded
    /// the record's exact MM and task identity before touching user memory.
    pub unsafe fn take_object_operation(&self) -> Option<OperationToken> {
        let index = self.object.operation.swap(0, Ordering::AcqRel);
        let generation = self.object.operation_generation.load(Ordering::Relaxed);
        if index == u64::MAX {
            OperationToken::metadata_request(generation)
        } else {
            OperationToken::new(index, generation)
        }
    }
}

impl ZoneTables {
    fn object_queue(&self, index: usize) -> &ObjectQueue {
        if index < ORIGINAL_OBJECT_WAIT_QUEUES {
            &self.object_waits[index]
        } else if index < DELEGATED_FILE_WAIT_BASE {
            &self.space_cause_waits[index - ORIGINAL_OBJECT_WAIT_QUEUES]
        } else {
            &self.delegated_file_waits[index - DELEGATED_FILE_WAIT_BASE]
        }
    }

    fn completion_transfer(&self, id: RecordId) -> HostTransfer<'_> {
        let claim = self.record(id).claim();
        assert!(
            matches!(claim, Claim::Transferring { .. }),
            "completion chain exact transfer custody"
        );
        let seq = claim.seq();
        HostTransfer {
            zone: self,
            record: self.record_ref(id),
            seq,
        }
    }
    /// Called at a notified host boundary, never as a periodic poll.
    pub fn take_completion_handbacks(
        &self,
        wait: &impl LockWait,
        handed: &mut impl FnMut(RecordRef),
    ) {
        // Host boundary only. Producers never acquire this consumer lock.
        let mut attempt = 0;
        while self
            .completion_consumer
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            assert!(
                wait.wait(attempt),
                "completion consumer must retain delivery custody"
            );
            attempt = attempt.saturating_add(1);
        }
        while let Some(id) = unsafe {
            self.completion_handbacks.pop(
                |id| {
                    self.record(RecordId(id))
                        .object
                        .next
                        .load(Ordering::Acquire)
                },
                |id, next| {
                    self.record(RecordId(id))
                        .object
                        .next
                        .store(next, Ordering::Release)
                },
            )
        } {
            if let Some(record) = self.completion_transfer(RecordId(id)).publish() {
                handed(record);
            }
        }
        self.completion_consumer.store(0, Ordering::Release);
    }
    fn lock_object_index(
        &self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
    ) -> Option<ObjectWaitGuard<'_>> {
        let queue = self.object_queue(key.index as usize);
        let mut attempt = 0;
        loop {
            if queue
                .lock
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(ObjectWaitGuard {
                    zone: self,
                    key,
                    completion: None,
                });
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
        if self
            .object_queue(key.index as usize)
            .completion_mode
            .load(Ordering::Acquire)
            != 0
        {
            return Err(ObjectWaitError::Occupied);
        }
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

    /// Generic admission. Rebinding cannot pass an admitted publisher or a
    /// holder responsible for its deferred effects.
    pub fn bind_object_wait_with_completion(
        &self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
        completion: &dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<(), ObjectWaitError> {
        let guard = self.lock_completion_index(key, wait, completion)?;
        let queue = guard.queue();
        if queue.generation.load(Ordering::Acquire) >= key.generation {
            return Err(ObjectWaitError::Stale);
        }
        if queue.head.load(Ordering::Relaxed) != NIL
            || queue.publishers.load(Ordering::Acquire) != 0
        {
            return Err(ObjectWaitError::Occupied);
        }
        queue.completion_mode.store(1, Ordering::Release);
        queue.generation.store(key.generation, Ordering::Release);
        queue.epoch.store(1, Ordering::SeqCst);
        Ok(())
    }
    fn lock_completion_index<'a>(
        &'a self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
        completion: &'a dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<ObjectWaitGuard<'a>, ObjectWaitError> {
        let queue = self.object_queue(key.index as usize);
        let mut attempt = 0;
        loop {
            let state = queue.lock.load(Ordering::SeqCst);
            if (state == 0 || state == NOTIFY_PENDING)
                && queue
                    .lock
                    .compare_exchange(
                        state,
                        OWNED_LOCK | state,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
            {
                // A pending notification always names the current incarnation.
                let actual = queue.generation.load(Ordering::Acquire);
                let guard = ObjectWaitGuard {
                    zone: self,
                    key: ObjectWaitKey {
                        index: key.index,
                        generation: actual,
                    },
                    completion: Some(completion),
                };
                return Ok(guard);
            }
            if !wait.wait(attempt) {
                return Err(ObjectWaitError::Busy);
            }
            attempt = attempt.saturating_add(1);
        }
    }
    pub fn completion_enabled(&self, key: ObjectWaitKey) -> bool {
        self.object_queue(key.index as usize)
            .completion_mode
            .load(Ordering::Acquire)
            != 0
    }
    pub fn object_wait_with_completion<'a>(
        &'a self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
        completion: &'a dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<ObjectWaitGuard<'a>, ObjectWaitError> {
        let guard = self.lock_completion_index(key, wait, completion)?;
        if guard.queue().completion_mode.load(Ordering::Acquire) == 0
            || guard.key.generation != key.generation
        {
            return Err(ObjectWaitError::Stale);
        }
        Ok(guard)
    }
    /// Reserve before a consuming operation becomes ready. The ticket pins
    /// this exact queue incarnation until cancellation or publication.
    pub fn admit_object_notification<'a>(
        &'a self,
        key: ObjectWaitKey,
        wait: &impl LockWait,
        completion: &dyn Fn(OwnedObjectWakeEffects),
    ) -> Result<ObjectNotificationTicket<'a>, ObjectWaitError> {
        if !self.completion_handbacks.initialize() {
            return Err(ObjectWaitError::Busy);
        }
        let guard = self.object_wait_with_completion(key, wait, completion)?;
        guard
            .queue()
            .publishers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| ObjectWaitError::Exhausted)?;
        Ok(ObjectNotificationTicket {
            zone: self,
            key,
            retained: true,
        })
    }
    /// Reconstitute custody moved into an owner-owned, exact-generation record.
    ///
    /// # Safety
    /// The caller exclusively owns one detached admission for this key.
    pub unsafe fn retained_object_notification(
        &self,
        key: ObjectWaitKey,
    ) -> ObjectNotificationTicket<'_> {
        ObjectNotificationTicket {
            zone: self,
            key,
            retained: true,
        }
    }
    pub(crate) fn notification_generation(&self, key: ObjectWaitKey) -> u64 {
        self.object_queue(key.index as usize)
            .generation
            .load(Ordering::Acquire)
    }
    pub(crate) fn notification_snapshot(&self, key: ObjectWaitKey) -> ObjectWaitSnapshot {
        let queue = self.object_queue(key.index as usize);
        assert_eq!(queue.generation.load(Ordering::Acquire), key.generation);
        ObjectWaitSnapshot {
            key,
            epoch: queue.epoch.load(Ordering::SeqCst),
        }
    }
    /// Lock-free census of queue `index` (never takes its lock).
    pub fn object_queue_census(&self, index: u32) -> Option<ObjectQueueCensus> {
        if index as usize >= OBJECT_WAIT_QUEUES {
            return None;
        }
        let queue = self.object_queue(index as usize);
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
        if self.completion_enabled(key) {
            return Err(ObjectWaitError::Occupied);
        }
        let guard = self
            .lock_object_index(key, wait)
            .ok_or(ObjectWaitError::Busy)?;
        if guard.queue().completion_mode.load(Ordering::Acquire) != 0 {
            return Err(ObjectWaitError::Occupied);
        }
        if guard.queue().generation.load(Ordering::Relaxed) != key.generation {
            return Err(ObjectWaitError::Stale);
        }
        Ok(guard)
    }

    /// EL1 timer: end the timed object park of `record` (parked under `seq`
    /// on `slot`, its home). Claimed under the record's queue lock, then the
    /// slot's (the lock order), exactly like a notification: the record is
    /// queued on `slot` with its operation, marked expired, and resumes at
    /// its saved entry (registers untouched). `Ok(false)`: a notification or
    /// a host claim won it first. `Err(())`: the queue lock stayed busy.
    pub(super) fn expire_object_park(
        &self,
        slot: SlotId,
        record: RecordId,
        seq: u32,
    ) -> Result<bool, ()> {
        let rec = self.record(record);
        let index = rec.object.queue.load(Ordering::Acquire);
        let Some(key) = ObjectWaitKey::from_retained_registration(
            index,
            rec.object.generation.load(Ordering::Relaxed),
        ) else {
            return Ok(false);
        };
        let guard = match self.object_wait(key, &BoundedSpin(EL1_SLOT_LOCK_SPINS)) {
            Ok(guard) => guard,
            Err(ObjectWaitError::Busy) => return Err(()),
            Err(_) => return Ok(false),
        };
        let Some(slot_guard) = self.slot_lock(slot, &SpinForever) else {
            return Err(());
        };
        if rec.object.queue.load(Ordering::Acquire) != index
            || !rec.cas(Claim::Parked { seq }, Claim::Queued { slot, seq })
        {
            return Ok(false);
        }
        rec.object.expired.store(1, Ordering::Release);
        guard.unlink(record);
        self.mark_woken(rec, 0);
        self.push_locked(&slot_guard, record, None);
        Ok(true)
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
            let Some(key) = ObjectWaitKey::from_retained_registration(
                index,
                rec.object.generation.load(Ordering::Relaxed),
            ) else {
                return;
            };
            let completion =
                |effects: OwnedObjectWakeEffects<'_>| wait.complete_object_wake(self, effects);
            let result = if self.completion_enabled(key) {
                self.object_wait_with_completion(key, wait, &completion)
            } else {
                self.object_wait(key, wait)
            };
            let Ok(guard) = result else {
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

    #[test]
    fn metadata_completion_follows_parked_record_after_slot_switch() {
        let zone = fixture(true);
        let key = ObjectWaitKey::metadata_request(17).unwrap();
        zone.bind_object_wait(key, &SpinForever).unwrap();
        let original = allocate(&zone, 101);
        let original_ref = zone.record_ref(original);
        let queue = zone.object_wait(key, &SpinForever).unwrap();
        queue
            .park(
                queue.snapshot(),
                original,
                OperationToken::metadata_request(17).unwrap(),
            )
            .unwrap();
        drop(queue);
        let mut census = std::string::String::new();
        zone.write_census(&mut census).unwrap();
        assert!(census.contains(&std::format!(
            "zone object queue {}: generation=17",
            key.index(),
        )));
        // A different guest now occupies the executor slot. Reconciliation
        // hands that record back; it must not receive the metadata wake.
        let occupant = park(&zone, 1, 202);
        notify(&zone, 1);
        assert_eq!(zone.switch_in(SLOT), Some(occupant));
        zone.leave_guest(SLOT, &SpinForever);
        assert_eq!(
            zone.handback_current(SLOT, occupant),
            CurrentHandback::HandedBack
        );
        let occupant_claim = zone.record(occupant).claim();
        let queue = zone.object_wait(key, &SpinForever).unwrap();
        let mut handed = Vec::new();
        let report = queue
            .notify_object_host(&mut |record| handed.push(record), &mut |_| {})
            .unwrap();
        assert_eq!(report.visited, 1);
        assert_eq!(handed.as_slice(), &[original_ref]);
        assert_eq!(zone.record(occupant).claim(), occupant_claim);
        assert_eq!(
            unsafe { zone.record(original).take_object_operation() }
                .unwrap()
                .metadata_generation(),
            Some(17)
        );
        drop(queue);
        // A later incarnation cannot alias an outstanding earlier wait.
        let next = ObjectWaitKey::metadata_request(18).unwrap();
        zone.bind_object_wait(next, &SpinForever).unwrap();
        assert!(zone.object_wait(key, &SpinForever).is_err());
    }

    #[test]
    fn metadata_wait_cancellation_unlinks_its_reserved_queue() {
        let zone = fixture(false);
        let key = ObjectWaitKey::metadata_request(1).unwrap();
        zone.bind_object_wait(key, &SpinForever).unwrap();
        let record = allocate(&zone, 1);
        let queue = zone.object_wait(key, &SpinForever).unwrap();
        queue
            .park(
                queue.snapshot(),
                record,
                OperationToken::metadata_request(1).unwrap(),
            )
            .unwrap();
        drop(queue);
        assert_eq!(
            zone.claim_for_host(
                zone.record_ref(record),
                None,
                Handback::Control,
                &SpinForever
            ),
            HostClaim::Claimed
        );
        let queue = zone.object_wait(key, &SpinForever).unwrap();
        assert_eq!(
            queue
                .notify_object_host(
                    &mut |_| panic!("cancelled metadata record woke"),
                    &mut |_| {}
                )
                .unwrap()
                .visited,
            0
        );
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
            lifecycle_page: 0,
            control_slot: 0,
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
    fn completion_held_queue_publication_advances_epoch_and_holder_delivers() {
        use std::cell::Cell;
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let delivered = Cell::new(0);
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            assert!(!zone.object_queue_census(key.index()).unwrap().locked);
            let (_, effects) =
                owned.deliver_handbacks(&mut |_| panic!("available slot should queue"));
            assert!(effects.queued_own);
            delivered.set(delivered.get() + 1);
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        assert!(matches!(
            zone.object_wait(key, &BoundedSpin(0)),
            Err(ObjectWaitError::Occupied)
        ));
        let ticket = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap();
        let record = allocate(&zone, 401);
        let guard = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let snapshot = guard.snapshot();
        guard
            .park(snapshot, record, OperationToken::new(401, 11).unwrap())
            .unwrap();
        ticket.publish(Waker::El1 { slot: SLOT }, &completion);
        assert_eq!(
            delivered.get(),
            0,
            "publication must return while queue remains held"
        );
        assert!(zone.object_queue_census(key.index()).unwrap().epoch > snapshot.epoch);
        let other = allocate(&zone, 402);
        assert!(matches!(
            guard.park(snapshot, other, OperationToken::new(402, 11).unwrap()),
            Err((ObjectWaitError::Changed, _))
        ));
        drop(guard);
        assert_eq!(delivered.get(), 1);
        assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
        assert!(matches!(zone.record(record).claim(), Claim::Queued { .. }));
        zone.free_record(other);
    }

    #[test]
    fn completion_admission_blocks_rebind_and_rejects_stale_incarnation() {
        let zone = fixture(false);
        let old = ObjectWaitKey::new(3, 11).unwrap();
        let new = ObjectWaitKey::new(3, 12).unwrap();
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            let _ = owned.into_parts();
        };
        zone.bind_object_wait_with_completion(old, &BoundedSpin(0), &completion)
            .unwrap();
        let ticket = zone
            .admit_object_notification(old, &BoundedSpin(0), &completion)
            .unwrap();
        assert_eq!(
            zone.bind_object_wait_with_completion(new, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Occupied)
        );
        let guard = zone
            .object_wait_with_completion(old, &BoundedSpin(0), &completion)
            .unwrap();
        ticket.publish(Waker::El1 { slot: SLOT }, &completion);
        assert_eq!(
            zone.bind_object_wait_with_completion(new, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Busy)
        );
        drop(guard);
        zone.bind_object_wait_with_completion(new, &BoundedSpin(0), &completion)
            .unwrap();
        assert!(matches!(
            zone.admit_object_notification(old, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Stale)
        ));
        assert_eq!(
            zone.object_queue_census(new.index()).unwrap().generation,
            12
        );
    }

    #[test]
    fn completion_held_slot_transfers_exact_saved_operation_to_host_boundary() {
        for held in [false, true] {
            let zone = fixture(true);
            let key = ObjectWaitKey::new(3, 11).unwrap();
            let completion = |owned: OwnedObjectWakeEffects<'_>| {
                let (_, _, deferred) = owned.defer_handbacks();
                assert!(deferred);
            };
            zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
                .unwrap();
            let ticket = zone
                .admit_object_notification(key, &BoundedSpin(0), &completion)
                .unwrap();
            let record = allocate(&zone, 403);
            // SAFETY: unpublished fixture record is exclusively owned here.
            unsafe {
                let context = zone.record(record).ctx_mut();
                context.pc = 0x1000;
                context.x[8] = 215;
                context.x[0] = 0x4000;
            }
            {
                let guard = zone
                    .object_wait_with_completion(key, &BoundedSpin(0), &completion)
                    .unwrap();
                guard
                    .park(
                        guard.snapshot(),
                        record,
                        OperationToken::new(403, 11).unwrap(),
                    )
                    .unwrap();
            }
            let slot = if held {
                Some(zone.slot_lock(SLOT, &BoundedSpin(0)).unwrap())
            } else {
                zone.leave_guest(SLOT, &SpinForever);
                zone.drive(SLOT, 999); // Original waker executor was detached/replaced.
                None
            };
            ticket.publish(Waker::El1 { slot: SLOT }, &completion);
            assert!(matches!(
                zone.record(record).claim(),
                Claim::Transferring { .. }
            ));
            assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
            drop(slot);
            let mut delivered = Vec::new();
            zone.take_completion_handbacks(&SpinForever, &mut |r| delivered.push(r));
            assert_eq!(delivered, [zone.record_ref(record)]);
            assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
            assert_eq!(zone.record(record).handback(), Some(Handback::Resumed));
            // SAFETY: boundary now owns this exact Host record and operation.
            let rec = zone.record(record);
            assert_eq!(unsafe { rec.ctx_mut() }.pc, 0x1000);
            assert_eq!(unsafe { rec.take_object_operation() }.unwrap().index(), 403);
        }
    }

    #[test]
    fn completion_internal_cancel_unlink_delivers_pending_wake_after_unlock() {
        use std::cell::Cell;
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let delivered = Cell::new(false);
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            assert!(!zone.object_queue_census(key.index()).unwrap().locked);
            let _ = owned.deliver_handbacks(&mut |_| {});
            delivered.set(true);
        };
        struct Venue<'a>(&'a dyn Fn(OwnedObjectWakeEffects));
        impl LockWait for Venue<'_> {
            fn wait(&self, _: u32) -> bool {
                false
            }
            fn complete_object_wake(&self, _: &ZoneTables, effects: OwnedObjectWakeEffects) {
                (self.0)(effects);
            }
        }
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let ticket = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap();
        let cancelled = allocate(&zone, 404);
        let other = allocate(&zone, 405);
        let guard = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        guard
            .park(
                guard.snapshot(),
                cancelled,
                OperationToken::new(404, 11).unwrap(),
            )
            .unwrap();
        guard
            .park(
                guard.snapshot(),
                other,
                OperationToken::new(405, 11).unwrap(),
            )
            .unwrap();
        let transfer = zone
            .begin_host_transfer(zone.record_ref(cancelled), zone.record(cancelled).claim())
            .unwrap();
        assert_eq!(
            zone.claim_for_host(
                zone.record_ref(cancelled),
                None,
                Handback::Cancelled,
                &Venue(&completion)
            ),
            HostClaim::Deferred
        );
        ticket.publish(Waker::El1 { slot: SLOT }, &completion);
        // Leave the already pending queue unlocked for internal cleanup; the
        // exact host transfer, not a queue observer, must supply delivery.
        core::mem::forget(guard);
        zone.object_queue(key.index as usize)
            .lock
            .store(NOTIFY_PENDING, Ordering::Release);
        let ready = transfer.finish(&Venue(&completion)).unwrap();
        assert_eq!(ready, zone.record_ref(cancelled));
        assert_eq!(zone.record(cancelled).handback(), Some(Handback::Cancelled));
        assert!(delivered.get());
        assert!(matches!(zone.record(other).claim(), Claim::Queued { .. }));
        assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
    }

    #[test]
    fn completion_publication_unlock_races_always_deliver() {
        use std::sync::atomic::AtomicUsize;
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let deliveries = AtomicUsize::new(0);
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            let _ = owned.deliver_handbacks(&mut |_| {});
            deliveries.fetch_add(1, Ordering::SeqCst);
        };
        zone.bind_object_wait_with_completion(key, &SpinForever, &completion)
            .unwrap();
        for tid in 500..564 {
            let ticket = zone
                .admit_object_notification(key, &SpinForever, &completion)
                .unwrap();
            let record = allocate(&zone, tid);
            let guard = zone
                .object_wait_with_completion(key, &SpinForever, &completion)
                .unwrap();
            guard
                .park(
                    guard.snapshot(),
                    record,
                    OperationToken::new(tid, 11).unwrap(),
                )
                .unwrap();
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    ticket.publish(Waker::El1 { slot: SLOT }, &completion);
                });
                barrier.wait();
                drop(guard);
            });
            assert_eq!(zone.object_queue_census(key.index()).unwrap().waiters, 0);
            assert!(matches!(zone.record(record).claim(), Claim::Queued { .. }));
        }
        assert_eq!(deliveries.load(Ordering::SeqCst), 64);
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
                lifecycle_page: 0,
                control_slot: 0,
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
                assert_eq!(
                    zone.release_current(SLOT, switched.record, &SpinForever),
                    crate::CurrentRelease::Released
                );
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
        for kind in [
            Handback::Signal,
            Handback::Control,
            Handback::Cancelled,
            Handback::GroupStop,
        ] {
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

    /// A timed park of the slot's home record (an epoll wait with a finite
    /// timeout): parked with `deadline` and armed on the slot's timer.
    fn park_home_until(zone: &ZoneTables, index: u32, deadline: u64) -> RecordId {
        let record = zone
            .current_or_new(
                SLOT,
                ThreadIdentity {
                    tid: 77,
                    serial: 77,
                    mm: MM,
                    file_table: 99,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                },
            )
            .unwrap();
        let seq = zone.next_seq(record);
        let guard = zone.object_wait(key(index), &SpinForever).unwrap();
        guard
            .park_until(
                guard.snapshot(),
                record,
                OperationToken::new(77, 1).unwrap(),
                deadline,
            )
            .unwrap();
        zone.arm_timer(SLOT, record, seq).unwrap();
        drop(guard);
        zone.clear_current(SLOT);
        record
    }

    /// The deadline alone ends the park: the record is queued on its home
    /// slot with its operation, marked expired, its registers untouched, and
    /// the queue no longer holds it.
    #[test]
    fn el1_epoll_timed_object_park_expires_at_its_deadline() {
        let zone = fixture(true);
        let record = park_home_until(&zone, 1, 1_000);
        assert_eq!(zone.timer_deadline(SLOT), Some(1_000));
        assert_eq!(zone.expire_timer(SLOT, 999, 0), Ok(false), "not yet");
        assert_eq!(zone.expire_timer(SLOT, 1_000, 0), Ok(true));
        let rec = zone.record(record);
        assert!(matches!(rec.claim(), Claim::Queued { slot, .. } if slot == SLOT));
        assert!(rec.object_wait_expired());
        assert!(rec.has_object_operation());
        assert_eq!(rec.handback(), Some(Handback::Resumed));
        assert_eq!(notify(&zone, 1).0.visited, 0, "unlinked from its queue");
        assert_eq!(zone.timer_deadline(SLOT), None);
        let switched = zone.switch_in_full(SLOT).unwrap();
        assert_eq!(switched.record, record);
        assert_eq!(
            switched.result, None,
            "the SVC re-enters with its registers"
        );
        // SAFETY: the test owns the switched-in context.
        assert_eq!(unsafe { rec.take_object_operation() }.unwrap().index(), 77);
    }

    /// A notification before the deadline wins: the expiry finds nothing to
    /// claim, and the record is not marked expired.
    #[test]
    fn el1_epoll_timed_object_park_woken_before_its_deadline() {
        let zone = fixture(true);
        let record = park_home_until(&zone, 1, 1_000);
        assert_eq!(notify(&zone, 1).0.queued, 1);
        assert_eq!(zone.expire_timer(SLOT, 5_000, 0), Ok(false));
        assert_eq!(
            zone.timer_deadline(SLOT),
            None,
            "the stale timer is dropped"
        );
        let rec = zone.record(record);
        assert!(!rec.object_wait_expired());
        assert!(rec.has_object_operation());
        assert_eq!(zone.slot(SLOT).queued(), 1, "queued exactly once");
    }

    /// A notification racing the deadline: exactly one claims the record,
    /// it is queued exactly once, and `expired` says which one did.
    #[test]
    fn el1_epoll_timed_object_park_wake_racing_its_deadline_claims_once() {
        for _ in 0..256 {
            let zone = fixture(true);
            let record = park_home_until(&zone, 1, 1_000);
            let barrier = Barrier::new(2);
            let (woken, expired) = std::thread::scope(|scope| {
                let waker = scope.spawn(|| {
                    barrier.wait();
                    notify(&zone, 1).0.queued
                });
                barrier.wait();
                let expired = loop {
                    match zone.expire_timer(SLOT, 1_000, 0) {
                        Ok(expired) => break expired,
                        Err(()) => core::hint::spin_loop(),
                    }
                };
                (waker.join().unwrap(), expired)
            });
            assert_eq!(u32::from(expired) + woken, 1, "exactly one claim");
            let rec = zone.record(record);
            assert_eq!(rec.object_wait_expired(), expired);
            assert!(rec.has_object_operation());
            assert_eq!(zone.slot(SLOT).queued(), 1);
            assert_eq!(notify(&zone, 1).0.visited, 0);
        }
    }

    /// A timed object park of `tid` (not the slot's home record) holding
    /// the slot's timer: a thread EL1 switched in on this vCPU.
    fn park_foreign_until(zone: &ZoneTables, index: u32, tid: u64, deadline: u64) -> RecordId {
        let record = allocate(zone, tid);
        let seq = zone.next_seq(record);
        zone.arm_timer(SLOT, record, seq).unwrap();
        let guard = zone.object_wait(key(index), &SpinForever).unwrap();
        guard
            .park_until(
                guard.snapshot(),
                record,
                OperationToken::new(tid, 1).unwrap(),
                deadline,
            )
            .unwrap();
        record
    }

    /// A slot's timer has exactly one owner, and whichever record owns it
    /// is handed to the host at every way the slot's executor leaves EL1:
    /// with its own thread running (a plain exit), with its own thread
    /// parked untimed (the settle path, before `unhome`), and before the
    /// `reset_slot` of a load. The home record's own deadline instead goes
    /// through `unhome`; a woken or stale owner leaves nothing to hand back.
    #[test]
    fn el1_epoll_slot_timer_owner_is_handed_back_at_every_exit() {
        // Plain exit, own thread running: the foreign owner is handed back.
        let zone = fixture(true);
        let foreign = park_foreign_until(&zone, 1, 300, 1_000);
        let owner = zone.timer_owner(SLOT).unwrap();
        assert_eq!(owner.record, foreign);
        let taken = zone.take_foreign_timer(SLOT).unwrap();
        assert_eq!(taken.record, zone.record_ref(foreign));
        assert_eq!(taken.seq, owner.seq);
        assert_eq!(zone.timer_owner(SLOT), None, "taken off the timer");
        assert_eq!(zone.take_foreign_timer(SLOT), None, "exactly once");
        assert_eq!(
            zone.claim_for_host(
                taken.record,
                Some(taken.seq),
                Handback::Control,
                &SpinForever
            ),
            HostClaim::Claimed
        );
        assert_eq!(notify(&zone, 1).0.visited, 0, "the claim unlinked it");

        // One owner: while it is live, no other park may take the timer;
        // the home record's timed park is refused (it forwards) too.
        let zone = fixture(true);
        let foreign = park_foreign_until(&zone, 1, 301, 1_000);
        let other = allocate(&zone, 302);
        assert_eq!(
            zone.arm_timer(SLOT, other, zone.next_seq(other)),
            Err(TimerBusy)
        );
        assert!(!zone.timer_free(SLOT));
        assert_eq!(zone.timer_owner(SLOT).unwrap().record, foreign);

        // Settle path: the home record parked untimed, the foreign record
        // owns the timer. The foreign park is handed back; `unhome` returns
        // no deadline for the home record.
        let home = zone
            .current_or_new(
                SLOT,
                ThreadIdentity {
                    tid: 77,
                    serial: 77,
                    mm: MM,
                    file_table: 99,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                },
            )
            .unwrap();
        let guard = zone.object_wait(key(2), &SpinForever).unwrap();
        guard
            .park(guard.snapshot(), home, OperationToken::new(77, 1).unwrap())
            .unwrap();
        drop(guard);
        zone.clear_current(SLOT);
        let taken = zone.take_foreign_timer(SLOT).unwrap();
        assert_eq!(taken.record, zone.record_ref(foreign));
        assert_eq!(zone.unhome(SLOT, home, 0), None);

        // The home record's own timed park is not foreign: `unhome` keeps it.
        let zone = fixture(true);
        let home = park_home_until(&zone, 1, 2_000);
        assert_eq!(zone.take_foreign_timer(SLOT), None);
        let seq = zone.timer_owner(SLOT).unwrap().seq;
        assert_eq!(zone.unhome(SLOT, home, 0), Some((seq, 2_000)));

        // Load path: hand back before the reset clears the timer.
        let zone = fixture(true);
        let foreign = park_foreign_until(&zone, 1, 303, 1_000);
        assert_eq!(
            zone.take_foreign_timer(SLOT).map(|t| t.record),
            Some(zone.record_ref(foreign))
        );
        assert!(zone.reset_slot(SLOT));
        assert_eq!(zone.timer_owner(SLOT), None);

        // A woken owner (a notification won it) is not live: nothing to
        // hand back, and the timer is free again.
        let zone = fixture(true);
        let _ = park_foreign_until(&zone, 1, 304, 1_000);
        assert_eq!(notify(&zone, 1).0.queued, 1);
        assert_eq!(zone.take_foreign_timer(SLOT), None);
        assert!(zone.timer_free(SLOT));
    }

    #[test]
    fn group_stop_survives_deferred_handback_but_preserves_completed_results() {
        for completed in [false, true] {
            let zone = fixture(true);
            let record = park(&zone, 1, 1);
            notify(&zone, 1);
            assert_eq!(zone.switch_in(SLOT), Some(record));
            let exact = zone.record_ref(record);
            assert_eq!(
                zone.claim_for_host(exact, None, Handback::GroupStop, &SpinForever),
                HostClaim::El1Held { slot: SLOT }
            );
            // A later ordinary control nudge cannot erase the stop cause.
            zone.claim_for_host(exact, None, Handback::Control, &SpinForever);
            if completed {
                // SAFETY: this slot owns the operation as its EL1 adapter.
                unsafe {
                    assert!(zone.record(record).take_object_operation().is_some());
                }
            }
            assert_eq!(
                zone.handback_current(SLOT, record),
                crate::CurrentHandback::HandedBack
            );
            assert_eq!(
                zone.record(record).handback(),
                Some(if completed {
                    Handback::Resumed
                } else {
                    Handback::GroupStop
                })
            );
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
    #[test]
    fn durable_notification_source_derives_while_queue_is_held() {
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let deliveries = std::cell::Cell::new(0);
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            assert!(!zone.object_queue_census(key.index()).unwrap().locked);
            let _ = owned.deliver_handbacks(&mut |_| {});
            deliveries.set(deliveries.get() + 1);
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap()
            .into_source();
        let guard = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let before = zone.object_queue_census(key.index()).unwrap().epoch;
        let derived = source.reserve();
        derived.publish(Waker::El1 { slot: SLOT }, &completion);
        assert_eq!(
            zone.object_queue_census(key.index()).unwrap().epoch,
            before + 1
        );
        assert!(zone.object_queue_census(key.index()).unwrap().locked);
        assert_eq!(deliveries.get(), 0);
        drop(guard);
        assert_eq!(
            deliveries.get(),
            1,
            "holder must deliver actual owned effects after unlock"
        );
        assert!(!zone.object_queue_census(key.index()).unwrap().locked);
    }
    #[test]
    fn durable_notification_source_and_derived_ticket_exclude_rebind() {
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let successor = ObjectWaitKey::new(3, 12).unwrap();
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            let _ = owned.deliver_handbacks(&mut |_| {});
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap()
            .into_source();
        let ticket = source.reserve();
        assert_eq!(
            zone.bind_object_wait_with_completion(successor, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Occupied)
        );
        drop(source);
        // Retirement of the source cannot recycle an outstanding old ticket.
        assert_eq!(
            zone.bind_object_wait_with_completion(successor, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Occupied)
        );
        ticket.publish(Waker::El1 { slot: SLOT }, &completion);
        zone.bind_object_wait_with_completion(successor, &BoundedSpin(0), &completion)
            .unwrap();
        let census = zone.object_queue_census(successor.index()).unwrap();
        assert_eq!(census.generation, 12);
        assert_eq!(
            census.epoch, 1,
            "old publication cannot wake recycled incarnation"
        );
        assert!(matches!(
            zone.object_wait_with_completion(key, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Stale)
        ));
    }
    #[test]
    fn borrowed_notification_source_cannot_retire_its_owner() {
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let successor = ObjectWaitKey::new(3, 12).unwrap();
        let completion = |owned: OwnedObjectWakeEffects<'_>| {
            let _ = owned.deliver_handbacks(&mut |_| {});
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap()
            .into_source();
        {
            let view = source.borrow();
            drop(view.reserve());
        }
        assert_eq!(
            zone.bind_object_wait_with_completion(successor, &BoundedSpin(0), &completion),
            Err(ObjectWaitError::Occupied),
            "borrowed view must not release durable admission"
        );
        drop(source);
        zone.bind_object_wait_with_completion(successor, &BoundedSpin(0), &completion)
            .unwrap();
    }
    #[test]
    fn completion_host_publisher_needs_no_el1_slot() {
        use std::cell::RefCell;
        for running in [false, true] {
            let zone = fixture(running);
            let key = ObjectWaitKey::new(3, 11).unwrap();
            let delivered = RefCell::new(Vec::new());
            let completion = |owned: OwnedObjectWakeEffects<'_>| {
                assert!(!zone.object_queue_census(key.index()).unwrap().locked);
                let (waker, effects) =
                    owned.deliver_handbacks(&mut |r| delivered.borrow_mut().push(r));
                assert_eq!(waker, Waker::Host);
                assert!(
                    !effects.queued_own && !effects.misplaced,
                    "a host publisher has no own guest slot"
                );
                if running {
                    assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), [SLOT]);
                }
            };
            zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
                .unwrap();
            let source = zone
                .admit_object_notification(key, &BoundedSpin(0), &completion)
                .unwrap()
                .into_source();
            let record = allocate(&zone, 490);
            {
                let guard = zone
                    .object_wait_with_completion(key, &BoundedSpin(0), &completion)
                    .unwrap();
                guard
                    .park(
                        guard.snapshot(),
                        record,
                        OperationToken::new(490, 11).unwrap(),
                    )
                    .unwrap();
            }
            source.reserve().publish(Waker::Host, &completion);
            if running {
                assert!(matches!(
                    zone.record(record).claim(),
                    Claim::Queued { slot: SLOT, .. }
                ));
                assert!(delivered.borrow().is_empty());
            } else {
                assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
                assert_eq!(*delivered.borrow(), [zone.record_ref(record)]);
            }
        }
    }

    #[test]
    fn completion_placement_tries_each_distinct_slot_once() {
        use std::cell::Cell;
        struct NoWait(Cell<usize>);
        impl LockWait for NoWait {
            fn wait(&self, attempt: u32) -> bool {
                assert_eq!(attempt, 1, "no repeated lock attempt");
                self.0.set(self.0.get() + 1);
                false
            }
        }
        let zone = fixture(true);
        let record = park(&zone, 1, 492);
        let guard = zone.object_wait(key(1), &BoundedSpin(0)).unwrap();
        let from = zone.record(record).claim();
        let held_slot = zone.slot_lock(SLOT, &BoundedSpin(0)).unwrap();
        let attempts = NoWait(Cell::new(0));
        assert!(matches!(
            zone.place_in_guest(record, from, None, &attempts, |_| guard.unlink(record)),
            Placement::NoSlot
        ));
        assert_eq!(attempts.0.get(), 1, "duplicate candidates do not retry");
        assert_eq!(zone.record(record).claim(), from);
        drop(held_slot);
        assert!(matches!(
            zone.place_in_guest(record, from, None, &attempts, |_| guard.unlink(record)),
            Placement::Placed(_)
        ));
        assert_eq!(attempts.0.get(), 1);
    }

    #[test]
    fn completion_host_publish_held_by_guest_delivers_owned_handback() {
        use std::cell::Cell;
        let zone = fixture(true);
        let key = ObjectWaitKey::new(3, 11).unwrap();
        let delivered = Cell::new(None);
        let guest_completion = |owned: OwnedObjectWakeEffects<'_>| {
            assert!(!zone.object_queue_census(key.index()).unwrap().locked);
            let (waker, effects, deferred) = owned.defer_handbacks();
            assert_eq!(waker, Waker::Host);
            delivered.set(Some((effects, deferred)));
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &guest_completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &guest_completion)
            .unwrap()
            .into_source();
        let record = allocate(&zone, 491);
        let guard = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &guest_completion)
            .unwrap();
        guard
            .park(
                guard.snapshot(),
                record,
                OperationToken::new(491, 11).unwrap(),
            )
            .unwrap();
        let held_slot = zone.slot_lock(SLOT, &BoundedSpin(0)).unwrap();
        std::thread::scope(|scope| {
            let (release, released) = std::sync::mpsc::channel();
            let holder = scope.spawn(move || {
                // Bound the regression witness, not the production operation.
                let forced = released
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .is_err();
                drop(held_slot);
                forced
            });
            source
                .reserve()
                .publish(Waker::Host, &|_| panic!("queue holder owns delivery"));
            assert!(delivered.get().is_none());
            drop(guard);
            let _ = release.send(());
            assert!(
                !holder.join().unwrap(),
                "completion delivery waited for a held target slot"
            );
        });
        assert_eq!(delivered.get(), Some((WakeEffects::default(), true)));
        assert!(matches!(
            zone.record(record).claim(),
            Claim::Transferring { .. }
        ));
        let mut handed = Vec::new();
        zone.take_completion_handbacks(&SpinForever, &mut |r| handed.push(r));
        assert_eq!(handed, [zone.record_ref(record)]);
        assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
        let placement = zone.place_from_host(record).unwrap();
        assert_eq!(placement.slot, SLOT);
        assert!(zone.place_from_host(record).is_none());
        let mut duplicate = Vec::new();
        zone.take_completion_handbacks(&SpinForever, &mut |r| duplicate.push(r));
        assert!(duplicate.is_empty());
        assert_eq!(zone.slot(SLOT).len.load(Ordering::Relaxed), 1);
        // SAFETY: the test owns the exact record and no executor is running.
        assert_eq!(
            unsafe { zone.record(record).take_object_operation() }.unwrap(),
            OperationToken::new(491, 11).unwrap()
        );
    }
}
