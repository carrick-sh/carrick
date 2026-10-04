//! Notification custody licensed by an authenticated delegated-inode guard.
use super::{
    BorrowedObjectNotificationSource, ObjectNotificationTicket, ObjectWaitError, ObjectWaitKey,
    OwnedObjectWakeEffects,
};
use crate::{Waker, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU32, Ordering};

/// One shared bound for delegated inode storage and its completion domain.
pub const DELEGATED_FILE_WAIT_QUEUES: usize = 128;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegatedFileWaitIndex(u8);
impl DelegatedFileWaitIndex {
    pub const fn from_index(index: usize) -> Option<Self> {
        if index < DELEGATED_FILE_WAIT_QUEUES {
            Some(Self(index as u8))
        } else {
            None
        }
    }
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}
#[derive(Clone, Copy)]
pub struct DelegatedReleaseVenue<'zone> {
    pub zone: &'zone ZoneTables,
    pub waker: Waker,
    pub deliver: for<'z> fn(&'z ZoneTables, Waker, OwnedObjectWakeEffects<'z>),
}
impl<'zone> DelegatedReleaseVenue<'zone> {
    /// Derive release custody from the live base pin protected by an inode lock.
    /// No queue admission, retry, or owning reconstruction is performed.
    ///
    /// # Safety
    /// The caller exclusively holds `lock` for this exact zone-bound inode and
    /// generation. Its authenticated inode record owns one detached source base
    /// publisher. That base pin cannot retire before this call completes. The
    /// returned custody must be owned by the inode guard, and becomes its sole
    /// unlock authority. No caller may unlock or use protected data afterward.
    pub unsafe fn retain_locked<'guard>(
        self,
        index: DelegatedFileWaitIndex,
        generation: NonZeroU64,
        lock: &'guard AtomicU32,
    ) -> Result<DelegatedLockRelease<'guard, 'zone>, ObjectWaitError> {
        let key = ObjectWaitKey::delegated_file(index, generation);
        let queue = self.zone.object_queue(key.index() as usize);
        if lock.load(Ordering::Acquire) == 0
            || queue.generation.load(Ordering::Acquire) != generation.get()
            || queue.publishers.load(Ordering::Acquire) == 0
        {
            return Err(ObjectWaitError::Stale);
        }
        let source = BorrowedObjectNotificationSource {
            zone: self.zone,
            key,
            _source: core::marker::PhantomData,
        };
        Ok(DelegatedLockRelease {
            venue: self,
            lock,
            ticket: Some(source.reserve()),
        })
    }
}

/// Exact lock plus one counted release ticket. Drop unlocks before delivering;
/// it never releases or reconstructs the detached source's base admission.
#[must_use = "the inode guard must retain its sole unlock authority"]
pub struct DelegatedLockRelease<'guard, 'zone> {
    venue: DelegatedReleaseVenue<'zone>,
    lock: &'guard AtomicU32,
    ticket: Option<ObjectNotificationTicket<'zone>>,
}
impl<'zone> DelegatedLockRelease<'_, 'zone> {
    pub fn key(&self) -> ObjectWaitKey {
        let Some(ticket) = &self.ticket else {
            unreachable!("live delegated release ticket")
        };
        ticket.key()
    }
    pub fn source(&self) -> BorrowedObjectNotificationSource<'_, 'zone> {
        BorrowedObjectNotificationSource {
            zone: self.venue.zone,
            key: self.key(),
            _source: core::marker::PhantomData,
        }
    }
}
struct Unlock<'a>(&'a AtomicU32);
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}
impl Drop for DelegatedLockRelease<'_, '_> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        let unlock = Unlock(self.lock);
        let completion = |effects: OwnedObjectWakeEffects<'_>| {
            (self.venue.deliver)(self.venue.zone, self.venue.waker, effects)
        };
        let publication = ticket.advance_revision(self.venue.waker, &completion);
        drop(unlock);
        publication.publish();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::OperationToken;
    use super::*;
    use crate::{BoundedSpin, ThreadIdentity};
    fn zone() -> std::boxed::Box<ZoneTables> {
        let ptr = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>()) };
        assert!(!ptr.is_null());
        unsafe { std::boxed::Box::from_raw(ptr.cast()) }
    }
    fn deliver(_: &ZoneTables, _: Waker, effects: OwnedObjectWakeEffects<'_>) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    #[test]
    fn delegated_domain_is_bounded_disjoint_and_appended() {
        let zone = zone();
        assert!(DelegatedFileWaitIndex::from_index(DELEGATED_FILE_WAIT_QUEUES).is_none());
        let generation = NonZeroU64::new(1).unwrap();
        let first = ObjectWaitKey::delegated_file(
            DelegatedFileWaitIndex::from_index(0).unwrap(),
            generation,
        );
        let last = ObjectWaitKey::delegated_file(
            DelegatedFileWaitIndex::from_index(DELEGATED_FILE_WAIT_QUEUES - 1).unwrap(),
            generation,
        );
        assert_eq!(
            last.index() - first.index() + 1,
            DELEGATED_FILE_WAIT_QUEUES as u32
        );
        assert!(
            first.index() as usize
                >= super::super::ORIGINAL_OBJECT_WAIT_QUEUES + super::super::EXTRA_CAUSE_QUEUES
        );
        assert_eq!(
            ObjectWaitKey::reservation_pool(generation).index() as usize,
            super::super::ADDRESS_SPACE_WAIT_BASE
        );
        assert!(ObjectWaitKey::new(first.index(), generation.get()).is_none());
        assert_eq!(
            core::mem::size_of_val(&zone.delegated_file_waits),
            DELEGATED_FILE_WAIT_QUEUES * core::mem::size_of::<super::super::ObjectQueue>()
        );
    }
    #[test]
    fn held_inode_release_notifies_after_unlock_and_retained_source_retirement() {
        let zone = zone();
        let index = DelegatedFileWaitIndex::from_index(5).unwrap();
        let generation = NonZeroU64::new(9).unwrap();
        let key = ObjectWaitKey::delegated_file(index, generation);
        let lock = AtomicU32::new(1);
        let delivered = core::cell::Cell::new(0);
        let completion = |effects: OwnedObjectWakeEffects<'_>| {
            assert_eq!(lock.load(Ordering::Acquire), 0);
            let _ = effects.deliver_handbacks(&mut |_| delivered.set(delivered.get() + 1));
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap()
            .into_source();
        let venue = DelegatedReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver,
        };
        let release = unsafe { venue.retain_locked(index, generation, &lock) }.unwrap();
        let derived = release.source().reserve();
        drop(derived);
        let queue = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 7,
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
            .park(queue.snapshot(), record, OperationToken::new(7, 9).unwrap())
            .unwrap();
        drop(source); // retiring base pin under the exact still-held inode lock
        drop(release);
        assert_eq!(lock.load(Ordering::Acquire), 0);
        assert_eq!(delivered.get(), 0);
        drop(queue);
        assert_eq!(delivered.get(), 1);
        let next = ObjectWaitKey::delegated_file(index, NonZeroU64::new(10).unwrap());
        zone.bind_object_wait_with_completion(next, &BoundedSpin(0), &completion)
            .unwrap();
        lock.store(1, Ordering::Release);
        assert!(matches!(
            unsafe { venue.retain_locked(index, generation, &lock) },
            Err(ObjectWaitError::Stale)
        ));
        lock.store(0, Ordering::Release);
    }
    #[test]
    fn inode_release_custody_unlocks_and_publishes_on_unwind() {
        let zone = zone();
        let lock = AtomicU32::new(1);
        let index = DelegatedFileWaitIndex::from_index(1).unwrap();
        let generation = NonZeroU64::new(1).unwrap();
        let key = ObjectWaitKey::delegated_file(index, generation);
        let completion = |effects: OwnedObjectWakeEffects<'_>| {
            assert_eq!(lock.load(Ordering::Acquire), 0);
            let _ = effects.deliver_handbacks(&mut |_| {});
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let source = zone
            .admit_object_notification(key, &BoundedSpin(0), &completion)
            .unwrap()
            .into_source();
        let queue = zone
            .object_wait_with_completion(key, &BoundedSpin(0), &completion)
            .unwrap();
        let before = queue.snapshot();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _release = unsafe {
                DelegatedReleaseVenue {
                    zone: &zone,
                    waker: Waker::Host,
                    deliver,
                }
                .retain_locked(index, generation, &lock)
            }
            .unwrap();
            panic!("inode owner unwinds");
        }));
        assert!(result.is_err());
        assert_eq!(lock.load(Ordering::Acquire), 0);
        assert_ne!(queue.snapshot(), before);
        drop(queue);
        drop(source);
    }
}
