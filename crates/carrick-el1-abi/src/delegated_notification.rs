//! Region-authenticated release custody for delegated inode locks.
use crate::{DelegatedFile, EL1_OBJECT_TABLE_OFFSET, EL1_ZONE_OFFSET, LOCK_HOST};
use carrick_sched_core::object_wait::{
    DelegatedFileWaitIndex, DelegatedLockRelease, DelegatedReleaseVenue, ObjectWaitError,
    ObjectWaitKey, OwnedObjectWakeEffects,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

/// One inode in the exact carrier region that owns its notification queue.
#[derive(Clone, Copy)]
pub struct DelegatedFileAuthority<'a> {
    file: &'a DelegatedFile,
    index: DelegatedFileWaitIndex,
    venue: DelegatedReleaseVenue<'a>,
}
impl<'a> DelegatedFileAuthority<'a> {
    pub fn new(
        file: &'a DelegatedFile,
        index: DelegatedFileWaitIndex,
        venue: DelegatedReleaseVenue<'a>,
    ) -> Result<Self, ObjectWaitError> {
        let file_region = (file as *const _ as usize)
            .checked_sub(index.index() * core::mem::size_of::<DelegatedFile>())
            .and_then(|base| base.checked_sub(EL1_OBJECT_TABLE_OFFSET as usize));
        let zone_region = (venue.zone as *const _ as usize).checked_sub(EL1_ZONE_OFFSET as usize);
        if file_region.is_none() || file_region != zone_region {
            return Err(ObjectWaitError::Stale);
        }
        Ok(Self { file, index, venue })
    }

    /// One strong attempt. The caller suspends on contention without retaining
    /// a borrowed guard or an execution slot.
    pub fn try_host(self) -> Result<Option<DelegatedFileGuard<'a>>, ObjectWaitError> {
        if self
            .file
            .lock
            .compare_exchange(0, LOCK_HOST, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Ok(None);
        }
        // SAFETY: the successful CAS exclusively claimed this exact inode.
        unsafe { self.from_locked() }.map(Some)
    }

    /// Transfer an already-held lock into its sole release authority.
    ///
    /// # Safety
    /// The caller exclusively owns this inode's lock and must never unlock it
    /// or access its protected state after the returned guard is released.
    pub unsafe fn from_locked(self) -> Result<DelegatedFileGuard<'a>, ObjectWaitError> {
        let mut guard = DelegatedFileGuard {
            authority: self,
            release: None,
        };
        if let Some(generation) =
            NonZeroU64::new(self.file.notification_generation.load(Ordering::Acquire))
        {
            // SAFETY: the authenticated inode lock protects its detached base
            // pin through derivation. The resulting guard owns the only unlock.
            guard.release = Some(unsafe {
                self.venue
                    .retain_locked(self.index, generation, &self.file.lock)?
            });
        }
        Ok(guard)
    }
}

/// Holds actual inode exclusion. A live source advances before unlock and
/// delivers only afterward; unpublished inodes have no enrolled consumers.
#[must_use = "retain inode exclusion until its protected operation finishes"]
pub struct DelegatedFileGuard<'a> {
    authority: DelegatedFileAuthority<'a>,
    release: Option<DelegatedLockRelease<'a, 'a>>,
}
impl DelegatedFileGuard<'_> {
    pub fn file(&self) -> &DelegatedFile {
        self.authority.file
    }

    /// Admit exactly one durable source before the fresh inode is published.
    pub fn admit_notifications(&mut self, generation: NonZeroU64) -> Result<(), ObjectWaitError> {
        if self.release.is_some()
            || self.file().notification_generation.load(Ordering::Relaxed) != 0
        {
            return Err(ObjectWaitError::Occupied);
        }
        let authority = self.authority;
        let key = ObjectWaitKey::delegated_file(authority.index, generation);
        let completion = |effects: OwnedObjectWakeEffects<'_>| {
            (authority.venue.deliver)(authority.venue.zone, authority.venue.waker, effects)
        };
        authority.venue.zone.bind_object_wait_with_completion(
            key,
            &carrick_sched_core::BoundedSpin(0),
            &completion,
        )?;
        let source = authority
            .venue
            .zone
            .admit_object_notification(key, &carrick_sched_core::BoundedSpin(0), &completion)?
            .into_source();
        let _ = source.detach();
        authority
            .file
            .notification_generation
            .store(generation.get(), Ordering::Release);
        // SAFETY: this guard protects the newly admitted base pin, and owns
        // the exact lock until the returned release custody takes over.
        match unsafe {
            authority
                .venue
                .retain_locked(authority.index, generation, &authority.file.lock)
        } {
            Ok(release) => {
                self.release = Some(release);
                Ok(())
            }
            Err(error) => {
                authority
                    .file
                    .notification_generation
                    .store(0, Ordering::Release);
                // SAFETY: unpublished admission still exclusively owns this
                // detached base pin, and no release ticket was constructed.
                drop(unsafe { authority.venue.zone.retained_object_notification(key) });
                Err(error)
            }
        }
    }

    /// Retire the unique base pin under exclusion. This guard's independent
    /// release ticket still publishes the terminal transition after unlock.
    pub fn retire_notifications(&mut self) {
        let generation = self
            .file()
            .notification_generation
            .swap(0, Ordering::AcqRel);
        if let Some(generation) = NonZeroU64::new(generation) {
            assert!(
                self.release.is_some(),
                "live inode retirement owns release custody"
            );
            let key = ObjectWaitKey::delegated_file(self.authority.index, generation);
            // SAFETY: swap uniquely consumes the detached base admission while
            // this guard excludes every source borrower and another retirement.
            drop(unsafe { self.authority.venue.zone.retained_object_notification(key) });
        }
    }
}
impl Drop for DelegatedFileGuard<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            drop(release);
        } else {
            self.authority.file.lock.store(0, Ordering::Release);
        }
    }
}
