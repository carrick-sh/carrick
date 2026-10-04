//! The EL1 venue of authenticated delegated-inode release.
use carrick_el1_abi::{DelegatedFile, DelegatedFileAuthority, DelegatedFileGuard, SlotId};
use carrick_sched_core::object_wait::{
    DelegatedFileWaitIndex, DelegatedReleaseVenue, OwnedObjectWakeEffects,
};
use carrick_sched_core::{Waker, ZoneTables};

#[derive(Clone, Copy)]
pub enum FileAccess<'a> {
    Notified(DelegatedReleaseVenue<'a>),
    Unavailable,
    #[cfg(any(test, feature = "host-test"))]
    SourceFreeModel,
}
impl<'a> FileAccess<'a> {
    pub fn notified(zone: &'a ZoneTables, slot: SlotId) -> Self {
        fn deliver(zone: &ZoneTables, waker: Waker, effects: OwnedObjectWakeEffects<'_>) {
            let Waker::El1 { slot } = waker else {
                unreachable!("EL1 delegated release has an exact execution slot")
            };
            super::sched::object_wait::deliver_completion(zone, slot, effects);
        }
        Self::Notified(DelegatedReleaseVenue {
            zone,
            waker: Waker::El1 { slot },
            deliver,
        })
    }
    pub fn lock(self, file: &'a DelegatedFile, handle: u32) -> Option<FileGuard<'a>> {
        match self {
            Self::Notified(venue) => {
                let index = DelegatedFileWaitIndex::from_index(handle.checked_sub(1)? as usize)?;
                let authority = DelegatedFileAuthority::new(file, index, venue).ok()?;
                if !file.lock_guest_bounded(carrick_el1_abi::EL1_GUEST_LOCK_SPINS) {
                    return None;
                }
                // SAFETY: the authenticated inode was exclusively acquired.
                unsafe { authority.from_locked() }
                    .ok()
                    .map(FileGuard::Notified)
            }
            Self::Unavailable => None,
            #[cfg(any(test, feature = "host-test"))]
            Self::SourceFreeModel => file
                .lock_guest_bounded(carrick_el1_abi::EL1_GUEST_LOCK_SPINS)
                .then(|| FileGuard::SourceFreeModel(file)),
        }
    }
}
#[must_use = "retain the inode guard through all protected effects"]
pub enum FileGuard<'a> {
    Notified(DelegatedFileGuard<'a>),
    #[cfg(any(test, feature = "host-test"))]
    SourceFreeModel(&'a DelegatedFile),
}
impl Drop for FileGuard<'_> {
    fn drop(&mut self) {
        #[cfg(any(test, feature = "host-test"))]
        if let Self::SourceFreeModel(file) = self {
            file.unlock();
        }
    }
}
