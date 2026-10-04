//! Authenticated delivery venue of the actual carrier root and scheduler.
use super::*;
use carrick_sched_core::spaces::notification::{
    ROOT_NOTIFICATION_REQUIRED, ResourceUnlocked, SpaceNotificationIdentity, SpaceReleaseVenue,
    SpaceWaitCause,
};
use core::num::NonZeroU64;
#[derive(Clone, Copy)]
pub(super) enum RootAuthority<'a> {
    Bound(RootReleaseVenue<'a>),
    #[cfg(any(test, feature = "host-test"))]
    SourceFree(SourceFreeReservations<'a>),
}
impl<'a> RootAuthority<'a> {
    pub fn release(self) -> Option<RootReleaseVenue<'a>> {
        match self {
            Self::Bound(venue) => Some(venue),
            #[cfg(any(test, feature = "host-test"))]
            Self::SourceFree(fixture) => {
                let _ = fixture.0;
                None
            }
        }
    }
}
#[cfg(any(test, feature = "host-test"))]
#[derive(Clone, Copy)]
pub struct SourceFreeReservations<'a>(&'a SharedReservations);
#[cfg(any(test, feature = "host-test"))]
impl SharedReservations {
    pub fn source_free(&self) -> SourceFreeReservations<'_> {
        SourceFreeReservations(self)
    }
}
impl SharedReservations {
    pub fn lock_in<'a>(
        &'a self,
        spaces: carrick_sched_core::spaces::notification::SpaceAccess<'a>,
        index: usize,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'a>, Refusal> {
        if let Some(venue) = spaces.venue() {
            return RootReleaseVenue::new(self, venue)?.lock_el1(index, mm, slot);
        }
        #[cfg(any(test, feature = "host-test"))]
        {
            self.lock_el1(index, mm, slot)
        }
        #[cfg(not(any(test, feature = "host-test")))]
        Err(Refusal::Stale)
    }
}
#[derive(Clone, Copy)]
pub struct RootReleaseVenue<'a> {
    pub(super) table: &'a SharedReservations,
    pub(crate) release: SpaceReleaseVenue<'a>,
}
impl<'a> RootReleaseVenue<'a> {
    pub fn new(
        table: &'a SharedReservations,
        release: SpaceReleaseVenue<'a>,
    ) -> Result<Self, Refusal> {
        let root_region =
            (table as *const _ as usize).checked_sub(EL1_RESERVATIONS_OFFSET as usize);
        let zone_region = (release.zone as *const _ as usize).checked_sub(EL1_ZONE_OFFSET as usize);
        if root_region.is_none() || root_region != zone_region {
            return Err(Refusal::Stale);
        }
        Ok(Self { table, release })
    }
    pub fn lock(
        self,
        index: usize,
        mm: ReservationMm,
        wait: &dyn RootWait,
    ) -> Result<Reservations<'a>, Refusal> {
        self.table.lock_using(
            index,
            mm,
            None,
            cfg!(target_os = "none"),
            wait,
            RootHolder::Host.word(),
            RootAuthority::Bound(self),
        )
    }
    pub fn lock_el1(
        self,
        index: usize,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'a>, Refusal> {
        self.table.lock_using(
            index,
            mm,
            None,
            cfg!(target_os = "none"),
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
            RootAuthority::Bound(self),
        )
    }
    pub fn lock_resolved<P: PinnedMetadataExtent>(
        self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P>,
        wait: &dyn RootWait,
    ) -> Result<Reservations<'a>, Refusal> {
        if !core::ptr::eq(nodes.table, self.table) {
            return Err(Refusal::Stale);
        }
        self.table.lock_using(
            index,
            mm,
            Some(nodes),
            false,
            wait,
            RootHolder::Host.word(),
            RootAuthority::Bound(self),
        )
    }
    pub fn lock_el1_resolved<P: PinnedMetadataExtent>(
        self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P>,
        slot: u32,
    ) -> Result<Reservations<'a>, Refusal> {
        if !core::ptr::eq(nodes.table, self.table) {
            return Err(Refusal::Stale);
        }
        self.table.lock_using(
            index,
            mm,
            Some(nodes),
            false,
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
            RootAuthority::Bound(self),
        )
    }
}
impl<'a> Reservations<'a> {
    pub(super) fn notification_identity(&self) -> Result<SpaceNotificationIdentity, Refusal> {
        Ok(SpaceNotificationIdentity {
            mm: NonZeroU64::new(self.mm.raw()).ok_or(Refusal::Stale)?,
            incarnation: NonZeroU64::new(self.incarnation().raw()).ok_or(Refusal::Stale)?,
        })
    }
    pub(super) fn admit_notifications(&mut self) -> Result<(), Refusal> {
        if self.notification.is_some() {
            return Ok(());
        }
        let Some(venue) = self.release_venue else {
            #[cfg(any(test, feature = "host-test"))]
            {
                return Ok(());
            }
            #[cfg(not(any(test, feature = "host-test")))]
            return Err(Refusal::Stale);
        };
        let identity = self.notification_identity()?;
        let entry = venue
            .release
            .zone
            .space_entry(identity.mm)
            .ok_or(Refusal::Stale)?;
        if entry.index().index() != self.index() {
            return Err(Refusal::Stale);
        }
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
            (venue.release.deliver)(venue.release.zone, venue.release.waker, effects)
        };
        entry
            .admit_notifications(
                identity.incarnation,
                &carrick_sched_core::BoundedSpin(0),
                &completion,
            )
            .map_err(|_| Refusal::Busy)?;
        self.notification = Some(
            entry
                .notifications(identity.incarnation)
                .map_err(|_| Refusal::Stale)?,
        );
        self.unlocked = ResourceUnlocked::NotificationRoot;
        self.root
            .locked
            .fetch_or(ROOT_NOTIFICATION_REQUIRED, Ordering::Release);
        Ok(())
    }
    pub(crate) fn notification_ticket(
        &self,
        cause: SpaceWaitCause,
    ) -> Option<carrick_sched_core::object_wait::ObjectNotificationTicket<'a>> {
        self.notification.as_ref().map(|lease| lease.reserve(cause))
    }
}
