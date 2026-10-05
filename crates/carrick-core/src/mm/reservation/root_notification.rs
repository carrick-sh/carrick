//! Authenticated delivery venue of the actual carrier root and scheduler.
use super::*;
use carrick_sched_core::spaces::notification::{
    ROOT_NOTIFICATION_REQUIRED, ResourceUnlocked, SpaceNotificationIdentity, SpaceReleaseVenue,
    SpaceWaitCause,
};
use core::num::NonZeroU64;
pub(super) enum RootAuthority<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry> {
    Bound(RootReleaseVenue<'a, Policy, Geometry>),
    #[cfg(any(test, feature = "host-test"))]
    SourceFree(SourceFreeReservations<'a, Policy, Geometry>),
}
impl<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry>
    RootAuthority<'a, Policy, Geometry>
{
    pub fn release(self) -> Option<RootReleaseVenue<'a, Policy, Geometry>> {
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
pub struct SourceFreeReservations<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry>(
    &'a SharedReservations<Policy, Geometry>,
);
#[cfg(any(test, feature = "host-test"))]
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry>
    SharedReservations<Policy, Geometry>
{
    pub fn source_free(&self) -> SourceFreeReservations<'_, Policy, Geometry> {
        SourceFreeReservations(self)
    }
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry>
    SharedReservations<Policy, Geometry>
{
    pub fn lock_in<'a>(
        &'a self,
        spaces: carrick_sched_core::spaces::notification::SpaceAccess<'a>,
        index: usize,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
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
pub struct RootReleaseVenue<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry> {
    pub(super) table: &'a SharedReservations<Policy, Geometry>,
    pub(crate) release: SpaceReleaseVenue<'a>,
}
impl<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry>
    RootReleaseVenue<'a, Policy, Geometry>
{
    pub fn new(
        table: &'a SharedReservations<Policy, Geometry>,
        release: SpaceReleaseVenue<'a>,
    ) -> Result<Self, Refusal> {
        let root_region = (table as *const _ as usize).checked_sub(Geometry::RESERVATIONS_OFFSET);
        let zone_region = (release.zone as *const _ as usize).checked_sub(Geometry::ZONE_OFFSET);
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
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        self.table.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: None,
                identity: cfg!(target_os = "none"),
            },
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
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        self.table.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: None,
                identity: cfg!(target_os = "none"),
            },
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
            RootAuthority::Bound(self),
        )
    }
    pub fn lock_resolved<P: PinnedMetadataExtent>(
        self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
        wait: &dyn RootWait,
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        if !core::ptr::eq(nodes.table, self.table) {
            return Err(Refusal::Stale);
        }
        self.table.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: Some(nodes),
                identity: false,
            },
            wait,
            RootHolder::Host.word(),
            RootAuthority::Bound(self),
        )
    }
    pub fn lock_el1_resolved<P: PinnedMetadataExtent>(
        self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
        slot: u32,
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        if !core::ptr::eq(nodes.table, self.table) {
            return Err(Refusal::Stale);
        }
        self.table.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: Some(nodes),
                identity: false,
            },
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
            RootAuthority::Bound(self),
        )
    }
}
impl<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry>
    Reservations<'a, Policy, Geometry>
{
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
    pub fn notification_ticket(
        &self,
        cause: SpaceWaitCause,
    ) -> Option<carrick_sched_core::object_wait::ObjectNotificationTicket<'a>> {
        self.notification.as_ref().map(|lease| lease.reserve(cause))
    }
}

impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Copy
    for RootReleaseVenue<'_, Policy, Geometry>
{
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Clone
    for RootReleaseVenue<'_, Policy, Geometry>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Copy
    for RootAuthority<'_, Policy, Geometry>
{
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Clone
    for RootAuthority<'_, Policy, Geometry>
{
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(any(test, feature = "host-test"))]
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Copy
    for SourceFreeReservations<'_, Policy, Geometry>
{
}
#[cfg(any(test, feature = "host-test"))]
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Clone
    for SourceFreeReservations<'_, Policy, Geometry>
{
    fn clone(&self) -> Self {
        *self
    }
}
