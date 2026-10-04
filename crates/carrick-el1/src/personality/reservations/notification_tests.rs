#![allow(clippy::unwrap_used)]
use super::*;

use carrick_sched_core::spaces::notification::SpaceWaitCause;
#[test]
fn actual_root_release_publishes_blocked_probe() {
    let layout = std::alloc::Layout::from_size_align(EL1_REGION_SIZE as usize, 64).unwrap();
    let region = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!region.is_null());
    let roots = unsafe {
        &*region
            .add(EL1_RESERVATIONS_OFFSET as usize)
            .cast::<SharedReservations>()
    };
    let zone = unsafe {
        &*region
            .add(EL1_ZONE_OFFSET as usize)
            .cast::<carrick_sched_core::ZoneTables>()
    };
    let mm = ReservationMm::new(77).unwrap();
    let index = zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
    roots
        .publish(
            index.index(),
            mm,
            Layout {
                heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
                arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
                brk: 0x1000,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    let key = zone
        .space_entry(core::num::NonZeroU64::new(77).unwrap())
        .unwrap()
        .notification_key(
            core::num::NonZeroU64::new(1).unwrap(),
            SpaceWaitCause::Reservations,
        )
        .unwrap();
    fn deliver(
        zone: &carrick_sched_core::ZoneTables,
        _: carrick_sched_core::Waker,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        // SAFETY: this fixture allocated one exact ABI region; the callback
        // receives its zone, and only reads the authenticated root lock word.
        let roots = unsafe {
            &*((zone as *const _ as usize - EL1_ZONE_OFFSET as usize
                + EL1_RESERVATIONS_OFFSET as usize) as *const SharedReservations)
        };
        let index = zone.spaces.find(77).unwrap();
        assert_eq!(
            roots.roots[index.index()].locked.load(Ordering::Acquire) & !ROOT_NOTIFICATION_REQUIRED,
            0,
            "root unlock precedes notification callback"
        );
        let _ = owned.deliver_handbacks(&mut |_| {});
    }
    let venue = RootReleaseVenue::new(
        roots,
        carrick_sched_core::spaces::notification::SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::Host,
            deliver,
        },
    )
    .unwrap();
    venue
        .lock(index.index(), mm, &NoRootWait)
        .unwrap()
        .finish_import()
        .unwrap();
    let root = venue.lock(index.index(), mm, &NoRootWait).unwrap();
    let before = zone.object_queue_census(key.index()).unwrap().epoch;
    assert!(matches!(
        venue.lock(index.index(), mm, &NoRootWait),
        Err(Refusal::Busy)
    ));
    struct NoLegacyWait;
    impl RootWait for NoLegacyWait {
        fn wait(&self, _: u32, _: RootHolder) -> bool {
            panic!("missing venue must refuse before waiting")
        }
    }
    assert!(matches!(
        roots.lock_waiting(index.index(), mm, &NoLegacyWait),
        Err(Refusal::Stale)
    ));
    drop(root);
    assert!(
        zone.object_queue_census(key.index()).unwrap().epoch > before,
        "actual root unlock must publish the blocked probe's producer edge"
    );
    venue
        .lock(index.index(), mm, &NoRootWait)
        .unwrap()
        .retire()
        .unwrap();
    unsafe {
        std::alloc::dealloc(region, layout);
    }
}

#[test]
fn wrong_region_notification_venue_is_rejected() {
    use crate::personality::mm_portal::test_support::Region;
    let a = Region::new();
    let b = Region::new();
    fn deliver(
        _: &carrick_sched_core::ZoneTables,
        _: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    assert!(matches!(
        RootReleaseVenue::new(
            a.table(),
            carrick_sched_core::spaces::notification::SpaceReleaseVenue {
                zone: b.zone(),
                waker: carrick_sched_core::Waker::Host,
                deliver,
            }
        ),
        Err(Refusal::Stale)
    ));
}

#[test]
fn delayed_old_root_admission_cannot_demote_reused_notification_word() {
    use crate::personality::mm_portal::test_support::{ROOT, Region, admit_notified};
    use carrick_sched_core::spaces::notification::SpaceReleaseVenue;
    use core::cell::{Cell, RefCell};
    let region = Region::new();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let zone = region.zone();
    let index = zone.spaces.find(mm.raw()).unwrap();
    zone.spaces.close(index);
    fn deliver(
        _: &carrick_sched_core::ZoneTables,
        _: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    let venue = RootReleaseVenue::new(
        region.table(),
        SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::Host,
            deliver,
        },
    )
    .unwrap();
    struct Recycle<'a> {
        venue: RootReleaseVenue<'a>,
        mm: ReservationMm,
        index: carrick_sched_core::SpaceIndex,
        held: RefCell<Option<Reservations<'a>>>,
        reused: Cell<bool>,
    }
    fn publish(
        venue: RootReleaseVenue<'_>,
        mm: ReservationMm,
        index: carrick_sched_core::SpaceIndex,
    ) {
        venue
            .table
            .publish(
                index.index(),
                mm,
                Layout {
                    heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
                    arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
                    brk: 0x1000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        venue
            .lock(index.index(), mm, &NoRootWait)
            .unwrap()
            .finish_import()
            .unwrap();
    }
    impl RootWait for Recycle<'_> {
        fn wait(&self, attempt: u32, _: RootHolder) -> bool {
            assert_eq!(attempt, 0, "one deterministic holder release");
            drop(self.held.borrow_mut().take());
            self.venue
                .lock(self.index.index(), self.mm, &NoRootWait)
                .unwrap()
                .retire()
                .unwrap();
            let zone = self.venue.release.zone;
            zone.space_entry(core::num::NonZeroU64::new(self.mm.raw()).unwrap())
                .unwrap()
                .retire_entry();
            let next_mm = self.mm.raw() + carrick_sched_core::spaces::ADDRESS_SPACES as u64;
            let next = zone.spaces.publish_closed(next_mm, ROOT, ROOT).unwrap();
            if next == self.index {
                self.reused.set(true);
                publish(self.venue, ReservationMm::new(next_mm).unwrap(), next);
            } else {
                // The counted old admission correctly retained the old entry.
                zone.space_entry(core::num::NonZeroU64::new(next_mm).unwrap())
                    .unwrap()
                    .retire_entry();
            }
            true
        }
    }
    let wait = Recycle {
        venue,
        mm,
        index,
        held: RefCell::new(Some(venue.lock(index.index(), mm, &NoRootWait).unwrap())),
        reused: Cell::new(false),
    };
    assert!(matches!(
        venue.lock(index.index(), mm, &wait),
        Err(Refusal::Stale)
    ));
    let next_mm =
        ReservationMm::new(mm.raw() + carrick_sched_core::spaces::ADDRESS_SPACES as u64).unwrap();
    if !wait.reused.get() {
        let next = zone
            .spaces
            .publish_closed(next_mm.raw(), ROOT, ROOT)
            .unwrap();
        assert_eq!(next, index);
        publish(venue, next_mm, next);
    }
    assert_eq!(
        region.table().roots[index.index()]
            .locked
            .load(Ordering::Acquire),
        ROOT_NOTIFICATION_REQUIRED,
        "stale old-MM admission must never demote the successor root's required venue"
    );
    assert!(matches!(
        region.table().lock(index.index(), next_mm),
        Err(Refusal::Stale)
    ));
    venue
        .lock(index.index(), next_mm, &NoRootWait)
        .unwrap()
        .retire()
        .unwrap();
}
