//! #2986: the page-table editor admission tells permanent closure from a
//! counted pause. A raised pause on an open space is "not now" until its
//! release lowers it; a closed gate is its own refusal, with or without
//! pauses still counted under it, and no release ends it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::num::NonZeroU64;

use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
use carrick_sched_core::spaces::notification::{
    SpaceAccess, SpaceReleaseVenue, SpaceWaitCause, SpaceWakeDelivery,
};
use carrick_sched_core::spaces::{EditAdmissionRefusal, GATE_CLOSED};
use carrick_sched_core::{BoundedSpin, Waker, ZoneTables};

const MM: u64 = 77;

fn zone() -> Box<ZoneTables> {
    // SAFETY: the shared ABI's all-zero state is its empty initialization.
    // Heap allocation avoids a large stack.
    unsafe {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(ptr)
    }
}

fn deliver(_: &ZoneTables, _: Waker, effects: OwnedObjectWakeEffects<'_>) {
    let _ = effects.deliver_handbacks(&mut |_| {});
}

/// With a live notification source and a matching key: a counted pause is
/// `Gate` until its venue release admits the editor; a closed gate is
/// `Closed` while a pause is still counted and after it lowers.
#[test]
fn editor_admission_classifies_closure_apart_from_a_counted_pause() {
    let zone = zone();
    zone.spaces.publish_closed(MM, 0x30000, 0x30000).unwrap();
    let entry = zone.space_entry(NonZeroU64::new(MM).unwrap()).unwrap();
    entry
        .admit_notifications(NonZeroU64::MIN, &BoundedSpin(0), &|effects| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        })
        .unwrap();
    let index = entry.index();
    let access = SpaceAccess::notified(SpaceReleaseVenue {
        zone: &zone,
        waker: Waker::Host,
        deliver: SpaceWakeDelivery::Function(deliver),
    });
    access.open(index);
    let admit = || {
        zone.spaces
            .try_begin_edit_cause(index, MM, NonZeroU64::MIN, access.venue())
            .map(drop)
    };

    let pause = access.try_exclude_editor(index, MM).unwrap();
    assert_eq!(admit(), Err(EditAdmissionRefusal::Gate));
    assert_eq!(
        EditAdmissionRefusal::Gate.wait_cause(),
        Some(SpaceWaitCause::Gate),
        "a counted pause waits on the gate's release"
    );
    drop(pause);
    assert_eq!(admit(), Ok(()), "the lowered pause admits the editor");

    let pause = access.try_exclude_editor(index, MM).unwrap();
    zone.spaces.close(index);
    assert!(
        entry.notifications(NonZeroU64::MIN).is_ok(),
        "the release source is still live"
    );
    assert_eq!(
        admit(),
        Err(EditAdmissionRefusal::Closed),
        "closure under a counted pause is not the pause"
    );
    drop(pause);
    assert_eq!(zone.spaces.gate(index), GATE_CLOSED);
    assert_eq!(
        admit(),
        Err(EditAdmissionRefusal::Closed),
        "lowering the pause leaves the space closed"
    );
    assert_eq!(EditAdmissionRefusal::Closed.wait_cause(), None);
    assert_eq!(EditAdmissionRefusal::Stale.wait_cause(), None);
}

/// A source-free space (no notification source attached) classifies the
/// same way: the admission alone decides, not the release machinery.
#[test]
fn source_free_admission_classifies_closure_apart_from_a_counted_pause() {
    let zone = zone();
    let index = zone.spaces.publish_closed(MM, 0x30000, 0x30000).unwrap();
    assert_eq!(
        zone.spaces
            .try_begin_edit_cause::<carrick_sched_core::ThreadCtx>(index, MM, NonZeroU64::MIN, None)
            .map(drop),
        Err(EditAdmissionRefusal::Closed),
        "a never-opened publication is closed, not paused"
    );
    zone.spaces.open(index);
    zone.spaces.raise(index);
    let admit = || {
        zone.spaces
            .try_begin_edit_cause::<carrick_sched_core::ThreadCtx>(index, MM, NonZeroU64::MIN, None)
            .map(drop)
    };
    assert_eq!(admit(), Err(EditAdmissionRefusal::Gate));
    zone.spaces.lower(index);
    assert_eq!(admit(), Ok(()));
    zone.spaces.raise(index);
    zone.spaces.close(index);
    assert_eq!(admit(), Err(EditAdmissionRefusal::Closed));
    zone.spaces.lower(index);
    assert_eq!(admit(), Err(EditAdmissionRefusal::Closed));
}
