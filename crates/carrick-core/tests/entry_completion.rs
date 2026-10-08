//! Entry-turn ownership joins the existing exact-record wait authority.
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_core::entry::{CompletionError, admit, complete, handoff};
use carrick_core::wait::{notify_object, park_object_record, take_object_operation};
use carrick_core_abi::{
    EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    ObjectParkRequest,
};
use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};
use carrick_sched_core::{ExecutionSlot, SlotId, ThreadIdentity, ZoneTables};

fn zone() -> Box<ZoneTables> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: ZoneTables supports its shared-region zero initialization, the
    // allocation has its exact size/alignment, and Box owns that allocation.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}

#[test]
fn suspended_turn_completes_only_through_exact_wait_owner() {
    for scale in [1, 2, 8] {
        let mut completions = 0;
        let mut result_writes = 0;
        for generation in 1..=scale {
            let zone = zone();
            let slot = SlotId::new(0);
            let mm = 7 + generation;
            zone.drive(slot, 3);
            zone.publish_slot(slot, mm, None, 0);
            let here = ExecutionSlot::zone(slot);
            zone.occupancy.vacate_any(here);
            assert!(zone.occupancy.replace(here, 0, mm));
            zone.enter_guest(slot);
            let space = zone.spaces.publish_closed(mm, 0x7000, 0x7000).unwrap();
            zone.spaces.open(space);
            assert!(zone.install_space(slot, mm).is_some());
            let key = ObjectWaitKey::new(1, generation).unwrap();
            let wait = carrick_sched_core::BoundedSpin(1024);
            zone.bind_object_wait(key, &wait).unwrap();
            let guard = zone.object_wait(key, &wait).unwrap();
            let snapshot = guard.snapshot();
            drop(guard);
            let identity = ThreadIdentity {
                tid: 41,
                serial: 100 + generation,
                mm,
                file_table: 5,
                generation,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            };
            let binding = ExecutionBinding {
                task: EntryTaskKey::from_raw(41),
                generation: EntryGeneration::from_raw(generation),
                mm: EntryMmKey::from_raw(mm),
                thread_generation: EntryThreadGeneration::from_raw(identity.serial),
            };
            let entry = admit(
                binding,
                Some(carrick_core_abi::BornInZoneSource { zone: &zone, slot }),
            )
            .unwrap();
            let record = zone.current_or_new(slot, identity).unwrap();
            let operation = OperationToken::new(17, generation).unwrap();
            let request = ObjectParkRequest::new(key, snapshot, operation, None);
            let mut parked =
                park_object_record(&zone, slot, request, 1024, &|_| {}, || Ok((record, false)))
                    .unwrap();
            assert!(parked.matches(&zone, slot));
            // The entry turn ends here. Its token cannot later take the
            // ordinary path; the record owns the sole remaining operation.
            handoff(entry, parked.take_receipt().unwrap()).unwrap();
            assert!(zone.slot(slot).current().is_none());
            let (wake, _) = notify_object(&zone, slot, key, 1024).unwrap();
            assert_eq!(wake.queued, 1);
            assert_eq!(notify_object(&zone, slot, key, 1024).unwrap().0.queued, 0);
            assert_eq!(zone.switch_in_full(slot).unwrap().record, record);
            for _ in 0..2 {
                if let Some(taken) = take_object_operation(&zone, slot, identity).unwrap() {
                    assert_eq!(taken, OperationToken::new(17, generation).unwrap());
                    completions += 1;
                    result_writes += 1;
                }
            }
        }
        assert_eq!(completions, scale);
        assert_eq!(result_writes, scale);
    }
}

#[test]
fn switched_record_cannot_use_captured_binding_for_ordinary_completion() {
    let original = ExecutionBinding {
        task: EntryTaskKey::from_raw(41),
        generation: EntryGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(7),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    // Same visible TID, but a different exact execution/MM/thread owner.
    for current in [
        ExecutionBinding {
            generation: EntryGeneration::from_raw(12),
            ..original
        },
        ExecutionBinding {
            mm: EntryMmKey::from_raw(8),
            ..original
        },
        ExecutionBinding {
            thread_generation: EntryThreadGeneration::from_raw(102),
            ..original
        },
    ] {
        assert_eq!(
            complete(
                admit::<carrick_sched_core::ThreadCtx>(original, None).unwrap(),
                current,
                None
            ),
            Err(CompletionError::WrongGeneration)
        );
    }
}

#[test]
fn record_owned_entry_does_not_require_host_adoption_generation() {
    use carrick_core::entry::{admit_born_in_zone, complete_born_in_zone};
    use carrick_core_abi::BornInZoneSource;
    let zone = zone();
    let slot = SlotId::new(0);
    let id = ThreadIdentity {
        tid: 41,
        serial: 101,
        mm: 7,
        file_table: 5,
        generation: 0,
        affinity: 0,
        lifecycle_page: 0x1000,
        control_slot: 0x2000,
    };
    zone.drive(slot, 3);
    zone.publish_slot(slot, id.mm, None, 0);
    let here = ExecutionSlot::zone(slot);
    zone.occupancy.vacate_any(here);
    assert!(zone.occupancy.replace(here, 0, id.mm));
    zone.enter_guest(slot);
    let space = zone.spaces.publish_closed(id.mm, 0x7000, 0x7000).unwrap();
    zone.spaces.open(space);
    assert!(zone.install_space(slot, id.mm).is_some());
    let record = zone.alloc_record(id).unwrap();
    zone.requeue_preempted(slot, record);
    assert_eq!(zone.switch_in(slot), Some(record));
    let binding = ExecutionBinding {
        task: EntryTaskKey::from_raw(id.tid),
        generation: EntryGeneration::from_raw(0),
        mm: EntryMmKey::from_raw(id.mm),
        thread_generation: EntryThreadGeneration::from_raw(id.serial),
    };
    assert!(admit::<carrick_sched_core::ThreadCtx>(binding, None).is_none());
    let source = BornInZoneSource { zone: &zone, slot };
    let token = admit_born_in_zone(binding, source).unwrap();
    assert_eq!(complete_born_in_zone(token, binding, source), Ok(()));
    for stale in [
        ExecutionBinding {
            mm: EntryMmKey::from_raw(8),
            ..binding
        },
        ExecutionBinding {
            thread_generation: EntryThreadGeneration::from_raw(102),
            ..binding
        },
    ] {
        assert!(admit_born_in_zone(stale, source).is_none());
    }
    let token = admit_born_in_zone(binding, source).unwrap();
    assert_eq!(
        zone.claim_for_host(
            zone.record_ref(record),
            None,
            carrick_sched_core::Handback::Signal,
            &carrick_sched_core::BoundedSpin(1024)
        ),
        carrick_sched_core::HostClaim::El1Held { slot }
    );
    assert!(zone.record(record).host_wanted());
    assert!(admit_born_in_zone(binding, source).is_none());
    assert_eq!(complete_born_in_zone(token, binding, source), Ok(()));
    assert!(
        zone.record(record).host_wanted(),
        "completion must preserve host request"
    );
    assert!(
        matches!(zone.record(record).claim(), carrick_sched_core::Claim::OnCpuRequested { slot: owner, .. } if owner == slot)
    );
    assert_eq!(zone.slot(slot).current(), Some(record));
    assert_eq!(
        zone.handback_current(slot, record),
        carrick_sched_core::CurrentHandback::HandedBack
    );
    assert!(matches!(
        zone.record(record).claim(),
        carrick_sched_core::Claim::Host { .. }
    ));
    let record = zone.alloc_record(id).unwrap();
    zone.requeue_preempted(slot, record);
    assert_eq!(zone.switch_in(slot), Some(record));
    let stale = admit_born_in_zone(binding, source).unwrap();
    let key = ObjectWaitKey::new(1, 13).unwrap();
    let wait = carrick_sched_core::BoundedSpin(1024);
    zone.bind_object_wait(key, &wait).unwrap();
    let guard = zone.object_wait(key, &wait).unwrap();
    let snapshot = guard.snapshot();
    drop(guard);
    let parked = park_object_record(
        &zone,
        slot,
        ObjectParkRequest::new(key, snapshot, OperationToken::new(17, 13).unwrap(), None),
        1024,
        &|_| {},
        || Ok((record, false)),
    )
    .unwrap();
    assert!(parked.matches(&zone, slot));
    assert_eq!(notify_object(&zone, slot, key, 1024).unwrap().0.queued, 1);
    assert_eq!(zone.switch_in(slot), Some(record));
    assert_eq!(
        complete_born_in_zone(stale, binding, source),
        Err(CompletionError::WrongGeneration),
        "claim seq changed"
    );
    assert!(take_object_operation(&zone, slot, id).unwrap().is_some());
    let token = admit_born_in_zone(binding, source).unwrap();
    let other = zone.alloc_record(id).unwrap();
    zone.clear_current(slot);
    zone.requeue_preempted(slot, other);
    assert_eq!(zone.switch_in(slot), Some(other));
    assert_eq!(
        complete_born_in_zone(token, binding, source),
        Err(CompletionError::WrongGeneration)
    );
    // Adoption publishes a nonzero host generation. The same thread now uses
    // ordinary admission and the Born constructor refuses both representations.
    let adopted = ExecutionBinding {
        generation: EntryGeneration::from_raw(11),
        ..binding
    };
    assert!(admit_born_in_zone(adopted, source).is_none());
    assert_eq!(
        complete(
            admit::<carrick_sched_core::ThreadCtx>(adopted, None).unwrap(),
            adopted,
            None
        ),
        Ok(())
    );
    let record = zone
        .alloc_record(ThreadIdentity {
            generation: 11,
            ..id
        })
        .unwrap();
    zone.clear_current(slot);
    zone.requeue_preempted(slot, record);
    assert_eq!(zone.switch_in(slot), Some(record));
    assert!(admit_born_in_zone(binding, source).is_none());
    assert!(admit_born_in_zone(adopted, source).is_none());
}

#[test]
fn ordinary_handoff_rejects_foreign_scheduler_owner() {
    use carrick_core::entry::{prepare_handoff, publish_handoff_park};
    use carrick_core_abi::{BornInZoneSource, EntryRecordGeneration};
    let first = zone();
    let second = zone();
    let slot = SlotId::new(0);
    let identity = ThreadIdentity {
        tid: 41,
        serial: 101,
        mm: 7,
        generation: 11,
        file_table: 5,
        ..ThreadIdentity::default()
    };
    for zone in [&first, &second] {
        zone.drive(slot, 3);
        zone.publish_slot(slot, 7, None, 0);
        let here = ExecutionSlot::zone(slot);
        zone.occupancy.vacate_any(here);
        assert!(zone.occupancy.replace(here, 0, 7));
    }
    let binding = ExecutionBinding {
        task: EntryTaskKey::from_raw(41),
        generation: EntryGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(7),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    let token = admit(binding, Some(BornInZoneSource { zone: &first, slot })).unwrap();
    let record = second.current_or_new(slot, identity).unwrap();
    let start = prepare_handoff(
        binding,
        BornInZoneSource {
            zone: &second,
            slot,
        },
        record,
    )
    .unwrap();
    let guard = second
        .lock(
            ZoneTables::bucket_of(7, 0x1000),
            &carrick_sched_core::BoundedSpin(1024),
        )
        .unwrap();
    let sequence = second.next_seq(record);
    second
        .enqueue(&guard, record, sequence, 7, 0x1000, u32::MAX, 0)
        .unwrap();
    let receipt = publish_handoff_park(start, &guard, EntryRecordGeneration(sequence)).unwrap();
    assert_eq!(
        handoff(token, receipt),
        Err(CompletionError::WrongGeneration)
    );
}

fn compact_zone() -> Box<ZoneTables<carrick_sched_core::ParkedContextWords>> {
    type CompactZone = ZoneTables<carrick_sched_core::ParkedContextWords>;
    let layout = std::alloc::Layout::new::<CompactZone>();
    // SAFETY: the exact compact-context shared region supports zero init;
    // the allocation has its actual alignment and Box retains its lifetime.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<CompactZone>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}

fn running_compact(
    zone: &ZoneTables<carrick_sched_core::ParkedContextWords>,
    generation: u64,
) -> (SlotId, carrick_sched_core::RecordId, ExecutionBinding) {
    let slot = SlotId::new(1);
    let identity = ThreadIdentity {
        tid: 71,
        serial: 113,
        mm: 29,
        file_table: 9,
        generation,
        affinity: 1 << 1,
        lifecycle_page: 0x1000,
        control_slot: 0x2000,
    };
    zone.drive(slot, 3);
    zone.publish_slot(slot, identity.mm, None, 0);
    let here = ExecutionSlot::zone(slot);
    zone.occupancy.vacate_any(here);
    assert!(zone.occupancy.replace(here, 0, identity.mm));
    zone.enter_guest(slot);
    let space = zone
        .spaces
        .publish_closed(identity.mm, 0x9000, 0x9000)
        .unwrap();
    zone.spaces.open(space);
    assert!(zone.install_space(slot, identity.mm).is_some());
    let record = zone.alloc_record(identity).unwrap();
    zone.requeue_preempted(slot, record);
    assert_eq!(zone.switch_in(slot), Some(record));
    (
        slot,
        record,
        ExecutionBinding {
            task: EntryTaskKey::from_raw(identity.tid),
            generation: EntryGeneration::from_raw(generation),
            mm: EntryMmKey::from_raw(identity.mm),
            thread_generation: EntryThreadGeneration::from_raw(identity.serial),
        },
    )
}

#[test]
fn compact_born_entry_parks_with_actual_handoff_receipt() {
    use carrick_core::entry::{
        admit_born_in_zone, handoff_born_in_zone, prepare_handoff, publish_handoff_park,
    };
    use carrick_core_abi::{BornInZoneSource, EntryRecordGeneration};
    let zone = compact_zone();
    let (slot, record, binding) = running_compact(&zone, 0);
    let source = BornInZoneSource { zone: &zone, slot };
    let token = admit_born_in_zone(binding, source).unwrap();
    assert!(
        admit_born_in_zone(
            ExecutionBinding {
                mm: EntryMmKey::from_raw(30),
                ..binding
            },
            source
        )
        .is_none()
    );
    let start = prepare_handoff(binding, source, record).unwrap();
    let guard = zone
        .lock(
            ZoneTables::bucket_of(binding.mm.raw(), 0x1000),
            &carrick_sched_core::BoundedSpin(1024),
        )
        .unwrap();
    let sequence = zone.next_seq(record);
    zone.enqueue(
        &guard,
        record,
        sequence,
        binding.mm.raw(),
        0x1000,
        u32::MAX,
        0,
    )
    .unwrap();
    let receipt = publish_handoff_park(start, &guard, EntryRecordGeneration(sequence)).unwrap();
    assert!(
        matches!(zone.record(record).claim(), carrick_sched_core::Claim::Parked { seq } if seq == sequence)
    );
    handoff_born_in_zone(token, receipt).unwrap();
}

#[test]
fn compact_ordinary_entry_retires_with_actual_handoff_receipt() {
    use carrick_core::entry::{prepare_handoff, retire_current};
    use carrick_core_abi::BornInZoneSource;
    let zone = compact_zone();
    let (slot, record, binding) = running_compact(&zone, 19);
    let source = BornInZoneSource { zone: &zone, slot };
    let token = admit(binding, Some(source)).unwrap();
    assert!(
        prepare_handoff(
            ExecutionBinding {
                thread_generation: EntryThreadGeneration::from_raw(114),
                ..binding
            },
            source,
            record
        )
        .is_none()
    );
    let receipt = retire_current(binding, source, record, 1024).unwrap();
    assert!(zone.slot(slot).current().is_none());
    handoff(token, receipt).unwrap();
    assert!(retire_current(binding, source, record, 1024).is_none());
}

#[test]
fn compact_handoff_rejects_stale_record_incarnation_receipt() {
    use carrick_core::entry::{admit_born_in_zone, handoff_born_in_zone, retire_current};
    use carrick_core_abi::{BornInZoneSource, EntryHandoffReceipt};
    let zone = compact_zone();
    let (slot, record, binding) = running_compact(&zone, 0);
    let source = BornInZoneSource { zone: &zone, slot };
    let first = admit_born_in_zone(binding, source).unwrap();
    let captured_record = first.record();
    let receipt = retire_current(binding, source, record, 1024).unwrap();
    handoff_born_in_zone(first, receipt).unwrap();
    let identity = ThreadIdentity {
        tid: binding.task.raw(),
        serial: binding.thread_generation.raw(),
        mm: binding.mm.raw(),
        file_table: 9,
        generation: 0,
        affinity: 1 << 1,
        lifecycle_page: 0x1000,
        control_slot: 0x2000,
    };
    let replacement = zone.alloc_record(identity).unwrap();
    zone.requeue_preempted(slot, replacement);
    assert_eq!(zone.switch_in(slot), Some(replacement));
    let second = admit_born_in_zone(binding, source).unwrap();
    assert_ne!(captured_record, second.record());
    // SAFETY: test-only adversarial reconstruction of old authenticated bytes;
    // safe production issuance consumes one exact successful transition.
    let replay =
        unsafe { EntryHandoffReceipt::from_published_transition(binding, captured_record) };
    assert_eq!(
        handoff_born_in_zone(second, replay),
        Err(CompletionError::WrongGeneration)
    );
}

#[test]
fn compact_fork_child_gate_releases_owned_wait_with_sourceful_access() {
    use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
    use carrick_sched_core::spaces::notification::SpaceAccess;
    use carrick_sched_core::spaces::notification::{
        SpaceReleaseVenue, SpaceWaitCause, SpaceWakeDelivery,
    };
    use carrick_sched_core::{BoundedSpin, Claim, Waker};
    use core::num::NonZeroU64;
    let zone = compact_zone();
    let (slot, _, _) = running_compact(&zone, 11);
    let index = zone.spaces.publish_closed(41, 0x30000, 0x30000).unwrap();
    let entry = zone.space_entry(NonZeroU64::new(41).unwrap()).unwrap();
    let complete = |effects: OwnedObjectWakeEffects<'_, carrick_sched_core::ParkedContextWords>| {
        let _ = effects.deliver_handbacks(&mut |_| panic!("no host handback admitted"));
    };
    entry
        .admit_notifications(NonZeroU64::MIN, &BoundedSpin(1024), &complete)
        .unwrap();
    let lease = entry.notifications(NonZeroU64::MIN).unwrap();
    let before = lease.observe(SpaceWaitCause::Gate);
    let record = zone
        .alloc_record(ThreadIdentity {
            tid: 72,
            serial: 115,
            mm: 29,
            file_table: 9,
            generation: 11,
            affinity: 2,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    lease
        .reserve(SpaceWaitCause::Gate)
        .park_host_rechecked(
            before,
            record,
            OperationToken::new(41, 1).unwrap(),
            &complete,
            || true,
        )
        .unwrap();
    let delivered = core::cell::Cell::new(0);
    let handed = core::cell::Cell::new(0);
    let delivery =
        |actual: &ZoneTables<carrick_sched_core::ParkedContextWords>,
         waker,
         effects: OwnedObjectWakeEffects<'_, carrick_sched_core::ParkedContextWords>| {
            assert!(core::ptr::eq(actual, &*zone));
            assert_eq!(waker, Waker::El1 { slot });
            let (_, work) = effects.deliver_handbacks(&mut |actual| {
                assert_eq!(actual.id, record);
                handed.set(handed.get() + 1);
            });
            assert!(!work.queued_own);
            delivered.set(delivered.get() + 1);
        };
    let access = SpaceAccess::notified(SpaceReleaseVenue {
        zone: &zone,
        waker: Waker::El1 { slot },
        deliver: SpaceWakeDelivery::Captured(&delivery),
    });
    access.open(index);
    assert_eq!(zone.spaces.gate(index), 0);
    assert_ne!(lease.observe(SpaceWaitCause::Gate), before);
    assert!(zone.spaces.grant(index, 41).is_some());
    assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
    assert_eq!(handed.get(), 1);
    assert_eq!(delivered.get(), 1);
}
