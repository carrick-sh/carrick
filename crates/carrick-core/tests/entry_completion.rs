//! Entry-turn ownership joins the existing exact-record wait authority.
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_core::entry::{CompletionError, admit, complete, handoff};
use carrick_core::wait::{notify_object, park_object_record, take_object_operation};
use carrick_core_abi::{
    EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, ObjectParkRequest,
    SnapshotGeneration,
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
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            };
            let binding = ExecutionBinding {
                task: EntryTaskKey::from_raw(41),
                generation: SnapshotGeneration::from_raw(generation),
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
                park_object_record(&zone, slot, request, &|_| {}, || Ok((record, false))).unwrap();
            assert!(parked.matches(&zone, slot));
            // The entry turn ends here. Its token cannot later take the
            // ordinary path; the record owns the sole remaining operation.
            handoff(entry, parked.take_receipt().unwrap()).unwrap();
            assert!(zone.slot(slot).current().is_none());
            let (wake, _) = notify_object(&zone, slot, key).unwrap();
            assert_eq!(wake.queued, 1);
            assert_eq!(notify_object(&zone, slot, key).unwrap().0.queued, 0);
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
        generation: SnapshotGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(7),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    // Same visible TID, but a different exact execution/MM/thread owner.
    for current in [
        ExecutionBinding {
            generation: SnapshotGeneration::from_raw(12),
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
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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
        generation: SnapshotGeneration::from_raw(0),
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
    let handed_back = zone.record_ref(record);
    assert_eq!(
        zone.handback_current(slot, record),
        carrick_sched_core::CurrentHandback::HandedBack
    );
    // Entry completion does not adopt this birth into the host graph. Its
    // frozen host custody must still authenticate the incarnation at mint.
    assert_eq!(
        zone.record(record).claim(),
        carrick_sched_core::Claim::FirstEntryHost {
            incarnation: handed_back.incarnation
        }
    );
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
        &|_| {},
        || Ok((record, false)),
    )
    .unwrap();
    assert!(parked.matches(&zone, slot));
    assert_eq!(notify_object(&zone, slot, key).unwrap().0.queued, 1);
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
        generation: SnapshotGeneration::from_raw(11),
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
        generation: SnapshotGeneration::from_raw(11),
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
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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
            generation: SnapshotGeneration::from_raw(generation),
            mm: EntryMmKey::from_raw(identity.mm),
            thread_generation: EntryThreadGeneration::from_raw(identity.serial),
        },
    )
}

#[test]
fn terminal_park_hands_back_only_an_exact_requested_owner() {
    use carrick_core::entry::{prepare_handoff, publish_handoff_park};
    use carrick_core_abi::{BornInZoneSource, EntryRecordGeneration};
    use carrick_sched_core::object_wait::OwnerEntry;
    use carrick_sched_core::{Claim, Handback, HostClaim, ShortLockSpin};

    for (terminal, owner_continuation, wrong_guard) in [
        (true, true, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let zone = compact_zone();
        let foreign = compact_zone();
        let (slot, record, binding) = running_compact(&zone, 19);
        let source = BornInZoneSource { zone: &zone, slot };
        let start = prepare_handoff(binding, source, record).unwrap();
        let reference = zone.record_ref(record);
        assert!(
            matches!(zone.claim_for_host(reference, None, Handback::Control, &ShortLockSpin),
            HostClaim::El1Held { slot: owner } if owner == slot)
        );
        if owner_continuation {
            // SAFETY: this exact fixture still owns the running record.
            unsafe {
                zone.record(record)
                    .publish_owner_continuation(OwnerEntry::Syscall)
            };
        }
        let guard = zone
            .lock(ZoneTables::bucket_of(29, 0x1000), &ShortLockSpin)
            .unwrap();
        let sequence = zone.next_seq(record);
        zone.enqueue(&guard, record, sequence, 29, 0x1000, u32::MAX, 0)
            .unwrap();
        let foreign_guard = foreign
            .lock(ZoneTables::bucket_of(29, 0x1000), &ShortLockSpin)
            .unwrap();
        let selected_guard = if wrong_guard { &foreign_guard } else { &guard };
        let receipt = if terminal {
            carrick_core::terminal::park_process_exit(
                start,
                selected_guard,
                EntryRecordGeneration(sequence),
            )
        } else {
            publish_handoff_park(start, selected_guard, EntryRecordGeneration(sequence))
        };
        let accepted = terminal && owner_continuation && !wrong_guard;
        assert_eq!(receipt.is_some(), accepted);
        if accepted {
            assert_eq!(zone.slot(slot).current(), None);
            assert_eq!(zone.record(record).entry_count(), 0);
            assert_eq!(zone.take_service_head(slot), Some(reference));
            assert!(zone.live(reference).is_some());
        } else {
            assert_eq!(zone.slot(slot).current(), Some(record));
            assert!(matches!(
                zone.record(record).claim(),
                Claim::OnCpuRequested { .. }
            ));
        }
    }
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
    let receipt = retire_current(binding, source, record).unwrap();
    assert!(zone.slot(slot).current().is_none());
    handoff(token, receipt).unwrap();
    assert!(retire_current(binding, source, record).is_none());
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
    let receipt = retire_current(binding, source, record).unwrap();
    handoff_born_in_zone(first, receipt).unwrap();
    let identity = ThreadIdentity {
        tid: binding.task.raw(),
        serial: binding.thread_generation.raw(),
        mm: binding.mm.raw(),
        file_table: 9,
        generation: 0,
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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

#[test]
fn terminal_member_proof_precedes_lifecycle_receipt_after_record_release() {
    use carrick_core::terminal::{
        Live, MissingContinuationVerdict, TerminalCustody, Thread, ThreadBirthIdentity,
        ThreadTerminalIdentity, missing_zone_continuation,
    };
    use carrick_el1_abi::{Lifecycle, ThreadControlSlot, ThreadLifecyclePage};
    let zone = compact_zone();
    let (slot, record, binding) = running_compact(&zone, 0);
    let reference = zone.record_ref(record);
    let source = carrick_core_abi::BornInZoneSource { zone: &zone, slot };
    let member = ThreadControlSlot::new();
    let birth = ThreadBirthIdentity::from_parts(
        binding.task,
        carrick_core_abi::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
        ),
        binding.thread_generation,
    )
    .unwrap();
    member.publish_host_birth_identity(birth);
    member.bind_zone_record(reference);
    let page = ThreadLifecyclePage::new();
    assert_eq!(page.thread_born(), Some(2));
    let identity = ThreadTerminalIdentity::from_exit(
        binding,
        None,
        carrick_sched_core::process::TerminationStatus::SUCCESS,
    )
    .unwrap();
    let (custody, mut _membership) = TerminalCustody::<Thread, Live>::admitted(identity)
        .begin()
        .reserve_member(&page, &member)
        .unwrap_or_else(|_| panic!("nonfinal member"));
    let classify = || {
        missing_zone_continuation(
            &member,
            birth,
            member.host_birth_identity(),
            reference,
            member.zone_record(),
        )
    };
    assert_eq!(classify(), MissingContinuationVerdict::InvariantViolation);
    let foreign = ExecutionBinding {
        thread_generation: EntryThreadGeneration::from_raw(999),
        ..binding
    };
    assert!(
        custody
            .retire_zone_current(&member, &mut _membership, foreign, source, record)
            .is_none()
    );
    assert_eq!(classify(), MissingContinuationVerdict::InvariantViolation);
    custody
        .retire_zone_current(&member, &mut _membership, binding, source, record)
        .unwrap();
    assert!(zone.live(reference).is_none());
    assert_eq!(
        carrick_core::lifecycle::recorded_member_exit_kind(&member, None),
        carrick_core::lifecycle::MemberExitKind::Active
    );
    assert_eq!(
        classify(),
        MissingContinuationVerdict::Terminal,
        "record release must never precede retained terminal proof"
    );
    drop(_membership);
    assert_eq!(
        page.live(),
        1,
        "released terminal membership must not refund on drop"
    );
    let host = carrick_core::terminal::reserve_host_thread_exit_membership(&page, &member)
        .unwrap_or_else(|_| panic!("native reservation also owns host graph cleanup"));
    assert_eq!(
        page.live(),
        1,
        "host must not reserve native membership twice"
    );
    host.commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
        .publish();
    assert_eq!(page.live(), 1, "native page retirement is still pending");
    let again = carrick_core::terminal::reserve_host_thread_exit_membership(&page, &member)
        .unwrap_or_else(|_| panic!("graph cleanup must preserve native provenance"));
    assert_eq!(page.live(), 1);
    again.publish();
}

#[test]
fn committed_host_zone_retirement_never_refunds_or_borrows_native_membership() {
    use carrick_core::terminal::reserve_host_thread_exit_membership;
    use carrick_el1_abi::{Lifecycle, ThreadControlSlot, ThreadLifecyclePage};
    let page = ThreadLifecyclePage::new();
    let member = ThreadControlSlot::new();
    assert_eq!(page.thread_born(), Some(2));
    drop(reserve_host_thread_exit_membership(&page, &member).unwrap_or_else(|_| panic!("reserve")));
    assert_eq!(page.live(), 2, "uncommitted preparation refunds membership");
    let committed = reserve_host_thread_exit_membership(&page, &member)
        .unwrap_or_else(|_| panic!("reserve"))
        .commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test());
    assert_eq!(page.live(), 1);
    assert!(
        reserve_host_thread_exit_membership(&page, &member).is_err(),
        "host intent cannot borrow a native-owned reservation"
    );
    drop(committed);
    assert_eq!(
        page.live(),
        1,
        "committed terminal ownership cannot refund live"
    );
}

/// Two live scheduler members share a lifecycle page. Keep both exit tokens
/// alive across the attempted release: destructor timing must not hide the
/// queue-publication window.
#[test]
fn requeued_terminal_attempt_restores_membership_and_admission_before_return() {
    terminal_attempt(TerminalAttempt::Requeue);
}
#[test]
fn refused_requeue_lock_keeps_membership_and_admission_for_commit() {
    terminal_attempt(TerminalAttempt::LockRefused);
}
#[test]
fn host_home_terminal_release_commits_the_same_exit_ownership() {
    terminal_attempt(TerminalAttempt::HostHome);
}

#[test]
fn losing_requeue_cas_keeps_membership_and_admission_for_commit() {
    terminal_attempt(TerminalAttempt::CasLost);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalAttempt {
    Requeue,
    LockRefused,
    HostHome,
    CasLost,
}

fn terminal_attempt(mode: TerminalAttempt) {
    let refuse_lock = mode == TerminalAttempt::LockRefused;
    let host_home = mode == TerminalAttempt::HostHome;
    let lose_cas = mode == TerminalAttempt::CasLost;
    use carrick_core::lifecycle::{EntryRef, MemberControl, MemberExitCustody};
    use carrick_core::terminal::{Live, TerminalCustody, Thread, ThreadTerminalIdentity};
    use carrick_el1_abi::{Lifecycle, ThreadLifecyclePage};
    use carrick_sched_core::{BoundedSpin, Claim, WakeEffects};
    struct Member(MemberExitCustody, EntryRef);
    impl MemberControl for Member {
        fn member_entry(&self) -> Option<EntryRef> {
            Some(self.1)
        }
        fn exit_custody(&self) -> &MemberExitCustody {
            &self.0
        }
        fn host_retirement(&self) -> Option<carrick_core::terminal::HostThreadRetirementReceipt> {
            None
        }
    }
    let zone = compact_zone();
    let (slot, record, binding) = running_compact(&zone, 19);
    let mut peer_identity = zone.record(record).identity();
    peer_identity.tid += 1;
    peer_identity.serial += 1;
    let peer = zone.alloc_record(peer_identity).unwrap();
    zone.requeue_preempted(SlotId::new(2), peer);
    let page = ThreadLifecyclePage::new();
    assert_eq!(page.thread_born(), Some(2));
    let entry = page.reserve_stock(0).unwrap();
    page.transition(
        entry,
        &[carrick_core::lifecycle::EntryState::Stocking],
        carrick_core::lifecycle::EntryState::Reserved,
        std::sync::atomic::Ordering::Release,
    )
    .unwrap();
    let claim = page.claim(entry).unwrap();
    page.complete_birth(claim).unwrap();
    page.publish(entry).unwrap();
    let member = Member(MemberExitCustody::new(), entry);
    let record = if host_home {
        let id = zone.record(record).identity();
        assert_eq!(
            zone.release_current(slot, record, &BoundedSpin(1024)),
            carrick_sched_core::CurrentRelease::Released
        );
        zone.current_or_new(slot, id).unwrap()
    } else {
        let key = ObjectWaitKey::new(41, 1).unwrap();
        zone.bind_object_wait(key, &BoundedSpin(1024)).unwrap();
        {
            let guard = zone.object_wait(key, &BoundedSpin(1024)).unwrap();
            guard
                .park(
                    guard.snapshot(),
                    record,
                    OperationToken::new(41, 1).unwrap(),
                )
                .unwrap();
        }
        zone.clear_current(slot);
        {
            let guard = zone.object_wait(key, &BoundedSpin(1024)).unwrap();
            assert_eq!(
                guard
                    .notify_object(slot, &mut WakeEffects::default())
                    .unwrap()
                    .queued,
                1
            );
        }
        assert_eq!(zone.switch_in(slot), Some(record));
        record
    };
    let identity = ThreadTerminalIdentity::from_exit(
        binding,
        Some(entry),
        carrick_sched_core::process::TerminationStatus::SUCCESS,
    )
    .unwrap();
    let (custody, mut membership) = TerminalCustody::<Thread, Live>::admitted(identity)
        .begin()
        .reserve_member(&page, &member)
        .unwrap_or_else(|_| panic!("member reservation"));
    let mut admission = page.begin_exit(entry).unwrap();
    let retirement = custody
        .zone_retirement(&member, &mut membership, Some(&mut admission))
        .unwrap();
    if lose_cas {
        // Keep the real member/admission tokens on this lane. The peer pauses
        // the actual slot-lock acquisition, then parks/wakes the record through
        // a fresh claim generation using production scheduler operations.
        struct Pause {
            reached: std::sync::mpsc::SyncSender<()>,
            resume: std::sync::mpsc::Receiver<()>,
            once: std::sync::atomic::AtomicBool,
        }
        impl carrick_sched_core::LockWait<carrick_sched_core::ParkedContextWords> for Pause {
            fn wait(&self, _: u32) -> bool {
                if !self.once.swap(true, std::sync::atomic::Ordering::AcqRel) {
                    self.reached.send(()).unwrap();
                    self.resume
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                }
                true
            }
        }
        let (held, held_rx) = std::sync::mpsc::sync_channel(1);
        let (reached, blocked) = std::sync::mpsc::sync_channel(1);
        let (resume, resumed) = std::sync::mpsc::sync_channel(1);
        let wait = Pause {
            reached,
            resume: resumed,
            once: std::sync::atomic::AtomicBool::new(false),
        };
        let zone = &*zone;
        std::thread::scope(|scope| {
            let actor = scope.spawn(move || {
                let guard = zone.slot_lock(slot, &BoundedSpin(1024)).unwrap();
                let before = zone.record(record).claim();
                held.send(()).unwrap();
                blocked
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                drop(guard);
                // SAFETY: the release lane is paused before its claim CAS;
                // this actor exclusively advances the fixture's native record.
                assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
                let key = ObjectWaitKey::new(42, 1).unwrap();
                zone.bind_object_wait(key, &BoundedSpin(1024)).unwrap();
                {
                    let guard = zone.object_wait(key, &BoundedSpin(1024)).unwrap();
                    guard
                        .park(
                            guard.snapshot(),
                            record,
                            OperationToken::new(42, 1).unwrap(),
                        )
                        .unwrap();
                }
                zone.clear_current(slot);
                {
                    let guard = zone.object_wait(key, &BoundedSpin(1024)).unwrap();
                    assert_eq!(
                        guard
                            .notify_object(slot, &mut WakeEffects::default())
                            .unwrap()
                            .queued,
                        1
                    );
                }
                assert_eq!(zone.switch_in(slot), Some(record));
                assert_ne!(zone.record(record).claim().seq(), before.seq());
                resume.send(()).unwrap();
            });
            held_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert_eq!(
                zone.release_current_with(slot, record, &wait, retirement),
                Some(carrick_sched_core::CurrentRelease::Released)
            );
            actor.join().unwrap();
        });
    } else if refuse_lock {
        let _guard = zone.slot_lock(slot, &BoundedSpin(1024)).unwrap();
        assert_eq!(
            zone.release_current_with(slot, record, &BoundedSpin(0), retirement),
            Some(carrick_sched_core::CurrentRelease::Released)
        );
    } else {
        let released = retirement.retire_current(
            binding,
            carrick_core_abi::BornInZoneSource { zone: &zone, slot },
            record,
        );
        assert_eq!(released.is_ok(), host_home);
    }
    if refuse_lock || host_home || lose_cas {
        assert_eq!(
            page.live(),
            1,
            "committing release lost its live reservation"
        );
        assert_eq!(
            page.state(0),
            Some((
                entry.generation(),
                carrick_core::lifecycle::EntryState::ExitingPublished
            )),
            "committing release rolled admission back"
        );
        admission.commit_with_member(&member).unwrap();
        membership.publish();
        assert_eq!(page.live(), 1);
        assert_eq!(
            page.state(0),
            Some((
                entry.generation(),
                carrick_core::lifecycle::EntryState::ExitedInZone
            ))
        );
        assert!(zone.live(zone.record_ref(peer)).is_some());
        return;
    }
    assert!(matches!(zone.record(record).claim(), Claim::Queued { .. }));
    assert_eq!(
        page.live(),
        2,
        "requeued record exposed a reserved live unit"
    );
    assert_eq!(
        page.state(0),
        Some((
            entry.generation(),
            carrick_core::lifecycle::EntryState::Published
        )),
        "requeued record exposed exit admission"
    );
    // A fresh owner can reserve immediately, while the old tokens still live.
    drop(
        carrick_core::terminal::reserve_host_thread_exit_membership(&page, &member)
            .unwrap_or_else(|_| panic!("requeued record exposed a native claim")),
    );
    let next_admission = page.begin_exit(entry).unwrap();
    assert!(
        admission.commit_with_member(&member).is_err(),
        "old rollback token published a later owner's exit"
    );
    assert_eq!(
        page.state(0),
        Some((
            entry.generation(),
            carrick_core::lifecycle::EntryState::ExitingPublished
        ))
    );
    drop(next_admission);
    drop(membership);
    assert_eq!(page.live(), 2);
    assert!(zone.live(zone.record_ref(peer)).is_some());
}

#[test]
fn pool_cancellation_refuses_record_release_before_terminal_gate() {
    use carrick_core::terminal::{Live, TerminalCustody, Thread, ThreadTerminalIdentity};
    use carrick_el1_abi::{
        BlockedMask, BornRecord, EntryIdentity, EntryState, Lifecycle, ThreadControlSlot,
        ThreadLifecyclePage,
    };
    let page = ThreadLifecyclePage::new();
    let member = ThreadControlSlot::new();
    let zone = compact_zone();
    let (slot, record, binding) = running_compact_with_identity(&zone, 11, |identity| {
        identity.lifecycle_page = &page as *const _ as u64;
        identity.control_slot = &member as *const _ as u64;
    });
    let reference = zone.record_ref(record);
    let source = carrick_core_abi::BornInZoneSource { zone: &zone, slot };
    let entry = page
        .stock(
            0,
            EntryIdentity {
                tid: 71,
                visible_tid: 71,
                thread_serial: 113,
                birth: carrick_core_abi::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
                ),
                uid_credit: 0,
            },
        )
        .unwrap();
    page.bind_control_address(entry, &member as *const _ as u64)
        .unwrap();
    member.reset_for_birth(BlockedMask(0), 0, entry).unwrap();
    member.bind_zone_record(reference);
    let claim = page.claim_any().unwrap();
    assert_eq!(page.thread_born(), Some(2));
    page.record_born(
        claim,
        BornRecord {
            caller_task: 41,
            caller_serial: 101,
            clone_flags: 0x0001_0000,
            clear_child_tid: 0,
            blocked: BlockedMask(0),
        },
    )
    .unwrap();
    let identity = ThreadTerminalIdentity::from_exit(
        binding,
        Some(entry),
        carrick_sched_core::process::TerminationStatus::SUCCESS,
    )
    .unwrap();
    let (custody, mut membership) = TerminalCustody::<Thread, Live>::admitted(identity)
        .begin()
        .reserve_member(&page, &member)
        .unwrap_or_else(|_| panic!("nonfinal member"));
    assert!(matches!(
        custody.retire_zone_current(&member, &mut membership, binding, source, record),
        Err(carrick_core::terminal::ZoneRetirementRefusal::HostCustody)
    ));
    assert!(
        zone.live(reference).is_some(),
        "neutral owner must refuse an open pool gate before Free"
    );
    assert_eq!(
        page.state(entry.index()),
        Some((entry.generation(), EntryState::Born))
    );
    drop(membership);
    assert_eq!(
        page.live(),
        2,
        "a refused release must refund its temporary reservation"
    );

    page.close();
    let (custody, mut membership) = TerminalCustody::<Thread, Live>::admitted(identity)
        .begin()
        .reserve_member(&page, &member)
        .unwrap_or_else(|_| panic!("nonfinal closing member"));
    custody
        .retire_zone_current(&member, &mut membership, binding, source, record)
        .unwrap();
    carrick_core::lifecycle::retire_cancelled_pool_member(&page, entry, &member, membership)
        .unwrap();
    assert!(zone.live(reference).is_none());
    assert_eq!(
        page.state(entry.index()),
        Some((entry.generation(), EntryState::Reaped))
    );
    assert_eq!(page.live(), 1);
}
