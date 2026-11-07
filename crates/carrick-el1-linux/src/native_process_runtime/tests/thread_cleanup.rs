//! Production terminal entry, real scheduler waiter and exact-MM producer queue.
use super::*;

#[test]
fn raw_exit_terminal_copies_park_and_finish_once() {
    for unadopted in [false, true] {
        for head_wait in [false, true] {
            for refused in [false, true] {
                parked_cleanup(unadopted, head_wait, refused, false);
            }
        }
    }
}

#[test]
fn raw_exit_terminal_supply_refusal_advances_instead_of_retrying() {
    for unadopted in [false, true] {
        for head_wait in [false, true] {
            parked_cleanup(unadopted, head_wait, true, true);
        }
    }
}

fn parked_cleanup(unadopted: bool, head_wait: bool, refused: bool, service_refusal: bool) {
    let fixture = native_exec_fixture();
    let sibling = add_signal_sibling(&fixture, None, false);
    if unadopted {
        assert!(fixture.zone.mark_native_owned(sibling.record.id));
    }
    let word = carrick_test_support::GuestUserBuffer::from_value(42_u32);
    let mut head = carrick_test_support::GuestUserBuffer::from_values(&[0_u64; 3]);
    head.set(0, head.arg());
    sibling.control.set_clear_child_tid(word.arg());
    if head_wait {
        sibling.control.set_robust_list(head.arg(), 24);
    }

    // The other live thread really waits on this exiting thread's TID word.
    let root_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let root_binding = crate::common_entry::execution_binding(fixture.task);
    let start =
        carrick_core::entry::prepare_handoff(root_binding, root_source, fixture.record.id).unwrap();
    let guard = fixture.zone.short_lock(
        ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, word.arg()),
        &carrick_sched_core::ShortLockSpin,
    );
    let sequence = fixture.zone.next_seq(fixture.record.id);
    fixture
        .zone
        .enqueue(
            &guard,
            fixture.record.id,
            sequence,
            1,
            word.arg(),
            u32::MAX,
            0,
        )
        .unwrap();
    let _receipt = carrick_core::entry::publish_handoff_park(
        start,
        &guard,
        carrick_core_abi::EntryRecordGeneration(sequence),
    )
    .unwrap();
    drop(guard);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let mut service = fixture.service();
    service.tid_words.insert((1, word.arg()), 42);
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    space
        .admit_notifications(
            handle.incarnation(),
            &carrick_sched_core::BoundedSpin(0),
            &|effects| {
                let _ = effects.defer_handbacks();
            },
        )
        .unwrap();
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(fixture.zone, sibling.slot);
    if service_refusal {
        let task = sibling.task;
        let control = sibling.control;
        let record = sibling.record;
        let zone = fixture.zone;
        set_service_published_hook(
            Arc::as_ptr(&fixture.runtime) as usize,
            Box::new(move || {
                let notice = task.service_notice.take().unwrap().unwrap();
                let queue = zone
                    .object_wait(
                        carrick_sched_core::object_wait::ObjectWaitKey::native_service(record)
                            .unwrap(),
                        &carrick_sched_core::ShortLockSpin,
                    )
                    .unwrap();
                let ticket = unsafe {
                    carrick_core_abi::service::ServiceCell::claim_notice(
                        &control.service,
                        notice,
                        NonZeroU64::MIN,
                        zone.record(record.id).identity(),
                    )
                }
                .unwrap();
                ticket
                    .complete(false)
                    .unwrap_or_else(|_| panic!("terminal supply refusal must complete"));
                drop(queue);
            }),
        );
        service.child_copy_error = Some(NativeProcessError::Busy);
    } else {
        access.raise(space.index());
        // SAFETY: this fixture retains the exact live owner and observed Gate.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_core_abi::PortalWaitCause::Gate,
                observed.revision(),
            )
        };
        service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    }
    service.child_copy_error_at = Some(if head_wait { head.arg() } else { word.arg() });
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                sibling.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry
                .exit_thread(carrick_sched_core::process::TerminationStatus::exited(7))
                .unwrap(),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert!(entry.take_run_failure().is_none());
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(!sibling.control.host_exit_requested());
    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 0);
    if !service_refusal {
        service.child_copy_error = refused.then_some(NativeProcessError::Fault);
        access.lower(space.index());
    }
    let memory_wakes = fixture.zone.counters.el1_wakes.load(Ordering::Acquire);
    let selected = fixture.zone.switch_in_full(sibling.slot).unwrap();
    assert_eq!(selected.record, sibling.record.id);
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                sibling.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_run_failure().is_none());
    }
    assert!(fixture.zone.live(sibling.record).is_none());
    assert_eq!(fixture.page.live(), 1);
    assert_eq!(sibling.control.clear_child_tid(), 0);
    assert_eq!(
        fixture.zone.counters.el1_wakes.load(Ordering::Acquire),
        memory_wakes + 1,
        "exactly one TID waiter wakes after memory preparation"
    );
    assert_eq!(
        service.tid_words[&(1, word.arg())],
        if refused && !head_wait { 42 } else { 0 }
    );
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .pending
            .has_cleanup(sibling.record)
    );
}
