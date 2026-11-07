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

#[test]
fn raw_exit_keeps_admission_when_fork_closes_gate_during_cleanup() {
    for unadopted in [false, true] {
        parked_cleanup_with_fork(unadopted, false, false, false, true);
    }
}

fn parked_cleanup(unadopted: bool, head_wait: bool, refused: bool, service_refusal: bool) {
    parked_cleanup_with_fork(unadopted, head_wait, refused, service_refusal, false);
}

fn parked_cleanup_with_fork(
    unadopted: bool,
    head_wait: bool,
    refused: bool,
    service_refusal: bool,
    fork_closing: bool,
) {
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
    if fork_closing {
        fixture.page.close_for_fork().unwrap();
    }
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

#[test]
fn two_raw_exits_finish_when_parked_cleanup_becomes_last() {
    let fixture = native_exec_fixture();
    let first = add_signal_sibling_at(&fixture, None, false, 42, 0, SlotId::new(1));
    let second = add_signal_sibling_at(&fixture, None, false, 43, 1, SlotId::new(2));
    // Establish the reachable precondition: the leader has already retired,
    // leaving two live pooled members. Use the neutral terminal transaction,
    // not a synthetic live-word write, and remove its actual graph membership.
    let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
        crate::common_entry::execution_binding(fixture.task),
        None,
        carrick_sched_core::process::TerminationStatus::exited(0),
    )
    .unwrap();
    let (custody, mut membership) = carrick_core::terminal::TerminalCustody::<
        carrick_core::terminal::Thread,
        carrick_core::terminal::Live,
    >::admitted(identity)
    .begin()
    .reserve_member(fixture.page, fixture.control)
    .unwrap_or_else(|_| panic!("leader terminal setup"));
    let _receipt = custody
        .retire_zone_current(
            fixture.control,
            &mut membership,
            identity.binding(),
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.record.id,
        )
        .unwrap();
    membership.publish();
    let key = fixture.runtime.graph.lock().root_key;
    {
        let mut graph = fixture.runtime.graph.lock();
        let task = graph.owner.task_mut(key).unwrap();
        task.remove_thread(41);
        task.native_mut()
            .resources_mut()
            .members
            .retain(|member| member.record != fixture.record);
    }
    fixture
        .registry
        .unregister_member(&fixture.runtime, key, fixture.record);
    assert!(fixture.zone.live(fixture.record).is_none());
    assert_eq!(fixture.page.live(), 2);

    let word = carrick_test_support::GuestUserBuffer::from_value(43_u32);
    second.control.set_clear_child_tid(word.arg());
    let mut service = fixture.service();
    service.tid_words.insert((1, word.arg()), 43);
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
    let access = crate::sched::object_wait::space_access(fixture.zone, second.slot);
    access.raise(space.index());
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    service.child_copy_error_at = Some(word.arg());
    let second_source = BornInZoneSource {
        zone: fixture.zone,
        slot: second.slot,
    };
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                second_source,
                second.task,
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
    assert_eq!(fixture.page.live(), 2);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: first.slot,
                },
                first.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry
                .exit_thread(carrick_sched_core::process::TerminationStatus::exited(3))
                .unwrap(),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert!(entry.take_run_failure().is_none());
    }
    assert_eq!(fixture.page.live(), 1);
    service.child_copy_error = None;
    access.lower(space.index());
    assert_eq!(
        fixture.zone.switch_in_full(second.slot).unwrap().record,
        second.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(second.record) }
        .unwrap()
        .words;
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            second_source,
            second.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Left(Some(status)) if status.raw() == LinuxWaitStatus::exited(7).raw())
    );
    assert!(entry.take_run_failure().is_none());
    assert_eq!(fixture.page.live(), 0);
}

#[test]
fn raw_exit_initial_fork_gate_retains_adopted_custody() {
    raw_exit_initial_fork_gate(false);
}

#[test]
fn raw_exit_initial_fork_gate_retains_unadopted_custody() {
    raw_exit_initial_fork_gate(true);
}

fn raw_exit_initial_fork_gate(unadopted: bool) {
    let fixture = native_exec_fixture();
    let sibling = add_signal_sibling(&fixture, None, false);
    if unadopted {
        assert!(fixture.zone.mark_native_owned(sibling.record.id));
    }
    let word = carrick_test_support::GuestUserBuffer::from_value(42_u32);
    sibling.control.set_clear_child_tid(word.arg());
    let mut service = fixture.service();
    service.tid_words.insert((1, word.arg()), 42);
    fixture.page.close_for_fork().unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
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
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(
            entry.take_run_failure().is_none(),
            "gate contention retains terminal custody"
        );
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(service.tid_words[&(1, word.arg())], 42);
    assert!(!sibling.control.host_exit_requested());
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .pending
            .has_cleanup(sibling.record)
    );
    assert!(fixture.zone.live(sibling.record).is_some());
    // The holder is still active. Actual release/resume must be witnessed
    // through its production notification venue once that protocol exists.
}

#[test]
fn raw_exit_faulting_robust_word_keeps_successor() {
    for unadopted in [false, true] {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        if unadopted {
            assert!(fixture.zone.mark_native_owned(sibling.record.id));
        }
        let mut head = carrick_test_support::GuestUserBuffer::from_values(&[0_u64; 3]);
        let mut first = carrick_test_support::GuestUserBuffer::from_values(&[0_u64, 0x8000_002a]);
        let mut second = carrick_test_support::GuestUserBuffer::from_values(&[0_u64, 0x8000_002a]);
        head.set(0, first.arg());
        head.set(1, 8_u64);
        first.set(0, second.arg());
        second.set(0, head.arg());
        sibling.control.set_robust_list(head.arg(), 24);
        let mut service = fixture.service();
        service.child_copy_error = Some(NativeProcessError::Fault);
        service.child_copy_error_at = Some(first.arg() + 8);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: sibling.slot,
                },
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
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_run_failure().is_none());
        assert!(fixture.zone.live(sibling.record).is_none());
        assert_eq!(fixture.page.live(), 1);
        assert_eq!(first.get::<u32>(2), 0x8000_002a);
        assert_eq!(second.get::<u32>(2), 0xc000_0000);
    }
}

#[test]
fn exit_group_worker_terminal_copy_wait_finishes_after_fault_or_supply() {
    for unadopted in [false, true] {
        for head_wait in [false, true] {
            for refused in [false, true] {
                group_worker_cleanup(unadopted, head_wait, refused);
            }
        }
    }
}

fn group_worker_cleanup(unadopted: bool, head_wait: bool, refused: bool) {
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
    let root_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let mut service = fixture.service();
    service.tid_words.insert((1, word.arg()), 42);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_run_failure().is_none());
        assert!(entry.take_handoff_receipt().is_some());
    }
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
    access.raise(space.index());
    // SAFETY: the fixture owns this live MM producer and its observed revision.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
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
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_run_failure().is_none());
        // resume_checkpoint validates and consumes the handoff receipt.
        // The parked record and retained TID below prove ongoing custody.
    }
    assert!(fixture.zone.live(sibling.record).is_some());
    assert_eq!(sibling.control.clear_child_tid(), word.arg());
    service.child_copy_error = refused.then_some(NativeProcessError::Fault);
    access.lower(space.index());
    assert_eq!(
        fixture.zone.switch_in_full(sibling.slot).unwrap().record,
        sibling.record.id
    );
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
    assert_eq!(sibling.control.clear_child_tid(), 0);
    assert_eq!(
        service.tid_words[&(1, word.arg())],
        if refused && !head_wait { 42 } else { 0 }
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            root_source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Left(Some(status))
        if status.raw() == LinuxWaitStatus::exited(7).raw())
    );
    assert!(entry.take_run_failure().is_none());
    assert_eq!(fixture.page.live(), 0);
    drop(entry);
    assert_eq!(
        service
            .tid_writes
            .iter()
            .filter(|(_, address, _)| *address == word.arg())
            .count(),
        usize::from(!refused || head_wait),
        "a completed clear-TID store is never replayed",
    );
}
