use super::*;

fn terminal_close_with_retained_service_entry_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    operation: carrick_core_abi::service::ServiceOperation,
    exit: NativeServiceExit,
) {
    use carrick_core_abi::service::ServiceOperation;

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let mut sibling = add_service_sibling(
        &fixture,
        Some(ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(64),
        }),
    );
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 1);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
    }
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record),
        "the cancelled service remains the sibling's exact retained owner"
    );
    assert!(
        sibling
            .service_ticket
            .take()
            .unwrap()
            .complete(true)
            .is_ok(),
        "the carrier settles the cancelled service ticket"
    );

    let slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .expect("the cancelled service wakes its exact member");
    assert_eq!(
        fixture.zone.switch_in_full(slot).unwrap().record,
        sibling.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = slot;
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let result = member.begin_service(operation, None);
    let phase = member.native_service_phase();
    let settled = member.settle_service_exit(result, exit);
    let resumed = crate::dispatch::native_service_completion(settled, phase)
        .unwrap_or_else(|fatal| panic!("terminal service entry became {fatal:?}"));
    assert!(matches!(resumed, NativeResume::Left(None)));
    assert!(
        member.take_handoff_receipt().is_none(),
        "production service settlement consumes the retirement receipt"
    );
    drop(member);

    assert!(fixture.zone.live(sibling.record).is_none());
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record)
    );
    assert!(sibling.task.service_notice.take().unwrap().is_none());
}

fn terminal_close_with_signal_wait_irq_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_service_sibling(&fixture, None);
    fixture.runtime.graph.lock().insert_member_wait(
        sibling.record,
        MemberWait::Signal(PendingSignalWait {
            kind: PendingSignalKind::Suspend,
            channel: Arc::new(WaitChannel {
                generation: ProcessWake::new(),
                mm: fixture.address.mm.raw().get(),
            }),
            deadline: None,
        }),
    );

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
    }
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record),
        "the terminal request has not yet consumed the sibling's signal wait"
    );

    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = sibling.slot;
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &(fixture.make_words)(fixture.address),
            &mut sibling_service,
        )
        .unwrap();
    let result = member.begin_service(
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        None,
    );
    let phase = member.native_service_phase();
    let settled = member.settle_service_exit(result, NativeServiceExit::CarrierWork);
    let resumed = crate::dispatch::native_service_completion(settled, phase)
        .unwrap_or_else(|fatal| panic!("terminal signal-wait IRQ entry became {fatal:?}"));
    assert!(matches!(resumed, NativeResume::Left(None)));
    assert!(member.take_handoff_receipt().is_none());
    drop(member);

    assert!(fixture.zone.live(sibling.record).is_none());
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record)
    );
    assert!(sibling.task.service_notice.take().unwrap().is_none());
}

/// A CarrierWork selector is only a demand to settle work already owed by
/// this execution lane. Another executor may consume that work after the
/// selector is captured but before its ticket is served. The carrier then
/// refuses the empty demand; the exact saved continuation must resume rather
/// than turning ordinary completion contention into an invariant.
fn refused_carrier_work_resumes_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    owner_entry: OwnerEntry,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let task = fixture.task;
    let zone = fixture.zone;
    let record = fixture.record;
    let control = fixture.control;
    on_service_doorbell(Some(Box::new(move || {
        let notice = task.service_notice.take().unwrap().unwrap();
        let key = carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap();
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        // SAFETY: the fixture retains this exact member and its service queue.
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &control.service,
                notice,
                NonZeroU64::MIN,
                zone.record(record.id).identity(),
            )
        }
        .unwrap();
        assert!(matches!(
            ticket.request().operation,
            ServiceOperation::CarrierWork { entry, .. } if entry == owner_entry
        ));
        // The selected work was consumed by another executor before this
        // physical intake. Refusal is the production transport answer.
        assert!(ticket.complete(false).is_ok());
        drop(queue);
        false
    })));

    let mut service = fixture.service();
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &(fixture.make_words)(fixture.address),
            &mut service,
        )
        .unwrap();
    let result = entry.begin_service(
        ServiceOperation::CarrierWork {
            entry: owner_entry,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        None,
    );
    let phase = entry.native_service_phase();
    let settled = entry.settle_service_exit(result, NativeServiceExit::CarrierWork);
    let resumed = crate::dispatch::native_service_completion(settled, phase)
        .unwrap_or_else(|fatal| panic!("refused completed CarrierWork became {fatal:?}"));
    on_service_doorbell(None);
    assert!(matches!(
        resumed,
        NativeResume::Returned(result) if result.raw() == 0
    ));
}

/// #2532 run B: a real SVC entry for mmap may race a sibling's terminal close
/// after this member's earlier service was cancelled but before its owner
/// checkpoint consumed that wait. Closing is authoritative: the new entry
/// settles the retained service and retires instead of becoming an invariant.
#[test]
fn arm_terminal_close_with_retained_service_accepts_mmap_entry() {
    terminal_close_with_retained_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(222),
        },
        NativeServiceExit::Bridge,
    );
}

#[test]
fn x86_terminal_close_with_retained_service_accepts_mmap_entry() {
    terminal_close_with_retained_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(9),
        },
        NativeServiceExit::Bridge,
    );
}

/// #2532 run A: the same terminal interleaving can arrive from an IRQ as
/// CarrierWork. Its exception continuation owns the exact retained record;
/// terminal settlement must not publish a second service or return to EL0.
#[test]
fn arm_terminal_close_with_retained_service_accepts_irq_carrier_work() {
    terminal_close_with_retained_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        NativeServiceExit::CarrierWork,
    );
}

#[test]
fn x86_terminal_close_with_retained_service_accepts_irq_carrier_work() {
    terminal_close_with_retained_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        NativeServiceExit::CarrierWork,
    );
}

/// #2532 round 2: terminal close can select a record whose retained owner is
/// a signal wait before its next IRQ CarrierWork entry. The close remains the
/// authoritative owner; no new service may replace the wait or return to EL0.
#[test]
fn arm_terminal_close_with_signal_wait_accepts_irq_carrier_work() {
    terminal_close_with_signal_wait_irq_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[test]
fn x86_terminal_close_with_signal_wait_accepts_irq_carrier_work() {
    terminal_close_with_signal_wait_irq_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

/// #2532 run B: the captured mmap SVC may be the saved syscall frame for
/// ServedWithWork rather than an mmap crossing. A refusal after another
/// executor drains that work resumes the completed mmap result.
#[test]
fn arm_refused_carrier_work_resumes_completed_syscall() {
    refused_carrier_work_resumes_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, OwnerEntry::Syscall);
}

#[test]
fn x86_refused_carrier_work_resumes_completed_syscall() {
    refused_carrier_work_resumes_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        OwnerEntry::Syscall,
    );
}

/// #2532 runs A and round 2: an IRQ frame captures the same empty
/// CarrierWork demand with an exception continuation.
#[test]
fn arm_refused_carrier_work_resumes_irq_continuation() {
    refused_carrier_work_resumes_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, OwnerEntry::Exception);
}

#[test]
fn x86_refused_carrier_work_resumes_irq_continuation() {
    refused_carrier_work_resumes_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        OwnerEntry::Exception,
    );
}

/// #2532 round 4: two live processes share one execution lane (`CurrentTask`).
/// Process 1 parks on a native service whose lane notice has not yet been taken
/// by the carrier when the in-ring scheduler selects Process 2 on that same
/// slot. Process 2 entering a native service must keep its owned operation,
/// enrol on Process 1's release, release execution capacity without polling on
/// the run queue, and publish its retained notice once after Process 1's
/// service completes.
fn busy_service_notice_parks_and_reruns_once_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    contender_operation: carrick_core_abi::service::ServiceOperation,
    contender_exit: NativeServiceExit,
    expected_return: i64,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    let capacity = NativeServiceCapacityFixture::<C>::new_for::<B>(2, make_words);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };

    // Process 1 publishes a real CarrierWork notice on the shared slot and
    // parks before the host takes `fixture.task.service_notice`.
    let (holder_record, holder_addr, holder_words) = capacity.select().unwrap();
    {
        let mut service = fixture.service();
        let mut holder = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                holder_addr,
                &holder_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            holder.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        let result = holder.begin_service(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            None,
        );
        let phase = holder.native_service_phase();
        let settled = holder.settle_service_exit(result, NativeServiceExit::CarrierWork);
        let resumed = crate::dispatch::native_service_completion(settled, phase)
            .unwrap_or_else(|fatal| panic!("holder service entry became {fatal:?}"));
        assert!(matches!(resumed, NativeResume::Left(None)));
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());

    // Process 2 is selected on the same slot before host intake and enters its
    // own native service while Process 1's notice still occupies the lane cell.
    let (contender_record, contender_addr, contender_words) = capacity.select().unwrap();
    assert_ne!(contender_record, holder_record);
    {
        let mut service = fixture.service();
        let mut contender = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                contender_addr,
                &contender_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            contender.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        let result = contender.begin_service(contender_operation, None);
        let phase = contender.native_service_phase();
        let settled = contender.settle_service_exit(result, contender_exit);
        let resumed = crate::dispatch::native_service_completion(settled, phase)
            .unwrap_or_else(|fatal| panic!("contended service notice became {fatal:?}"));
        assert!(matches!(resumed, NativeResume::Left(None)));
    }
    assert!(
        fixture.zone.slot(fixture.slot).current().is_none(),
        "contended notice wait must release execution capacity"
    );
    assert_eq!(
        fixture.zone.slot(fixture.slot).queued(),
        0,
        "contended notice wait must enrol on holder release rather than requeue to poll"
    );
    assert!(
        fixture.task.linux.has_pending_host_work(),
        "with both members parked and nothing runnable, the occupied notice must force the vCPU to the carrier"
    );

    // Host intake consumes Process 1's preserved notice, completes its ticket,
    // and notifies Process 1's service queue, waking both Process 1 and Process 2.
    let holder_notice = fixture
        .task
        .service_notice
        .take()
        .unwrap()
        .expect("holder notice must remain intact across contended entry");
    assert_eq!(holder_notice.record, holder_record);
    if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }
    assert!(
        !fixture.task.linux.has_pending_host_work(),
        "carrier intake must consume the ring raised for the holder's notice"
    );
    {
        let identity = fixture.zone.record(holder_record.id).identity();
        let key =
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(holder_record).unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        // SAFETY: the fixture retains this exact member and its service queue.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let ticket = unsafe {
            ServiceCell::claim_notice(&control.service, holder_notice, NonZeroU64::MIN, identity)
        }
        .unwrap();
        assert!(ticket.complete(true).is_ok());
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
    }

    // Drain the two woken records: Process 1 returns from CarrierWork, and
    // Process 2 publishes its retained sequence-1 request once and parks on its
    // own service queue.
    let mut holder_resumed = false;
    let mut contender_published = false;
    for _ in 0..2 {
        let (record, addr, saved) = capacity.select().unwrap();
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                addr,
                &saved,
                &mut service,
            )
            .unwrap();
        let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        if record == holder_record {
            assert!(matches!(resumed, NativeResume::Returned(result) if result.raw() == 0));
            let _ = fixture.zone.release_current(
                fixture.slot,
                record.id,
                &carrick_sched_core::ShortLockSpin,
            );
            holder_resumed = true;
        } else {
            assert_eq!(record, contender_record);
            assert!(matches!(resumed, NativeResume::Left(None)));
            contender_published = true;
        }
    }
    assert!(holder_resumed && contender_published);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
    assert!(
        fixture.task.linux.has_pending_host_work(),
        "the contender's rerun publication and park must ring the carrier"
    );

    // Host intake now consumes Process 2's retained sequence-1 notice and
    // completes it.
    let contender_notice = fixture
        .task
        .service_notice
        .take()
        .unwrap()
        .expect("woken contender must publish its retained service notice once");
    assert_eq!(contender_notice.record, contender_record);
    assert_eq!(
        contender_notice.sequence.get(),
        1,
        "retained request must publish once without minting a second sequence"
    );
    {
        let identity = fixture.zone.record(contender_record.id).identity();
        let key = carrick_sched_core::object_wait::ObjectWaitKey::native_service(contender_record)
            .unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        // SAFETY: the fixture retains this exact member and its service queue.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &control.service,
                contender_notice,
                NonZeroU64::MIN,
                identity,
            )
        }
        .unwrap();
        assert_eq!(ticket.request().operation, contender_operation);
        let supplied = matches!(contender_operation, ServiceOperation::CarrierWork { .. });
        assert!(ticket.complete(supplied).is_ok());
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
    }

    let (record, addr, saved) = capacity.select().unwrap();
    assert_eq!(record, contender_record);
    let mut service = fixture.service();
    let mut contender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            addr,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        contender.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::Returned(result) if result.raw() == expected_return
    ));
}

/// Many live processes sharing one single execution lane contend on an occupied
/// `service_notice` cell; each wait must release execution capacity so every
/// contender parks without exhausting the lane, then drain cleanly one notice
/// per carrier intake.
fn busy_service_notice_releases_execution_capacity_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    const PROCESSES: usize = 5;
    let capacity = NativeServiceCapacityFixture::<C>::new_for::<B>(PROCESSES, make_words);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };

    for index in 0..PROCESSES {
        let (_, addr, saved) = capacity.select().unwrap();
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                addr,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        let result = entry.begin_service(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            None,
        );
        let phase = entry.native_service_phase();
        let settled = entry.settle_service_exit(result, NativeServiceExit::CarrierWork);
        let resumed = crate::dispatch::native_service_completion(settled, phase)
            .unwrap_or_else(|fatal| panic!("process {index} contended notice became {fatal:?}"));
        assert!(matches!(resumed, NativeResume::Left(None)));
        assert!(
            fixture.zone.slot(fixture.slot).current().is_none(),
            "process {index} must release the single slot's execution capacity"
        );
    }
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);

    let mut completed = 0usize;
    while completed < PROCESSES {
        let notice = fixture
            .task
            .service_notice
            .take()
            .unwrap()
            .expect("each round must expose one published service notice");
        assert_eq!(notice.sequence.get(), 1);
        let holder = notice.record;
        let identity = fixture.zone.record(holder.id).identity();
        let key = carrick_sched_core::object_wait::ObjectWaitKey::native_service(holder).unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        // SAFETY: the fixture retains this exact member and its service queue.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let ticket = unsafe {
            ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, identity)
        }
        .unwrap();
        assert!(ticket.complete(true).is_ok());
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
        drop(queue);

        while let Some((record, addr, saved)) = capacity.select() {
            let mut service = fixture.service();
            let mut entry = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    source,
                    fixture.task,
                    addr,
                    &saved,
                    &mut service,
                )
                .unwrap();
            match entry.resume_checkpoint(|_| Ok(None)).unwrap() {
                NativeResume::Returned(result) => {
                    assert_eq!(result.raw(), 0);
                    let _ = fixture.zone.release_current(
                        fixture.slot,
                        record.id,
                        &carrick_sched_core::ShortLockSpin,
                    );
                    completed += 1;
                }
                NativeResume::Left(None) => {}
                _ => panic!("unexpected resume"),
            }
        }
    }
    assert!(fixture.task.service_notice.take().unwrap().is_none());
}

#[test]
fn arm_busy_service_notice_parks_and_reruns_mmap_crossing_once() {
    busy_service_notice_parks_and_reruns_once_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(222),
        },
        NativeServiceExit::Bridge,
        carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
    );
}

#[test]
fn x86_busy_service_notice_parks_and_reruns_mmap_crossing_once() {
    busy_service_notice_parks_and_reruns_once_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(9),
        },
        NativeServiceExit::Bridge,
        carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
    );
}

#[test]
fn arm_busy_service_notice_parks_and_reruns_irq_carrier_work_once() {
    busy_service_notice_parks_and_reruns_once_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        NativeServiceExit::CarrierWork,
        0,
    );
}

#[test]
fn x86_busy_service_notice_parks_and_reruns_irq_carrier_work_once() {
    busy_service_notice_parks_and_reruns_once_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        NativeServiceExit::CarrierWork,
        0,
    );
}

#[test]
fn arm_busy_service_notice_releases_execution_capacity() {
    busy_service_notice_releases_execution_capacity_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[test]
fn x86_busy_service_notice_releases_execution_capacity() {
    busy_service_notice_releases_execution_capacity_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

fn busy_service_notice_cancellation_wakes_and_retires_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    crossing_ordinal: u64,
    close_during_adapter_admission: bool,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    let fixture: &'static _ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
    let sibling = add_service_sibling(fixture, None);
    assert_eq!(fixture.page.live(), 2);

    let (contender_slot, contender_task, contender_record) = if close_during_adapter_admission {
        assert!(fixture.zone.mark_native_owned(sibling.record.id));
        (sibling.slot, sibling.task, sibling.record)
    } else {
        (fixture.slot, fixture.task, fixture.record)
    };
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: contender_slot,
    };

    // Fork a second live process on the contender's lane and let it publish a
    // CarrierWork notice before the contender is selected on that same lane.
    {
        let mut fork_service = fixture.service();
        fork_service.waker_slot = contender_slot;
        fork_service.page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        fork_service.controls = Box::leak(Box::new(core::array::from_fn::<_, 9, _>(|_| {
            ThreadControlSlot::new()
        })));
        let mut contender = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                contender_task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut fork_service,
            )
            .unwrap();
        assert!(matches!(
            contender.fork(ProcessForkChildTid::NONE),
            LifecycleOutcome::Returned { result, .. } if result.raw() > 0
        ));
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(contender_slot, contender_record.id)
            .is_queued()
    );
    fixture.zone.clear_current(contender_slot);

    let selected_child = fixture.zone.switch_in_full(contender_slot).unwrap();
    assert_ne!(selected_child.record, contender_record.id);
    let child_record = fixture.zone.record_ref(selected_child.record);
    let child_identity = fixture.zone.record(selected_child.record).identity();
    let child_key = fixture
        .registry
        .state
        .lock()
        .members
        .values()
        .find(|member| member.record == child_record)
        .unwrap()
        .process;
    let child_addr = fixture.runtime.task_binding(child_key).unwrap().address;
    fixture
        .zone
        .install_space(contender_slot, child_identity.mm)
        .unwrap();
    contender_task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(child_identity.tid as i32),
        carrick_core_abi::SnapshotGeneration::from_raw(child_identity.generation),
        child_identity.file_table,
    );
    contender_task
        .mm
        .key
        .store(child_identity.mm, Ordering::Release);
    contender_task
        .mm
        .thread_generation
        .store(child_identity.serial, Ordering::Release);
    let child_ns_pid = fixture
        .runtime
        .graph
        .lock()
        .owner
        .task_mut(child_key)
        .unwrap()
        .metadata()
        .namespace_pid;
    contender_task.publish_visible_pid(child_ns_pid);
    contender_task.publish_root_generation(child_addr.generation);
    contender_task.publish_lifecycle(child_identity.lifecycle_page, child_identity.control_slot);
    let child_words = unsafe { *fixture.zone.record(selected_child.record).ctx_mut() };
    {
        let mut service = fixture.service();
        service.waker_slot = contender_slot;
        let mut child = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                contender_task,
                child_addr,
                &child_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            child.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        let result = child.begin_service(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            None,
        );
        let phase = child.native_service_phase();
        let settled = child.settle_service_exit(result, NativeServiceExit::CarrierWork);
        let resumed = crate::dispatch::native_service_completion(settled, phase).unwrap();
        assert!(matches!(resumed, NativeResume::Left(None)));
    }

    // Select the contender before the carrier takes the child's notice.
    let selected_contender = fixture.zone.switch_in_full(contender_slot).unwrap();
    assert_eq!(selected_contender.record, contender_record.id);
    let contender_identity = fixture.zone.record(contender_record.id).identity();
    fixture
        .zone
        .install_space(contender_slot, contender_identity.mm)
        .unwrap();
    contender_task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(contender_identity.tid as i32),
        carrick_core_abi::SnapshotGeneration::from_raw(contender_identity.generation),
        contender_identity.file_table,
    );
    contender_task
        .mm
        .key
        .store(contender_identity.mm, Ordering::Release);
    contender_task
        .mm
        .thread_generation
        .store(contender_identity.serial, Ordering::Release);
    let root_key = fixture.runtime.graph.lock().root_key;
    let contender_ns_pid = fixture
        .runtime
        .graph
        .lock()
        .owner
        .task_mut(root_key)
        .unwrap()
        .metadata()
        .namespace_pid;
    contender_task.publish_visible_pid(contender_ns_pid);
    contender_task.publish_root_generation(fixture.address.generation);
    contender_task.publish_lifecycle(
        contender_identity.lifecycle_page,
        contender_identity.control_slot,
    );
    let (worker_slot, worker_task) = if close_during_adapter_admission {
        (fixture.slot, fixture.task)
    } else {
        (sibling.slot, sibling.task)
    };
    let close_group = move || {
        let mut service = fixture.service();
        service.waker_slot = worker_slot;
        let mut worker = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: worker_slot,
                },
                worker_task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            worker.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(worker.take_run_failure().is_none());
        assert!(worker.take_handoff_receipt().is_some());
    };
    if close_during_adapter_admission {
        let (region, object, _, token) =
            retained_pipe_read(fixture.zone, sibling.slot, sibling.task);
        let mut service = fixture.service();
        service.waker_slot = sibling.slot;
        service.native_ipc = Some(region);
        let mut member = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: sibling.slot,
                },
                sibling.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        member.suspend_adapter_operation(
            token,
            ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                address: UserVa::new(0x10000),
                access: carrick_guest_arch::Access::Write,
                present: true,
            }),
            None,
        );
        let record = sibling.record;
        super::SERVICE_NOTICE_WAIT_HOOK.with(|hook| {
            assert!(
                hook.borrow_mut()
                    .replace(Box::new(move || {
                        assert_eq!(
                            carrick_el1_abi::Lifecycle::gate(fixture.page),
                            carrick_el1_abi::GateState::Open
                        );
                        assert!(fixture.zone.record(record.id).has_adapter_operation());
                        close_group();
                    }))
                    .is_none()
            );
        });
        member.drain_owned_preparation();
        assert!(
            !fixture
                .zone
                .record(sibling.record.id)
                .has_adapter_operation(),
            "the closing adapter preparation must release its OperationToken"
        );
        assert!(member.take_run_failure().is_none());
        assert!(member.take_handoff_receipt().is_some());
        assert!(fixture.zone.live(sibling.record).is_none());
        assert!(
            region.observe(object).is_err(),
            "terminal settlement must release the final pipe endpoint OfdPin"
        );
        assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    } else {
        {
            let mut service = fixture.service();
            let mut leader = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    source,
                    fixture.task,
                    fixture.address,
                    &(fixture.make_words)(fixture.address),
                    &mut service,
                )
                .unwrap();
            let result = leader.begin_service(
                ServiceOperation::Crossing {
                    ordinal: carrick_guest_arch::NativeOrdinal::new(crossing_ordinal),
                },
                None,
            );
            let phase = leader.native_service_phase();
            let settled = leader.settle_service_exit(result, NativeServiceExit::Bridge);
            let resumed = crate::dispatch::native_service_completion(settled, phase).unwrap();
            assert!(matches!(resumed, NativeResume::Left(None)));
        }
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
        assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 1);

        close_group();

        // `cancel_service` must wake the leader off `child_record`'s queue without
        // disturbing the child's live selector in `fixture.task.service_notice`.
        let woken_slot = [fixture.slot, sibling.slot]
            .into_iter()
            .find(|slot| fixture.zone.slot(*slot).queued() != 0)
            .expect("cancelling a contended notice wait must wake the parked member");
        assert_eq!(
            fixture.zone.switch_in_full(woken_slot).unwrap().record,
            fixture.record.id
        );
        let leader_saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
        {
            let mut leader_service = fixture.service();
            leader_service.waker_slot = woken_slot;
            let mut leader = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource {
                        zone: fixture.zone,
                        slot: woken_slot,
                    },
                    fixture.task,
                    fixture.address,
                    &leader_saved,
                    &mut leader_service,
                )
                .unwrap();
            assert!(matches!(
                leader.resume_checkpoint(|_| Ok(None)).unwrap(),
                NativeResume::Left(_)
            ));
        }
        assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
        assert!(
            !fixture
                .runtime
                .graph
                .lock()
                .has_member_wait(&fixture.record)
        );
    }

    // The holder's selector survives both cancellation paths.
    let child_notice = contender_task
        .service_notice
        .take()
        .unwrap()
        .expect("peer notice must survive cancellation of a contended waiter");
    assert_eq!(child_notice.record, child_record);
    let child_key =
        carrick_sched_core::object_wait::ObjectWaitKey::native_service(child_record).unwrap();
    let queue = fixture
        .zone
        .object_wait(child_key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    let child_control = unsafe { &*(child_identity.control_slot as *const ThreadControlSlot) };
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &child_control.service,
            child_notice,
            NonZeroU64::MIN,
            child_identity,
        )
    }
    .unwrap();
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(
            fixture.slot,
            &mut carrick_sched_core::WakeEffects::default(),
        )
        .unwrap();
}

#[test]
fn arm_busy_service_notice_cancellation_wakes_and_retires() {
    busy_service_notice_cancellation_wakes_and_retires_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, 222, false);
}

#[test]
fn x86_busy_service_notice_cancellation_wakes_and_retires() {
    busy_service_notice_cancellation_wakes_and_retires_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, 9, false);
}

#[test]
fn arm_terminal_close_during_contended_adapter_preparation() {
    busy_service_notice_cancellation_wakes_and_retires_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, 222, true);
}

#[test]
fn x86_terminal_close_during_contended_adapter_preparation() {
    busy_service_notice_cancellation_wakes_and_retires_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, 9, true);
}

#[derive(Clone, Copy)]
enum RetainedAdapterClosingEntrant {
    MmapCrossing { ordinal: u64 },
    IrqCarrierWork,
    DrainOwnedPreparation,
    ResumeCheckpoint,
}

// The numeric fd is closed before service admission, leaving the read's
// exact operation as the sole owner of the pipe endpoint.
fn retained_pipe_read<C: ProcessContext>(
    zone: &ZoneTables<C>,
    slot: SlotId,
    task: &CurrentTask,
) -> (
    carrick_el1_abi::ipc::IpcRegion<'static>,
    carrick_el1_abi::ipc::IpcObjectHandle,
    carrick_el1_abi::ipc::OfdPin,
    carrick_sched_core::object_wait::OperationToken,
) {
    use carrick_el1_abi::ipc::{
        IpcBacking, IpcMmKey, IpcOpKind, IpcOperation, IpcTaskKey, IpcUserVa, OfdPin,
        WriteProgress, fd,
    };

    let binding = crate::common_entry::execution_binding(task);
    let shared = Box::leak(Box::new(std::sync::Arc::new(
        carrick_kernel::el1_ipc::HostIpc::with_limits(
            1 << 20,
            carrick_el1_abi::ipc::IpcLimits::ZONE,
        )
        .unwrap(),
    )));
    let object = shared.create_pipe(65536).unwrap();
    for lane in [
        carrick_el1_abi::ipc::pipe::WaitFor::Readable,
        carrick_el1_abi::ipc::pipe::WaitFor::Writable,
    ] {
        let key = carrick_el1_abi::ipc::object_wait_key(object, lane).unwrap();
        zone.bind_object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    }
    let table = shared.create_table(64, 64).unwrap();
    let reader = shared
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: carrick_el1_abi::ipc::pipe::End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    reader.install(table, fd::Fd(0), false).unwrap();
    drop(reader);
    let writer = shared
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: carrick_el1_abi::ipc::pipe::End::Writer,
            }
            .encode(),
            fd::AccessMode::WriteOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    writer.install(table, fd::Fd(1), false).unwrap();
    drop(writer);

    let region = shared.region();
    let writer_release = region
        .fd(carrick_sched_core::ShortLockSpin)
        .close(table, fd::Fd(1))
        .unwrap()
        .unwrap();
    crate::ipc::settle_native_release(
        &region,
        fd::DeferredRelease::Now(writer_release),
        Some((zone, slot)),
        task,
    )
    .unwrap();

    let (pin, _) = region
        .fd(carrick_sched_core::ShortLockSpin)
        .pin(table, fd::Fd(0))
        .unwrap();
    let raw_pin = pin.into_raw();
    let raw_ipc_token = region
        .begin_operation(IpcOperation {
            kind: IpcOpKind::PipeRead,
            pin: raw_pin,
            object: object.to_raw(),
            task: IpcTaskKey(binding.task.raw()),
            mm: IpcMmKey(binding.mm.raw()),
            buf: IpcUserVa(0x10000),
            progress: WriteProgress::new(8),
            ..IpcOperation::EMPTY
        })
        .unwrap();
    let token = carrick_el1::substrate::ipc::to_sched_token(raw_ipc_token).unwrap();
    assert!(
        region
            .fd(carrick_sched_core::ShortLockSpin)
            .close(table, fd::Fd(0))
            .unwrap()
            .is_none(),
        "closing the numeric fd leaves only the retained operation's OfdPin"
    );
    assert!(region.observe(object).is_ok());
    (region, object, OfdPin::from_raw(raw_pin), token)
}

fn terminal_close_with_retained_adapter_service_entry_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    entrant: RetainedAdapterClosingEntrant,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_signal_sibling(&fixture, None, false);
    assert!(fixture.zone.mark_native_owned(sibling.record.id));
    assert_eq!(fixture.page.live(), 2);

    let (region, object, pin, token) = retained_pipe_read(fixture.zone, sibling.slot, sibling.task);
    let sibling_binding = crate::common_entry::execution_binding(sibling.task);
    let token_identity = token.identity();
    let (token_index, token_generation) = (token.index(), token.generation());

    {
        let mut sibling_service = fixture.service();
        sibling_service.waker_slot = sibling.slot;
        sibling_service.native_ipc = Some(region);
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
                &(fixture.make_words)(fixture.address),
                &mut sibling_service,
            )
            .unwrap();
        entry.suspend_adapter_operation(
            token,
            ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                address: UserVa::new(0x10000),
                access: carrick_guest_arch::Access::Write,
                present: true,
            }),
            None,
        );
        entry.drain_owned_preparation();
        assert!(entry.take_handoff_receipt().is_some());
        assert!(entry.take_run_failure().is_none());
    }
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record),
        "the sibling must hold a retained adapter backing-supply service"
    );
    assert!(
        fixture
            .zone
            .record(sibling.record.id)
            .has_adapter_operation(),
        "the parked adapter service must retain the pipe OperationToken"
    );
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 1);

    let notice = sibling.task.service_notice.take().unwrap().unwrap();
    let service_key =
        carrick_sched_core::object_wait::ObjectWaitKey::native_service(sibling.record).unwrap();
    let ticket = {
        let _queue = fixture
            .zone
            .object_wait(service_key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        // SAFETY: the fixture retains this exact member and its service queue.
        unsafe {
            ServiceCell::claim_notice(
                &sibling.control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(sibling.record.id).identity(),
            )
        }
        .unwrap()
    };

    let leader_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    {
        let mut service = fixture.service();
        service.native_ipc = Some(region);
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                leader_source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
        assert!(root.take_handoff_receipt().is_some());
    }
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );

    {
        let queue = fixture
            .zone
            .object_wait(service_key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        assert!(ticket.complete(false).is_ok());
        queue
            .notify_object(sibling.slot, &mut WakeEffects::default())
            .unwrap();
    }

    let slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .expect("the cancelled adapter service wakes its exact member");
    assert_eq!(
        fixture.zone.switch_in_full(slot).unwrap().record,
        sibling.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = slot;
    sibling_service.native_ipc = Some(region);
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    match entrant {
        RetainedAdapterClosingEntrant::MmapCrossing { ordinal } => {
            let result = member.begin_service(
                ServiceOperation::Crossing {
                    ordinal: carrick_guest_arch::NativeOrdinal::new(ordinal),
                },
                None,
            );
            let phase = member.native_service_phase();
            let settled = member.settle_service_exit(result, NativeServiceExit::Bridge);
            let resumed = crate::dispatch::native_service_completion(settled, phase)
                .unwrap_or_else(|fatal| {
                    panic!("terminal retained-adapter mmap entry became {fatal:?}")
                });
            assert!(matches!(resumed, NativeResume::Left(None)));
            assert!(member.take_handoff_receipt().is_none());
        }
        RetainedAdapterClosingEntrant::IrqCarrierWork => {
            let result = member.begin_service(
                ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Exception,
                    demand: carrick_core_abi::service::CarrierDemand::Work,
                },
                None,
            );
            let phase = member.native_service_phase();
            let settled = member.settle_service_exit(result, NativeServiceExit::CarrierWork);
            let resumed = crate::dispatch::native_service_completion(settled, phase)
                .unwrap_or_else(|fatal| {
                    panic!("terminal retained-adapter IRQ entry became {fatal:?}")
                });
            assert!(matches!(resumed, NativeResume::Left(None)));
            assert!(member.take_handoff_receipt().is_none());
        }
        RetainedAdapterClosingEntrant::ResumeCheckpoint => {
            let result = member.resume_checkpoint(|_| Ok(None));
            assert!(
                !fixture
                    .zone
                    .record(sibling.record.id)
                    .has_adapter_operation(),
                "the closing checkpoint must release its OperationToken, failure: {:?}",
                result.as_ref().err()
            );
            assert!(matches!(result, Ok(NativeResume::Left(None))));
        }
        RetainedAdapterClosingEntrant::DrainOwnedPreparation => {
            member.adapter_ready = Some(Box::new(super::super::service::AdapterPreparation {
                service: ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Syscall,
                    demand: carrick_core_abi::service::CarrierDemand::Work,
                },
                sequence: None,
                identity: token_identity,
            }));
            member.drain_owned_preparation();
            assert!(member.take_handoff_receipt().is_some());
            assert!(member.adapter_ready.is_none());
        }
    }
    assert!(member.take_run_failure().is_none());
    drop(member);

    assert!(fixture.zone.live(sibling.record).is_none());
    assert!(
        !fixture
            .zone
            .record(sibling.record.id)
            .has_object_operation()
    );
    assert!(
        !fixture
            .zone
            .record(sibling.record.id)
            .has_adapter_operation()
    );
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&sibling.record)
    );
    assert!(sibling.task.service_notice.take().unwrap().is_none());

    let replay_token =
        carrick_sched_core::object_wait::OperationToken::new(token_index, token_generation)
            .unwrap();
    let replay_ipc = carrick_el1::substrate::ipc::from_sched_token(replay_token).unwrap();
    assert!(
        region.operation(&replay_ipc).is_err(),
        "the IPC operation record must be retired"
    );
    assert!(
        region.observe(object).is_err()
            && region
                .lock(object, &carrick_sched_core::ShortLockSpin)
                .is_err(),
        "terminal settlement must release the final pipe endpoint OfdPin"
    );
    assert!(
        region
            .fd(carrick_sched_core::ShortLockSpin)
            .unpin_filtered(pin, crate::ipc::is_zone_releasable_backing,)
            .is_err(),
        "a second unpin of the retired OfdPin must fail"
    );
    assert!(matches!(
        crate::ipc::retire_native_operation(
            &region,
            fixture.zone,
            slot,
            sibling.task,
            sibling_binding,
            carrick_sched_core::object_wait::OperationToken::new(token_index, token_generation)
                .unwrap(),
        ),
        Err(NativeProcessError::Stale)
    ));

    let leader_slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|candidate| fixture.zone.slot(*candidate).queued() != 0)
        .expect("retiring the sibling must wake the closing leader");
    assert_eq!(
        fixture.zone.switch_in_full(leader_slot).unwrap().record,
        fixture.record.id
    );
    let leader_saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut leader_service = fixture.service();
    leader_service.waker_slot = leader_slot;
    leader_service.native_ipc = Some(region);
    let mut leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: leader_slot,
            },
            fixture.task,
            fixture.address,
            &leader_saved,
            &mut leader_service,
        )
        .unwrap();
    assert!(matches!(
        leader.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::Left(Some(status)) if status == LinuxWaitStatus::exited(7)
    ));
}

#[test]
fn arm_terminal_close_with_retained_adapter_service_accepts_mmap_entry() {
    terminal_close_with_retained_adapter_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        RetainedAdapterClosingEntrant::MmapCrossing { ordinal: 222 },
    );
}

#[test]
fn x86_terminal_close_with_retained_adapter_service_accepts_mmap_entry() {
    terminal_close_with_retained_adapter_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        RetainedAdapterClosingEntrant::MmapCrossing { ordinal: 9 },
    );
}

#[test]
fn arm_terminal_close_with_retained_adapter_service_accepts_irq_carrier_work() {
    terminal_close_with_retained_adapter_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, RetainedAdapterClosingEntrant::IrqCarrierWork);
}

#[test]
fn x86_terminal_close_with_retained_adapter_service_accepts_irq_carrier_work() {
    terminal_close_with_retained_adapter_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, RetainedAdapterClosingEntrant::IrqCarrierWork);
}

#[test]
fn arm_terminal_close_with_retained_adapter_service_accepts_drain_owned_preparation() {
    terminal_close_with_retained_adapter_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        RetainedAdapterClosingEntrant::DrainOwnedPreparation,
    );
}

#[test]
fn x86_terminal_close_with_retained_adapter_service_accepts_drain_owned_preparation() {
    terminal_close_with_retained_adapter_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, RetainedAdapterClosingEntrant::DrainOwnedPreparation);
}

#[test]
fn arm_terminal_close_with_retained_adapter_service_resume_checkpoint() {
    terminal_close_with_retained_adapter_service_entry_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, RetainedAdapterClosingEntrant::ResumeCheckpoint);
}

#[test]
fn x86_terminal_close_with_retained_adapter_service_resume_checkpoint() {
    terminal_close_with_retained_adapter_service_entry_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, RetainedAdapterClosingEntrant::ResumeCheckpoint);
}

fn terminal_close_with_retained_service_propagates_lifecycle_run_failure_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    host_requested: bool,
) {
    use carrick_core_abi::service::ServiceOperation;

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let mut sibling = add_service_sibling(
        &fixture,
        Some(ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(64),
        }),
    );

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
    }
    assert!(
        sibling
            .service_ticket
            .take()
            .unwrap()
            .complete(true)
            .is_ok()
    );

    let slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .unwrap();
    assert_eq!(
        fixture.zone.switch_in_full(slot).unwrap().record,
        sibling.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = slot;
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();

    if host_requested {
        assert_eq!(
            fixture.zone.claim_for_host(
                sibling.record,
                None,
                carrick_sched_core::Handback::Control,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            ),
            carrick_sched_core::HostClaim::El1Held { slot }
        );
    }
    let root_key = fixture.runtime.graph.lock().root_key;
    let removed_task = fixture
        .runtime
        .graph
        .lock()
        .owner
        .tasks_mut()
        .remove(&root_key.id)
        .unwrap();

    let result = member.begin_service(
        ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        None,
    );
    let phase = member.native_service_phase();
    let settled = member.settle_service_exit(result, NativeServiceExit::CarrierWork);
    let fatal = crate::dispatch::native_service_completion(settled, phase).err();
    let run_failure = member.take_run_failure();
    let receipt = member.take_handoff_receipt();
    drop(member);
    fixture
        .runtime
        .graph
        .lock()
        .owner
        .tasks_mut()
        .insert(root_key.id, removed_task);

    assert!(run_failure.is_none());
    assert!(receipt.is_none());
    assert!(
        matches!(
            fatal,
            Some(crate::dispatch::NativeInvariant::NativeService(
                carrick_el1_abi::EntryBindingFatalReason::NativeServiceCompleteStale
            ))
        ),
        "expected NativeServiceCompleteStale propagation (host_requested={host_requested}), got {fatal:?}"
    );
}

#[test]
fn arm_terminal_close_with_retained_service_propagates_lifecycle_run_failure() {
    for host_requested in [true, false] {
        terminal_close_with_retained_service_propagates_lifecycle_run_failure_for::<
            carrick_el1_abi::Aarch64ParkedContext,
            carrick_mmu_core::owner_mmu::Aarch64Mmu,
        >(arm_words, host_requested);
    }
}

#[test]
fn x86_terminal_close_with_retained_service_propagates_lifecycle_run_failure() {
    for host_requested in [true, false] {
        terminal_close_with_retained_service_propagates_lifecycle_run_failure_for::<
            ParkedContextWords,
            carrick_mmu_core::x86::owner_mmu::X86Mmu,
        >(words, host_requested);
    }
}

fn terminal_close_with_signal_wait_rejects_installed_adapter_operation_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_service_sibling(&fixture, None);
    fixture.runtime.graph.lock().insert_member_wait(
        sibling.record,
        MemberWait::Signal(PendingSignalWait {
            kind: PendingSignalKind::Suspend,
            channel: Arc::new(WaitChannel {
                generation: ProcessWake::new(),
                mm: fixture.address.mm.raw().get(),
            }),
            deadline: None,
        }),
    );
    // SAFETY: test-only corruption installing an adapter OperationToken beside
    // a retained signal wait on the sibling's owned executing record.
    unsafe {
        fixture
            .zone
            .record(sibling.record.id)
            .restore_object_operation(
                carrick_sched_core::object_wait::OperationToken::new(1, 1).unwrap(),
            )
    }
    .unwrap();
    assert!(
        fixture
            .zone
            .record(sibling.record.id)
            .has_adapter_operation()
    );

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
    }

    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = sibling.slot;
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &(fixture.make_words)(fixture.address),
            &mut sibling_service,
        )
        .unwrap();
    let result = member.begin_service(
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        None,
    );
    let phase = member.native_service_phase();
    let settled = member.settle_service_exit(result, NativeServiceExit::CarrierWork);
    let fatal = crate::dispatch::native_service_completion(settled, phase).err();
    assert!(member.take_run_failure().is_none());
    assert!(member.take_handoff_receipt().is_none());
    assert!(
        matches!(
            fatal,
            Some(crate::dispatch::NativeInvariant::NativeService(
                carrick_el1_abi::EntryBindingFatalReason::SignalWaitAdapterQuarantine
            ))
        ),
        "expected SignalWaitAdapterQuarantine, got {fatal:?}"
    );
}

#[test]
fn arm_terminal_close_with_signal_wait_rejects_installed_adapter_operation() {
    terminal_close_with_signal_wait_rejects_installed_adapter_operation_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[test]
fn x86_terminal_close_with_signal_wait_rejects_installed_adapter_operation() {
    terminal_close_with_signal_wait_rejects_installed_adapter_operation_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

fn terminal_close_with_foreign_service_control_quarantines_at_member_guard_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core_abi::service::ServiceOperation;

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let mut sibling = add_service_sibling(
        &fixture,
        Some(ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(64),
        }),
    );

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(root.take_run_failure().is_none());
    }
    assert!(
        sibling
            .service_ticket
            .take()
            .unwrap()
            .complete(true)
            .is_ok()
    );

    let slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .unwrap();
    assert_eq!(
        fixture.zone.switch_in_full(slot).unwrap().record,
        sibling.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = slot;
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();

    {
        let mut graph = fixture.runtime.graph.lock();
        let root_key = graph.root_key;
        let root_control = graph
            .owner
            .task(root_key)
            .unwrap()
            .native()
            .resources()
            .members
            .iter()
            .find(|candidate| candidate.record == fixture.record)
            .unwrap()
            .control
            .clone();
        graph.service_wait_mut(&sibling.record).unwrap().control = root_control;
    }

    let result = member.begin_service(
        ServiceOperation::CarrierWork {
            entry: OwnerEntry::Exception,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        None,
    );
    let phase = member.native_service_phase();
    let settled = member.settle_service_exit(result, NativeServiceExit::CarrierWork);
    let fatal = crate::dispatch::native_service_completion(settled, phase).err();
    assert!(member.take_run_failure().is_none());
    assert!(member.take_handoff_receipt().is_none());
    assert!(
        matches!(
            fatal,
            Some(crate::dispatch::NativeInvariant::NativeService(
                carrick_el1_abi::EntryBindingFatalReason::RetainedControlQuarantine
            ))
        ),
        "expected RetainedControlQuarantine, got {fatal:?}"
    );
}

#[test]
fn arm_terminal_close_with_foreign_service_control_quarantines_at_member_guard() {
    terminal_close_with_foreign_service_control_quarantines_at_member_guard_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[test]
fn x86_terminal_close_with_foreign_service_control_quarantines_at_member_guard() {
    terminal_close_with_foreign_service_control_quarantines_at_member_guard_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[derive(Clone, Copy)]
enum ClosingObjectParkCause {
    ExitGroup,
    Abort,
}

/// #2620 (npm after a V8 fatal): a sibling parked in an in-ring object wait
/// (the readable lane of a ring pipe, as a ring `epoll_pwait(-1)` parks) while
/// its leader closes the process. The close interrupts the park; the member
/// must be placed back in the ring without a carrier round trip, and its next
/// owner entry must retire it with the close status, settling its operation,
/// rather than replay the wait.
fn closing_process_retires_object_parked_member_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    cause: ClosingObjectParkCause,
) {
    use carrick_core::wait::{ObjectParkRequest, observe_object, park_object_record};
    use carrick_el1_abi::ipc::{object_wait_key, pipe::WaitFor};
    use carrick_sched_core::object_wait::ObjectWaitError;

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_signal_sibling(&fixture, None, false);
    assert!(fixture.zone.mark_native_owned(sibling.record.id));
    // An unbound thread may run on either CPU, as in production; the shared
    // sibling fixture pins it to the leader's.
    fixture.zone.record(sibling.record.id).set_affinity(0b11);
    assert_eq!(fixture.page.live(), 2);

    let (region, object, pin, token) = retained_pipe_read(fixture.zone, sibling.slot, sibling.task);
    let (token_index, token_generation) = (token.index(), token.generation());
    let key = object_wait_key(object, WaitFor::Readable).unwrap();
    let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>| {
        crate::sched::object_wait::deliver_completion(fixture.zone, sibling.slot, effects)
    };
    assert_eq!(
        fixture
            .zone
            .slot(sibling.slot)
            .current()
            .or_else(|| fixture.zone.slot(sibling.slot).host_record()),
        Some(sibling.record.id)
    );
    let snapshot = observe_object(fixture.zone, sibling.slot, key, &completion).unwrap();
    // SAFETY: nothing publishes on this fixture's pipe between the
    // observation and the park; the park revalidates the revision.
    let snapshot = unsafe {
        carrick_sched_core::object_wait::ObjectStateSnapshot::taken_under_object_lock(snapshot)
    };
    let request = ObjectParkRequest::from_locked_snapshot(key, snapshot, token, None);
    let mut parked = park_object_record(fixture.zone, sibling.slot, request, &completion, || {
        let record = fixture
            .zone
            .slot(sibling.slot)
            .current()
            .or_else(|| fixture.zone.slot(sibling.slot).host_record())
            .ok_or(ObjectWaitError::Stale)?;
        // SAFETY: this fixture owns the selected sibling record until park publishes.
        *unsafe { fixture.zone.record(record).ctx_mut() } = (fixture.make_words)(fixture.address);
        Ok((record, false))
    })
    .unwrap_or_else(|(error, _)| panic!("the sibling's object park failed: {error:?}"));
    assert!(parked.matches(fixture.zone, sibling.slot));
    let _ = parked.take_receipt();
    assert!(matches!(
        fixture.zone.record(sibling.record.id).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    assert!(
        fixture
            .zone
            .record(sibling.record.id)
            .has_adapter_operation()
    );

    let (status, signaled) = match cause {
        ClosingObjectParkCause::ExitGroup => (LinuxWaitStatus::exited(7), false),
        ClosingObjectParkCause::Abort => (LinuxWaitStatus::signaled(6, false), true),
    };
    {
        let mut service = fixture.service();
        service.native_ipc = Some(region);
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        let outcome = if signaled {
            let abort = carrick_signal_core::policy::Signal::from_number(6).unwrap();
            root.exit_with_signal(abort).unwrap()
        } else {
            root.exit_group(7)
        };
        assert!(matches!(outcome, LifecycleOutcome::Transferred { .. }));
        assert!(root.take_run_failure().is_none());
        assert!(root.take_handoff_receipt().is_some());
    }
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );

    // The interrupted member is an in-zone object's waiter: the ring places
    // it, never the carrier's completion chain (KVM drains no such chain).
    let claim = fixture.zone.record(sibling.record.id).claim();
    let carrick_sched_core::Claim::Queued { slot, .. } = claim else {
        panic!("the close must place the interrupted object waiter in the ring, got {claim:?}");
    };
    assert_eq!(
        fixture.zone.switch_in_full(slot).unwrap().record,
        sibling.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = slot;
    sibling_service.native_ipc = Some(region);
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    // The production syscall entry offers retained custody first: a closing
    // member retires here; `None` would replay its object wait.
    let retired = member.resume_owned_continuation();
    assert!(
        matches!(retired, Some(LifecycleOutcome::Transferred { .. })),
        "the closing member's entry must retire it, not replay its wait (replayed: {})",
        retired.is_none()
    );
    assert!(member.take_run_failure().is_none());
    drop(member);

    assert!(fixture.zone.live(sibling.record).is_none());
    assert!(
        !fixture
            .zone
            .record(sibling.record.id)
            .has_object_operation()
    );
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    let retired_token =
        carrick_sched_core::object_wait::OperationToken::new(token_index, token_generation)
            .unwrap();
    assert!(
        region
            .operation(&carrick_el1::substrate::ipc::from_sched_token(retired_token).unwrap())
            .is_err(),
        "the retired member's IPC operation must be released"
    );
    assert!(
        region
            .fd(carrick_sched_core::ShortLockSpin)
            .unpin_filtered(pin, crate::ipc::is_zone_releasable_backing)
            .is_err(),
        "terminal settlement must release the operation's endpoint pin"
    );

    let leader_slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|candidate| fixture.zone.slot(*candidate).queued() != 0)
        .expect("retiring the sibling must wake the closing leader");
    assert_eq!(
        fixture.zone.switch_in_full(leader_slot).unwrap().record,
        fixture.record.id
    );
    let leader_saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut leader_service = fixture.service();
    leader_service.waker_slot = leader_slot;
    leader_service.native_ipc = Some(region);
    let mut leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: leader_slot,
            },
            fixture.task,
            fixture.address,
            &leader_saved,
            &mut leader_service,
        )
        .unwrap();
    let resumed = leader.resume_checkpoint(|_| Ok(None));
    assert!(
        matches!(resumed, Ok(NativeResume::Left(Some(got))) if got == status),
        "the closing leader must finish with {status:?}"
    );
}

#[test]
fn arm_exit_group_retires_object_parked_member() {
    closing_process_retires_object_parked_member_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, ClosingObjectParkCause::ExitGroup);
}

#[test]
fn x86_exit_group_retires_object_parked_member() {
    closing_process_retires_object_parked_member_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, ClosingObjectParkCause::ExitGroup);
}

#[test]
fn arm_abort_retires_object_parked_member() {
    closing_process_retires_object_parked_member_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, ClosingObjectParkCause::Abort);
}

#[test]
fn x86_abort_retires_object_parked_member() {
    closing_process_retires_object_parked_member_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, ClosingObjectParkCause::Abort);
}

/// #2749 route A: two live processes share one execution lane. Process 1
/// parks on a fault it selected nothing for, and its notice is not yet taken
/// when Process 2 faults on the same lane, selects its copy-on-write supply
/// and parks behind that notice. The carrier's intake of Process 1 must not
/// see Process 2's selection, and Process 2's selection must reach exactly
/// Process 2's own ticket after the lane has been reused.
fn fault_selection_travels_with_its_request_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceFaultSupply, ServiceOperation};

    const PAGE: u64 = 0x7000_0000;
    let capacity = NativeServiceCapacityFixture::<C>::new_for::<B>(2, make_words);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    // The per-CPU selection lane of `fixture.slot`.
    let lane: &'static carrick_el1_abi::PortalGrantSlot =
        Box::leak(Box::new(carrick_el1_abi::PortalGrantSlot::new()));
    let fault = |present| {
        ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
            address: UserVa::new(PAGE + 0x123),
            access: carrick_guest_arch::Access::Write,
            present,
        })
    };
    let window_for = |mm: u64, sequence: u64| carrick_core_abi::PortalGrantWindow {
        operation: carrick_core_abi::PortalOperation {
            carrier: NonZeroU64::MIN,
            mm: carrick_core_abi::ReservationMm::new(mm).unwrap(),
            incarnation: NonZeroU64::MIN,
            sequence: NonZeroU64::new(sequence).unwrap(),
        },
        mapping_incarnation: carrick_core_abi::ReservationIncarnation::new(1).unwrap(),
        range: carrick_core_abi::ReservationRange::new(PAGE, PAGE + 4096).unwrap(),
        protection: carrick_core_abi::ReservationProtection::from_bits(3).unwrap(),
        fault_page: PAGE,
        host_backing: None,
        fork_sequence: None,
    };
    let claim = |notice: carrick_core_abi::service::ServiceSelector| {
        let identity = fixture.zone.record(notice.record.id).identity();
        // SAFETY: the fixture retains this exact member and its control.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        unsafe { ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, identity) }
            .unwrap()
    };
    let notify = |record: RecordRef| {
        let key = carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
    };

    // Process 1 forwards a fault with no selection and parks; the carrier has
    // not yet taken its notice.
    let (holder_record, holder_addr, holder_words) = capacity.select().unwrap();
    {
        let mut service = fixture.service();
        let mut holder = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                holder_addr,
                &holder_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            holder.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        let result = holder.begin_service(fault(false), None);
        let phase = holder.native_service_phase();
        let settled = holder.settle_service_exit(result, NativeServiceExit::Bridge);
        let resumed = crate::dispatch::native_service_completion(settled, phase)
            .unwrap_or_else(|fatal| panic!("holder fault entry became {fatal:?}"));
        assert!(matches!(resumed, NativeResume::Left(None)));
    }

    // Process 2 runs on the same lane, stamps its selection there, and parks
    // behind Process 1's notice.
    let (contender_record, contender_addr, contender_words) = capacity.select().unwrap();
    assert_ne!(contender_record, holder_record);
    let selected = window_for(contender_addr.mm.raw().get(), 9);
    {
        let mut service = fixture.service();
        let mut contender = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                contender_addr,
                &contender_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            contender.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        assert!(lane.publish_cow_fault_selection(9, selected));
        let result = contender.begin_service(fault(true), Some(selected.operation.sequence));
        let phase = contender.native_service_phase();
        let settled = contender.settle_service_exit(result, NativeServiceExit::Bridge);
        let resumed = crate::dispatch::native_service_completion(settled, phase)
            .unwrap_or_else(|fatal| panic!("contender fault entry became {fatal:?}"));
        assert!(matches!(resumed, NativeResume::Left(None)));
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());

    // Carrier intake of Process 1, as the HVF and CPL0 hosts perform it.
    let holder_notice = fixture.task.service_notice.take().unwrap().unwrap();
    assert_eq!(holder_notice.record, holder_record);
    if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }
    let mut holder_ticket = claim(holder_notice);
    assert_eq!(holder_ticket.request().fault_sequence, None);
    assert_eq!(
        holder_ticket.take_fault_selection(lane),
        Ok(None),
        "an unselected fault's intake must not be refused by a peer's selection"
    );
    assert!(holder_ticket.complete(false).is_ok());
    notify(holder_record);

    // Process 1 resumes refused; Process 2 publishes its retained request.
    let mut holder_resumed = false;
    let mut contender_published = false;
    for _ in 0..2 {
        let (record, addr, saved) = capacity.select().unwrap();
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                addr,
                &saved,
                &mut service,
            )
            .unwrap();
        let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        if record == holder_record {
            assert!(!matches!(
                resumed,
                NativeResume::Invalid | NativeResume::Left(_)
            ));
            let _ = fixture.zone.release_current(
                fixture.slot,
                record.id,
                &carrick_sched_core::ShortLockSpin,
            );
            holder_resumed = true;
        } else {
            assert_eq!(record, contender_record);
            assert!(matches!(resumed, NativeResume::Left(None)));
            contender_published = true;
        }
    }
    assert!(holder_resumed && contender_published);

    // Carrier intake of Process 2 takes exactly the selection it stamped.
    let contender_notice = fixture.task.service_notice.take().unwrap().unwrap();
    assert_eq!(contender_notice.record, contender_record);
    let mut contender_ticket = claim(contender_notice);
    assert_eq!(
        contender_ticket.request().fault_sequence,
        Some(selected.operation.sequence)
    );
    assert_eq!(
        contender_ticket.take_fault_selection(lane),
        Ok(Some(ServiceFaultSupply::Cow(selected)))
    );
    assert!(contender_ticket.complete(false).is_ok());
    notify(contender_record);
}

#[test]
fn arm_fault_selection_travels_with_its_request() {
    fault_selection_travels_with_its_request_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[test]
fn x86_fault_selection_travels_with_its_request() {
    fault_selection_travels_with_its_request_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}
