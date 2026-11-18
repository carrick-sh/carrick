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

    // Host intake consumes Process 1's preserved notice, completes its ticket,
    // and notifies Process 1's service queue, waking both Process 1 and Process 2.
    let holder_notice = fixture
        .task
        .service_notice
        .take()
        .unwrap()
        .expect("holder notice must remain intact across contended entry");
    assert_eq!(holder_notice.record, holder_record);
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
