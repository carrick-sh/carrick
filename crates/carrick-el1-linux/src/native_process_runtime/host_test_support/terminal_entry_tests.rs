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
