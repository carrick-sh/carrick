//! Linux authority: setresuid(2), clone(2), execve(2), futex(2).
//! Internal admission contention cannot manufacture EAGAIN; a wake cannot
//! disappear between predicate check and enrollment; reused queue identities
//! must never complete an old operation. No guest instructions are executed.
#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::{
    compat::{CompatReporter, SyscallArgs},
    dispatch::{CarrierBridges, DispatchOutcome, LinearMemory, SyscallDispatcher, SyscallRequest},
    kernel::{
        CarrierProcess, ClonePlan, KernelContext,
        operations::ThreadPublicationReservationAttempt,
        schedule::{Authority, Point as KPoint},
    },
};
use carrick_kernel_example::{
    Point, Schedule,
    process::{AddressSpace, AsidAllocator, ExampleProcess},
    schedule::Actor,
};
use carrick_sched_core::{
    BoundedSpin, Handback, HostClaim, SlotId, ThreadIdentity, ZoneTables,
    object_wait::{ObjectWaitError, ObjectWaitKey, OperationToken},
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

fn thread_plan() -> ClonePlan {
    ClonePlan::from_flags(LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM)
        .unwrap()
}

#[test]
fn thread_publication_receipt_names_creator_and_child_once() {
    let (_, contexts) = pair();
    let kernel = contexts[0].kernel().clone();
    let prepared = kernel
        .reserve_thread_clone(&contexts[0], thread_plan(), None)
        .unwrap()
        .prepare(ThreadId::from_guest_supplied_tid(3))
        .unwrap();
    let child = prepared.prepared_execution_identity().1;
    let prepared = Mutex::new(Some(prepared));
    let receipt = Schedule::explore(7)
        .run_operations(
            &kernel,
            "thread-publication-authority",
            1,
            &contexts,
            |index, _| {
                if index == 0 {
                    let prepared = prepared.lock().take().unwrap();
                    let published = prepared.commit().unwrap();
                    let context = published.into_context().unwrap();
                    assert_eq!(context.thread().key(), child);
                }
            },
        )
        .unwrap();
    let publications: Vec<_> = receipt
        .decisions
        .iter()
        .filter(|d| d.point == Point::Kernel(KPoint::ThreadPublished))
        .collect();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].actor, actor(&contexts[0]));
    let Some(carrick_kernel::kernel::schedule::AuthorityStamp::Thread(stamp)) =
        &publications[0].authority
    else {
        panic!("publication must name the child's authority")
    };
    assert_eq!(stamp.thread_id, child.tid.raw());
    assert_eq!(stamp.thread_serial, child.serial.raw());
    kernel.validate_invariants().unwrap();
}

#[test]
fn admitted_credential_wait_releases_permit_without_redispatch() {
    for scale in [1, 8, 32] {
        for seed in 0..16 {
            let (process, contexts) = pair();
            let kernel = contexts[0].kernel().clone();
            let prepared = kernel
                .reserve_thread_clone(&contexts[1], thread_plan(), None)
                .unwrap()
                .prepare(ThreadId::from_guest_supplied_tid(3))
                .unwrap();
            let ThreadPublicationReservationAttempt::Reserved(prepared) =
                prepared.try_reserve_publication().unwrap()
            else {
                panic!("fixture must own the one conflicting publication reservation");
            };
            let reservation = Mutex::new(Some(prepared));
            let root_actor = actor(&contexts[0]);
            let process = Arc::new(process) as Arc<dyn CarrierProcess>;
            let outcomes = Mutex::new(Vec::new());
            let reporter = CompatReporter::default();
            let receipt = Schedule::explore(seed)
                .max_transitions(512)
                .run_operations(
                    &kernel,
                    &format!("credential-admission-wait/{scale}"),
                    scale as usize,
                    &contexts,
                    |index, lane| {
                        if index == 0 {
                            let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
                                host_signal: Arc::new(NullHostSignalBridge::default()),
                                timers: Arc::new(NullGuestTimerBridge::default()),
                            });
                            dispatcher.bind_hvpatch_process(process.clone());
                            let mut memory = LinearMemory::new(0, vec![0; 1024]);
                            for iteration in 0..scale {
                                let current = kernel
                                    .context(
                                        contexts[0].task().key().id,
                                        contexts[0].thread().key().tid,
                                    )
                                    .unwrap();
                                outcomes.lock().push(
                                    dispatcher
                                        .dispatch(
                                            &current,
                                            SyscallRequest::new(
                                                nr::SETRESUID.raw(),
                                                SyscallArgs::new([
                                                    10 + iteration,
                                                    0,
                                                    100 + iteration,
                                                    0,
                                                    0,
                                                    0,
                                                ]),
                                            ),
                                            &mut memory,
                                            &reporter,
                                        )
                                        .unwrap(),
                                );
                            }
                        } else {
                            lane.after(root_actor, Point::WaitEnrolled).unwrap();
                            drop(reservation.lock().take().unwrap());
                            // Eligibility follows the reservation owner's recorded
                            // release decision, independently of condvar delivery.
                            lane.release_admission(&contexts[0]);
                        }
                    },
                )
                .unwrap();
            assert!(
                outcomes
                    .lock()
                    .iter()
                    .all(|o| *o == DispatchOutcome::Returned { value: 0 })
            );
            assert_eq!(reporter.snapshot().summary.syscall_invocations, scale);
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::WaitEnrolled)
                    .count(),
                1
            );
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::WaitResumed)
                    .count(),
                1
            );
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::Kernel(KPoint::CredentialPublished))
                    .count(),
                scale as usize
            );
            kernel.validate_invariants().unwrap();
        }
    }
}
fn pair() -> (ExampleProcess, [KernelContext; 2]) {
    let (process, root) = ExampleProcess::boot_root(
        1,
        "admission schedules",
        Arc::new(NullHostSignalBridge::default()),
        AddressSpace::allocate(&AsidAllocator::new()).unwrap(),
    )
    .unwrap();
    let sibling = root
        .kernel()
        .reserve_thread_clone(&root, thread_plan(), None)
        .unwrap()
        .prepare(ThreadId::from_guest_supplied_tid(2))
        .unwrap()
        .commit()
        .unwrap()
        .into_context()
        .unwrap();
    (process, [root, sibling])
}
fn actor(context: &KernelContext) -> Actor {
    Actor {
        task_id: context.task().key().id.raw(),
        task_serial: context.task().key().serial.raw(),
        thread_id: context.thread().key().tid.raw(),
        thread_serial: context.thread().key().serial.raw(),
        execution_generation: context
            .thread()
            .execution_state()
            .generation()
            .map_or(0, |g| g.raw()),
    }
}

#[test]
fn operation_receipt_rejects_authority_and_scale_drift() {
    let run = |schedule: &Schedule| {
        let (_, contexts) = pair();
        let key = ObjectWaitKey::new(1, 7).unwrap();
        schedule.run_operations(
            contexts[0].kernel(),
            "authority-replay",
            8,
            &contexts,
            |_, lane| {
                lane.authority_point(KPoint::BeforeLock, Authority::Object(key));
            },
        )
    };
    let recorded = run(&Schedule::explore(5)).unwrap();
    assert_eq!(recorded.scale, 8);
    assert_eq!(run(&Schedule::replay(recorded.clone())).unwrap(), recorded);
    let mut wrong_authority = recorded.clone();
    wrong_authority.decisions[0].authority =
        Some(carrick_kernel::kernel::schedule::AuthorityStamp::Object {
            index: 1,
            generation: 8,
        });
    assert!(
        run(&Schedule::replay(wrong_authority))
            .unwrap_err()
            .contains("authority")
    );
    let mut wrong_scale = recorded;
    wrong_scale.scale = 32;
    assert!(
        run(&Schedule::replay(wrong_scale))
            .unwrap_err()
            .contains("scale")
    );
}

#[test]
fn wait_service_keeps_a_wake_published_before_enrollment() {
    use carrick_kernel::kernel::{
        continuation::{
            BlockedContinuation, CancellationCause, CarrierWaitService, ContinuationCapture,
            ContinuationEvent, RestartClass,
        },
        schedule::{Event, Subject},
        scheduler::{GuestCpuPolicy, Scheduler},
    };
    use carrick_observability::work_meter::{WorkMeter, WorkMetric};
    for seed in 0..16 {
        let (process, contexts) = pair();
        let process = Arc::new(process) as Arc<dyn CarrierProcess>;
        let kernel = contexts[0].kernel().clone();
        let generation = carrick_kernel_example::seed_initial_task_state(&contexts[0], 1).unwrap();
        let root_actor = actor(&contexts[0]);
        let producer = actor(&contexts[1]);
        let subject = Subject::from_context(&contexts[0]);
        let service = CarrierWaitService::try_new(Arc::new(Scheduler::new_with_policy(
            kernel.clone(),
            Arc::new(GuestCpuPolicy::new(1)),
        )))
        .unwrap();
        let meter = WorkMeter::default();
        let work = meter.new_scope();
        service.set_work_scope(work.clone());
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let graph = kernel.clone();
        service.schedule_hooks().set(Some(Arc::new(move |event| {
            seen.lock().push(event);
            if event.point == KPoint::BeforeWaitEnrollment {
                // The enrollment call runs on the root operation actor. Wake
                // callbacks are passive observations of the exact token.
                carrick_kernel::schedule_point!(
                    graph.schedule_hooks(),
                    Event {
                        actor: Some(subject),
                        ..event
                    }
                );
            }
        })));
        let token = Mutex::new(None);
        Schedule::explore(seed)
            .max_transitions(64)
            .run_operations(
                &kernel,
                "service-wake/before-enroll",
                1,
                &contexts,
                |index, lane| {
                    if index == 0 {
                        let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
                            host_signal: Arc::new(NullHostSignalBridge::default()),
                            timers: Arc::new(NullGuestTimerBridge::default()),
                        });
                        dispatcher.bind_hvpatch_process(process.clone());
                        let mut bytes = vec![0; 1024];
                        bytes[128..136].copy_from_slice(&10_i64.to_le_bytes());
                        let mut memory = LinearMemory::new(0, bytes);
                        let request = SyscallRequest::new(
                            nr::NANOSLEEP.raw(),
                            SyscallArgs::new([128, 0, 0, 0, 0, 0]),
                        );
                        let outcome = dispatcher
                            .dispatch(
                                &contexts[0],
                                request,
                                &mut memory,
                                &CompatReporter::default(),
                            )
                            .unwrap();
                        let capture = ContinuationCapture::new(
                            &contexts[0],
                            generation,
                            request,
                            RestartClass::Never,
                        )
                        .unwrap();
                        let continuation =
                            BlockedContinuation::from_dispatch_outcome(outcome, capture).unwrap();
                        let mut registration = service.prepare_registration(&continuation);
                        let current = registration.wake_token();
                        *token.lock() = Some(current);
                        service.enroll(&mut registration).unwrap();
                        lane.after(producer, Point::Kernel(KPoint::AfterUnlock))
                            .unwrap();
                        let event = carrick_kernel_example::block_on_timeout(
                            service.event(current),
                            Duration::from_secs(1),
                        )
                        .unwrap()
                        .unwrap();
                        assert_eq!(event, ContinuationEvent::Ready);
                        // Ready has already won publication. Cancellation
                        // closes it, but reports no still-active enrollment.
                        assert!(matches!(
                            service.cancel_registration(registration),
                            Err(carrick_kernel::kernel::continuation::WaitServiceError::StaleRegistration)
                        ));
                        assert!(matches!(
                            carrick_kernel_example::block_on_timeout(
                                service.event(current),
                                Duration::from_secs(1),
                            ).unwrap(),
                            Err(carrick_kernel::kernel::continuation::WaitServiceError::Cancelled(
                                CancellationCause::ServiceShutdown
                            ))
                        ));
                        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
                        // A transport edge is not permission to complete nanosleep.
                        assert!(!service.publish_ready(current).accepted());
                    } else {
                        lane.after(root_actor, Point::Kernel(KPoint::BeforeWaitEnrollment))
                            .unwrap();
                        assert!(service.publish_ready(token.lock().unwrap()).accepted());
                        lane.point(KPoint::AfterUnlock);
                    }
                },
            )
            .unwrap();
        service.schedule_hooks().set(None);
        let events = events.lock();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.point == KPoint::BeforeWaitEnrollment)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.point == KPoint::WaitEnrolled)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.point == KPoint::WakePublished)
                .count(),
            1
        );
        let snapshot = work.snapshot().unwrap();
        assert_eq!(snapshot.get(WorkMetric::ContinuationEnrollments), Some(1));
        assert_eq!(snapshot.get(WorkMetric::WakePublications), Some(1));
    }
}

#[test]
fn setresuid_during_sibling_birth_completes_once() {
    for scale in [1, 8, 32] {
        for seed in 0..16 {
            let (process, contexts) = pair();
            let kernel = contexts[0].kernel().clone();
            let page = contexts[0].thread().control_lease().lifecycle().clone();
            // The exact Phase-B claimant that made BirthAdmissionGuard reject
            // credentials before 800247419. It belongs to this live process.
            let claimed = Mutex::new(Some(page.claim_any().unwrap()));
            assert_eq!(page.claimed_count(), 1);
            let pending = kernel
                .reserve_thread_clone(&contexts[1], thread_plan(), None)
                .unwrap()
                .prepare(ThreadId::from_guest_supplied_tid(3))
                .unwrap();
            let born_key = pending.prepared_execution_identity().1;
            let pending = Mutex::new(Some(pending));
            let sibling_credentials = contexts[1].resources().credentials();
            let process = Arc::new(process) as Arc<dyn CarrierProcess>;
            let outcomes = Mutex::new(Vec::new());
            let reporter = CompatReporter::default();
            let root_actor = actor(&contexts[0]);
            let schedule = Schedule::explore(seed).max_transitions(512);
            let mut receipt = schedule
                .run_operations(
                    &kernel,
                    &format!("setresuid-held-birth/{scale}"),
                    scale as usize,
                    &contexts,
                    |index, lane| {
                        if index == 0 {
                            let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
                                host_signal: Arc::new(NullHostSignalBridge::default()),
                                timers: Arc::new(NullGuestTimerBridge::default()),
                            });
                            dispatcher.bind_hvpatch_process(process.clone());
                            let mut memory = LinearMemory::new(0, vec![0; 1024]);
                            for iteration in 0..scale {
                                let current = kernel
                                    .context(
                                        contexts[0].task().key().id,
                                        contexts[0].thread().key().tid,
                                    )
                                    .unwrap();
                                outcomes.lock().push(
                                    dispatcher
                                        .dispatch(
                                            &current,
                                            SyscallRequest::new(
                                                nr::SETRESUID.raw(),
                                                SyscallArgs::new([
                                                    10 + iteration,
                                                    0,
                                                    100 + iteration,
                                                    0,
                                                    0,
                                                    0,
                                                ]),
                                            ),
                                            &mut memory,
                                            &reporter,
                                        )
                                        .unwrap(),
                                );
                            }
                        } else {
                            lane.after(root_actor, Point::Finish).unwrap();
                            page.unclaim(claimed.lock().take().unwrap()).unwrap();
                            // One real ledger birth; its inherited resources came
                            // from the unaffected sibling, not the setid caller.
                            let pending = pending.lock().take().unwrap();
                            assert_eq!(pending.record_birth(), born_key);
                            lane.point(KPoint::AdmissionReleased);
                        }
                    },
                )
                .unwrap();
            // Retain the smallest source-qualified historical witness before
            // its semantic assertion fails. This is an explicit recorder,
            // following schedule_replay's VMFREE_TRACE convention.
            if seed == 0 && scale == 1 {
                receipt.result = format!("setresuid outcomes: {:?}", *outcomes.lock());
                if let Ok(path) = std::env::var("VMFREE_TRACE") {
                    std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
                }
            }
            for outcome in outcomes.lock().iter() {
                assert_eq!(
                    *outcome,
                    DispatchOutcome::Returned { value: 0 },
                    "seed {seed}, scale {scale}: guest EAGAIN is not admission"
                );
            }
            assert_eq!(reporter.snapshot().summary.syscall_invocations, scale);
            let born = kernel
                .context(contexts[0].task().key().id, born_key.tid)
                .unwrap();
            assert_eq!(born.thread().key(), born_key);
            let inherited = born.resources().credentials();
            assert_eq!(inherited.ruid(), sibling_credentials.ruid());
            assert_eq!(inherited.euid(), sibling_credentials.euid());
            assert_eq!(inherited.suid(), sibling_credentials.suid());
            assert_eq!(page.claimed_count(), 0);
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::Kernel(KPoint::BirthRecorded))
                    .count(),
                1
            );
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::Kernel(KPoint::CredentialPublished))
                    .count(),
                scale as usize
            );
            assert!(
                !receipt
                    .decisions
                    .iter()
                    .any(|d| matches!(d.point, Point::WaitEnrolled | Point::WaitResumed))
            );
            assert_eq!(
                receipt
                    .decisions
                    .iter()
                    .filter(|d| d.point == Point::Kernel(KPoint::AdmissionReleased))
                    .count(),
                1
            );
            kernel.validate_invariants().unwrap();
        }
    }
}

#[test]
fn exec_publication_retires_late_ledger_entry() {
    // This proves the portable graph boundary. The c1ea66b63 runtime member
    // admission gate has no public VM-free adapter; its original red belongs
    // to the handoff, not to this narrower test's acceptance claim.
    for seed in 0..32 {
        let (_, contexts) = pair();
        let kernel = contexts[0].kernel().clone();
        let born = kernel
            .reserve_thread_clone(&contexts[1], thread_plan(), None)
            .unwrap()
            .prepare(ThreadId::from_guest_supplied_tid(3))
            .unwrap()
            .record_birth();
        // Force the real settled view to publish the one ledger birth.
        let root = kernel
            .context(contexts[0].task().key().id, contexts[0].thread().key().tid)
            .unwrap();
        assert_eq!(root.task().threads().len(), 3);
        let peer = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "independent peer".into(),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(
                AddressSpace::allocate(&AsidAllocator::new())
                    .unwrap()
                    .mm_backend(),
                ThreadId::from_guest_supplied_tid(4),
            )
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let owner = actor(&contexts[0]);
        let late_entries = Mutex::new(Vec::new());
        let receipt = Schedule::explore(seed)
            .max_transitions(64)
            .run_operations(
                &kernel,
                "exec-publication/late-ledger-entry",
                1,
                &contexts,
                |index, lane| {
                    if index == 0 {
                        let current = kernel
                            .context(contexts[0].task().key().id, contexts[0].thread().key().tid)
                            .unwrap();
                        let prepared = kernel.prepare_exec(&current, None).unwrap();
                        let successor = kernel.commit_exec(prepared, None).unwrap();
                        assert_ne!(successor.thread().key(), contexts[0].thread().key());
                        lane.point(KPoint::AfterUnlock);
                    } else {
                        lane.after(owner, Point::Kernel(KPoint::AfterUnlock))
                            .unwrap();
                        late_entries.lock().push(
                            kernel
                                .adopt_born_thread_at_first_entry(
                                    born,
                                    &carrick_el1_abi::ThreadCtx::ZERO,
                                )
                                .unwrap(),
                        );
                        assert!(
                            kernel
                                .context(contexts[0].task().key().id, born.tid)
                                .is_err()
                        );
                    }
                },
            )
            .unwrap();
        assert_eq!(*late_entries.lock(), [false]);
        assert!(kernel.task_key_is_live(peer.task().key()));
        assert_eq!(peer.task().threads().len(), 1);
        assert_eq!(contexts[0].task().threads().len(), 1);
        assert_eq!(
            receipt
                .decisions
                .iter()
                .filter(|d| d.point == Point::Kernel(KPoint::ExecAdmitted))
                .count(),
            1
        );
        kernel.validate_invariants().unwrap();
    }
}

const SLOT: SlotId = SlotId::new(3);
const MM: u64 = 7;
fn zone() -> Box<ZoneTables> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: all-zero is the documented empty ZoneTables ABI, and the heap
    // owns this properly aligned, exclusively allocated record array.
    let zone = unsafe {
        let pointer = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!pointer.is_null());
        Box::from_raw(pointer)
    };
    zone.drive(SLOT, 1);
    zone.publish_slot(SLOT, MM, None, 0);
    assert!(
        zone.occupancy
            .replace(carrick_sched_core::ExecutionSlot::zone(SLOT), 0, MM)
    );
    zone.enter_guest(SLOT);
    zone
}
fn identity(tid: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid,
        serial: tid + 100,
        mm: MM,
        file_table: 99,
        generation: 1,
        affinity: 0,
        lifecycle_page: 0,
        control_slot: 0,
    }
}
fn park(zone: &ZoneTables, key: ObjectWaitKey, tid: u64) -> carrick_sched_core::RecordId {
    let guard = zone.object_wait(key, &BoundedSpin(0)).unwrap();
    let record = zone.alloc_record(identity(tid)).unwrap();
    guard
        .park(
            guard.snapshot(),
            record,
            OperationToken::new(tid, 1).unwrap(),
        )
        .unwrap();
    record
}

#[test]
fn check_enroll_wake_interleaving_preserves_epoch() {
    for seed in 0..32 {
        let (_, contexts) = pair();
        let kernel = contexts[0].kernel().clone();
        let zone = zone();
        let key = ObjectWaitKey::new(1, 1).unwrap();
        zone.bind_object_wait(key, &BoundedSpin(0)).unwrap();
        let snapshot = zone.object_wait(key, &BoundedSpin(0)).unwrap().snapshot();
        let waiter = actor(&contexts[0]);
        let producer = actor(&contexts[1]);
        let refused = Mutex::new(None);
        Schedule::explore(seed)
            .max_transitions(64)
            .run_operations(
                &kernel,
                "object-check/enroll-wake",
                1,
                &contexts,
                |index, lane| {
                    if index == 0 {
                        lane.authority_point(KPoint::AfterUnlock, Authority::Object(key));
                        lane.after(producer, Point::Kernel(KPoint::WakePublished))
                            .unwrap();
                        lane.authority_point(KPoint::BeforeLock, Authority::Object(key));
                        let record = zone.alloc_record(identity(1)).unwrap();
                        let guard = zone.object_wait(key, &BoundedSpin(0)).unwrap();
                        let operation = OperationToken::new(1, 1).unwrap();
                        let refusal = guard.park(snapshot, record, operation).unwrap_err();
                        *refused.lock() = Some(refusal.0);
                        assert_eq!(refusal.1.index(), 1);
                        assert_eq!(refusal.1.generation(), 1);
                        assert!(!zone.record(record).has_object_operation());
                        guard.park(guard.snapshot(), record, refusal.1).unwrap();
                        drop(guard);
                        lane.authority_point(KPoint::WaitEnrolled, Authority::Object(key));
                    } else {
                        lane.after(waiter, Point::Kernel(KPoint::AfterUnlock))
                            .unwrap();
                        let guard = zone.object_wait(key, &BoundedSpin(0)).unwrap();
                        let report = guard
                            .notify_object_host(&mut |_| panic!("not enrolled yet"), &mut |_| {})
                            .unwrap();
                        assert_eq!(report.visited, 0);
                        drop(guard);
                        lane.authority_point(KPoint::WakePublished, Authority::Object(key));
                    }
                },
            )
            .unwrap();
        assert_eq!(*refused.lock(), Some(ObjectWaitError::Changed));
        let guard = zone.object_wait(key, &BoundedSpin(0)).unwrap();
        let report = guard.notify_object_host(&mut |_| {}, &mut |_| {}).unwrap();
        assert_eq!(report.visited, 1);
        assert_eq!(report.queued + report.handed, 1);
    }
}

#[test]
fn claim_reuse_removes_queue_entries_and_stale_completions() {
    for scale in [1, 8, 32] {
        for seed in 0..16 {
            let (_, contexts) = pair();
            let kernel = contexts[0].kernel().clone();
            let zone = zone();
            let old = ObjectWaitKey::new(1, 7).unwrap();
            let new = ObjectWaitKey::new(1, 8).unwrap();
            let unrelated = ObjectWaitKey::new(2, 1).unwrap();
            zone.bind_object_wait(old, &BoundedSpin(0)).unwrap();
            zone.bind_object_wait(unrelated, &BoundedSpin(0)).unwrap();
            for tid in 100..132 {
                park(&zone, unrelated, tid);
            }
            let records: Vec<_> = (1..=scale).map(|tid| park(&zone, old, tid)).collect();
            let stale: Vec<_> = records
                .iter()
                .map(|record| zone.record_ref(*record))
                .collect();
            let owner = actor(&contexts[0]);
            Schedule::explore(seed)
                .max_transitions(64)
                .run_operations(
                    &kernel,
                    &format!("claim-reuse/{scale}"),
                    scale as usize,
                    &contexts,
                    |index, lane| {
                        if index == 0 {
                            for (record, old_ref) in records.iter().zip(&stale) {
                                assert_eq!(
                                    zone.claim_for_host(
                                        *old_ref,
                                        None,
                                        Handback::Cancelled,
                                        &BoundedSpin(0)
                                    ),
                                    HostClaim::Claimed
                                );
                                assert_eq!(zone.record(*record).entry_count(), 0);
                                // SAFETY: the real host claim detached both queues and
                                // transferred exclusive ownership of this record.
                                unsafe {
                                    assert!(zone.record(*record).take_object_operation().is_some());
                                }
                                zone.free_record(*record);
                                assert!(zone.live(*old_ref).is_none());
                            }
                            lane.authority_point(KPoint::AfterUnlock, Authority::Object(old));
                        } else {
                            lane.after(owner, Point::Kernel(KPoint::AfterUnlock))
                                .unwrap();
                            zone.bind_object_wait(new, &BoundedSpin(0)).unwrap();
                            for tid in 1..=scale {
                                park(&zone, new, tid);
                            }
                            for old_ref in &stale {
                                assert_eq!(
                                    zone.claim_for_host(
                                        *old_ref,
                                        None,
                                        Handback::Control,
                                        &BoundedSpin(0)
                                    ),
                                    HostClaim::Stale
                                );
                            }
                            let guard = zone.object_wait(new, &BoundedSpin(0)).unwrap();
                            let report =
                                guard.notify_object_host(&mut |_| {}, &mut |_| {}).unwrap();
                            assert_eq!(
                                report.visited, scale as u32,
                                "work touches affected waiters only"
                            );
                            assert_eq!(report.queued + report.handed, scale as u32);
                            drop(guard);
                            lane.authority_point(KPoint::WakePublished, Authority::Object(new));
                        }
                    },
                )
                .unwrap();
            assert!(matches!(
                zone.object_wait(old, &BoundedSpin(0)),
                Err(ObjectWaitError::Stale)
            ));
            assert_eq!(
                zone.object_queue_census(unrelated.index()).unwrap().waiters,
                32
            );
            assert!(zone.switch_in_full(SLOT).is_some());
        }
    }
}
