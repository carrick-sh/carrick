//! A native parent park retains the child's existing in-ring execution.
use super::*;

#[test]
fn arm_native_fork_child_runs_after_parent_host_handoff() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
    )
    .with_words(words);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    let child_pid = frame.x[0];
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    let identity = fixture.zone.record(child).identity();
    assert!(matches!(
        fixture.zone.record(child).claim(),
        carrick_sched_core::Claim::Queued { slot, .. } if slot == fixture.slot
    ));
    // The root's host continuation blocked and its executor detached the
    // loaded task. A native child is the only runnable work left.
    fixture.zone.publish_slot(fixture.slot, 0, None, 0);
    fixture.task.mm.key.store(0, Ordering::Release);
    assert!(
        fixture
            .zone
            .take_service_head_for_executor(fixture.slot)
            .is_none(),
        "the executor cannot adopt a child with no host thread"
    );
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    let action = super::super::dispatch::native_scheduler(
        &mut zone,
        &fixture.task,
        &counters,
        fixture.slot,
        &mut handoff,
    )
    .idle_entry(&mut frame, 0);
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    assert!(matches!(
        fixture.zone.record(child).claim(),
        carrick_sched_core::Claim::OnCpu { slot, .. } if slot == fixture.slot
    ));
    assert_eq!(frame.x[0], 0);

    let owner = registry()
        .for_record(fixture.zone, fixture.zone.record_ref(child))
        .expect("native child retains its process owner");
    assert!(matches!(
        super::super::aarch64_process::resume_selected(
            &owner,
            registry(),
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            child,
            &mut service,
        ),
        super::super::native_process_runtime::NativeResume::NoPending
            | super::super::native_process_runtime::NativeResume::Returned(_)
    ));
    // SAFETY: the child owner retains its lifecycle and control until this
    // fixture ends, and the selected record is OnCpu on the only slot.
    let child_page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
    let child_control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    frame.x[8] = 172; // getpid, the child's first EL0 syscall.
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let grant = fixture
        .zone
        .spaces
        .grant(fixture.zone.spaces.find(identity.mm).unwrap(), identity.mm)
        .unwrap();
    let route = super::super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        child_page,
        child_control,
        &ThreadCtx::ZERO,
        grant.ttbr0,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(frame.x[0], child_pid);
}

#[test]
fn arm_native_fork_timer_delivers_child_without_parent_wait() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
    )
    .with_words(words);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    let deadline = cpu.timer.expect("fork must arm a preemption timer");

    cpu.now = deadline;
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    let action = super::super::dispatch::native_scheduler(
        &mut zone,
        &fixture.task,
        &counters,
        fixture.slot,
        &mut handoff,
    )
    .interrupt(&mut frame, 0);
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    assert_eq!(frame.x[0], 0, "the child receives fork's zero return");
}

#[test]
fn arm_native_wait_runs_ready_child_before_host_handoff() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
    )
    .with_words(words);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    frame.x[8] = 220;
    frame.x[0] = 17; // SIGCHLD, no child-TID effect in this scheduler witness.
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    let child_pid = frame.x[0];
    assert!(child_pid > 0 && child_pid <= u64::from(u32::MAX));
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    let identity = fixture.zone.record(child).identity();
    assert!(identity.affinity_source.is_guest_mapped());
    assert_eq!(identity.affinity_source.load(), Some(1));
    assert!(matches!(
        fixture.zone.record(child).claim(),
        carrick_sched_core::Claim::Queued { slot, .. } if slot == fixture.slot
    ));
    assert_eq!(
        identity.generation,
        carrick_el1_abi::SnapshotGeneration::INITIAL.raw()
    );
    assert_ne!(identity.mm, fixture.address.mm.raw().get());
    assert!(fixture.zone.spaces.is_open(identity.mm));
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(
        service
            .crossing
            .settlements_committed
            .load(Ordering::Acquire),
        1
    );
    assert!(
        cpu.timer.is_some(),
        "a native fork must arm the run-queue timer so its child gets a first EL0 entry"
    );

    frame.x = [0; 31];
    frame.x[8] = 260;
    frame.x[0] = child_pid;
    frame.x[2] = 1; // WNOHANG retains the parent's ordinary return.
    arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert_eq!(frame.x[0], 0);
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        fixture.address.mm.raw().get()
    );
    assert_eq!(fixture.zone.runnable_head(fixture.slot), Some(child));

    frame.x = [0; 31];
    frame.x[8] = 260;
    frame.x[0] = child_pid;
    let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    assert_eq!(
        fixture.task.execution.task.load(Ordering::Acquire),
        identity.tid
    );
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), identity.mm);
    assert!(matches!(
        fixture.zone.record(child).claim(),
        carrick_sched_core::Claim::OnCpu { slot, .. } if slot == fixture.slot
    ));
    assert_eq!(frame.x[0], 0, "the child retains its fork return");
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
    assert_eq!(
        fixture.zone.counters.el1_switches.load(Ordering::Acquire),
        1
    );
    assert_eq!(
        fixture.zone.counters.lost_adoptions.load(Ordering::Acquire),
        0
    );

    // SAFETY: this fixture owns the selected OnCpu record on this slot.
    let child_context = unsafe { fixture.zone.record(child).ctx_mut() }
        .address_context()
        .unwrap();
    let index = fixture.zone.spaces.find(identity.mm).unwrap();
    let grant = fixture.zone.spaces.grant(index, identity.mm).unwrap();
    assert_ne!(fixture.zone.slot(fixture.slot).mm(), identity.mm);
    // SAFETY: this fixture owns the selected OnCpu record on this slot.
    let observed = unsafe {
        observed_entry_address(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            grant.ttbr0,
            child,
        )
    };
    assert_eq!(observed, Ok(child_context));

    let owner = registry()
        .for_record(fixture.zone, fixture.zone.record_ref(child))
        .expect("fork child retains its native process owner");
    assert!(matches!(
        super::super::aarch64_process::resume_selected(
            &owner,
            registry(),
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            child,
            &mut service,
        ),
        super::super::native_process_runtime::NativeResume::NoPending
            | super::super::native_process_runtime::NativeResume::Returned(_)
    ));

    // Re-enter the selected native child through the production syscall
    // adapter. A queued record and a loaded context alone do not prove its
    // first EL0 trap can reach the native process owner.
    // SAFETY: the committed child retains its lifecycle page and control
    // through the native owner registry for this entire test.
    let child_page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
    // SAFETY: the same child owner retains this exact control slot.
    let child_control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    frame.x[8] = 172; // getpid
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let route = super::super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        child_page,
        child_control,
        &ThreadCtx::ZERO,
        grant.ttbr0,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(frame.x[0], child_pid);
}

/// Match the production crossing's allocation-domain requirement using the
/// actual current pthread stack, not a guessed distance from a local variable.
#[cfg(target_os = "linux")]
pub(super) fn assert_current_stack_commit(address: u64) {
    let mut attributes = core::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    // SAFETY: attributes is initialized by the successful pthread query below.
    assert_eq!(
        unsafe { libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr()) },
        0
    );
    // SAFETY: pthread_getattr_np succeeded and initialized this value.
    let mut attributes = unsafe { attributes.assume_init() };
    let mut base = core::ptr::null_mut();
    let mut size = 0;
    // SAFETY: initialized attributes and valid output storage; destroy on both
    // success and failure before asserting the query result.
    let queried = unsafe { libc::pthread_attr_getstack(&attributes, &mut base, &mut size) };
    // SAFETY: these initialized attributes have not yet been destroyed.
    let destroyed = unsafe { libc::pthread_attr_destroy(&mut attributes) };
    assert_eq!(queried, 0);
    assert_eq!(destroyed, 0);
    let start = base as usize;
    let end = start.checked_add(size).unwrap();
    let address = usize::try_from(address).unwrap();
    let record_end = address
        .checked_add(core::mem::size_of::<ForkStockSettlement>())
        .unwrap();
    assert!(address.is_multiple_of(core::mem::align_of::<ForkStockSettlement>()));
    assert!(
        start <= address && record_end <= end,
        "fork Commit must be a complete current-stack record, not retained heap custody: record={address:#x}..{record_end:#x}, stack={start:#x}..{end:#x}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn arm_exec_binding_then_native_fork_commits_on_current_stack() {
    arm_binding_then_native_fork_commits_on_current_stack(true);
}

#[cfg(target_os = "linux")]
#[test]
fn arm_fresh_binding_then_native_fork_commits_on_current_stack() {
    arm_binding_then_native_fork_commits_on_current_stack(false);
}

#[cfg(target_os = "linux")]
fn arm_binding_then_native_fork_commits_on_current_stack(exec: bool) {
    use carrick_el1_abi::Lifecycle;
    use carrick_kernel::kernel::thread_adoption::{
        ThreadBirthAdoptionFactory, ThreadBirthAdoptionReservation,
    };
    use carrick_kernel::kernel::{Kernel, RootBootstrap};

    #[derive(Debug)]
    struct ExecutableFactory(carrick_kernel::kernel::TaskKey);
    impl ThreadBirthAdoptionFactory for ExecutableFactory {
        fn executable_births(&self) -> bool {
            true
        }
        fn owner(&self) -> carrick_kernel::kernel::TaskKey {
            self.0
        }
        fn reserve(
            &self,
            _: carrick_kernel::kernel::ThreadKey,
        ) -> Option<ThreadBirthAdoptionReservation> {
            None
        }
    }

    {
        let input = RootBootstrap::for_reference_model(
            41,
            carrick_hal::ThreadId::synthetic_for_tests(41),
            "exec-fork-stack".into(),
        )
        .unwrap();
        let (kernel, initial) = Kernel::bootstrap_root(input).unwrap();
        let root = if exec {
            let prepared = kernel.prepare_exec(&initial, None).unwrap();
            let committed = kernel.commit_exec(prepared, None).unwrap();
            assert_ne!(committed.shared().mm().id(), initial.shared().mm().id());
            assert_eq!(
                committed.lifecycle_page().gate(),
                carrick_el1_abi::GateState::AwaitingExecBinding
            );
            committed
        } else {
            initial
        };
        let root = Box::leak(Box::new(root));
        root.task()
            .install_thread_adoption_factory(std::sync::Arc::new(ExecutableFactory(
                root.task().key(),
            )))
            .unwrap();
        kernel.prepare_executable_thread_births(root);
        assert_eq!(
            root.lifecycle_page().gate(),
            carrick_el1_abi::GateState::Open
        );
        let page_lease = Box::leak(Box::new(root.lifecycle_page()));
        let page = &**page_lease;
        let control = root.thread().control_slot();
        let fixture = Box::leak(Box::new(Fixture::with_identity(
            0x10000,
            asid(1),
            page,
            control,
            ThreadIdentity {
                tid: root.thread().key().tid.raw() as u64,
                serial: root.thread().key().serial.raw(),
                generation: if exec { 2 } else { 1 },
                mm: root.shared().mm().id().raw(),
                file_table: root.resources().files().id().raw(),
                affinity: 1,
                affinity_source: Default::default(),
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )));
        let home = fixture.zone.slot(fixture.slot).host_record().unwrap();
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert_eq!(
            fixture.zone.record(home).claim(),
            carrick_sched_core::Claim::Free,
            "exec binding must retain the same host-home convention as fresh execution"
        );
        let binding = super::super::common_entry::execution_binding(&fixture.task);
        assert!(
            carrick_core::entry::prepare_handoff(
                binding,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot
                },
                home
            )
            .is_some()
        );

        let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
        let mut crossing = TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]);
        crossing.require_stack_commit = true;
        let mut service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            crossing,
        )
        .with_words(words);
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 220;
        frame.x[0] = 17;
        let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
        assert!(matches!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Served
                | carrick_personality_linux::dispatch::CompletionRoute::WithWork
        ));
        assert!(frame.x[0] > 0 && frame.x[0] <= u64::from(u32::MAX));
        assert_eq!(
            super::super::common_entry::execution_binding(&fixture.task),
            binding
        );
        let child = fixture.zone.runnable_head(fixture.slot).unwrap();
        assert!(
            fixture
                .zone
                .spaces
                .is_open(fixture.zone.record(child).identity().mm)
        );
        assert_eq!(
            service
                .crossing
                .settlements_committed
                .load(Ordering::Acquire),
            1
        );
    }
}

/// VM-free transport binding for `kernel.scheduler.runnable-progress`.
#[test]
fn two_native_children_service_waits_release_the_only_execution_slot() {
    two_native_children_service_waits(ServiceWitness::Fault);
}

#[test]
fn completed_native_service_preserves_result_through_cancellation() {
    two_native_children_service_waits(ServiceWitness::Completed);
}

#[test]
fn deferred_native_service_retries_original_instruction_after_carrier_work() {
    two_native_children_service_waits(ServiceWitness::Retry);
}

#[test]
fn interrupted_native_service_preserves_instruction_and_registers() {
    two_native_children_service_waits(ServiceWitness::Interrupt);
}

#[test]
fn native_service_intake_does_not_reacquire_the_busy_mm_root() {
    two_native_children_service_waits(ServiceWitness::RootBusy);
}

#[derive(Clone, Copy)]
enum ServiceWitness {
    RootBusy,
    Fault,
    Completed,
    Retry,
    Interrupt,
}

fn two_native_children_service_waits(witness: ServiceWitness) {
    use super::super::native_process_runtime::NativeResume;
    use carrick_core::lifecycle::Lifecycle;
    use carrick_core_abi::service::{ServiceCell, ServiceError};
    use carrick_sched_core::object_wait::ObjectWaitKey;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let pages: Vec<_> = (0..16).map(|index| 0x20000 + index * 4096).collect();
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&pages),
    )
    .with_words(words);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    for _ in 0..2 {
        frame.x[8] = 220;
        frame.x[0] = 17;
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
        assert!((frame.x[0] as i64) > 0, "actual native fork must succeed");
    }
    fixture.zone.publish_slot(fixture.slot, 0, None, 0);
    fixture.task.mm.key.store(0, Ordering::Release);
    let counters = carrick_el1_abi::Counters::new();
    let mut pending = Vec::new();
    for _ in 0..2 {
        let mut handoff = None;
        let mut zone = crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        };
        assert_eq!(
            super::super::dispatch::native_scheduler(
                &mut zone,
                &fixture.task,
                &counters,
                fixture.slot,
                &mut handoff
            )
            .idle_entry(&mut frame, 0),
            carrick_el1_abi::Action::Served
        );
        let child = fixture.zone.slot(fixture.slot).current().unwrap();
        let record = fixture.zone.record_ref(child);
        let identity = fixture.zone.record(child).identity();
        let owner = registry().for_record(fixture.zone, record).unwrap();
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        assert!(matches!(
            resume_selected(
                &owner,
                registry(),
                source,
                &fixture.task,
                child,
                &mut service
            ),
            NativeResume::NoPending
        ));
        // SAFETY: the real native owner retains these published allocations.
        let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let mut saved = unsafe { *fixture.zone.record(child).ctx_mut() };
        frame.x[0] = 73;
        frame.elr = 0x4004;
        frame.esr = 0x15 << 26;
        let action = match witness {
            ServiceWitness::Completed => {
                fixture.task.linux.record_completed_with_work();
                carrick_el1_abi::Action::ServedWithWork
            }
            ServiceWitness::Retry => {
                fixture.task.linux.record_forward_work(42);
                frame.x[0] = 0xbeef;
                carrick_el1_abi::Action::ServedWithWork
            }
            ServiceWitness::Interrupt => {
                frame.esr = 0;
                fixture.task.linux.mark_pending_host_work();
                carrick_el1_abi::Action::Forward
            }
            ServiceWitness::Fault | ServiceWitness::RootBusy => {
                frame.esr = 0x9200004f;
                frame.far = 0x6000000fd8;
                carrick_el1_abi::Action::Forward
            }
        };
        let operation = super::super::dispatch::native_service_operation(
            &mut frame,
            &fixture.task.linux,
            action,
        )
        .unwrap();
        saved.native.x[0] = frame.x[0];
        saved.native.pc = frame.elr;
        let grant = fixture
            .zone
            .spaces
            .grant(fixture.zone.spaces.find(identity.mm).unwrap(), identity.mm)
            .unwrap();
        assert_eq!(page.claimed_count(), 0);
        let result = with_process_entry(
            source,
            &fixture.task,
            &saved.native,
            grant.ttbr0,
            page,
            control,
            &mut service,
            |entry| {
                let _root = matches!(witness, ServiceWitness::RootBusy).then(|| {
                    fixture
                        .region
                        .table()
                        .lock_in(
                            crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
                            fixture.zone.spaces.find(identity.mm).unwrap().index(),
                            ReservationMm::new(identity.mm).unwrap(),
                            1,
                        )
                        .unwrap()
                });
                let result = entry.begin_service(operation).unwrap();
                assert!(entry.take_handoff_receipt().is_some());
                result
            },
        )
        .unwrap();
        assert!(matches!(result, NativeResume::Left(None)));
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert!(matches!(
            fixture.zone.record(child).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        assert_eq!(page.claimed_count(), 1);
        let selector = fixture.task.service_notice.take().unwrap().unwrap();
        // No real wake sources are attached in this fixture; consume the
        // announced carrier work before the single lane selects another child.
        if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
            doorbell.settled();
        }
        assert_eq!(selector.record, record);
        let key = ObjectWaitKey::native_service(record).unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        assert_eq!(queue.native_service_member(record), Some(identity));
        let mut recycled = record;
        recycled.incarnation += 1;
        assert_eq!(queue.native_service_member(recycled), None);
        let mut stale = selector;
        stale.execution =
            carrick_core_abi::SnapshotGeneration::from_raw(selector.execution.raw() + 1);
        assert!(matches!(
            unsafe {
                ServiceCell::claim_notice(&control.service, stale, NonZeroU64::MIN, identity)
            },
            Err(ServiceError::Stale)
        ));
        drop(queue);
        pending.push((owner, page, control, selector, identity));
    }
    assert!(
        fixture.zone.runnable_head(fixture.slot).is_none(),
        "both children wait with the single executor free"
    );
    pending[0]
        .0
        .cancel_service(pending[0].3.record, fixture.slot, &mut service)
        .unwrap();
    assert_eq!(
        pending[0].1.claimed_count(),
        1,
        "queued cancellation retains the MM before intake"
    );
    assert_eq!(
        pending[0].2.service.reset_unpublished(),
        Err(ServiceError::Busy)
    );
    let mut pending: Vec<_> = pending
        .into_iter()
        .map(|(owner, page, control, selector, identity)| {
            let key = ObjectWaitKey::native_service(selector.record).unwrap();
            let queue = fixture
                .zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin)
                .unwrap();
            assert_eq!(queue.native_service_member(selector.record), Some(identity));
            let ticket = unsafe {
                ServiceCell::claim_notice(&control.service, selector, NonZeroU64::MIN, identity)
            }
            .unwrap();
            (owner, page, control, ticket)
        })
        .collect();
    assert_ne!(
        pending[0].3.request().identity.birth.process,
        pending[1].3.request().identity.birth.process
    );
    assert_ne!(
        pending[0].3.request().identity.birth.mm,
        pending[1].3.request().identity.birth.mm
    );
    let (first_owner, first_page, first_control, first_ticket) = pending.remove(0);
    let first_request = first_ticket.request();
    let first_key = ObjectWaitKey::native_service(first_request.identity.birth.record).unwrap();
    {
        let queue = fixture
            .zone
            .object_wait(first_key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        assert!(
            !first_control
                .service
                .cancel(first_request.identity)
                .unwrap()
        );
        assert_eq!(
            first_control.service.consume(first_request.identity),
            Err(ServiceError::Busy)
        );
        assert_eq!(
            first_page.claimed_count(),
            1,
            "cancellation is not physical acknowledgment"
        );
        queue
            .notify_object(fixture.slot, &mut Default::default())
            .unwrap();
    }
    // A cancellation wake before physical ACK must repark the exact owner.
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        super::super::dispatch::native_scheduler(
            &mut zone,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff
        )
        .idle_entry(&mut frame, 0),
        carrick_el1_abi::Action::Served
    );
    let child = fixture.zone.slot(fixture.slot).current().unwrap();
    assert!(matches!(
        resume_selected(
            &first_owner,
            registry(),
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot
            },
            &fixture.task,
            child,
            &mut service
        ),
        NativeResume::Left(None)
    ));
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert_eq!(first_page.claimed_count(), 1);
    let (second_owner, second_page, second_control, second_ticket) = pending.remove(0);
    // Complete out of order while the first child's resources remain retained.
    for (owner, page, control, ticket) in [
        (second_owner, second_page, second_control, second_ticket),
        (first_owner, first_page, first_control, first_ticket),
    ] {
        let request = ticket.request();
        let key = ObjectWaitKey::native_service(request.identity.birth.record).unwrap();
        {
            let queue = fixture
                .zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin)
                .unwrap();
            assert!(ticket.complete(true).is_ok());
            queue
                .notify_object(fixture.slot, &mut Default::default())
                .unwrap();
        }
        assert_eq!(
            page.claimed_count(),
            1,
            "ring still owes continuation consumption"
        );
        let mut handoff = None;
        let mut zone = crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        };
        assert_eq!(
            super::super::dispatch::native_scheduler(
                &mut zone,
                &fixture.task,
                &counters,
                fixture.slot,
                &mut handoff
            )
            .idle_entry(&mut frame, 0),
            carrick_el1_abi::Action::Served
        );
        let child = fixture.zone.slot(fixture.slot).current().unwrap();
        assert_eq!(child, request.identity.birth.record.id);
        assert!(matches!(
            resume_selected(
                &owner,
                registry(),
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot
                },
                &fixture.task,
                child,
                &mut service
            ),
            NativeResume::NoPending
        ));
        assert_eq!(page.claimed_count(), 0);
        let retained = unsafe { &fixture.zone.record(child).ctx_mut().native };
        let expected = match witness {
            ServiceWitness::Retry => (42, 0x4000),
            _ => (73, 0x4004),
        };
        assert_eq!((retained.x[0], retained.pc), expected);
        assert_eq!(
            control.service.consume(request.identity),
            Err(ServiceError::Busy),
            "exactly one continuation consumed"
        );
        assert!(matches!(
            fixture
                .zone
                .release_current(fixture.slot, child, &carrick_sched_core::ShortLockSpin),
            carrick_sched_core::CurrentRelease::Released
        ));
    }
}
