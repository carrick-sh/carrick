//! A host control wake must survive a native close while EL1 owns its target.
use super::*;
use carrick_kernel::kernel::continuation::{
    BlockedContinuation, CarrierWaitService, ContinuationCapture, RestartClass, ZoneWait,
    test_support::{bootstrap, publish},
};
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, KernelContext, Scheduler,
};
use carrick_sched_core::{Claim, CurrentHandback, Handback, ShortLockSpin, Waker};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

#[derive(Debug, Default)]
struct Kick(Mutex<Option<ExecutorBinding>>);
impl ExecutorKick for Kick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.0.lock().unwrap();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }
    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.0.lock().unwrap();
        if *current == Some(binding) {
            *current = None;
        }
    }
    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.0.lock().unwrap();
        if *current != Some(predecessor) || !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }
    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        *self.0.lock().unwrap() == Some(token.binding())
    }
    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.0.lock().unwrap()
    }
}

fn clone_thread(root: &KernelContext, tid: i32) -> &'static KernelContext {
    let plan = ClonePlan::from_flags(
        carrick_abi::LinuxCloneFlags::THREAD
            | carrick_abi::LinuxCloneFlags::SIGHAND
            | carrick_abi::LinuxCloneFlags::VM
            | carrick_abi::LinuxCloneFlags::FILES
            | carrick_abi::LinuxCloneFlags::FS,
    )
    .unwrap();
    Box::leak(Box::new(
        root.kernel()
            .reserve_thread_clone(root, plan, None)
            .unwrap()
            .prepare(carrick_hal::ThreadId::synthetic_for_tests(tid))
            .unwrap()
            .commit_for_el1()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context(),
    ))
}

#[test]
fn serial_host_arm_exit_group_preserves_deferred_control_handback() {
    deferred_control_handback(true);
}

#[test]
fn serial_host_arm_exit_group_unregistered_sibling_wakes_parked_host() {
    deferred_control_handback(false);
}

fn deferred_control_handback(registered: bool) {
    use carrick_el1_abi::Lifecycle;
    let (kernel, root) = bootstrap(41);
    let root = Box::leak(Box::new(root));
    root.thread().set_affinity(carrick_hal::CpuAffinity::all(2));
    let page = Box::leak(Box::new(root.lifecycle_page()));
    let page = &**page;
    let fixture = Box::leak(Box::new(Fixture::with_identity(
        0x10000,
        asid(1),
        page,
        root.thread().control_slot(),
        ThreadIdentity {
            tid: root.thread().key().tid.raw() as u64,
            serial: root.thread().key().serial.raw(),
            mm: root.shared().mm().id().raw(),
            file_table: root.resources().files().id().raw(),
            generation: root.task().key().serial.raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 3,
            lifecycle_page: page as *const _ as u64,
            control_slot: root.thread().control_slot() as *const _ as u64,
        },
    )));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let members = [clone_thread(root, 42), clone_thread(root, 43)];
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture
        .zone
        .publish_slot(slot, fixture.leader.mm, Some(1), 3);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    let mut records = Vec::new();
    for member in members {
        let control = member.thread().control_slot();
        // The host entry binder publishes this before the first EL1 entry.
        assert!(control.publish_visible_tid(member.thread().key().tid.raw() as u32));
        assert_eq!(control.entry(), None, "host clone control");
        let birth = control.host_birth_identity().unwrap();
        assert!(
            (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
                .any(|index| page.host_birth_identity(index) == Some(birth))
        );
        run_as(
            fixture,
            member.thread().key().tid.raw(),
            root.task().key().serial.raw(),
            member.thread().key().serial.raw(),
            control,
        );
        let mut sibling_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        let park = || {
            let record = fixture.zone.slot(slot).host_record().unwrap();
            let reference = fixture.zone.record_ref(record);
            let address = 0x8000 + member.thread().key().tid.raw() as u64 * 4;
            let guard = fixture.zone.short_lock(
                ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(1, address),
                &ShortLockSpin,
            );
            let seq = fixture.zone.next_seq(record);
            fixture
                .zone
                .enqueue(&guard, record, seq, 1, address, u32::MAX, 0)
                .unwrap();
            fixture.zone.publish_park(record, seq);
            drop(guard);
            fixture.zone.unhome(slot, record, 3);
            (reference, address)
        };
        let (reference, address) = if registered {
            fixture
                .enter(
                    control,
                    fixture_ttbr0(fixture),
                    &mut sibling_service,
                    |_| park(),
                )
                .unwrap()
        } else {
            let record = fixture
                .zone
                .current_or_new(
                    slot,
                    ThreadIdentity {
                        tid: member.thread().key().tid.raw() as u64,
                        serial: member.thread().key().serial.raw(),
                        generation: 1,
                        lifecycle_page: page as *const _ as u64,
                        control_slot: control as *const _ as u64,
                        ..fixture.leader
                    },
                )
                .unwrap();
            control.bind_zone_record(fixture.zone.record_ref(record));
            park()
        };
        records.push((reference, address));
    }
    run_as_leader(fixture);
    assert_eq!(page.live(), 3);
    let scheduler = Arc::new(Scheduler::new(kernel.clone()));
    let executor = scheduler
        .register_executor(Arc::new(Kick::default()))
        .unwrap();
    let waits = CarrierWaitService::new(scheduler.clone());
    // Publish the actual zone waits while no global carrier aperture is bound:
    // enrollment must not confuse an in-zone OnCpu member with host readiness.
    for (member, (record, _)) in members.iter().zip(&records) {
        let generation = publish(member, 0x700);
        let capture = ContinuationCapture::new(
            member,
            generation,
            carrick_kernel::dispatch::SyscallRequest::new(
                98,
                carrick_kernel::compat::SyscallArgs([0; 6]),
            ),
            RestartClass::Never,
        )
        .unwrap();
        let continuation =
            BlockedContinuation::from_zone_park(capture, ZoneWait::new(*record, 0), None);
        scheduler.make_runnable(member.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        let mut registration = waits.prepare_registration(&continuation);
        scheduler.begin_switch_out(&running).unwrap();
        waits.enroll(&mut registration).unwrap();
        assert!(
            !waits
                .registration_timing(registration.wake_token())
                .unwrap()
                .has_periodic_probe()
        );
        scheduler
            .settle_blocked_continuation(running, continuation, registration)
            .unwrap();
    }
    // The first sibling was parked in EL1, then another guest thread woke it
    // and switched it in. Its host logical job still owns its zone wait.
    let (record, address) = records[0];
    let guard = fixture.zone.short_lock(
        ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(1, address),
        &ShortLockSpin,
    );
    fixture
        .zone
        .wake_placed(
            &guard,
            1,
            address,
            u32::MAX,
            1,
            Waker::El1 { slot },
            &mut [],
            &mut carrick_sched_core::WakeEffects::default(),
        )
        .unwrap();
    drop(guard);
    assert_eq!(fixture.zone.switch_in_full(slot).unwrap().record, record.id);
    assert!(matches!(
        fixture.zone.record(record.id).claim(),
        Claim::OnCpu { .. }
    ));
    // The third live thread closes the process on a different CPU.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 42;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(page.live(), 2);
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    assert!(members.iter().all(|member| {
        let control = member.thread().control_slot();
        control.host_exit_requested()
            || control
                .host_birth_identity()
                .is_some_and(|birth| page.host_birth_requested(birth))
    }));

    struct ClearAperture;
    impl Drop for ClearAperture {
        fn drop(&mut self) {
            carrick_el1_abi::record_el1_region_host_ptr(0);
        }
    }
    carrick_el1_abi::record_el1_region_host_ptr(fixture.region.ptr.as_ptr() as usize);
    let _clear = ClearAperture;
    fixture.zone.leave_guest(fixture.slot, &ShortLockSpin);
    fixture.zone.leave_guest(slot, &ShortLockSpin);
    // The production host adapter issues this one control wake per member.
    // The OnCpu target defers to its slot; the other target can run now.
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        for member in members {
            scheduler.wake_control(member.thread().key()).unwrap();
        }
    });
    if !registered {
        let member = members[0];
        run_as(
            fixture,
            member.thread().key().tid.raw(),
            1,
            member.thread().key().serial.raw(),
            member.thread().control_slot(),
        );
        let mut sibling_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        assert_eq!(
            crate::aarch64_process::resume_production_with_service(
                fixture.zone,
                &fixture.task,
                slot,
                record.id,
                &mut sibling_service,
            ),
            crate::sched::ResumeAction::Left
        );
        // The host-work boundary is the next producer opportunity. The wait
        // was enrolled before cancellation, so its initial probe cannot see
        // this retirement. No later guest event is required to finish exit.
        let doorbell = fixture.task.linux.take_host_work_doorbell();
        carrick_kernel::el1_delegation::settle_host_work_boundary(&kernel, false, doorbell);
        assert!(
            matches!(
                members[0].thread().execution_state(),
                carrick_kernel::kernel::objects::ThreadExecutionState::Runnable { .. }
            ),
            "retired native record must wake its enrolled host continuation; record={:?}",
            fixture.zone.live(record).map(|r| r.claim())
        );
    }
    if registered {
        let (tx, rx) = mpsc::channel();
        // The stopped executor's normal reconciliation. Old Cancelled intent
        // retires this plain futex record and emits no handback at all.
        if fixture.zone.handback_current(slot, record.id) == CurrentHandback::HandedBack {
            scheduler.publish_zone_handback(record);
            tx.send(()).unwrap();
        }
        let handback = rx.recv_timeout(Duration::from_millis(100));
        assert!(
            handback.is_ok(),
            "exit_group lost the deferred control handback: live={} sibling={:?} record={:?}",
            page.live(),
            members[0].thread().execution_state(),
            fixture.zone.live(record).map(|r| r.claim())
        );
        assert_eq!(fixture.zone.record(record.id).entry_count(), 0);
        assert!(!fixture.zone.record(record.id).is_cancelled());
        assert_ne!(
            fixture.zone.record(record.id).handback(),
            Some(Handback::Cancelled)
        );
    }
    assert!(members.iter().all(|member| matches!(
        member.thread().execution_state(),
        carrick_kernel::kernel::objects::ThreadExecutionState::Runnable { .. }
    )));
    run_as_leader(fixture);
    // Consume each real host job and withdraw its actual Kernel thread before
    // publishing the exact retirement receipt, as the runtime exit path does.
    let mut service_records = Vec::new();
    for slot in [fixture.slot, slot] {
        while let Some(ready) = fixture.zone.take_service_head(slot) {
            service_records.push(ready);
            assert!(service_records.len() <= members.len());
        }
    }
    let mut remaining: std::collections::BTreeMap<_, _> = members
        .iter()
        .map(|member| (member.thread().key(), *member))
        .collect();
    if !registered {
        // The closing owner's executor is now idle in the guest, so its
        // native continuation has a live home when host receipts arrive.
        fixture.zone.enter_guest(fixture.slot);
    }
    let mut exit_wakes = 0;
    for _ in members {
        let running = if let Some(ready) = service_records.pop() {
            let member = remaining
                .values()
                .find(|member| {
                    fixture.zone.record(ready.id).identity().tid
                        == member.thread().key().tid.raw() as u64
                })
                .expect("exact woken service member");
            let running = scheduler
                .take_zone(
                    &executor,
                    member.thread().key(),
                    member.thread().execution_state().generation().unwrap(),
                )
                .unwrap()
                .expect("woken service member");
            fixture.zone.free_record(ready.id);
            running
        } else {
            scheduler
                .try_take(&executor)
                .unwrap()
                .expect("woken host member")
        };
        // Affinity placement can change ready-job order. Retire each exact
        // participant once, using the job actually owned by this executor.
        let member = remaining
            .remove(&running.thread().key())
            .expect("each exact member is dequeued once");
        assert_eq!(running.thread().key(), member.thread().key());
        kernel.exit_thread(member, None).unwrap();
        let birth =
            carrick_kernel::kernel::host_birth_identity(member.task().key(), member.thread().key())
                .unwrap();
        page.publish_exact_host_retirement(member.thread().control_slot(), birth.retirement());
        if !registered {
            let (mm, address) = page.exit_wait().unwrap();
            carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                exit_wakes += carrick_kernel::el1_zone::wake_exit_wait_channel(
                    mm,
                    NonZeroU64::new(address).unwrap(),
                )
                .unwrap();
            });
        }
        scheduler.settle_exited(running).unwrap();
    }
    assert!(remaining.is_empty());
    assert!(service_records.is_empty());
    assert_eq!(page.live(), 0);
    assert!(members.iter().all(|member| !member.exact_thread_is_live()));
    if registered {
        fixture.zone.enter_guest(fixture.slot);
    } else {
        assert_eq!(
            exit_wakes, 1,
            "host retirement wakes the closing owner once"
        );
    }
    assert!(matches!(
        if registered {
            wake_closing_root(fixture, &mut service)
        } else {
            resume_closing_root(fixture, &mut service)
        },
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        service.crossing.root_exit_status.load(Ordering::Acquire),
        42
    );
    scheduler.close();
}

#[test]
fn serial_host_adopted_fault_checkpoint_transfers_terminal_custody() {
    use crate::native_process_runtime::NativeResume;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_guest_arch::{Access, FaultInfo};
    use carrick_sched_core::object_wait::{ObjectWaitKey, ResumeDisposition};

    let (kernel, root) = bootstrap(41);
    let root = Box::leak(Box::new(root));
    root.thread().set_affinity(carrick_hal::CpuAffinity::all(2));
    let page = Box::leak(Box::new(root.lifecycle_page()));
    let page = &**page;
    let fixture = Box::leak(Box::new(Fixture::with_identity(
        0x10000,
        asid(1),
        page,
        root.thread().control_slot(),
        ThreadIdentity {
            tid: root.thread().key().tid.raw() as u64,
            serial: root.thread().key().serial.raw(),
            mm: root.shared().mm().id().raw(),
            file_table: root.resources().files().id().raw(),
            generation: root.task().key().serial.raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 3,
            lifecycle_page: page as *const _ as u64,
            control_slot: root.thread().control_slot() as *const _ as u64,
        },
    )));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let mut root_service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut root_service,
            |_| (),
        )
        .unwrap();
    let sibling = clone_thread(root, 42);
    let control = sibling.thread().control_slot();
    assert!(control.publish_visible_tid(42));
    assert!(
        control.entry().is_none(),
        "adopted host member, not a pool birth"
    );
    let scheduler = Arc::new(Scheduler::new(kernel.clone()));
    let executor = scheduler
        .register_executor(Arc::new(Kick::default()))
        .unwrap();
    publish(sibling, 0x700);
    scheduler.make_runnable(sibling.thread().key()).unwrap();
    let running = scheduler.try_take(&executor).unwrap().unwrap();
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture
        .zone
        .publish_slot(slot, fixture.leader.mm, Some(1), 3);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    run_as(
        fixture,
        42,
        root.task().key().serial.raw(),
        sibling.thread().key().serial.raw(),
        control,
    );
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x401234;
    with_process_entry(
        BornInZoneSource {
            zone: fixture.zone,
            slot,
        },
        &fixture.task,
        &native,
        fixture_ttbr0(fixture),
        page,
        control,
        &mut service,
        |entry| {
            assert!(matches!(
                entry.begin_service(
                    ServiceOperation::Fault(FaultInfo {
                        address: UserVa::new(0x4000),
                        access: Access::Read,
                        present: false,
                    }),
                    None
                ),
                Ok(NativeResume::Left(None))
            ));
            assert!(entry.take_handoff_receipt().is_some());
        },
    )
    .unwrap();
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let record = notice.record;
    let key = ObjectWaitKey::native_service(record).unwrap();
    // SAFETY: the fixture retains this control and exact record through ticket
    // completion and the host retirement below.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(record.id).identity(),
        )
    }
    .unwrap();
    let owner = registry().for_record(fixture.zone, record).unwrap();
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        scheduler.settle_runnable(running).unwrap();
        scheduler.wake_control(sibling.thread().key()).unwrap();
    });
    assert!(scheduler.try_take(&executor).unwrap().is_none());
    assert_eq!(
        fixture.zone.record(record.id).resume_disposition(),
        ResumeDisposition::OwnerContinuation(
            carrick_sched_core::object_wait::OwnerEntry::Exception
        )
    );
    // The host executor's real park boundary releases home and MM custody.
    fixture.zone.unhome(slot, record.id, 3);
    let mut cpu = crate::sched::FakeCpu::default();
    crate::dispatch::native_service_idle(fixture.zone, slot, &mut cpu);
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut root_service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        scheduler.wake_control(sibling.thread().key()).unwrap();
    });
    assert!(
        scheduler.try_take(&executor).unwrap().is_none(),
        "no exception-owner host load"
    );
    ticket
        .complete(true)
        .unwrap_or_else(|_| panic!("cancelled ticket ACK"));
    fixture
        .zone
        .object_wait(key, &ShortLockSpin)
        .unwrap()
        .notify_object(slot, &mut Default::default())
        .unwrap();
    let selected = fixture
        .zone
        .switch_in_full(slot)
        .or_else(|| fixture.zone.steal(slot));
    assert_eq!(
        selected.map(|selected| selected.record),
        Some(record.id),
        "fault ACK must retain a native checkpoint: claim={:?} queues={:?}",
        fixture.zone.record(record.id).claim(),
        [
            fixture.zone.slot(fixture.slot).queued(),
            fixture.zone.slot(slot).queued()
        ]
    );
    fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    run_as(
        fixture,
        42,
        root.task().key().serial.raw(),
        sibling.thread().key().serial.raw(),
        control,
    );
    let resumed = resume_selected(
        &owner,
        registry(),
        BornInZoneSource {
            zone: fixture.zone,
            slot,
        },
        &fixture.task,
        record.id,
        &mut service,
    );
    assert_eq!(
        map_resume(resumed, &mut service, &fixture.task, slot),
        crate::sched::ResumeAction::Left,
        "adopted fault terminal checkpoint must transfer host custody without EL0 return",
    );
    assert!(control.host_exit_requested());
    assert_eq!(
        fixture.zone.record(record.id).resume_disposition(),
        ResumeDisposition::UserReturn
    );
    assert!(
        fixture.zone.head_needs_host(slot),
        "terminal host job must remain deliverable"
    );
    let ready = fixture
        .zone
        .take_service_head(slot)
        .expect("exact terminal host handback");
    assert_eq!(ready, record);
    let terminal = carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        scheduler.adopt_zone_handback(&executor, ready)
    })
    .unwrap()
    .expect("terminal host row");
    assert_eq!(terminal.thread().key(), sibling.thread().key());
    kernel.exit_thread(sibling, None).unwrap();
    let birth =
        carrick_kernel::kernel::host_birth_identity(sibling.task().key(), sibling.thread().key())
            .unwrap();
    page.publish_exact_host_retirement(control, birth.retirement());
    scheduler.settle_exited(terminal).unwrap();
    fixture.zone.free_record(record.id);
    fixture.zone.enter_guest(fixture.slot);
    assert!(matches!(
        resume_closing_root(fixture, &mut root_service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(
        root_service
            .crossing
            .root_exit_status
            .load(Ordering::Acquire),
        7
    );
    scheduler.close();
}
