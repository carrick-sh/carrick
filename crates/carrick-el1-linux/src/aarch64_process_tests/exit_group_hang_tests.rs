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

// The replacement image's execution lane binds its own birth factory. Use
// genuine kernel pool capacity and settle an ABI Born publication, so rebind
// imports a real second live thread rather than a fabricated census unit.
fn birth_after_host_exec(root: &KernelContext) -> &'static KernelContext {
    use carrick_el1_abi::{BlockedMask, BornRecord, Lifecycle};
    use carrick_kernel::kernel::thread_adoption::{
        ThreadBirthAdoptionFactory, ThreadBirthAdoptionReservation,
    };
    use carrick_kernel::kernel::{TaskKey, ThreadKey};
    #[derive(Debug)]
    struct Factory(TaskKey);
    impl ThreadBirthAdoptionFactory for Factory {
        fn executable_births(&self) -> bool {
            true
        }
        fn owner(&self) -> TaskKey {
            self.0
        }
        fn reserve(&self, thread: ThreadKey) -> Option<ThreadBirthAdoptionReservation> {
            Some(ThreadBirthAdoptionReservation::new(self.0, thread, ()))
        }
    }
    let kernel = root.kernel();
    root.task()
        .install_thread_adoption_factory(Arc::new(Factory(root.task().key())))
        .unwrap();
    kernel.prepare_executable_thread_births(root);
    let priming = clone_thread(root, 44);
    let (entry, control) = root
        .thread()
        .control_lease()
        .birth_controls()
        .into_iter()
        .next()
        .unwrap();
    let page = root.lifecycle_page();
    let identity = page.identity(entry).unwrap();
    page.bind_control_address(entry, core::ptr::from_ref(&*control) as u64)
        .unwrap();
    let claim = page.claim(entry).unwrap();
    control.reset_for_birth(BlockedMask(0), 0, entry).unwrap();
    page.thread_born().unwrap();
    page.record_born(
        claim,
        BornRecord {
            caller_task: root.thread().key().tid.raw() as u64,
            caller_serial: root.thread().key().serial.raw(),
            clone_flags: (carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM
                | carrick_abi::LinuxCloneFlags::FILES
                | carrick_abi::LinuxCloneFlags::FS)
                .bits(),
            clear_child_tid: 0,
            blocked: BlockedMask(0),
        },
    )
    .unwrap();
    let sibling = kernel
        .context(
            root.task().key().id,
            carrick_kernel::kernel::LinuxTid::from_abi_positive(identity.tid as i32).unwrap(),
        )
        .unwrap();
    let priming = kernel
        .context(priming.task().key().id, priming.thread().key().tid)
        .unwrap();
    kernel.exit_thread(&priming, None).unwrap();
    assert_eq!(page.live(), 2);
    assert_eq!(
        page.state(entry.index()),
        Some((entry.generation(), carrick_el1_abi::EntryState::Published))
    );
    assert_eq!(sibling.thread().control_slot().entry(), Some(entry));
    Box::leak(Box::new(
        kernel
            .context(sibling.task().key().id, sibling.thread().key().tid)
            .unwrap(),
    ))
}

fn admit_exec_caller(fixture: &'static Fixture, caller: &'static KernelContext) {
    let control = caller.thread().control_slot();
    assert!(control.publish_visible_tid(caller.thread().key().tid.raw() as u32));
    run_as(
        fixture,
        caller.thread().key().tid.raw(),
        caller.task().key().serial.raw(),
        caller.thread().key().serial.raw(),
        control,
    );
    let mut service = fixture.process_service();
    fixture
        .enter(control, fixture_ttbr0(fixture), &mut service, |_| ())
        .unwrap();
}

#[test]
fn serial_host_arm_exit_group_preserves_deferred_control_handback() {
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
        let (reference, address) = fixture
            .enter(
                control,
                fixture_ttbr0(fixture),
                &mut sibling_service,
                |_| {
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
                },
            )
            .unwrap();
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
    assert!(
        members
            .iter()
            .all(|member| member.thread().control_slot().host_exit_requested())
    );

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
    assert!(members.iter().all(|member| matches!(
        member.thread().execution_state(),
        carrick_kernel::kernel::objects::ThreadExecutionState::Runnable { .. }
    )));
    assert_eq!(fixture.zone.record(record.id).entry_count(), 0);
    assert!(!fixture.zone.record(record.id).is_cancelled());
    assert_ne!(
        fixture.zone.record(record.id).handback(),
        Some(Handback::Cancelled)
    );
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
        scheduler.settle_exited(running).unwrap();
    }
    assert!(remaining.is_empty());
    assert!(service_records.is_empty());
    assert_eq!(page.live(), 0);
    assert!(members.iter().all(|member| !member.exact_thread_is_live()));
    fixture.zone.enter_guest(fixture.slot);
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
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

#[test]
fn arm_host_exec_from_sibling_with_parked_threads_rebinds_root_entry() {
    use carrick_personality_linux::identity::ProcessIdentityVenue;

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

    // `AdmissionHome` discards the unpublished host home record when `enter` returns.
    let leader_pre_ref = fixture.control.zone_record().unwrap();
    assert_eq!(fixture.zone.record(leader_pre_ref.id).claim(), Claim::Free);

    // Clone two siblings in the real Kernel: `caller` (tid 42) and `parked_sibling` (tid 43).
    let caller = clone_thread(root, 42);
    let parked_sibling = clone_thread(root, 43);
    let slot_b = SlotId::new(1);
    fixture.zone.drive(slot_b, 2);
    fixture
        .zone
        .publish_slot(slot_b, fixture.leader.mm, Some(1), 3);
    fixture.zone.enter_guest(slot_b);
    fixture
        .zone
        .install_space(slot_b, fixture.leader.mm)
        .unwrap();

    // Admit `caller` (tid 42) on slot 1 and mutate its credentials and comm.
    let caller_control = caller.thread().control_slot();
    assert!(caller_control.publish_visible_tid(42));
    run_as(
        fixture,
        42,
        root.task().key().serial.raw(),
        caller.thread().key().serial.raw(),
        caller_control,
    );
    let mut caller_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        slot_b,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    with_process_entry(
        BornInZoneSource {
            zone: fixture.zone,
            slot: slot_b,
        },
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        fixture.page,
        caller_control,
        &mut caller_service,
        |entry| {
            entry
                .set_resgid(Some(2001), Some(2002), Some(2003))
                .unwrap();
            entry
                .set_resuid(Some(1001), Some(1002), Some(1003))
                .unwrap();
            entry.prctl_set_name(b"sib-exec-caller\0");
        },
    )
    .unwrap();
    let caller_ref = caller_control.zone_record().unwrap();
    assert_eq!(fixture.zone.record(caller_ref.id).claim(), Claim::Free);

    // Admit `parked_sibling` (tid 43) on slot 1 and park its zone record in EL1.
    let parked_control = parked_sibling.thread().control_slot();
    assert!(parked_control.publish_visible_tid(43));
    run_as(
        fixture,
        43,
        root.task().key().serial.raw(),
        parked_sibling.thread().key().serial.raw(),
        parked_control,
    );
    let parked_ref = fixture
        .enter(
            parked_control,
            fixture_ttbr0(fixture),
            &mut caller_service,
            |_| {
                let record = fixture.zone.slot(slot_b).host_record().unwrap();
                let reference = fixture.zone.record_ref(record);
                let address = 0x9000;
                let guard = fixture.zone.short_lock(
                    ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(
                        fixture.leader.mm,
                        address,
                    ),
                    &ShortLockSpin,
                );
                let seq = fixture.zone.next_seq(record);
                fixture
                    .zone
                    .enqueue(&guard, record, seq, fixture.leader.mm, address, u32::MAX, 0)
                    .unwrap();
                fixture.zone.publish_park(record, seq);
                drop(guard);
                fixture.zone.unhome(slot_b, record, 3);
                reference
            },
        )
        .unwrap();
    assert!(matches!(
        fixture.zone.record(parked_ref.id).claim(),
        Claim::Parked { .. }
    ));

    // Drive the real Kernel host-exec transition from sibling `caller` (tid 42).
    let caller = Box::leak(Box::new(
        kernel
            .context(caller.task().key().id, caller.thread().key().tid)
            .unwrap(),
    ));
    let prepared = kernel.prepare_exec(caller, None).unwrap();
    let committed = Box::leak(Box::new(kernel.commit_exec(prepared, None).unwrap()));
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(page),
        carrick_el1_abi::GateState::AwaitingExecBinding
    );
    assert_eq!(committed.thread().key().tid.raw(), 41);
    assert!(
        committed
            .thread()
            .control_slot()
            .host_exec_receipt()
            .is_some()
    );

    // Publish a real post-exec pool birth: two live kernel threads at rebind.
    let post_exec_sibling = birth_after_host_exec(committed);
    let post_tid = post_exec_sibling.thread().key().tid.raw() as u32;
    assert_eq!(carrick_el1_abi::Lifecycle::live(page), 2);
    let mm_after = committed.shared().mm().id().raw();
    let root_gpa_after = 0x20000;
    let ttbr0_after = (u64::from(asid(2).raw()) << 48) | root_gpa_after;
    let space_after = fixture
        .zone
        .spaces
        .publish_closed(mm_after, ttbr0_after, ttbr0_after)
        .unwrap();
    fixture.zone.spaces.open(space_after);
    let address_after = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(root_gpa_after)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::new(mm_after).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::new(102).unwrap()),
    };
    fixture.zone.mm_issuer().observe_existing(address_after.mm);
    fixture
        .zone
        .serial_issuer()
        .advance_past(NonZeroU64::new(committed.thread().key().serial.raw()).unwrap());
    fixture
        .zone
        .serial_issuer()
        .advance_past(NonZeroU64::new(post_exec_sibling.thread().key().serial.raw()).unwrap());

    // Give the published post-exec sibling a parked record in the new MM.
    let post_sib_control = post_exec_sibling.thread().control_slot();
    assert!(post_sib_control.publish_visible_tid(post_tid));
    post_sib_control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
    unsafe {
        post_sib_control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
            core::ptr::from_ref(post_sib_control).expose_provenance() as u64,
        ));
    }
    let post_sib_identity = ThreadIdentity {
        tid: u64::from(post_tid),
        serial: post_exec_sibling.thread().key().serial.raw(),
        mm: mm_after,
        file_table: committed.resources().files().id().raw(),
        generation: committed.task().key().serial.raw(),
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
        affinity: 3,
        lifecycle_page: page as *const _ as u64,
        control_slot: post_sib_control as *const _ as u64,
    };
    fixture.zone.drive(slot_b, mm_after);
    fixture.zone.publish_slot(slot_b, mm_after, Some(1), 3);
    fixture.zone.release_space(slot_b);
    fixture.zone.install_space(slot_b, mm_after).unwrap();
    let post_sib_rec = fixture
        .zone
        .current_or_new(slot_b, post_sib_identity)
        .unwrap();
    unsafe {
        *fixture.zone.record(post_sib_rec).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, address_after);
    }
    post_sib_control.bind_zone_record(fixture.zone.record_ref(post_sib_rec));
    {
        let guard = fixture.zone.short_lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm_after, 0x9100),
            &ShortLockSpin,
        );
        let seq = fixture.zone.next_seq(post_sib_rec);
        fixture
            .zone
            .enqueue(&guard, post_sib_rec, seq, mm_after, 0x9100, u32::MAX, 0)
            .unwrap();
        fixture.zone.publish_park(post_sib_rec, seq);
        drop(guard);
        fixture.zone.unhome(slot_b, post_sib_rec, 3);
    }

    // Bind replacement leader (tid 41) on slot 0 in `mm_after`.
    let replacement_control = committed.thread().control_slot();
    assert!(replacement_control.publish_visible_tid(41));
    replacement_control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
    unsafe {
        replacement_control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
            core::ptr::from_ref(replacement_control).expose_provenance() as u64,
        ));
    }
    fixture.zone.drive(fixture.slot, mm_after);
    fixture
        .zone
        .publish_slot(fixture.slot, mm_after, Some(0), 3);
    fixture.zone.release_space(fixture.slot);
    fixture.zone.install_space(fixture.slot, mm_after).unwrap();
    fixture.task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(committed.task().key().serial.raw()),
        committed.resources().files().id().raw(),
    );
    fixture.task.mm.key.store(mm_after, Ordering::Release);
    fixture
        .task
        .mm
        .thread_generation
        .store(committed.thread().key().serial.raw(), Ordering::Release);
    fixture.task.publish_visible_pid(41);
    fixture
        .task
        .publish_root_generation(address_after.generation);
    fixture.task.publish_lifecycle(
        page as *const _ as u64,
        replacement_control as *const _ as u64,
    );

    // First post-exec native process entry rebinds with two actual live threads.
    assert_eq!(committed.task().threads().len(), 2);
    assert_eq!(carrick_el1_abi::Lifecycle::live(page), 2);
    let (uids, gids, comm) = with_process_entry(
        BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        },
        &fixture.task,
        &ThreadCtx::ZERO,
        ttbr0_after,
        fixture.page,
        replacement_control,
        &mut service,
        |entry| {
            let mut comm = [0u8; 16];
            entry.prctl_get_name(&mut comm).unwrap();
            (entry.get_uids().unwrap(), entry.get_gids().unwrap(), comm)
        },
    )
    .expect("replacement leader must rebind root entry after sibling host exec");

    assert_eq!(
        replacement_control.host_exec_receipt(),
        None,
        "rebind_host_exec must consume the one-shot HostExecReceipt"
    );
    assert_eq!(
        uids,
        (1001, 1002, 1003, 1002),
        "rebound leader must inherit credentials from the exec caller sibling (tid 42)"
    );
    assert_eq!(
        gids,
        (2001, 2002, 2003, 2002),
        "rebound leader must inherit GIDs from the exec caller sibling (tid 42)"
    );
    assert_eq!(
        &comm, b"sib-exec-caller\0",
        "rebound leader must inherit comm from the exec caller sibling (tid 42)"
    );
    assert_eq!(
        fixture.zone.record(parked_ref.id).claim(),
        Claim::Free,
        "parked predecessor sibling zone record must be claimed for host and freed"
    );
    assert_ne!(
        fixture.zone.record(parked_ref.id).incarnation(),
        parked_ref.incarnation,
        "freed predecessor record incarnation must advance"
    );
    assert_eq!(
        fixture.zone.record(leader_pre_ref.id).claim(),
        Claim::Free,
        "already-freed pre-exec leader record must remain free"
    );
}

#[test]
fn arm_host_exec_rebind_parks_on_predecessor_on_cpu_once_then_succeeds() {
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

    // `AdmissionHome` discards the unpublished host home record when `enter` returns.
    let leader_pre_ref = fixture.control.zone_record().unwrap();
    assert_eq!(fixture.zone.record(leader_pre_ref.id).claim(), Claim::Free);

    // Clone sibling 42 (exec caller) and sibling 43 (still OnCpu on slot 1 when exec commits).
    let caller = clone_thread(root, 42);
    admit_exec_caller(fixture, caller);
    let on_cpu_sibling = clone_thread(root, 43);
    let slot_b = SlotId::new(1);
    fixture.zone.drive(slot_b, 2);
    fixture
        .zone
        .publish_slot(slot_b, fixture.leader.mm, Some(1), 3);
    fixture.zone.enter_guest(slot_b);
    fixture
        .zone
        .install_space(slot_b, fixture.leader.mm)
        .unwrap();

    let on_cpu_control = on_cpu_sibling.thread().control_slot();
    assert!(on_cpu_control.publish_visible_tid(43));
    run_as(
        fixture,
        43,
        root.task().key().serial.raw(),
        on_cpu_sibling.thread().key().serial.raw(),
        on_cpu_control,
    );
    let on_cpu_binding = crate::common_entry::execution_binding(&fixture.task);
    let mut sib_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        slot_b,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let pred_record = fixture
        .enter(
            on_cpu_control,
            fixture_ttbr0(fixture),
            &mut sib_service,
            |_| {
                let record = fixture.zone.slot(slot_b).host_record().unwrap();
                let address = 0x9200;
                let guard = fixture.zone.short_lock(
                    ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(
                        fixture.leader.mm,
                        address,
                    ),
                    &ShortLockSpin,
                );
                let seq = fixture.zone.next_seq(record);
                fixture
                    .zone
                    .enqueue(&guard, record, seq, fixture.leader.mm, address, u32::MAX, 0)
                    .unwrap();
                fixture.zone.publish_park(record, seq);
                drop(guard);
                fixture.zone.unhome(slot_b, record, 3);
                fixture.zone.record_ref(record)
            },
        )
        .unwrap();
    // Switch `pred_record` into `Claim::OnCpu` on `slot_b`.
    {
        let guard = fixture.zone.short_lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(fixture.leader.mm, 0x9200),
            &ShortLockSpin,
        );
        fixture
            .zone
            .wake_placed(
                &guard,
                fixture.leader.mm,
                0x9200,
                u32::MAX,
                1,
                Waker::El1 { slot: slot_b },
                &mut [],
                &mut carrick_sched_core::WakeEffects::default(),
            )
            .unwrap();
    }
    assert_eq!(
        fixture.zone.switch_in_full(slot_b).unwrap().record,
        pred_record.id
    );
    assert!(matches!(
        fixture.zone.record(pred_record.id).claim(),
        Claim::OnCpu { .. }
    ));

    // Commit real Kernel host exec from sibling 42 while sibling 43's record is still OnCpu on slot 1.
    let caller = Box::leak(Box::new(
        kernel
            .context(caller.task().key().id, caller.thread().key().tid)
            .unwrap(),
    ));
    let prepared = kernel.prepare_exec(caller, None).unwrap();
    let committed = Box::leak(Box::new(kernel.commit_exec(prepared, None).unwrap()));
    carrick_el1_abi::Lifecycle::reopen_after_exec_binding(page).unwrap();
    let mm_after = committed.shared().mm().id().raw();
    let root_gpa_after = 0x20000;
    let ttbr0_after = (u64::from(asid(2).raw()) << 48) | root_gpa_after;
    let space_after = fixture
        .zone
        .spaces
        .publish_closed(mm_after, ttbr0_after, ttbr0_after)
        .unwrap();
    fixture.zone.spaces.open(space_after);
    let address_after = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(root_gpa_after)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::new(mm_after).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::new(102).unwrap()),
    };
    fixture.zone.mm_issuer().observe_existing(address_after.mm);
    fixture
        .zone
        .serial_issuer()
        .advance_past(NonZeroU64::new(committed.thread().key().serial.raw()).unwrap());

    let replacement_control = committed.thread().control_slot();
    assert!(replacement_control.publish_visible_tid(41));
    replacement_control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
    unsafe {
        replacement_control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
            core::ptr::from_ref(replacement_control).expose_provenance() as u64,
        ));
    }
    fixture.zone.drive(fixture.slot, mm_after);
    fixture
        .zone
        .publish_slot(fixture.slot, mm_after, Some(0), 3);
    fixture.zone.release_space(fixture.slot);
    fixture.zone.install_space(fixture.slot, mm_after).unwrap();
    fixture.task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(committed.task().key().serial.raw()),
        committed.resources().files().id().raw(),
    );
    fixture.task.mm.key.store(mm_after, Ordering::Release);
    fixture
        .task
        .mm
        .thread_generation
        .store(committed.thread().key().serial.raw(), Ordering::Release);
    fixture.task.publish_visible_pid(41);
    fixture
        .task
        .publish_root_generation(address_after.generation);
    fixture.task.publish_lifecycle(
        page as *const _ as u64,
        replacement_control as *const _ as u64,
    );

    // 1. First attempt: `pred_record` is still OnCpu on `slot_b`, so replacement leader parks
    // on its own `native_service` queue, enrolled on predecessor release and returns `CompletionRoute::Suspended` (`Action::Idle`).
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: fixture.slot.index() as u64,
        elr: 0x4004,
        ..Default::default()
    };
    frame.x[8] = 172; // SYS_GETPID
    let mut native = ThreadCtx::ZERO;
    native.pc = frame.elr;
    native.x[8] = frame.x[8];
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
    let route = crate::dispatch::dispatch_arm_syscall_with_native_process(
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
        fixture.page,
        replacement_control,
        &native,
        ttbr0_after,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .expect("Busy predecessor OnCpu must park rather than fail");
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::Idle
    );
    assert!(
        replacement_control.host_exec_receipt().is_some(),
        "HostExecReceipt must remain intact while parked on busy predecessor"
    );
    let waiter_record = replacement_control.zone_record().expect("waiter record");
    assert!(matches!(
        fixture.zone.record(waiter_record.id).claim(),
        Claim::Parked { .. }
    ));

    // 2. Release `pred_record` from `slot_b` via `retire_current`: this triggers `on_record_released`
    // and wakes `waiter_record` onto `fixture.slot`!
    assert!(
        carrick_core::entry::retire_current(
            on_cpu_binding,
            BornInZoneSource {
                zone: fixture.zone,
                slot: slot_b,
            },
            pred_record.id,
        )
        .is_some()
    );
    assert!(
        matches!(
            fixture.zone.record(waiter_record.id).claim(),
            Claim::Queued { slot, .. } if slot == fixture.slot
        ),
        "releasing predecessor OnCpu record must wake and queue the parked rebind waiter"
    );

    // 3. Switch `waiter_record` back onto `fixture.slot` and re-execute the SVC ("then success").
    let switched = fixture
        .zone
        .switch_in_full(fixture.slot)
        .expect("switch in woken waiter");
    assert_eq!(switched.record, waiter_record.id);
    assert_eq!(switched.result, None, "resumed operation preserves x0");
    let resumed_ctx = unsafe { *fixture.zone.record(waiter_record.id).ctx_mut() };
    assert_eq!(
        resumed_ctx.native.pc, 0x4000,
        "parked rebind waiter must resume at elr - 4 to replay the SVC"
    );
    let route2 = crate::dispatch::dispatch_arm_syscall_with_native_process(
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
        fixture.page,
        replacement_control,
        &resumed_ctx.native,
        ttbr0_after,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .expect("resumed call after predecessor release must succeed");
    assert_eq!(
        route2,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    // GETPID retains the completed result for the existing host return-event
    // publisher (Pending::return_requires_host_boundary), even on success.
    assert_eq!(
        arm_route_action(fixture, route2, &mut frame),
        carrick_el1_abi::Action::ServedWithWork
    );
    assert_eq!(frame.x[0], 41);
    assert_eq!(replacement_control.host_exec_receipt(), None);
    assert_eq!(fixture.zone.record(pred_record.id).claim(), Claim::Free);
    assert!(!registry().host_exec_waiters().retains_source(
        fixture.zone,
        super::super::native_process_runtime::HostExecRebindWait::PredecessorOnCpu(pred_record)
    ));
}

#[test]
fn arm_host_exec_rebind_parks_on_pending_custody_once_then_succeeds() {
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

    // `AdmissionHome` discards the unpublished host home record when `enter` returns.
    let leader_pre_ref = fixture.control.zone_record().unwrap();
    assert_eq!(fixture.zone.record(leader_pre_ref.id).claim(), Claim::Free);

    // Commit real Kernel host exec from sibling 42.
    let caller = clone_thread(root, 42);
    admit_exec_caller(fixture, caller);
    let prepared = kernel.prepare_exec(caller, None).unwrap();
    let committed = Box::leak(Box::new(kernel.commit_exec(prepared, None).unwrap()));
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(page),
        carrick_el1_abi::GateState::AwaitingExecBinding
    );
    let post_exec_sibling = birth_after_host_exec(committed);
    let post_tid = post_exec_sibling.thread().key().tid.raw() as u32;

    let mm_after = committed.shared().mm().id().raw();
    let root_gpa_after = 0x20000;
    let ttbr0_after = (u64::from(asid(2).raw()) << 48) | root_gpa_after;
    let space_after = fixture
        .zone
        .spaces
        .publish_closed(mm_after, ttbr0_after, ttbr0_after)
        .unwrap();
    fixture.zone.spaces.open(space_after);
    let address_after = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(root_gpa_after)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::new(mm_after).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::new(102).unwrap()),
    };
    fixture.zone.mm_issuer().observe_existing(address_after.mm);
    fixture
        .zone
        .serial_issuer()
        .advance_past(NonZeroU64::new(committed.thread().key().serial.raw()).unwrap());
    fixture
        .zone
        .serial_issuer()
        .advance_past(NonZeroU64::new(post_exec_sibling.thread().key().serial.raw()).unwrap());

    let slot_b = SlotId::new(1);
    let post_sib_control = post_exec_sibling.thread().control_slot();
    assert!(post_sib_control.publish_visible_tid(post_tid));
    post_sib_control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
    unsafe {
        post_sib_control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
            core::ptr::from_ref(post_sib_control).expose_provenance() as u64,
        ));
    }
    let post_sib_identity = ThreadIdentity {
        tid: u64::from(post_tid),
        serial: post_exec_sibling.thread().key().serial.raw(),
        mm: mm_after,
        file_table: committed.resources().files().id().raw(),
        generation: committed.task().key().serial.raw(),
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
        affinity: 3,
        lifecycle_page: page as *const _ as u64,
        control_slot: post_sib_control as *const _ as u64,
    };
    fixture.zone.drive(slot_b, mm_after);
    fixture.zone.publish_slot(slot_b, mm_after, Some(1), 3);
    fixture.zone.enter_guest(slot_b);
    fixture.zone.install_space(slot_b, mm_after).unwrap();
    let post_sib_rec = fixture
        .zone
        .current_or_new(slot_b, post_sib_identity)
        .unwrap();
    unsafe {
        *fixture.zone.record(post_sib_rec).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, address_after);
    }
    post_sib_control.bind_zone_record(fixture.zone.record_ref(post_sib_rec));
    {
        let guard = fixture.zone.short_lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm_after, 0x9300),
            &ShortLockSpin,
        );
        let seq = fixture.zone.next_seq(post_sib_rec);
        fixture
            .zone
            .enqueue(&guard, post_sib_rec, seq, mm_after, 0x9300, u32::MAX, 0)
            .unwrap();
        fixture.zone.publish_park(post_sib_rec, seq);
        drop(guard);
        fixture.zone.unhome(slot_b, post_sib_rec, 3);
    }

    // Hold transient `NativePendingCustody` on `post_sib_control`.
    let retained_sib_control =
        carrick_core::lifecycle::MemberControlCustody::retain(post_sib_control)
            .map(Arc::new)
            .unwrap();
    let pending_custody =
        carrick_el1_abi::NativePendingCustody::try_admit(retained_sib_control).unwrap();
    assert!(post_sib_control.native_pending_busy());

    let replacement_control = committed.thread().control_slot();
    assert!(replacement_control.publish_visible_tid(41));
    replacement_control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
    unsafe {
        replacement_control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
            core::ptr::from_ref(replacement_control).expose_provenance() as u64,
        ));
    }
    fixture.zone.drive(fixture.slot, mm_after);
    fixture
        .zone
        .publish_slot(fixture.slot, mm_after, Some(0), 3);
    fixture.zone.release_space(fixture.slot);
    fixture.zone.install_space(fixture.slot, mm_after).unwrap();
    fixture.task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(committed.task().key().serial.raw()),
        committed.resources().files().id().raw(),
    );
    fixture.task.mm.key.store(mm_after, Ordering::Release);
    fixture
        .task
        .mm
        .thread_generation
        .store(committed.thread().key().serial.raw(), Ordering::Release);
    fixture.task.publish_visible_pid(41);
    fixture
        .task
        .publish_root_generation(address_after.generation);
    fixture.task.publish_lifecycle(
        page as *const _ as u64,
        replacement_control as *const _ as u64,
    );

    // 1. First attempt: `post_sib_control` holds `NativePendingCustody`, so replacement leader parks
    // on `ObjectWaitKey::native_service(post_sib_rec)` and returns `CompletionRoute::Suspended` (`Action::Idle`).
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: fixture.slot.index() as u64,
        elr: 0x4004,
        ..Default::default()
    };
    frame.x[8] = 172; // SYS_GETPID
    let mut native = ThreadCtx::ZERO;
    native.pc = frame.elr;
    native.x[8] = frame.x[8];
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
    let route = crate::dispatch::dispatch_arm_syscall_with_native_process(
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
        fixture.page,
        replacement_control,
        &native,
        ttbr0_after,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .expect("Busy NativePendingCustody must park rather than fail");
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::Idle
    );
    assert!(
        replacement_control.host_exec_receipt().is_some(),
        "HostExecReceipt must remain intact while parked on busy pending custody"
    );
    let waiter_record = replacement_control.zone_record().expect("waiter record");
    assert!(matches!(
        fixture.zone.record(waiter_record.id).claim(),
        Claim::Parked { .. }
    ));

    // 2. Drop `pending_custody`: this triggers `on_native_pending_released` and wakes `waiter_record`!
    drop(pending_custody);
    assert!(!post_sib_control.native_pending_busy());
    assert!(
        matches!(
            fixture.zone.record(waiter_record.id).claim(),
            Claim::Queued { slot, .. } if slot == fixture.slot
        ),
        "releasing NativePendingCustody must wake and queue the parked rebind waiter"
    );

    // 3. Switch `waiter_record` back onto `fixture.slot` and re-execute the SVC ("then success").
    let switched = fixture
        .zone
        .switch_in_full(fixture.slot)
        .expect("switch in woken waiter");
    assert_eq!(switched.record, waiter_record.id);
    assert_eq!(switched.result, None, "resumed operation preserves x0");
    let resumed_ctx = unsafe { *fixture.zone.record(waiter_record.id).ctx_mut() };
    assert_eq!(
        resumed_ctx.native.pc, 0x4000,
        "parked rebind waiter must resume at elr - 4 to replay the SVC"
    );
    let route2 = crate::dispatch::dispatch_arm_syscall_with_native_process(
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
        fixture.page,
        replacement_control,
        &resumed_ctx.native,
        ttbr0_after,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .expect("resumed call after pending custody release must succeed");
    assert_eq!(
        route2,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    // GETPID retains the completed result for the existing host return-event
    // publisher (Pending::return_requires_host_boundary), even on success.
    assert_eq!(
        arm_route_action(fixture, route2, &mut frame),
        carrick_el1_abi::Action::ServedWithWork
    );
    assert_eq!(frame.x[0], 41);
    assert_eq!(replacement_control.host_exec_receipt(), None);
    assert!(!registry().host_exec_waiters().retains_source(
        fixture.zone,
        super::super::native_process_runtime::HostExecRebindWait::PendingCustody {
            record: fixture.zone.record_ref(post_sib_rec),
            control: core::ptr::from_ref(post_sib_control).addr(),
        }
    ));
}

#[test]
fn arm_host_exec_rebind_release_before_enrollment_queues_one_retry() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x4004;
    let record = process_record_for_call(
        source,
        &fixture.task,
        &native,
        fixture_ttbr0(fixture),
        fixture.control,
    )
    .unwrap();
    let released = Box::leak(Box::new(ThreadControlSlot::new()));
    // A prior admission observed Busy, but its source released before this
    // turn enrolled. The one locked predicate probe must queue the owned SVC;
    // a new contender cannot force an inline retry into a fatal Busy refusal.
    let wait = super::super::native_process_runtime::HostExecRebindWait::PendingCustody {
        record: fixture.zone.record_ref(record),
        control: core::ptr::from_ref(released).addr(),
    };
    super::super::aarch64_process::park_host_exec_rebind_wait(source, &native, record, wait)
        .unwrap();
    assert!(
        matches!(fixture.zone.record(record).claim(), Claim::Queued { slot, .. } if slot == fixture.slot)
    );
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(!fixture.zone.record(record).has_object_operation());
    assert_eq!(
        unsafe { fixture.zone.record(record).ctx_mut() }.native.pc,
        0x4000
    );
    assert!(
        !registry()
            .host_exec_waiters()
            .retains_source(fixture.zone, wait)
    );
}
