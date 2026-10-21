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
    for _ in members {
        let running = scheduler
            .try_take(&executor)
            .unwrap()
            .expect("woken member");
        let member = members
            .iter()
            .find(|member| member.thread().key() == running.thread().key())
            .unwrap();
        kernel.exit_thread(member, None).unwrap();
        let birth =
            carrick_kernel::kernel::host_birth_identity(member.task().key(), member.thread().key())
                .unwrap();
        page.publish_exact_host_retirement(member.thread().control_slot(), birth.retirement());
        scheduler.settle_exited(running).unwrap();
    }
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
