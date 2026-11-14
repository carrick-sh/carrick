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
    deferred_control_handback(true, false);
}

#[test]
fn serial_host_arm_exit_group_unregistered_sibling_wakes_parked_host() {
    deferred_control_handback(false, false);
}

#[test]
fn serial_host_arm_group_close_checkpoints_running_and_parked_siblings() {
    deferred_control_handback(true, true);
}

/// An unregistered host-born sibling switched in at EL0 has no ring owner to
/// register with after the gate closes. Its user return stays on the host
/// route: the host's control kick forwards it and its record is handed back.
#[test]
fn serial_host_arm_group_close_running_unregistered_sibling_leaves_through_host() {
    deferred_control_handback(false, true);
}

fn deferred_control_handback(registered: bool, checkpoint: bool) {
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
    fixture.zone.wake_placed(
        &guard,
        1,
        address,
        u32::MAX,
        1,
        Waker::El1 { slot },
        &mut [],
        &mut carrick_sched_core::WakeEffects::default(),
    );
    drop(guard);
    assert_eq!(fixture.zone.switch_in_full(slot).unwrap().record, record.id);
    assert!(matches!(
        fixture.zone.record(record.id).claim(),
        Claim::OnCpu { .. }
    ));
    // The third live thread closes the process on a different CPU.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let status = if checkpoint { 5 } else { 42 };
    frame.x[0] = status;
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

    if checkpoint {
        let member = members[0];
        let control = member.thread().control_slot();
        run_as(
            fixture,
            member.thread().key().tid.raw(),
            root.task().key().serial.raw(),
            member.thread().key().serial.raw(),
            control,
        );
        let gate = crate::dispatch::arm_signal_return_gate(
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            &fixture.task,
            page,
            control,
            0,
            0,
            true,
        );
        let mut sibling_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        let mut return_frame = carrick_el1_abi::TrapFrame::default();
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let action = crate::dispatch::arm_signal_user_return_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            page,
            control,
            (0, 0),
            true,
            &mut sibling_service,
            |process| {
                crate::signal_delivery::deliver_signal_on_syscall_return(
                    &fixture.task,
                    control,
                    process,
                    &mut return_frame,
                    zerocopy::IntoBytes::as_bytes(&fp),
                    &mut ArmWaitSignalMachine {
                        user_sp: UserVa::new(0),
                        backend: ArmWaitSignalBackend,
                    },
                )
            },
        )
        .unwrap_or_else(|error| panic!("closing member user return refused: {error:?}"));
        assert_eq!(
            gate,
            registered.then_some(true),
            "only a registered switched-in member enters the ring terminal checkpoint"
        );
        if registered {
            assert_eq!(action, carrick_el1_abi::Action::Idle);
        } else {
            assert_eq!(action, carrick_el1_abi::Action::Served);
            assert_eq!(fixture.zone.slot(slot).current(), Some(record.id));
        }
        run_as_leader(fixture);
    }

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
    if !registered && checkpoint {
        // The control wake found its target held by EL1 and kicked the slot.
        // The kick IRQ at EL0 forwards (the closed gate's Host venue), and
        // the vCPU loop hands the switched-in record back to its host owner.
        let member = members[0];
        run_as(
            fixture,
            member.thread().key().tid.raw(),
            1,
            member.thread().key().serial.raw(),
            member.thread().control_slot(),
        );
        let mut cpu = crate::sched::FakeCpu::default();
        cpu.pending.push_back(carrick_el1_abi::GIC_KICK_INTID);
        let counters = carrick_el1_abi::Counters::new();
        let mut irq = carrick_el1_abi::TrapFrame {
            elr: 0x401000,
            slot: u64::from(slot.raw()),
            ..Default::default()
        };
        assert_eq!(
            (crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot,
                task: &fixture.task,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            })
            .interrupt(&mut irq, 0),
            carrick_el1_abi::Action::Forward
        );
        assert_eq!(
            fixture.zone.handback_current(slot, record.id),
            CurrentHandback::HandedBack
        );
        carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
            scheduler.publish_zone_handback(record);
        });
        run_as_leader(fixture);
    } else if !registered {
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
    if registered && !checkpoint {
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
        status
    );
    scheduler.close();
}

/// A registered host-cloned sibling computing on its own executor has no
/// switched zone record: its home record is free and host-loaded. Returning
/// to user after the leader's `exit_group(5)`, it must not claim that free
/// record for the ring. It returns, the host's control kick forwards it at
/// the next IRQ, and the host retires the exact thread.
#[test]
fn serial_host_arm_group_close_entryless_host_loaded_member_leaves_through_host() {
    entryless_host_loaded_member_leaves_through_host(0, false);
}

/// The member enters `FUTEX_WAIT_PRIVATE` after the close's one-shot member
/// interrupt scan. Its park record is fresh: the native registry has never
/// seen it, and no close interrupt will target it. The bucket-held probe
/// must still see the member's published terminal request and refuse the
/// park with `-EINTR`, so the close wake is never parked away.
#[test]
fn serial_host_arm_futex_wait_after_group_close_scan_returns_eintr() {
    entryless_host_loaded_member_leaves_through_host(0, true);
}

/// The host's owner-cancel checkpoint (`esr` 0xfffc) still admits a native
/// signal owner after the gate closes. Its terminal resume reports host
/// custody, which for a member with no switched record is its executor's
/// own: it returns to user rather than yielding a free record.
#[test]
fn serial_host_arm_owner_cancel_entryless_member_keeps_host_custody() {
    entryless_host_loaded_member_leaves_through_host(0xfffc, false);
}

fn entryless_host_loaded_member_leaves_through_host(esr: u64, futex_wait: bool) {
    use crate::sched::LinuxSchedEntry as _;
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
    let mut root_service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut root_service,
            |_| (),
        )
        .unwrap();
    let member = clone_thread(root, 42);
    let control = member.thread().control_slot();
    assert!(control.publish_visible_tid(member.thread().key().tid.raw() as u32));
    assert_eq!(control.entry(), None, "host clone control");
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture
        .zone
        .publish_slot(slot, fixture.leader.mm, Some(1), 3);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    let as_member = || {
        run_as(
            fixture,
            member.thread().key().tid.raw(),
            root.task().key().serial.raw(),
            member.thread().key().serial.raw(),
            control,
        )
    };
    as_member();
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    // Its first native entry admits it as a signal owner; it keeps running
    // host-loaded with no zone record switched in on its slot.
    fixture
        .enter(control, fixture_ttbr0(fixture), &mut service, |_| ())
        .unwrap();
    assert!(control.native_signal_owner());
    assert_eq!(fixture.zone.slot(slot).current(), None);
    let scheduler = Arc::new(Scheduler::new(kernel.clone()));
    let executor = scheduler
        .register_executor(Arc::new(Kick::default()))
        .unwrap();
    publish(member, 0x700);
    scheduler.make_runnable(member.thread().key()).unwrap();
    let running = scheduler.try_take(&executor).unwrap().unwrap();

    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 5;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut root_service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert!(control.host_exit_requested());
    assert_eq!(fixture.zone.slot(slot).current(), None);

    as_member();
    let (mut esr, mut x0) = (esr, 0);
    if futex_wait {
        let word = carrick_test_support::GuestUserBuffer::from_value(0u32);
        let mut wait = carrick_el1_abi::TrapFrame {
            esr: 0x5600_0000,
            elr: 0x401004,
            slot: u64::from(slot.raw()),
            ..Default::default()
        };
        wait.x[8] = crate::sched::SYS_FUTEX as u64;
        wait.x[0] = word.arg();
        wait.x[1] = crate::sched::FUTEX_WAIT_PRIVATE;
        let parks = fixture.zone.counters.el1_parks.load(Ordering::Relaxed);
        let counters = carrick_el1_abi::Counters::new();
        let mut cpu = crate::sched::FakeCpu::default();
        let served = (crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .serve_futex(&mut wait);
        assert_eq!(
            served,
            Some(crate::sched::Served::Returned { switched: false }),
            "a published group close must refuse the futex park"
        );
        assert_eq!(
            wait.x[0],
            carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
        );
        assert_eq!(
            fixture.zone.counters.el1_parks.load(Ordering::Relaxed),
            parks
        );
        assert_eq!(fixture.zone.slot(slot).current(), None);
        (esr, x0) = (wait.esr, wait.x[0]);
    }
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot,
    };
    let gate = crate::dispatch::arm_signal_return_gate(
        source,
        &fixture.task,
        page,
        control,
        esr,
        x0,
        true,
    );
    let mut return_frame = carrick_el1_abi::TrapFrame::default();
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let action = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        page,
        control,
        (esr, x0),
        true,
        &mut service,
        |process| {
            crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                control,
                process,
                &mut return_frame,
                zerocopy::IntoBytes::as_bytes(&fp),
                &mut ArmWaitSignalMachine {
                    user_sp: UserVa::new(0),
                    backend: ArmWaitSignalBackend,
                },
            )
        },
    )
    .unwrap_or_else(|error| panic!("closing member user return refused: {error:?}"));
    assert_eq!(
        gate,
        (esr == 0xfffc).then_some(true),
        "only the owner-cancel checkpoint admits a member with no switched record"
    );
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(fixture.zone.slot(slot).current(), None);

    // The host wake batch kicks the executor running this exact thread. Its
    // control quantum survives until that executor next settles it.
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        scheduler.wake_control(member.thread().key()).unwrap();
    });
    let mut cpu = crate::sched::FakeCpu::default();
    cpu.pending.push_back(carrick_el1_abi::GIC_KICK_INTID);
    let counters = carrick_el1_abi::Counters::new();
    let mut irq = carrick_el1_abi::TrapFrame {
        elr: 0x401000,
        slot: u64::from(slot.raw()),
        ..Default::default()
    };
    assert_eq!(
        (crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .interrupt(&mut irq, 0),
        carrick_el1_abi::Action::Forward,
        "the kick leaves through the host with the member loaded"
    );
    // The executor retires the exact thread on the host and publishes its
    // receipt, as the runtime's exit path does.
    fixture.zone.leave_guest(slot, &ShortLockSpin);
    kernel.exit_thread(member, None).unwrap();
    let birth =
        carrick_kernel::kernel::host_birth_identity(member.task().key(), member.thread().key())
            .unwrap();
    page.publish_exact_host_retirement(control, birth.retirement());
    scheduler.settle_exited(running).unwrap();
    assert!(!member.exact_thread_is_live());
    assert_eq!(carrick_el1_abi::Lifecycle::live(page), 0);
    assert!(matches!(
        wake_closing_root(fixture, &mut root_service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(root_service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        root_service
            .crossing
            .root_exit_status
            .load(Ordering::Acquire),
        5
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
        .object_wait(key, &ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
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
