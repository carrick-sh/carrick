use super::*;
use crate::native_process_runtime::host_test_support::{Physical, take_signal_copies};
use carrick_el1_abi::Lifecycle;
use carrick_personality_linux::signal::{
    ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
};
use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};

#[test]
fn arm_host_owned_sigprocmask_resume_delivers_before_host_handback() {
    host_owned_signal_resume(false, false, false);
}

#[test]
fn arm_host_owned_sigprocmask_resume_drains_real_carrier_work_before_signal() {
    host_owned_signal_resume(true, false, false);
}

#[test]
fn arm_host_owned_sigprocmask_resume_inline_carrier_ack_delivers_before_handback() {
    host_owned_signal_resume(true, true, false);
}

#[test]
fn arm_host_owned_signal_work_deferral_survives_concurrent_drain() {
    host_owned_signal_resume(false, false, true);
}

fn host_owned_signal_resume(pending_work: bool, inline_ack: bool, defer_race: bool) {
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let runtime = std::sync::Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            initial,
        )
        .unwrap(),
    );
    registry()
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let original = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap()
        .record
        .id;
    let identity = fixture.zone.record(original).identity();
    fixture.zone.discard_unpublished(fixture.slot, original);
    let host_record = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
    let host_reference = fixture.zone.record_ref(host_record);
    unsafe {
        *fixture.zone.record(host_record).ctx_mut() = initial;
    }
    fixture.control.bind_zone_record(host_reference);
    registry()
        .rehome_entry(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    assert!(!fixture.zone.record(host_record).is_native_owned());
    let owner_record = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap()
        .record
        .id;
    let member = fixture.zone.record_ref(owner_record);
    let (peer_control, peer) = imported_thread(fixture);
    let peer_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    assert_eq!(fixture.page.live(), 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, owner_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        peer.id
    );
    run_as(fixture, 42, 12, 102, peer_control);
    // SAFETY: switch_in_full gave this lane exclusive sibling custody.
    unsafe {
        let context = fixture.zone.record(peer.id).ctx_mut();
        context.native.pc = 0x500004;
        context.native.sp_el0 = peer_stack.va_at(peer_stack.len()).raw();
    }

    registry()
        .register_thread(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            peer_control,
        )
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, peer.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        owner_record
    );
    run_as_leader(fixture);
    let control = fixture.control;
    let peer_record = peer.id;
    let signal = Signal::PIPE;
    let mask_bits = carrick_signal_core::SignalSet::EMPTY.with(signal).bits();
    control.init_blocked(carrick_el1_abi::BlockedMask(mask_bits));
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut words = initial;
    words.native.pc = 0x400004;
    words.native.sp_el0 = stack.va_at(stack.len()).raw();
    let mut physical = Physical {
        zone: fixture.zone,
        page: fixture.page,
        controls: &[],
        copies: Vec::new(),
        tid_words: Default::default(),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: None,
        refuse_copy: false,
        on_signal_clock: None,
    };
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &words,
                &mut physical,
            )
            .unwrap();
        entry
            .rt_sigaction(
                signal,
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x700000)),
                    ..Default::default()
                }),
            )
            .unwrap();
        entry
            .tgkill(
                SignalThreadSelector::from_abi(41),
                SignalThreadSelector::from_abi(41),
                SignalRequest::from_abi(13).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    let handle = crate::cow_resolver::admitted_fault_mm_handle(
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        fixture.slot,
        &fixture.task,
    )
    .unwrap();
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    let index = access.find(handle.mm().raw()).unwrap();
    let notifications = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap()
        .notifications(handle.incarnation())
        .unwrap();
    let observed =
        notifications.observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
    let editor = access
        .try_begin_edit_bounded(index, handle.mm().raw(), NonZeroU64::new(91).unwrap(), 0)
        .unwrap();
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Editor,
            observed.revision(),
        )
    };
    let mask = carrick_test_support::GuestUserBuffer::from_value(mask_bits);
    let oldset = carrick_test_support::GuestUserBuffer::from_value(0xdead_beef_u64);
    physical.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    physical.child_copy_error_at = Some(oldset.arg());
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x54000000,
        elr: words.native.pc,
        ..Default::default()
    };
    frame.x[..4].copy_from_slice(&[1, mask.arg(), oldset.arg(), 8]);
    frame.x[8] = 135;
    words.native.x = frame.x;
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &words,
                &mut physical,
            )
            .unwrap();
        crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
        let route = crate::dispatch::dispatch_syscall_with_native(
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
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Served
        );
        crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    }
    assert_eq!(
        control.blocked().0 & mask_bits,
        0,
        "unblock commits before oldset output parks"
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(peer_record));
    assert_eq!(fixture.task.execution.task.load(Ordering::Acquire), 42);
    assert!(
        take_signal_copies().is_empty(),
        "parked oldset has not been written"
    );
    drop(editor);
    physical.child_copy_error = None;
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, peer_record)
            .is_queued()
    );
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    if pending_work {
        fixture.task.linux.mark_pending_host_work();
    }
    if inline_ack {
        crate::native_process_runtime::host_test_support::set_service_published_hook(
            runtime.as_ref() as *const _ as usize,
            Box::new(move || {
                let notice = fixture.task.service_notice.take().unwrap().unwrap();
                let queue = fixture
                    .zone
                    .object_wait(
                        carrick_sched_core::object_wait::ObjectWaitKey::native_service(member)
                            .unwrap(),
                        &carrick_sched_core::ShortLockSpin,
                    )
                    .unwrap();
                // SAFETY: the real publication hook claims this exact member
                // under its production intake queue, then acknowledges work.
                let ticket = unsafe {
                    carrick_core_abi::service::ServiceCell::claim_notice(
                        &control.service,
                        notice,
                        NonZeroU64::MIN,
                        fixture.zone.record(member.id).identity(),
                    )
                }
                .unwrap();
                assert!(matches!(
                    ticket.request().operation,
                    carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
                ));
                drop(queue);
                fixture
                    .task
                    .linux
                    .take_host_work_doorbell()
                    .unwrap()
                    .settled();
                ticket
                    .complete(true)
                    .unwrap_or_else(|_| panic!("inline carrier ACK was refused"));
            }),
        );
    }
    let mut service = fixture.process_service();
    if defer_race {
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            member.id
        );
        run_as_leader(fixture);
        let saved = unsafe { *fixture.zone.record(member.id).ctx_mut() };
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let result = entry
            .resume_checkpoint(|entry| {
                fixture.task.linux.mark_pending_host_work();
                frame.x = entry.resume_context().native.x;
                frame.elr = entry.resume_context().native.pc;
                let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
                let route = crate::signal_delivery::deliver_signal_on_syscall_return(
                    &fixture.task,
                    control,
                    entry,
                    &mut frame,
                    zerocopy::IntoBytes::as_bytes(&fp),
                    &mut ArmWaitSignalMachine {
                        user_sp: stack.va_at(stack.len()),
                        backend: ArmWaitSignalBackend,
                    },
                );
                assert_eq!(route, None);
                fixture
                    .task
                    .linux
                    .take_host_work_doorbell()
                    .unwrap()
                    .settled();
                Ok(None)
            })
            .unwrap();
        assert!(matches!(
            result,
            crate::native_process_runtime::NativeResume::Left(None)
        ));
        drop(entry);
        assert!(
            fixture.zone.record(member.id).requires_native_entry(),
            "the owned signal-work refusal must survive a concurrent work drain"
        );
        assert!(!fixture.task.linux.has_pending_host_work());
    }
    let mut cpu = HostResumeCpu {
        inner: cpu,
        fixture,
        service: &mut service,
        owner: member.id,
        owner_resumes: 0,
        expect_initial_deferred: pending_work,
        deferred_return_observed: false,
    };
    let mut scheduler = crate::sched::Sched {
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
        counters: &counters,
        handoff: None,
    };
    if !defer_race {
        let _ = scheduler.run_ready(&mut frame);
        assert_eq!(cpu.owner_resumes, if inline_ack { 2 } else { 1 });
        assert_eq!(cpu.deferred_return_observed, pending_work);
    } else {
        // The direct refusal checkpoint parked A. Let the real scheduler
        // select its runnable peer before the host ACK wakes A again.
        let _ = scheduler.run_ready(&mut frame);
        assert_eq!(cpu.owner_resumes, 0);
        assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(peer_record));
    }
    if (pending_work && !inline_ack) || defer_race {
        let parked = fixture.zone.record(member.id);
        assert!(
            parked.has_object_operation(),
            "the exact service operation must survive a ready-reply owner yield"
        );
        assert!(
            parked.requires_native_entry(),
            "real carrier work must retain the native owner before host return"
        );
        assert_eq!(unsafe { parked.ctx_mut() }.native.pc, 0x400004);
        assert!(stack.as_bytes().iter().all(|byte| *byte == 0));
        assert!(
            runtime
                .current_signals(&fixture.task)
                .unwrap()
                .pending_set(member)
                .contains(signal)
        );
        if !inline_ack {
            let notice = fixture
                .task
                .service_notice
                .take()
                .unwrap()
                .expect("actual carrier work needs its service request");
            let queue = fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                )
                .unwrap();
            // SAFETY: claim the exact live member's notice under the same service
            // queue used by carrier intake. Its committed result remains owned.
            let ticket = unsafe {
                carrick_core_abi::service::ServiceCell::claim_notice(
                    &control.service,
                    notice,
                    NonZeroU64::MIN,
                    parked.identity(),
                )
            }
            .unwrap();
            assert!(matches!(
                ticket.request().operation,
                carrick_core_abi::service::ServiceOperation::CarrierWork {
                    entry: carrick_sched_core::object_wait::OwnerEntry::Syscall
                }
            ));
            drop(queue);
            // The race callback already drained its observed work. Ordinary
            // delayed carrier settlement consumes the live doorbell here.
            if defer_race {
                assert!(!fixture.task.linux.has_pending_host_work());
            } else {
                fixture
                    .task
                    .linux
                    .take_host_work_doorbell()
                    .unwrap()
                    .settled();
            }
            ticket
                .complete(true)
                .unwrap_or_else(|_| panic!("committed carrier work was cancelled"));
            fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                )
                .unwrap()
                .notify_object(fixture.slot, &mut Default::default())
                .unwrap();
        }
        if fixture.zone.slot(fixture.slot).current() == Some(peer_record) {
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, peer_record)
                    .is_queued()
            );
        }
        let mut scheduler = crate::sched::Sched {
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
            handoff: None,
        };
        let _ = scheduler.run_ready(&mut frame);
        assert_eq!(cpu.owner_resumes, if defer_race { 1 } else { 2 });
    }

    // The production checkpoint must publish handler words before the host
    // can consume this exact member's UserReturn handback.
    let returned = unsafe { *fixture.zone.record(member.id).ctx_mut() };
    assert_eq!(
        returned.native.pc, 0x700000,
        "host handback must contain the signal handler before executor return"
    );
    assert_eq!(returned.native.x[0], 13);
    let handler_sp = returned.native.sp_el0;
    assert!(handler_sp < words.native.sp_el0);
    let offset = usize::try_from(handler_sp - stack.va().raw()).unwrap();
    let public: carrick_personality_linux::signal::arm::RtSigframe = stack.read(offset);
    let saved_pc = public.ucontext.uc_mcontext.pc;
    let saved_sp = public.ucontext.uc_mcontext.sp;
    let saved_result = public.ucontext.uc_mcontext.regs[0];
    assert_eq!(
        saved_pc, 0x400004,
        "one handler frame saves the completed SVC"
    );
    assert_eq!(saved_sp, words.native.sp_el0);
    assert_eq!(
        saved_result, 0,
        "the handler sees the completed syscall result"
    );
    assert_eq!(oldset.get::<u64>(0), mask_bits);
    let writes = crate::native_process_runtime::host_test_support::take_return_copyouts();
    assert_eq!(
        writes
            .iter()
            .filter(|(address, len)| *address == oldset.va() && *len == 8)
            .count(),
        1,
        "the retained old mask is written exactly once"
    );
    assert_eq!(
        writes
            .iter()
            .filter(|(address, _)| address.raw() == handler_sp)
            .count(),
        1,
        "the native owner publishes exactly one handler frame"
    );

    assert!(
        stack.as_bytes()[..offset].iter().all(|byte| *byte == 0),
        "delivery publishes one frame, without a nested handler frame"
    );
    assert!(
        !runtime
            .current_signals(&fixture.task)
            .unwrap()
            .pending_set(member)
            .contains(signal)
    );
    assert_eq!(fixture.page.live(), 2);
}

struct HostResumeCpu<'a> {
    inner: crate::sched::FakeCpu,
    fixture: &'static Fixture,
    service: &'a mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    owner: RecordId,
    owner_resumes: usize,
    expect_initial_deferred: bool,
    deferred_return_observed: bool,
}
impl crate::sched::ThreadCpu for HostResumeCpu<'_> {
    fn save(&mut self, f: &carrick_el1_abi::TrapFrame, c: &mut Aarch64ParkedContext) {
        self.inner.save(f, c);
    }
    fn load(&mut self, f: &mut carrick_el1_abi::TrapFrame, c: &Aarch64ParkedContext) {
        self.inner.load(f, c);
    }
    fn resume_lifecycle(
        &mut self,
        _: &ZoneTables<Aarch64ParkedContext>,
        _: &CurrentTask,
        _: SlotId,
        record: RecordId,
    ) -> crate::sched::ResumeAction {
        self.owner_resumes += usize::from(record == self.owner);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::aarch64_process::resume_production_with_service(
                self.fixture.zone,
                &self.fixture.task,
                self.fixture.slot,
                record,
                self.service,
            )
        }))
        .unwrap_or_else(|payload| {
            if let Some(failure) =
                payload.downcast_ref::<crate::native_run_failure::NativeRunFailurePanic>()
            {
                panic!("production native resume failed: {failure:?}");
            }
            std::panic::resume_unwind(payload)
        });
        if record == self.owner {
            assert_eq!(result, crate::sched::ResumeAction::Left);
            if self.expect_initial_deferred && self.owner_resumes == 1 {
                // Observe the first completed production selection before
                // run_ready can select the already-ACKed continuation again.
                let retained = self.fixture.zone.record(record);
                assert!(
                    retained.has_object_operation(),
                    "the exact service token must survive ready-reply yielding"
                );
                assert!(retained.requires_native_entry());
                assert_eq!(
                    unsafe { retained.ctx_mut() }.native.pc,
                    0x400004,
                    "the first yield retains the completed SVC before signal return"
                );
                self.deferred_return_observed = true;
            }
        }
        result
    }
    fn set_translation(&mut self, a: u64, b: u64) {
        self.inner.set_translation(a, b);
    }
    fn live_ttbr0(&self) -> Option<u64> {
        self.inner.live_ttbr0()
    }
    fn invalidate_asid(&mut self, r: u64) {
        self.inner.invalidate_asid(r);
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn freq(&self) -> u64 {
        self.inner.freq()
    }
    fn set_timer(&mut self, d: Option<u64>) {
        self.inner.set_timer(d);
    }
    fn send_sgi(&mut self, r: u64) {
        self.inner.send_sgi(r);
    }
    fn ack_irq(&mut self) -> u32 {
        self.inner.ack_irq()
    }
    fn end_irq(&mut self, i: u32) {
        self.inner.end_irq(i);
    }
    fn wait_for_interrupt(&mut self) {
        self.inner.wait_for_interrupt();
    }
    fn spin(&mut self) {
        self.inner.spin();
    }
    fn own_sgi_target(&self) -> u64 {
        self.inner.own_sgi_target()
    }
}
