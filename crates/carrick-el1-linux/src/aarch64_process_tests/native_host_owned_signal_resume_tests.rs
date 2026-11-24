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
        waker_slot: carrick_sched_core::SlotId::new(0),
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
                        &|owned| {
                            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                        },
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
        // The drain settled the earlier work, but the deferral then
        // published its own CarrierWork notice and left into `Sched::idle`.
        // Without a physical doorbell that notice must ring host work, or
        // the idle vCPU strands it behind WFI (#2620).
        assert!(fixture.task.linux.has_pending_host_work());
    }
    let mut cpu = HostResumeCpu {
        inner: cpu,
        fixture,
        service: &mut service,
        owner: member.id,
        owner_resumes: 0,
        expect_left: true,
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
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
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
                    entry: carrick_sched_core::object_wait::OwnerEntry::Syscall,
                    demand: carrick_core_abi::service::CarrierDemand::Work,
                }
            ));
            drop(queue);
            // Delayed carrier settlement consumes the live doorbell here: the
            // real work's mark, or the deferral notice's ring after the race
            // callback drained the earlier work.
            fixture
                .task
                .linux
                .take_host_work_doorbell()
                .unwrap()
                .settled();
            ticket
                .complete(true)
                .unwrap_or_else(|_| panic!("committed carrier work was cancelled"));
            fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
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

#[test]
fn arm_woken_sigsuspend_inline_carrier_ack_preserves_eintr() {
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
    let owner_record = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap()
        .record
        .id;
    let member = fixture.zone.record_ref(owner_record);
    assert!(fixture.zone.record(owner_record).is_native_owned());

    let (peer_control, peer) = imported_thread(fixture);
    let peer_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
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
        waker_slot: carrick_sched_core::SlotId::new(0),
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
    control.init_blocked(carrick_el1_abi::BlockedMask(0));

    // Park and wake `owner_record` on a guest futex so its `ZoneRecord`
    // carries `Handback::Woken` (`result == 0`) while `peer` waits in queue.
    let futex_addr = 0x9000_u64;
    let mm = fixture.address.mm.raw().get();
    {
        let guard = fixture.zone.short_lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm, futex_addr),
            &carrick_sched_core::ShortLockSpin,
        );
        let seq = fixture.zone.next_seq(owner_record);
        fixture
            .zone
            .enqueue_observed(&guard, owner_record, seq, mm, futex_addr, u32::MAX, 0, None)
            .unwrap();
        assert!(
            fixture
                .zone
                .publish_guest_park(&guard, fixture.slot, owner_record, seq)
        );
    }
    fixture.zone.clear_current(fixture.slot);
    {
        let guard = fixture.zone.short_lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm, futex_addr),
            &carrick_sched_core::ShortLockSpin,
        );
        let mut effects = carrick_sched_core::WakeEffects::default();
        assert_eq!(
            fixture.zone.wake_placed(
                &guard,
                mm,
                futex_addr,
                u32::MAX,
                1,
                carrick_sched_core::Waker::El1 { slot: fixture.slot },
                &mut [],
                &mut effects,
            ),
            1
        );
    }
    assert_eq!(
        fixture.zone.record(owner_record).handback(),
        Some(carrick_sched_core::Handback::Woken)
    );
    // Rotate `peer` behind the freshly woken `owner_record`: `[owner_record, peer]`.
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        peer.id
    );
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, peer.id)
            .is_queued()
    );
    let switched = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(switched.record, owner_record);
    assert_eq!(switched.result, Some(0));

    // Simulate `owner_record` consuming 0 from futex_wait and entering a
    // subsequent `rt_sigsuspend` that completes with `-EINTR` (-4), hits an
    // untouched-altstack `NeedsSupply` fault, and receives a synchronous
    // service doorbell completion (`deferred = true` -> `yield_service_checkpoint_as`).
    let eintr = (-4_i64) as u64;
    words.native.x[0] = eintr;
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x54000000,
        elr: words.native.pc,
        ..Default::default()
    };
    frame.x[0] = eintr;
    physical.child_copy_error = Some(NativeProcessError::NeedsSupply);
    crate::native_process_runtime::host_test_support::on_service_doorbell(Some(Box::new(
        move || {
            let notice = fixture.task.service_notice.take().unwrap().unwrap();
            let queue = fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
                .unwrap();
            // SAFETY: claims this exact member's published fault notice under
            // the production intake queue, then supplies it before park.
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
                carrick_core_abi::service::ServiceOperation::Fault(_)
            ));
            drop(queue);
            ticket
                .complete(true)
                .unwrap_or_else(|_| panic!("inline fault supply was refused"));
            true
        },
    )));
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
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let route = crate::signal_delivery::deliver_signal_on_syscall_return(
            &fixture.task,
            control,
            &mut entry,
            &mut frame,
            zerocopy::IntoBytes::as_bytes(&fp),
            &mut ArmWaitSignalMachine {
                user_sp: stack.va_at(stack.len()),
                backend: ArmWaitSignalBackend,
            },
        );
        assert_eq!(
            route,
            Some(carrick_personality_linux::dispatch::CompletionRoute::Suspended)
        );
    }
    crate::native_process_runtime::host_test_support::on_service_doorbell(None);
    let mut service = fixture.process_service();
    assert_eq!(
        fixture.zone.record(owner_record).handback(),
        Some(carrick_sched_core::Handback::Resumed),
        "yield_service_checkpoint_as must replace stale Handback::Woken with Handback::Resumed"
    );
    assert_eq!(
        fixture.zone.runnable_head(fixture.slot),
        Some(owner_record),
        "yield_service_checkpoint_as must keep the checkpointed member ahead of queued peers"
    );

    let counters = carrick_el1_abi::Counters::new();
    let inner = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let mut cpu = HostResumeCpu {
        inner,
        fixture,
        service: &mut service,
        owner: owner_record,
        owner_resumes: 0,
        expect_left: false,
        expect_initial_deferred: false,
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
    let served = scheduler.run_ready(&mut frame);
    assert_eq!(
        served,
        Some(crate::sched::Served::Returned { switched: true })
    );
    assert_eq!(cpu.owner_resumes, 1);
    assert_eq!(frame.elr, 0x400004);
    assert_eq!(
        frame.x[0], eintr,
        "stale wake handback must not overwrite completed rt_sigsuspend -EINTR in x0"
    );

    // Complete the EL0 user-return delivery now that the backing is ready.
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &words,
                &mut service,
            )
            .unwrap();
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let route = crate::arm_signal::deliver_on_user_return_with(
            &fixture.task,
            control,
            &mut entry,
            &mut frame,
            zerocopy::IntoBytes::as_bytes(&fp),
            &mut ArmWaitSignalMachine {
                user_sp: stack.va_at(stack.len()),
                backend: ArmWaitSignalBackend,
            },
        );
        assert_eq!(route, None);
    }
    assert_eq!(frame.elr, 0x700000);
    assert_eq!(frame.x[0], 13);
    let writes = crate::native_process_runtime::host_test_support::take_return_copyouts();
    assert_eq!(writes.len(), 1);
    let handler_sp = writes[0].0;
    assert!(handler_sp.raw() < stack.va_at(stack.len()).raw());
    let offset = usize::try_from(handler_sp.raw() - stack.va().raw()).unwrap();
    let public: carrick_personality_linux::signal::arm::RtSigframe = stack.read(offset);
    let saved_pc = public.ucontext.uc_mcontext.pc;
    let saved_result = public.ucontext.uc_mcontext.regs[0];
    assert_eq!(saved_pc, 0x400004);
    assert_eq!(
        saved_result, eintr,
        "signal frame must preserve completed rt_sigsuspend -EINTR across yield_service_checkpoint_as"
    );
}

struct HostResumeCpu<'a> {
    inner: crate::sched::FakeCpu,
    fixture: &'static Fixture,
    service: &'a mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    owner: RecordId,
    owner_resumes: usize,
    expect_left: bool,
    expect_initial_deferred: bool,
    deferred_return_observed: bool,
}
impl crate::sched::ThreadCpu for HostResumeCpu<'_> {
    fn save(&mut self, f: &carrick_el1_abi::TrapFrame, c: &mut Aarch64ParkedContext) {
        self.inner.save(f, c);
    }
    fn publish_user_sp(&mut self, sp: carrick_guest_arch::UserVa) {
        self.inner.publish_user_sp(sp);
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
            if self.expect_left {
                assert_eq!(result, crate::sched::ResumeAction::Left);
            }
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

#[test]
fn arm_host_owned_sigsuspend_across_admission_home_drop_preserves_suspend_mask() {
    use carrick_signal_core::policy::{ActionFlags, RestorerAddress, SigBlockMask};
    use zerocopy::FromBytes;

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
    fixture.zone.discard_unpublished(fixture.slot, original);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());
    run_as_leader(fixture);

    let sig = Signal::from_number(10).unwrap();
    let empty_mask = SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::EMPTY);
    let orig_mask = SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::EMPTY.with(sig));
    fixture
        .control
        .init_blocked(carrick_el1_abi::BlockedMask(orig_mask.signals().bits()));

    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let sp_top = stack.va_at(stack.len());
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = sp_top.raw();
    let ttbr0 = fixture_ttbr0(fixture);
    let mut service = fixture.process_service();

    // Setup: install handler and queue SIGUSR1 while masked.
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            let current_record = fixture.control.zone_record().unwrap();
            assert!(!fixture.zone.record(current_record.id).is_native_owned());
            entry
                .rt_sigaction(
                    sig,
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                        flags: ActionFlags {
                            restart: true,
                            siginfo: true,
                            ..Default::default()
                        },
                        restorer: Some(RestorerAddress(0x71_0000)),
                        ..Default::default()
                    }),
                )
                .unwrap();
            entry
                .tgkill(
                    SignalThreadSelector::from_abi(41),
                    SignalThreadSelector::from_abi(41),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        },
    )
    .unwrap();
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    // Round 0 rt_sigsuspend(&empty): queued SIGUSR1 settles inline with
    // -EINTR (Served); AdmissionHome::drop frees this call's record.
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            fixture
                .control
                .init_blocked(carrick_el1_abi::BlockedMask(0));
            let parked = entry.rt_sigsuspend(empty_mask, orig_mask).unwrap();
            assert!(
                !parked,
                "queued SIGUSR1 settles rt_sigsuspend without parking"
            );
        },
    )
    .unwrap();
    let after_suspend_record = fixture.control.zone_record().unwrap();
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    // Immediately following SVC user-return checkpoint must rehome suspend_mask
    // onto the newly allocated home record and preserve orig_mask in uc_sigmask.
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5600_0000,
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    frame.x[0] = (-4_i64) as u64;
    let mut delivery_native = ThreadCtx::ZERO;
    delivery_native.pc = 0x40_0004;
    delivery_native.x[0] = (-4_i64) as u64;
    delivery_native.sp_el0 = sp_top.raw();
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    let action = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &delivery_native,
        ttbr0,
        fixture.page,
        fixture.control,
        (frame.esr, frame.x[0]),
        true,
        &mut service,
        |process| {
            crate::arm_signal::deliver_on_user_return_at(
                &fixture.task,
                fixture.control,
                process,
                &mut frame,
                |_, _| sp_top,
            )
        },
    )
    .unwrap();
    assert_eq!(action, carrick_el1_abi::Action::Served);
    let after_delivery_record = fixture.control.zone_record().unwrap();
    assert_ne!(after_delivery_record, after_suspend_record);
    assert_eq!(frame.elr, 0x70_0000);
    assert_eq!(frame.x[0], 10);

    let writes = crate::native_process_runtime::host_test_support::take_return_copyouts();
    assert_eq!(writes.len(), 1);
    let written_sp = writes[0].0.raw();
    let offset = usize::try_from(written_sp - stack.va().raw()).unwrap();
    let sigframe = carrick_personality_linux::signal::arm::SignalFrame::read_from_bytes(
        &stack.as_bytes()[offset
            ..offset + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
    )
    .unwrap();
    let saved_sigmask = sigframe.rt.ucontext.uc_sigmask;
    assert_eq!(
        saved_sigmask,
        orig_mask.signals().bits(),
        "suspend_mask must survive AdmissionHome::drop + rehome_entry into uc_sigmask"
    );
    assert!(
        !registry().signal_checkpoint_needed(fixture.zone, after_delivery_record),
        "delivered member must have no remaining suspend_mask or pending signal"
    );
}

#[test]
fn arm_host_owned_member_without_zone_record_accepts_tgkill_and_delivers_on_reentry() {
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
    fixture.zone.discard_unpublished(fixture.slot, original);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    let sib_control = host_born_sibling(fixture, 42);
    let sib_identity = sib_control.host_birth_identity().unwrap();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let sp_top = stack.va_at(stack.len());
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = sp_top.raw();
    let ttbr0 = fixture_ttbr0(fixture);
    let mut service = fixture.process_service();
    let sig = Signal::from_number(10).unwrap();

    // Admit sibling through production with_process_entry, then drop its
    // AdmissionHome so the host-loaded sibling runs in EL0 with no ZoneRecord.
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        sib_control,
        &mut service,
        |entry| {
            entry
                .rt_sigaction(
                    sig,
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                        ..Default::default()
                    }),
                )
                .unwrap();
        },
    )
    .unwrap();
    assert!(sib_control.entry().is_none());
    assert!(sib_control.native_signal_owner());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    // Leader sends tgkill to sibling while sibling has no live zone record.
    run_as_leader(fixture);
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            assert_eq!(
                entry.tgkill(
                    SignalThreadSelector::from_abi(41),
                    SignalThreadSelector::from_abi(42),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                ),
                Ok(()),
                "live host-loaded SignalOwner sibling without a zone record must accept tgkill"
            );
        },
    )
    .unwrap();
    assert!(registry().signal_checkpoint_needed(fixture.zone, sib_control.zone_record().unwrap()));

    // Sibling sends tgkill to host-loaded leader while leader has no zone record.
    run_as(
        fixture,
        sib_identity.task().raw() as i32,
        sib_identity.birth().task_serial().raw(),
        sib_identity.thread().raw(),
        sib_control,
    );
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        sib_control,
        &mut service,
        |entry| {
            assert_eq!(
                entry.tgkill(
                    SignalThreadSelector::from_abi(41),
                    SignalThreadSelector::from_abi(41),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                ),
                Ok(()),
                "live host-loaded SignalOwner leader without a zone record must accept tgkill"
            );
        },
    )
    .unwrap();

    // Sibling re-enters EL1 user-return gate and receives the queued SIGUSR1.
    let mut sib_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5600_0000,
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    let action = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        sib_control,
        (sib_frame.esr, sib_frame.x[0]),
        true,
        &mut service,
        |process| {
            crate::arm_signal::deliver_on_user_return_at(
                &fixture.task,
                sib_control,
                process,
                &mut sib_frame,
                |_, _| sp_top,
            )
        },
    )
    .unwrap();
    assert_eq!(
        crate::native_process_runtime::host_test_support::take_return_copyouts().len(),
        1
    );
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(sib_frame.elr, 0x70_0000);
    assert_eq!(sib_frame.x[0], 10);

    // Host-loaded leader also re-enters EL1 user-return gate and receives SIGUSR1.
    run_as_leader(fixture);
    let mut leader_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5600_0000,
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    let leader_action = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        (leader_frame.esr, leader_frame.x[0]),
        true,
        &mut service,
        |process| {
            crate::arm_signal::deliver_on_user_return_at(
                &fixture.task,
                fixture.control,
                process,
                &mut leader_frame,
                |_, _| sp_top,
            )
        },
    )
    .unwrap();
    assert_eq!(
        crate::native_process_runtime::host_test_support::take_return_copyouts().len(),
        1
    );
    assert_eq!(leader_action, carrick_el1_abi::Action::Served);
    assert_eq!(leader_frame.elr, 0x70_0000);
    assert_eq!(leader_frame.x[0], 10);

    // Process-directed kill() across dropped ZoneRecords (for_each_live_signal_member):
    // block SIGUSR2 on leader, send process SIGUSR2 while sibling has no live ZoneRecord,
    // and deliver SIGUSR2 when sibling re-enters.
    let sig2 = Signal::from_number(12).unwrap();
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            entry
                .rt_sigaction(
                    sig2,
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x74_0000)),
                        ..Default::default()
                    }),
                )
                .unwrap();
            fixture.control.init_blocked(carrick_el1_abi::BlockedMask(
                carrick_signal_core::SignalSet::EMPTY.with(sig2).bits(),
            ));
            assert!(sib_control.entry().is_none());
            assert!(
                fixture
                    .zone
                    .live(sib_control.zone_record().unwrap())
                    .is_none()
            );
            assert_eq!(
                entry.kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                    SignalRequest::from_abi(12).unwrap(),
                    SignalInfo::Generated(None),
                ),
                Ok(())
            );
        },
    )
    .unwrap();
    run_as(
        fixture,
        sib_identity.task().raw() as i32,
        sib_identity.birth().task_serial().raw(),
        sib_identity.thread().raw(),
        sib_control,
    );
    let mut sib_frame2 = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5600_0000,
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    let action2 = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        sib_control,
        (sib_frame2.esr, sib_frame2.x[0]),
        true,
        &mut service,
        |process| {
            crate::arm_signal::deliver_on_user_return_at(
                &fixture.task,
                sib_control,
                process,
                &mut sib_frame2,
                |_, _| sp_top,
            )
        },
    )
    .unwrap();
    assert_eq!(
        crate::native_process_runtime::host_test_support::take_return_copyouts().len(),
        1
    );
    assert_eq!(action2, carrick_el1_abi::Action::Served);
    assert_eq!(sib_frame2.elr, 0x74_0000);
    assert_eq!(sib_frame2.x[0], 12);

    // Negative control: retired host-loaded sibling must still fail with ESRCH.
    let _reserved =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sib_control)
            .unwrap();
    run_as_leader(fixture);
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            assert_eq!(
                entry.tgkill(
                    SignalThreadSelector::from_abi(41),
                    SignalThreadSelector::from_abi(42),
                    SignalRequest::Probe,
                    SignalInfo::Generated(None),
                ),
                Err(carrick_syscall_abi::LINUX_ESRCH)
            );
        },
    )
    .unwrap();
}

#[test]
fn arm_host_owned_member_without_zone_record_does_not_sample_released_cpu_clock() {
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
    fixture.zone.discard_unpublished(fixture.slot, original);

    let sib_control = host_born_sibling(fixture, 42);
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = stack.va_at(stack.len()).raw();
    let ttbr0 = fixture_ttbr0(fixture);
    let mut service = fixture.process_service();

    // Admit host-loaded SignalOwner sibling 42 and release its temporary ZoneRecord.
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        sib_control,
        &mut service,
        |_entry| {},
    )
    .unwrap();
    assert!(sib_control.entry().is_none());
    assert!(sib_control.native_signal_owner());
    let released_record = sib_control.zone_record().unwrap();
    assert!(fixture.zone.live(released_record).is_none());

    let clock_id = (((!(42_i32)) << 3) | 4) as u32 as u64;
    let carrick_syscall_abi::LinuxClockRead::Cpu(peer_clock) =
        carrick_syscall_abi::linux_clock_read(clock_id).unwrap()
    else {
        panic!("expected per-thread CPU clock");
    };
    run_as_leader(fixture);
    crate::aarch64_process::with_process_entry(
        source,
        &fixture.task,
        &native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            assert_eq!(
                entry.cpu_clock_nanos(peer_clock),
                Some(Err(carrick_syscall_abi::LINUX_EINVAL)),
                "peer thread without a live ZoneRecord must not sample its released RecordRef"
            );
        },
    )
    .unwrap();
}

#[test]
fn sigsuspend_refused_frame_supply_preserves_saved_mask_for_forced_sigsegv() {
    use carrick_signal_core::policy::{ActionFlags, RestorerAddress, SigBlockMask};
    use zerocopy::FromBytes;

    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    initial.native.pc = 0x40_0004;
    initial.native.sp_el0 = stack.va_at(stack.len()).raw();
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
    let owner_record = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap()
        .record
        .id;
    let member = fixture.zone.record_ref(owner_record);
    run_as_leader(fixture);
    let control = fixture.control;

    let sig_usr1 = Signal::from_number(10).unwrap();
    let sig_usr2 = Signal::from_number(12).unwrap();
    let orig_mask =
        SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::EMPTY.with(sig_usr1));
    let temp_mask =
        SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::EMPTY.with(sig_usr2));
    control.init_blocked(carrick_el1_abi::BlockedMask(orig_mask.signals().bits()));

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
        waker_slot: carrick_sched_core::SlotId::new(0),
        on_signal_clock: None,
    };
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut physical,
            )
            .unwrap();
        entry
            .rt_sigaction(
                sig_usr1,
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                    flags: ActionFlags {
                        on_stack: true,
                        siginfo: true,
                        ..Default::default()
                    },
                    restorer: Some(RestorerAddress(0x71_0000)),
                    ..Default::default()
                }),
            )
            .unwrap();
        entry
            .rt_sigaction(
                Signal::SEGV,
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x72_0000)),
                    flags: ActionFlags {
                        siginfo: true,
                        ..Default::default()
                    },
                    restorer: Some(RestorerAddress(0x73_0000)),
                    ..Default::default()
                }),
            )
            .unwrap();
        entry
            .tgkill(
                SignalThreadSelector::from_abi(41),
                SignalThreadSelector::from_abi(41),
                SignalRequest::from_abi(10).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
        control.init_blocked(carrick_el1_abi::BlockedMask(temp_mask.signals().bits()));
        let parked = entry.rt_sigsuspend(temp_mask, orig_mask).unwrap();
        assert!(!parked);
    }

    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5400_0000,
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    frame.x[0] = (-4_i64) as u64;
    physical.child_copy_error = Some(NativeProcessError::NeedsSupply);
    crate::native_process_runtime::host_test_support::on_service_doorbell(Some(Box::new(
        move || {
            let notice = fixture.task.service_notice.take().unwrap().unwrap();
            let queue = fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
                .unwrap();
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
                carrick_core_abi::service::ServiceOperation::Fault(_)
            ));
            drop(queue);
            ticket
                .complete(false)
                .unwrap_or_else(|_| panic!("fault refusal was cancelled"));
            true
        },
    )));
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut physical,
            )
            .unwrap();
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let route = crate::signal_delivery::deliver_signal_on_syscall_return(
            &fixture.task,
            control,
            &mut entry,
            &mut frame,
            zerocopy::IntoBytes::as_bytes(&fp),
            &mut ArmWaitSignalMachine {
                user_sp: stack.va_at(stack.len()),
                backend: ArmWaitSignalBackend,
            },
        );
        assert_eq!(
            route,
            Some(carrick_personality_linux::dispatch::CompletionRoute::Suspended)
        );
    }
    crate::native_process_runtime::host_test_support::on_service_doorbell(None);

    let mut service = fixture.process_service();
    let counters = carrick_el1_abi::Counters::new();
    let mut cpu = HostResumeCpu {
        inner: crate::sched::FakeCpu {
            ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
            ..Default::default()
        },
        fixture,
        service: &mut service,
        owner: owner_record,
        owner_resumes: 0,
        expect_left: false,
        expect_initial_deferred: false,
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
    let served = scheduler.run_ready(&mut frame);
    assert_eq!(
        served,
        Some(crate::sched::Served::Returned { switched: true })
    );

    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut service,
            )
            .unwrap();
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let route = crate::arm_signal::deliver_on_user_return_with(
            &fixture.task,
            control,
            &mut entry,
            &mut frame,
            zerocopy::IntoBytes::as_bytes(&fp),
            &mut ArmWaitSignalMachine {
                user_sp: stack.va_at(stack.len()),
                backend: ArmWaitSignalBackend,
            },
        );
        assert_eq!(route, None);
    }
    assert_eq!(frame.elr, 0x72_0000);
    assert_eq!(frame.x[0], 11);
    let writes = crate::native_process_runtime::host_test_support::take_return_copyouts();
    assert_eq!(writes.len(), 1);
    let written_sp = writes[0].0.raw();
    let offset = usize::try_from(written_sp - stack.va().raw()).unwrap();
    let sigframe = carrick_personality_linux::signal::arm::SignalFrame::read_from_bytes(
        &stack.as_bytes()[offset
            ..offset + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
    )
    .unwrap();
    let saved_sigmask = sigframe.rt.ucontext.uc_sigmask;
    assert_eq!(
        saved_sigmask,
        orig_mask.signals().without(Signal::SEGV).bits(),
        "forced SIGSEGV after refused sigsuspend frame supply must preserve saved orig_mask, not temporary sigsuspend mask"
    );
}

#[test]
fn arm_pool_born_host_adopted_member_without_zone_record_accepts_tgkill_and_delivers_on_altstack() {
    use carrick_signal_core::policy::SigBlockMask;
    use zerocopy::FromBytes;

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
    fixture.zone.discard_unpublished(fixture.slot, original);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    // Construct a pool-born, host-adopted sibling matching
    // adopt_born_thread_at_first_entry + free_first_entry_activation:
    // sib_control.entry() is Some(entry) in EntryState::Published, its birth
    // ZoneRecord is retired, and its slot is idle.
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            use carrick_sched_core::process::identity_allocator::*;
            if !ns.is_reserved_number(42) {
                ns.reserve_exact(42, ClaimKind::Thread).unwrap();
            }
            let domain = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
            ns.bind_visible_domain(42, domain).unwrap();
            ns.advance_visible_past(
                domain,
                VisibleIdentity::from_existing_member(NonZeroU32::new(42).unwrap()),
            )
            .unwrap();
        });
    let entry = fixture
        .page
        .stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
                ),
                uid_credit: 0,
            },
        )
        .unwrap();
    let sib_control: &'static ThreadControlSlot = Box::leak(Box::new(ThreadControlSlot::new()));
    fixture
        .page
        .bind_control_address(entry, sib_control as *const _ as u64)
        .unwrap();
    sib_control
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
        .unwrap();
    assert!(sib_control.publish_visible_tid(42));
    let birth_claim = fixture.page.claim_any().unwrap();
    fixture.page.thread_born().unwrap();
    fixture
        .page
        .record_born(
            birth_claim,
            carrick_el1_abi::BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x0001_0000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    fixture.page.publish(entry).unwrap();
    let birth_record = fixture
        .zone
        .alloc_record(carrick_sched_core::ThreadIdentity {
            tid: 42,
            serial: 102,
            mm: 1,
            file_table: 5,
            generation: 12,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: fixture.page as *const _ as u64,
            control_slot: sib_control as *const _ as u64,
        })
        .unwrap();
    let birth_ref = fixture.zone.record_ref(birth_record);
    sib_control.bind_zone_record(birth_ref);
    fixture.zone.discard_unpublished(fixture.slot, birth_record);
    assert!(fixture.zone.live(birth_ref).is_none());
    assert_eq!(sib_control.entry(), Some(entry));

    let main_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let main_sp_top = main_stack.va_at(main_stack.len());
    let alt_stack = carrick_test_support::GuestUserBuffer::zeroed(32768);
    let alt_top = alt_stack.va_at(alt_stack.len());
    let mut native = ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = main_sp_top.raw();
    let ttbr0 = fixture_ttbr0(fixture);
    let mut service = fixture.process_service();

    // Sibling installs SIGURG (23) handler with SA_ONSTACK + sigaltstack via production arm_call.
    // Non-parking return runs AdmissionHome::drop, leaving sibling without a live ZoneRecord
    // while retaining sib_control.entry() == Some(entry) and native_signal_owner() == true.
    run_as(fixture, 42, 12, 102, sib_control);
    let sigurg = Signal::from_number(23).unwrap();
    let orig_mask =
        SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::EMPTY.with(sigurg));
    sib_control.init_blocked(carrick_el1_abi::BlockedMask(orig_mask.signals().bits()));
    let act_buf = carrick_test_support::GuestUserBuffer::from_value([
        0x70_0000_u64,
        carrick_syscall_abi::LINUX_SA_ONSTACK
            | carrick_syscall_abi::LINUX_SA_RESTORER
            | carrick_syscall_abi::LINUX_SA_SIGINFO,
        0x71_0000_u64,
        0_u64,
    ]);
    let mut sigact_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0004,
        spsr: 0x3c0,
        ..Default::default()
    };
    sigact_frame.x[8] = 134;
    sigact_frame.x[0] = 23;
    sigact_frame.x[1] = act_buf.arg();
    sigact_frame.x[3] = 8;
    let sigact_route = arm_call(fixture, sib_control, &mut service, &mut sigact_frame).unwrap();
    assert!(matches!(
        sigact_route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(sigact_frame.x[0], 0);

    let ss_buf = carrick_test_support::GuestUserBuffer::from_value([
        alt_stack.va().raw(),
        0_u64,
        alt_stack.len() as u64,
    ]);
    let mut sigalt_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0008,
        spsr: 0x3c0,
        ..Default::default()
    };
    sigalt_frame.x[8] = 132;
    sigalt_frame.x[0] = ss_buf.arg();
    arm_call(fixture, sib_control, &mut service, &mut sigalt_frame).unwrap();
    assert_eq!(sigalt_frame.x[0], 0);
    assert_eq!(sib_control.entry(), Some(entry));
    assert!(sib_control.native_signal_owner());
    assert!(
        fixture
            .zone
            .live(sib_control.zone_record().unwrap())
            .is_none()
    );
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());

    // Leader sends tgkill(41, 42, SIGURG) while pool-born host-adopted sibling is in EL0
    // with no live ZoneRecord. Before the fix this returned -ESRCH (-3).
    run_as_leader(fixture);
    let mut tgkill_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0010,
        spsr: 0x3c0,
        ..Default::default()
    };
    tgkill_frame.x[8] = 131;
    tgkill_frame.x[0] = 41;
    tgkill_frame.x[1] = 42;
    tgkill_frame.x[2] = 23;
    arm_call(fixture, fixture.control, &mut service, &mut tgkill_frame).unwrap();
    assert_eq!(
        tgkill_frame.x[0], 0,
        "pool-born host-adopted SignalOwner sibling without a live ZoneRecord must accept tgkill (got {})",
        tgkill_frame.x[0] as i64
    );

    // Sibling calls rt_sigsuspend(&empty) via production arm_call -> settles with -EINTR,
    // AdmissionHome drops again, and user-return reentry delivers SIGURG onto alt_stack.
    run_as(fixture, 42, 12, 102, sib_control);
    let empty_mask_buf = carrick_test_support::GuestUserBuffer::from_value(0_u64);
    let mut suspend_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x5600_0000,
        elr: 0x40_0020,
        spsr: 0x3c0,
        ..Default::default()
    };
    suspend_frame.x[8] = 133;
    suspend_frame.x[0] = empty_mask_buf.arg();
    suspend_frame.x[1] = 8;
    let suspend_route = arm_call(fixture, sib_control, &mut service, &mut suspend_frame).unwrap();
    assert!(matches!(
        suspend_route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(suspend_frame.x[0] as i64, -4);

    let mut delivery_native = native;
    delivery_native.pc = 0x40_0020;
    delivery_native.x[0] = suspend_frame.x[0];
    crate::native_process_runtime::host_test_support::observe_return_copyouts();
    let action = crate::dispatch::arm_signal_user_return_entry(
        source,
        &fixture.task,
        &delivery_native,
        ttbr0,
        fixture.page,
        sib_control,
        (suspend_frame.esr, suspend_frame.x[0]),
        true,
        &mut service,
        |process| {
            crate::arm_signal::deliver_on_user_return_at(
                &fixture.task,
                sib_control,
                process,
                &mut suspend_frame,
                |_, _| main_sp_top,
            )
        },
    )
    .unwrap();
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(suspend_frame.elr, 0x70_0000);
    assert_eq!(suspend_frame.x[0], 23);
    let writes = crate::native_process_runtime::host_test_support::take_return_copyouts();
    assert_eq!(writes.len(), 1);
    let written_sp = writes[0].0.raw();
    assert!(
        written_sp >= alt_stack.va().raw() && written_sp < alt_top.raw(),
        "SA_ONSTACK signal frame must land on alt_stack ({:#x}..{:#x}), got {written_sp:#x}",
        alt_stack.va().raw(),
        alt_top.raw()
    );
    let offset = usize::try_from(written_sp - alt_stack.va().raw()).unwrap();
    let sigframe = carrick_personality_linux::signal::arm::SignalFrame::read_from_bytes(
        &alt_stack.as_bytes()[offset
            ..offset + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
    )
    .unwrap();
    let saved_sigmask = sigframe.rt.ucontext.uc_sigmask;
    assert_eq!(saved_sigmask, orig_mask.signals().bits());

    // Another non-parking EL1 syscall by sibling drops AdmissionHome again, and leader's
    // subsequent tgkill still succeeds.
    let mut gettid_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0030,
        spsr: 0x3c0,
        ..Default::default()
    };
    gettid_frame.x[8] = 178;
    arm_call(fixture, sib_control, &mut service, &mut gettid_frame).unwrap();
    assert_eq!(gettid_frame.x[0], 42);
    assert!(
        fixture
            .zone
            .live(sib_control.zone_record().unwrap())
            .is_none()
    );

    run_as_leader(fixture);
    let mut tgkill2 = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0040,
        spsr: 0x3c0,
        ..Default::default()
    };
    tgkill2.x[8] = 131;
    tgkill2.x[0] = 41;
    tgkill2.x[1] = 42;
    tgkill2.x[2] = 23;
    arm_call(fixture, fixture.control, &mut service, &mut tgkill2).unwrap();
    assert_eq!(tgkill2.x[0], 0);

    // Negative control: once host retires the pool-born sibling, tgkill returns -ESRCH.
    let _reserved =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sib_control)
            .unwrap();
    let mut tgkill_retired = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0050,
        spsr: 0x3c0,
        ..Default::default()
    };
    tgkill_retired.x[8] = 131;
    tgkill_retired.x[0] = 41;
    tgkill_retired.x[1] = 42;
    tgkill_retired.x[2] = 0;
    arm_call(fixture, fixture.control, &mut service, &mut tgkill_retired).unwrap();
    assert_eq!(
        tgkill_retired.x[0] as i64,
        carrick_syscall_abi::LINUX_ESRCH.guest_retval()
    );
}
