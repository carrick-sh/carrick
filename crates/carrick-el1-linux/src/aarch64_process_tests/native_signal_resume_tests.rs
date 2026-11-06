use super::*;
use crate::native_process_runtime::host_test_support::{Physical, take_signal_copies};
use carrick_el1_abi::Lifecycle;
use carrick_personality_linux::signal::{
    ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
};
use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
use zerocopy::IntoBytes;

#[test]
fn arm_retained_sigprocmask_copyout_delivers_before_svc_user_return() {
    retained_signal_copy(false, false);
}

#[test]
fn arm_parked_signal_copyout_rejects_stale_owner_after_peer_selection() {
    retained_signal_copy(false, true);
}

#[test]
fn arm_parked_signal_input_rejects_stale_owner_after_peer_selection() {
    retained_signal_copy(true, true);
}

fn retained_signal_copy(input_wait: bool, check_stale: bool) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
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
    if input_wait {
        physical.prepare_copy_error = Some(NativeProcessError::OwnerWait(wait));
        // A blocked pending signal must remain blocked when input has not arrived.
    } else {
        physical.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    }
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
        if input_wait {
            crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
        } else {
            crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
        }
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
            Some(&*fixture),
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
        if check_stale {
            assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(peer_record));
            let original_blocked = peer_control.blocked();
            let original_pc = frame.elr;
            let original_x = frame.x;
            let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
            let selected = crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                peer_control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut ArmWaitSignalMachine {
                    user_sp: peer_stack.va_at(peer_stack.len()),
                    backend: ArmWaitSignalBackend,
                },
            );
            assert_eq!(
                selected, None,
                "a parked owner's signal must not enter its runnable peer"
            );
            assert_eq!(frame.elr, original_pc);
            assert_eq!(frame.x, original_x);
            assert_eq!(peer_control.blocked(), original_blocked);
            assert!(take_signal_copies().is_empty());
            assert!(
                runtime
                    .current_signals(&fixture.task)
                    .unwrap()
                    .pending_set(member)
                    .contains(signal),
                "wrong-owner checkpoint must leave A's pending signal untouched"
            );
            drop(entry);
            let mut peer_service = fixture.process_service();
            let mut peer_context = initial;
            crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut peer_context);
            let mut checkpoints = 0;
            assert_eq!(
                crate::dispatch::final_user_return(
                    &mut frame,
                    carrick_el1_abi::Action::Served,
                    |frame| {
                        checkpoints += 1;
                        let mut peer_entry = runtime
                            .enter_registered(
                                registry(),
                                source,
                                &fixture.task,
                                fixture.address,
                                &peer_context,
                                &mut peer_service,
                            )
                            .unwrap();
                        assert_eq!(
                            crate::signal_delivery::deliver_signal_on_syscall_return(
                                &fixture.task,
                                peer_control,
                                &mut peer_entry,
                                frame,
                                fp.as_bytes(),
                                &mut ArmWaitSignalMachine {
                                    user_sp: peer_stack.va_at(peer_stack.len()),
                                    backend: ArmWaitSignalBackend,
                                },
                            ),
                            None
                        );
                        carrick_el1_abi::Action::Served
                    },
                ),
                carrick_el1_abi::Action::Served
            );
            assert_eq!(
                checkpoints, 1,
                "SVC return must enter the freshly selected peer"
            );
            assert_eq!(frame.elr, original_pc);
            assert_eq!(frame.x, original_x);
            assert_eq!(peer_control.blocked(), original_blocked);
            assert!(take_signal_copies().is_empty());
            assert!(
                runtime
                    .current_signals(&fixture.task)
                    .unwrap()
                    .pending_set(member)
                    .contains(signal)
            );
            return;
        }
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
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        member.id
    );
    run_as_leader(fixture);
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
        assert!(
            matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), crate::native_process_runtime::NativeResume::Returned(result) if result.raw() == 0)
        );
    }
    let outputs = take_signal_copies();
    assert_eq!(outputs, [(oldset.va(), mask_bits.to_ne_bytes().to_vec())]);
    // The scheduler-selected record retains the original SVC context.
    // SAFETY: switch_in_full gave this lane exclusive OnCpu custody.
    let resumed_context = unsafe { *fixture.zone.record(member.id).ctx_mut() };
    crate::sched::ThreadCpu::load(&mut cpu, &mut frame, &resumed_context);
    frame.x[0] = 0;
    frame.esr = 0x54000000;
    let mut deliveries = 0;
    for _ in 0..2 {
        assert_eq!(
            crate::dispatch::final_user_return(
                &mut frame,
                carrick_el1_abi::Action::Served,
                |frame| {
                    let mut checkpoint_context = resumed_context;
                    crate::sched::ThreadCpu::save(&mut cpu, frame, &mut checkpoint_context);
                    let mut entry = runtime
                        .enter_registered(
                            registry(),
                            source,
                            &fixture.task,
                            fixture.address,
                            &checkpoint_context,
                            &mut physical,
                        )
                        .unwrap();
                    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
                    let route = crate::signal_delivery::deliver_signal_on_syscall_return(
                        &fixture.task,
                        control,
                        &mut entry,
                        frame,
                        fp.as_bytes(),
                        &mut ArmWaitSignalMachine {
                            user_sp: stack.va_at(stack.len()),
                            backend: ArmWaitSignalBackend,
                        },
                    );
                    assert_eq!(route, None);
                    deliveries += take_signal_copies().len();
                    carrick_el1_abi::Action::Served
                }
            ),
            carrick_el1_abi::Action::Served
        );
    }
    assert_eq!(
        frame.elr, 0x700000,
        "resumed SVC must build handler before returning to EL0"
    );
    assert_eq!(
        deliveries, 1,
        "retained copyout may not redeliver the signal"
    );
}
