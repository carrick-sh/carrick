use super::*;
use crate::native_process_runtime::host_test_support::{Physical, take_signal_copies};
use carrick_el1::substrate::sched::{Sched, Served};
use carrick_el1_abi::Lifecycle;
use carrick_personality_linux::signal::{
    ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
};
use carrick_sched_core::WakeEffects;
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
            crate::sched::ThreadCpu::save(
                &mut cpu,
                &frame,
                &mut peer_context,
                crate::sched::CpuExitCause::Svc,
            );
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
                    crate::sched::ThreadCpu::save(
                        &mut cpu,
                        frame,
                        &mut checkpoint_context,
                        crate::sched::CpuExitCause::Svc,
                    );
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalFrameWaitMode {
    OwnerWaitParksThenDelivers,
    OwnerWaitReleasedBeforeProbe,
    BusyOnceParksThenDelivers,
}

fn run_arm_signal_user_return_wait_witness(mode: SignalFrameWaitMode) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
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
    fixture.control.bind_zone_record(member);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, owner_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        owner_record
    );
    run_as_leader(fixture);

    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let altstack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut service = fixture.process_service();
    let ttbr0 = fixture_ttbr0(fixture);
    let task: &'static CurrentTask = &fixture.task;
    let usr1 = Signal::from_number(10).unwrap();
    fixture
        .control
        .write_altstack(carrick_personality_linux::abi::thread::AltStack {
            sp: altstack.arg(),
            size: altstack.len() as u64,
            flags: 0,
        });

    {
        let words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        with_process_entry(
            source,
            task,
            &words.native,
            ttbr0,
            fixture.page,
            fixture.control,
            &mut service,
            |entry| {
                entry
                    .rt_sigaction(
                        Signal::SEGV,
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x72_0000)),
                            flags: carrick_signal_core::policy::ActionFlags {
                                siginfo: true,
                                on_stack: true,
                                ..Default::default()
                            },
                            restorer: Some(carrick_signal_core::policy::RestorerAddress(0x73_0000)),
                            ..Default::default()
                        }),
                    )
                    .unwrap();
                entry
                    .rt_sigaction(
                        usr1,
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                            flags: carrick_signal_core::policy::ActionFlags {
                                reset_hand: true,
                                restart: true,
                                ..Default::default()
                            },
                            restorer: Some(carrick_signal_core::policy::RestorerAddress(0x71_0000)),
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
    }

    let handle = crate::cow_resolver::admitted_fault_mm_handle(
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        fixture.slot,
        task,
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

    let mut held_editor = None;
    let injected_wait = match mode {
        SignalFrameWaitMode::OwnerWaitParksThenDelivers => {
            let observed = notifications
                .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
            let editor = access
                .try_begin_edit_bounded(index, handle.mm().raw(), NonZeroU64::new(91).unwrap(), 0)
                .unwrap();
            held_editor = Some(editor);
            Some(unsafe {
                carrick_core_abi::PortalOwnerWait::from_owner(
                    handle,
                    carrick_core_abi::PortalWaitCause::Editor,
                    observed.revision(),
                )
            })
        }
        SignalFrameWaitMode::OwnerWaitReleasedBeforeProbe => {
            let observed = notifications
                .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
            let editor = access
                .try_begin_edit_bounded(index, handle.mm().raw(), NonZeroU64::new(92).unwrap(), 0)
                .unwrap();
            let wait = unsafe {
                carrick_core_abi::PortalOwnerWait::from_owner(
                    handle,
                    carrick_core_abi::PortalWaitCause::Editor,
                    observed.revision(),
                )
            };
            drop(editor);
            Some(wait)
        }
        SignalFrameWaitMode::BusyOnceParksThenDelivers => None,
    };

    // A released-before-probe holder is refused on every attempt until
    // `RELEASED_REFUSALS` are spent: a checkpoint that rebuilt in place would
    // spend them all inside one lease.
    const RELEASED_REFUSALS: usize = 64;
    let refusals_left = std::rc::Rc::new(core::cell::Cell::new(match mode {
        SignalFrameWaitMode::OwnerWaitReleasedBeforeProbe => RELEASED_REFUSALS,
        _ => 1,
    }));
    let frame_copy_attempts = std::rc::Rc::new(core::cell::Cell::new(0usize));
    crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| {
        let refusals_left = refusals_left.clone();
        let frame_copy_attempts = frame_copy_attempts.clone();
        *hook.borrow_mut() = Some(Box::new(move |_, _, _, bytes, _| {
            if bytes.is_some() {
                frame_copy_attempts.set(frame_copy_attempts.get() + 1);
            }
            if bytes.is_some() && refusals_left.get() > 0 {
                refusals_left.set(refusals_left.get() - 1);
                return Some(Err(match mode {
                    SignalFrameWaitMode::OwnerWaitParksThenDelivers
                    | SignalFrameWaitMode::OwnerWaitReleasedBeforeProbe => {
                        NativeProcessError::OwnerWait(injected_wait.unwrap())
                    }
                    SignalFrameWaitMode::BusyOnceParksThenDelivers => NativeProcessError::Busy,
                }));
            }
            None
        }));
    });
    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| *hook.borrow_mut() = None);
        }
    }
    let _clear = ClearHook;

    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0xfffe,
        elr: 0x40_0004,
        far: 0x99,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    frame.x[8] = 63; // SYS_read
    frame.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
    let sp_top = stack.va_at(stack.len());

    let run_checkpoint = |service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
                          frame: &mut carrick_el1_abi::TrapFrame| {
        let mut saved = Box::new(Aarch64ParkedContext::ZERO);
        crate::sched::ThreadCpu::save(
            &mut crate::sched::FakeCpu::default(),
            frame,
            &mut saved,
            crate::sched::CpuExitCause::Svc,
        );
        saved.native.sp_el0 = sp_top.raw();
        crate::dispatch::arm_signal_user_return_entry(
            source,
            task,
            &saved.native,
            ttbr0,
            fixture.page,
            fixture.control,
            service,
            |process| {
                crate::arm_signal::deliver_on_user_return_at(
                    task,
                    fixture.control,
                    process,
                    frame,
                    |_, _| sp_top,
                )
            },
        )
        .unwrap()
    };

    let first_action = run_checkpoint(&mut service, &mut frame);
    match mode {
        SignalFrameWaitMode::OwnerWaitReleasedBeforeProbe => {
            // Each checkpoint makes one frame-copy attempt, then returns its
            // owned continuation and releases the lease; the released holder
            // resumes through normal re-entry, never an in-place rebuild.
            let mut action = first_action;
            let mut checkpoints = 1;
            assert_eq!(
                frame_copy_attempts.get(),
                1,
                "the first checkpoint lease made more than one frame-copy attempt"
            );
            while action != carrick_el1_abi::Action::Served {
                assert_eq!(
                    action,
                    carrick_el1_abi::Action::Idle,
                    "released holder must park the checkpoint (elr={:#x})",
                    frame.elr
                );
                assert_eq!(
                    frame_copy_attempts.get(),
                    checkpoints,
                    "one checkpoint lease made more than one frame-copy attempt"
                );
                assert!(
                    fixture.zone.slot(fixture.slot).current().is_none(),
                    "a released-holder wait must release the vCPU execution lease"
                );
                assert!(checkpoints <= RELEASED_REFUSALS, "re-entry never converged");
                // The owner checkpoint re-enters on the carrier's ACK, the
                // same path a transient Busy takes.
                let notice = fixture
                    .task
                    .service_notice
                    .take()
                    .expect("service_notice cell")
                    .expect("CarrierWork service notice published");
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
                let ticket = unsafe {
                    carrick_core_abi::service::ServiceCell::claim_notice(
                        &fixture.control.service,
                        notice,
                        NonZeroU64::MIN,
                        fixture.zone.record(owner_record).identity(),
                    )
                }
                .unwrap();
                assert!(ticket.complete(true).is_ok());
                queue
                    .notify_object(fixture.slot, &mut WakeEffects::default())
                    .unwrap();
                drop(queue);
                let counters = carrick_el1_abi::Counters::new();
                let mut cpu = ResumeCpu {
                    inner: crate::sched::FakeCpu {
                        ttbr: (ttbr0, ttbr0),
                        ..Default::default()
                    },
                    runtime: &runtime,
                    registry: registry(),
                    source,
                    task,
                    service: &mut service,
                };
                assert_eq!(
                    (Sched {
                        handoff: None,
                        zone: fixture.zone,
                        slot: fixture.slot,
                        task,
                        cpu: &mut cpu,
                        user: &crate::sched::HardwareUserWord,
                        counters: &counters,
                    })
                    .run_next(&mut frame, 0),
                    Served::Returned { switched: true }
                );
                action = run_checkpoint(&mut service, &mut frame);
                checkpoints += 1;
            }
            assert_eq!(
                frame_copy_attempts.get(),
                RELEASED_REFUSALS + 1,
                "every refusal costs exactly one attempt in its own lease"
            );
        }
        SignalFrameWaitMode::OwnerWaitParksThenDelivers => {
            assert_eq!(
                first_action,
                carrick_el1_abi::Action::Idle,
                "owner contention on signal frame write must park instead of forcing SIGSEGV (elr={:#x})",
                frame.elr
            );
            assert!(
                fixture.zone.slot(fixture.slot).current().is_none(),
                "parked signal delivery must release the vCPU execution lease"
            );
            assert!(
                fixture.zone.runnable_head(fixture.slot).is_none(),
                "owner wait must enrol on holder release rather than busy-requeueing"
            );
            drop(held_editor.take());
            assert_eq!(
                fixture.zone.runnable_head(fixture.slot),
                Some(owner_record),
                "releasing the address-space editor must wake the enrolled signal waiter"
            );
            let counters = carrick_el1_abi::Counters::new();
            let mut cpu = ResumeCpu {
                inner: crate::sched::FakeCpu {
                    ttbr: (ttbr0, ttbr0),
                    ..Default::default()
                },
                runtime: &runtime,
                registry: registry(),
                source,
                task,
                service: &mut service,
            };
            assert_eq!(
                (Sched {
                    handoff: None,
                    zone: fixture.zone,
                    slot: fixture.slot,
                    task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters: &counters,
                })
                .run_next(&mut frame, 0),
                Served::Returned { switched: true }
            );
            assert_eq!(
                run_checkpoint(&mut service, &mut frame),
                carrick_el1_abi::Action::Served
            );
        }
        SignalFrameWaitMode::BusyOnceParksThenDelivers => {
            assert_eq!(
                first_action,
                carrick_el1_abi::Action::Idle,
                "transient Busy on signal frame write must park instead of forcing SIGSEGV (elr={:#x})",
                frame.elr
            );
            assert!(fixture.zone.slot(fixture.slot).current().is_none());
            let notice = fixture
                .task
                .service_notice
                .take()
                .expect("service_notice cell")
                .expect("CarrierWork service notice published");
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
                    &fixture.control.service,
                    notice,
                    NonZeroU64::MIN,
                    fixture.zone.record(owner_record).identity(),
                )
            }
            .unwrap();
            assert!(ticket.complete(true).is_ok());
            queue
                .notify_object(fixture.slot, &mut WakeEffects::default())
                .unwrap();
            drop(queue);
            let counters = carrick_el1_abi::Counters::new();
            let mut cpu = ResumeCpu {
                inner: crate::sched::FakeCpu {
                    ttbr: (ttbr0, ttbr0),
                    ..Default::default()
                },
                runtime: &runtime,
                registry: registry(),
                source,
                task,
                service: &mut service,
            };
            assert_eq!(
                (Sched {
                    handoff: None,
                    zone: fixture.zone,
                    slot: fixture.slot,
                    task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters: &counters,
                })
                .run_next(&mut frame, 0),
                Served::Returned { switched: true }
            );
            assert_eq!(
                run_checkpoint(&mut service, &mut frame),
                carrick_el1_abi::Action::Served
            );
        }
    }

    assert_eq!(
        frame.elr, 0x70_0000,
        "original SIGUSR1 handler must run (not SIGSEGV at 0x72_0000)"
    );
    assert_eq!(frame.x[0], 10, "x0 must carry SIGUSR1");
    assert_eq!(frame.x[30], 0x71_0000, "x30 must carry SA_RESTORER");

    let written_sp = sp_top.raw()
        - (core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>() as u64);
    let written_sp = written_sp & !15;
    let offset = (written_sp - stack.arg()) as usize;
    let sigframe: carrick_personality_linux::signal::arm::SignalFrame =
        zerocopy::FromBytes::read_from_bytes(
            &stack.as_bytes()[offset
                ..offset
                    + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
        )
        .unwrap();
    let saved_pc = { sigframe.rt.ucontext.uc_mcontext.pc };
    let saved_x0 = { sigframe.rt.ucontext.uc_mcontext.regs[0] };
    assert_eq!(
        saved_pc, 0x40_0000,
        "SA_RESTART must rewind saved PC exactly once"
    );
    assert_eq!(
        saved_x0, 0x99,
        "SA_RESTART must restore original syscall arg0 in saved frame"
    );

    {
        let words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        let old = with_process_entry(
            source,
            task,
            &words.native,
            ttbr0,
            fixture.page,
            fixture.control,
            &mut service,
            |entry| entry.rt_sigaction(usr1, None).unwrap(),
        )
        .unwrap();
        assert_eq!(old.disposition, Disposition::Default);
    }
    frame.esr = 0x5600_0000;
    assert_eq!(
        run_checkpoint(&mut service, &mut frame),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(frame.elr, 0x70_0000, "signal must not be delivered twice");
}

#[test]
fn arm_signal_user_return_owner_wait_once_parks_and_delivers_original_signal() {
    run_arm_signal_user_return_wait_witness(SignalFrameWaitMode::OwnerWaitParksThenDelivers);
}

#[test]
fn arm_signal_user_return_owner_wait_released_before_probe_delivers_inline() {
    run_arm_signal_user_return_wait_witness(SignalFrameWaitMode::OwnerWaitReleasedBeforeProbe);
}

#[test]
fn arm_signal_user_return_busy_once_parks_and_delivers_original_signal() {
    run_arm_signal_user_return_wait_witness(SignalFrameWaitMode::BusyOnceParksThenDelivers);
}

#[test]
fn signal_stack_real_fault_forces_sigsegv_with_oracle_si_code_128() {
    for read_only in [false, true] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        fixture.zone.spaces.set_idle_ttbr(0x30000);
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
        fixture.control.bind_zone_record(member);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, owner_record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            owner_record
        );
        run_as_leader(fixture);

        let ro_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
        let altstack = carrick_test_support::GuestUserBuffer::zeroed(16384);
        let mut service = fixture.process_service();
        let ttbr0 = fixture_ttbr0(fixture);
        let task: &'static CurrentTask = &fixture.task;
        let bad_sp = if read_only {
            ro_stack.va_at(ro_stack.len())
        } else {
            UserVa::new(0x0000_0000_0000_2000)
        };
        let usr1 = Signal::from_number(10).unwrap();
        fixture
            .control
            .write_altstack(carrick_personality_linux::abi::thread::AltStack {
                sp: altstack.arg(),
                size: altstack.len() as u64,
                flags: 0,
            });

        {
            let words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
            with_process_entry(
                source,
                task,
                &words.native,
                ttbr0,
                fixture.page,
                fixture.control,
                &mut service,
                |entry| {
                    entry
                        .rt_sigaction(
                            Signal::SEGV,
                            Some(Action {
                                disposition: Disposition::Handler(HandlerAddress(0x72_0000)),
                                flags: carrick_signal_core::policy::ActionFlags {
                                    siginfo: true,
                                    on_stack: true,
                                    ..Default::default()
                                },
                                restorer: Some(carrick_signal_core::policy::RestorerAddress(
                                    0x73_0000,
                                )),
                                ..Default::default()
                            }),
                        )
                        .unwrap();
                    entry
                        .rt_sigaction(
                            usr1,
                            Some(Action {
                                disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                                restorer: Some(carrick_signal_core::policy::RestorerAddress(
                                    0x71_0000,
                                )),
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
        }

        let ro_start = ro_stack.arg();
        let ro_end = ro_start + ro_stack.len() as u64;
        let unmapped_limit = 0x1_0000_u64;
        crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_, address, _, bytes, _| {
                if bytes.is_some() {
                    if read_only && address.raw() >= ro_start && address.raw() < ro_end {
                        return Some(Err(NativeProcessError::Fault));
                    }
                    if !read_only && address.raw() < unmapped_limit {
                        return Some(Err(NativeProcessError::Fault));
                    }
                }
                None
            }));
        });
        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _clear = ClearHook;

        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x5600_0000,
            elr: 0x40_0004,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        let mut saved = Box::new(Aarch64ParkedContext::ZERO);
        crate::sched::ThreadCpu::save(
            &mut crate::sched::FakeCpu::default(),
            &frame,
            &mut saved,
            crate::sched::CpuExitCause::Svc,
        );
        saved.native.sp_el0 = bad_sp.raw();
        let action = crate::dispatch::arm_signal_user_return_entry(
            source,
            task,
            &saved.native,
            ttbr0,
            fixture.page,
            fixture.control,
            &mut service,
            |process| {
                crate::arm_signal::deliver_on_user_return_at(
                    task,
                    fixture.control,
                    process,
                    &mut frame,
                    |_, _| bad_sp,
                )
            },
        )
        .unwrap();
        assert_eq!(action, carrick_el1_abi::Action::Served);
        assert_eq!(
            frame.elr, 0x72_0000,
            "real fault on signal stack (read_only={read_only}) must force SIGSEGV handler"
        );
        assert_eq!(frame.x[0], 11, "x0 must carry SIGSEGV (11)");
        let info_offset = (frame.x[1] - altstack.arg()) as usize;
        let siginfo: carrick_syscall_abi::LinuxSiginfo = zerocopy::FromBytes::read_from_bytes(
            &altstack.as_bytes()[info_offset
                ..info_offset + core::mem::size_of::<carrick_syscall_abi::LinuxSiginfo>()],
        )
        .unwrap();
        let si_signo = { siginfo.si_signo };
        let si_code = { siginfo.si_code };
        let si_addr = { siginfo.si_addr };
        assert_eq!(si_signo, 11);
        assert_eq!(
            si_code, 128,
            "Linux setup_rt_frame force_sigsegv sets SI_KERNEL (128)"
        );
        assert_eq!(si_addr, 0);
    }
}

/// How long one blocking wait may last before the test fails. It bounds a
/// lost wake; it is not a throughput budget, so it restarts for every wait.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Host-thread analogue of the carrier's idle wait for the two-thread
/// witness. Each thread publishes after every attempt, served or refused,
/// which is after any editor or reservation guard it held has been released
/// and its production wake delivered. A thread that was refused blocks until its
/// predicate holds; there is no spinning or sleeping, and a wake that never
/// comes fails the test at `WAIT_BOUND`.
struct ReleaseSignal {
    published: std::sync::Mutex<u64>,
    changed: std::sync::Condvar,
}

impl ReleaseSignal {
    fn new() -> Self {
        Self {
            published: std::sync::Mutex::new(0),
            changed: std::sync::Condvar::new(),
        }
    }

    fn publish(&self) {
        *self.published.lock().unwrap() += 1;
        self.changed.notify_all();
    }

    fn seen(&self) -> u64 {
        *self.published.lock().unwrap()
    }

    fn wait_until(&self, what: &str, mut ready: impl FnMut(u64) -> bool) {
        let guard = self.published.lock().unwrap();
        let (_guard, result) = self
            .changed
            .wait_timeout_while(guard, WAIT_BOUND, |count| !ready(*count))
            .unwrap();
        assert!(!result.timed_out(), "{what}: release never arrived");
    }
}

#[test]
fn two_threads_concurrent_mmap_munmap_delivers_thousand_signals_without_sigsegv() {
    use carrick_core::mm::transaction::{SelectionVenues, UserWriteRequest, UserWriteVenue};
    use carrick_core::mm::transfer::ValidatedChunk;
    use carrick_el1::fault::{NoopCowResolver, NoopPreparedResolver};
    use carrick_el1_abi::{
        FrameGrantResidencyTable, PortalGrantWindow, ReservationNodeFlags, ReservationProtection,
        ReservationRange,
    };
    use carrick_mmu_core::aarch64::GuestLeafPublication;
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan, TableGrants,
        execute_descriptor_op,
    };

    struct StackWriteVenue {
        prepared: NoopPreparedResolver,
        cow: NoopCowResolver,
        residency: Box<FrameGrantResidencyTable>,
        stack_ipa_base: u64,
        bytes: Vec<u8>,
    }
    impl UserWriteVenue<Aarch64ParkedContext> for StackWriteVenue {
        type Prepared = NoopPreparedResolver;
        type Cow = NoopCowResolver;
        type Error = NativeProcessError;
        fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow> {
            SelectionVenues {
                prepared: &mut self.prepared,
                cow: &mut self.cow,
                residency: &self.residency,
                slot: 0,
            }
        }
        fn settle_completions(
            &mut self,
            _: &UserWriteRequest<'_>,
        ) -> Result<(), NativeProcessError> {
            Ok(())
        }
        fn supply_cow(&mut self, _: PortalGrantWindow) -> Result<(), NativeProcessError> {
            panic!("private stack pages must not request COW supply")
        }
        fn copy(&mut self, fence: &ValidatedChunk<'_, Aarch64ParkedContext>, src: &[u8]) -> bool {
            let chunk = fence.selected();
            let offset = (chunk.ipa - self.stack_ipa_base) as usize;
            self.bytes[offset..offset + src.len()].copy_from_slice(src);
            true
        }
    }

    struct UnbackedMmapMemory<'a> {
        tables: &'a crate::mm_portal::test_support::Tables,
    }
    impl carrick_el1::memory::AnonymousBackingProbe for UnbackedMmapMemory<'_> {
        fn backing(
            &mut self,
            _: carrick_guest_arch::AddressSpaceRegister,
            _: UserVa,
            _: carrick_guest_arch::GuestLen,
        ) -> carrick_el1::memory::Stage1Backing {
            carrick_el1::memory::Stage1Backing::of(carrick_el1::memory::RangeBacking::Empty)
        }
        fn stock_span(
            &mut self,
            _: ReservationMm,
            _: UserVa,
        ) -> Option<carrick_guest_arch::UserRange> {
            None
        }
    }
    impl carrick_el1::memory::AnonymousPermissionEditor for UnbackedMmapMemory<'_> {
        fn protect_and_invalidate(
            &mut self,
            _root: carrick_guest_arch::AddressSpaceRegister,
            edit: carrick_mmu_core::aarch64::GuestPermissionEdit,
        ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
            unsafe {
                carrick_mmu_core::aarch64::protect_existing_el1_private_pages(
                    self.tables.words.as_ptr().cast_mut(),
                    self.tables.base,
                    self.tables.words.len() * 8,
                    None,
                    edit,
                )
            }
            .map(|_| ())
        }
    }
    impl carrick_el1::memory::AnonymousRetirementEditor for UnbackedMmapMemory<'_> {
        fn retire_and_invalidate(
            &mut self,
            _: ReservationMm,
            _: carrick_guest_arch::AddressSpaceRegister,
            _: UserVa,
            _: carrick_guest_arch::GuestLen,
        ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
            Ok(())
        }
    }

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
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
    fixture.control.bind_zone_record(member);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, owner_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        owner_record
    );
    run_as_leader(fixture);

    let root_gpa = fixture.address.root.address().raw();
    let stack_va = crate::mm_portal::test_support::VA;
    let stack_len = 4 * 4096_u64;
    let one = NonZeroU64::MIN;
    for word in &fixture.tables.words[1536..1536 + 4] {
        word.store(0, Ordering::Relaxed);
    }
    assert!(matches!(
        execute_descriptor_op(
            &fixture.tables.live(&fixture.maintenance),
            carrick_mmu_core::aarch64::SubstrateGpa(root_gpa),
            DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: stack_va,
                    ipa: crate::mm_portal::test_support::IPA,
                    len: stack_len,
                    writable: true,
                    executable: false,
                },
                resident: PageSpan::new(stack_va, stack_len),
                backing: BackingIdentity {
                    frame_id: one,
                    mapping_id: one,
                    owner_generation: one,
                    inventory_revision: one,
                },
            },
            &TableGrants::NONE,
            &mut InlineJournal::new(),
        ),
        DescriptorOutcome::Applied(_)
    ));
    let portal = Box::leak(Box::new(crate::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    )));
    let mm_key = ReservationMm::new(fixture.address.mm.raw().get()).unwrap();
    {
        let mut root = portal.root(mm_key, u32::from(fixture.slot.raw())).unwrap();
        let range = ReservationRange::new(stack_va, stack_va + stack_len).unwrap();
        let _ = root.retire_opaque(range);
        root.insert_opaque(
            range,
            ReservationProtection::READ_WRITE,
            ReservationNodeFlags::PRIVATE,
        )
        .unwrap();
    }

    let altstack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut service = fixture.process_service();
    let ttbr0 = fixture_ttbr0(fixture);
    let task: &'static CurrentTask = &fixture.task;
    let sp_top = UserVa::new(stack_va + stack_len);
    let usr1 = Signal::from_number(10).unwrap();
    fixture
        .control
        .write_altstack(carrick_personality_linux::abi::thread::AltStack {
            sp: altstack.arg(),
            size: altstack.len() as u64,
            flags: 0,
        });

    {
        let words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        with_process_entry(
            source,
            task,
            &words.native,
            ttbr0,
            fixture.page,
            fixture.control,
            &mut service,
            |entry| {
                entry
                    .rt_sigaction(
                        Signal::SEGV,
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x72_0000)),
                            flags: carrick_signal_core::policy::ActionFlags {
                                siginfo: true,
                                on_stack: true,
                                ..Default::default()
                            },
                            restorer: Some(carrick_signal_core::policy::RestorerAddress(0x73_0000)),
                            ..Default::default()
                        }),
                    )
                    .unwrap();
                entry
                    .rt_sigaction(
                        usr1,
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x70_0000)),
                            restorer: Some(carrick_signal_core::policy::RestorerAddress(0x71_0000)),
                            ..Default::default()
                        }),
                    )
                    .unwrap();
            },
        )
        .unwrap();
    }

    let sibling_slot = SlotId::new(1);
    fixture.zone.drive(sibling_slot, 2);
    fixture.zone.publish_slot(sibling_slot, 1, Some(1), 1);
    fixture.zone.enter_guest(sibling_slot);
    fixture
        .zone
        .install_space(sibling_slot, mm_key.raw())
        .unwrap();
    let (peer_control, peer) = imported_thread_on_slot(fixture, sibling_slot, |id| {
        id.affinity = 1 << sibling_slot.raw();
    });
    assert_eq!(
        fixture.zone.switch_in_full(sibling_slot).unwrap().record,
        peer.id
    );
    let sibling_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling_slot,
    };
    let sibling_task: &'static CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    sibling_task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        fixture.leader.file_table,
    );
    sibling_task.mm.key.store(mm_key.raw(), Ordering::Release);
    sibling_task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    sibling_task.publish_visible_pid(41);
    sibling_task.publish_root_generation(fixture.address.generation);
    sibling_task.publish_lifecycle(
        fixture.page as *const _ as u64,
        peer_control as *const _ as u64,
    );
    let peer_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let peer_sp_top = peer_stack.va_at(peer_stack.len());
    // SAFETY: switch_in_full gave sibling_slot exclusive custody of peer.id.
    unsafe {
        let context = fixture.zone.record(peer.id).ctx_mut();
        context.native.pc = 0x50_0004;
        context.native.sp_el0 = peer_sp_top.raw();
    }
    registry()
        .register_thread(
            sibling_source,
            sibling_task,
            fixture.address,
            fixture.page,
            peer_control,
        )
        .unwrap();

    let done = core::sync::atomic::AtomicBool::new(false);
    let mmap_cycles = AtomicUsize::new(0);
    let parked_waits = AtomicUsize::new(0);
    let releases = ReleaseSignal::new();

    std::thread::scope(|scope| {
        let done_ref = &done;
        struct StopMapper<'a>(&'a core::sync::atomic::AtomicBool);
        impl Drop for StopMapper<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _stop_mapper = StopMapper(done_ref);
        let mmap_cycles_ref = &mmap_cycles;
        let releases_ref = &releases;
        let leader_slot = fixture.slot;
        let mapper_tables = &fixture.tables;
        let mapper_zone = fixture.zone;
        let mapper_reservations = fixture.region.table();
        let mapper_page = fixture.page;
        let mapper = scope.spawn(move || {
            let counters = Box::new(carrick_el1_abi::Counters::new());
            let mut sibling_service = Aarch64NativeProcessService::with_crossing(
                sibling_task,
                sibling_slot,
                mapper_zone,
                mapper_reservations,
                NonZeroU64::MIN,
                TestStockCrossing::new(&[]),
            );
            let mut peer_saved = Box::new(Aarch64ParkedContext::ZERO);
            let mut memory = UnbackedMmapMemory {
                tables: mapper_tables,
            };
            while !done_ref.load(Ordering::Acquire) {
                let access = crate::sched::object_wait::space_access(mapper_zone, sibling_slot);
                let mut map_frame = carrick_el1_abi::TrapFrame {
                    esr: 0x5600_0000,
                    elr: 0x50_0004,
                    slot: u64::from(sibling_slot.raw()),
                    ..Default::default()
                };
                map_frame.x[8] = 222;
                map_frame.x[..6].copy_from_slice(&[0, 4096, 3, 0x22, u64::MAX, 0]);
                let mapped = carrick_el1::memory::serve_delegated_anonymous(
                    &mut map_frame,
                    &counters,
                    sibling_task,
                    access,
                    mapper_reservations,
                    &mut memory,
                    None,
                );
                if mapped == carrick_el1::memory::DelegatedAnonymous::Served {
                    let mapped_va = map_frame.x[0];
                    assert!(
                        (mapped_va as i64) > 0,
                        "concurrent mmap returned error {mapped_va:#x}"
                    );
                    *peer_saved = Aarch64ParkedContext::ZERO;
                    crate::sched::ThreadCpu::save(
                        &mut crate::sched::FakeCpu::default(),
                        &map_frame,
                        &mut peer_saved,
                        crate::sched::CpuExitCause::Svc,
                    );
                    peer_saved.native.sp_el0 = peer_sp_top.raw();
                    assert_eq!(
                        crate::dispatch::arm_signal_user_return_entry(
                            sibling_source,
                            sibling_task,
                            &peer_saved.native,
                            ttbr0,
                            mapper_page,
                            peer_control,
                            &mut sibling_service,
                            |process| {
                                crate::arm_signal::deliver_on_user_return_at(
                                    sibling_task,
                                    peer_control,
                                    process,
                                    &mut map_frame,
                                    |_, _| peer_sp_top,
                                )
                            },
                        )
                        .unwrap(),
                        carrick_el1_abi::Action::Served
                    );
                    assert_eq!(map_frame.elr, 0x50_0004);
                    releases_ref.publish();
                    loop {
                        let access =
                            crate::sched::object_wait::space_access(mapper_zone, sibling_slot);
                        let mut unmap_frame = carrick_el1_abi::TrapFrame {
                            esr: 0x5600_0000,
                            elr: 0x50_0004,
                            slot: u64::from(sibling_slot.raw()),
                            ..Default::default()
                        };
                        unmap_frame.x[8] = 215;
                        unmap_frame.x[0] = mapped_va;
                        unmap_frame.x[1] = 4096;
                        match carrick_el1::memory::serve_delegated_anonymous(
                            &mut unmap_frame,
                            &counters,
                            sibling_task,
                            access,
                            mapper_reservations,
                            &mut memory,
                            None,
                        ) {
                            carrick_el1::memory::DelegatedAnonymous::Served => {
                                assert_eq!(unmap_frame.x[0], 0);
                                *peer_saved = Aarch64ParkedContext::ZERO;
                                crate::sched::ThreadCpu::save(
                                    &mut crate::sched::FakeCpu::default(),
                                    &unmap_frame,
                                    &mut peer_saved,
                                    crate::sched::CpuExitCause::Svc,
                                );
                                peer_saved.native.sp_el0 = peer_sp_top.raw();
                                assert_eq!(
                                    crate::dispatch::arm_signal_user_return_entry(
                                        sibling_source,
                                        sibling_task,
                                        &peer_saved.native,
                                        ttbr0,
                                        mapper_page,
                                        peer_control,
                                        &mut sibling_service,
                                        |process| {
                                            crate::arm_signal::deliver_on_user_return_at(
                                                sibling_task,
                                                peer_control,
                                                process,
                                                &mut unmap_frame,
                                                |_, _| peer_sp_top,
                                            )
                                        },
                                    )
                                    .unwrap(),
                                    carrick_el1_abi::Action::Served
                                );
                                assert_eq!(unmap_frame.elr, 0x50_0004);
                                break;
                            }
                            carrick_el1::memory::DelegatedAnonymous::Contended(cause) => {
                                // Refused with nothing held: block until the
                                // other thread completes an operation.
                                // A refused attempt may itself drop guards and wake the peer.
                                releases_ref.publish();
                                let seen = releases_ref.seen();
                                releases_ref.wait_until(
                                    &format!("munmap of {mapped_va:#x} refused on {cause:?}"),
                                    |now| now > seen || done_ref.load(Ordering::Acquire),
                                );
                            }
                            other => {
                                panic!("unexpected munmap outcome {other:?} for {mapped_va:#x}");
                            }
                        }
                    }
                    mmap_cycles_ref.fetch_add(1, Ordering::Release);
                    releases_ref.publish();
                } else if let carrick_el1::memory::DelegatedAnonymous::Contended(cause) = mapped {
                    // A refused attempt may itself drop guards and wake the peer.
                    releases_ref.publish();
                    let seen = releases_ref.seen();
                    releases_ref.wait_until(&format!("mmap refused on {cause:?}"), |now| {
                        now > seen || done_ref.load(Ordering::Acquire)
                    });
                } else {
                    panic!("unexpected mmap outcome {mapped:?}");
                }
            }
        });

        releases.wait_until("mapper never started", |_| {
            mmap_cycles.load(Ordering::Acquire) > 0
        });

        let venue = core::cell::RefCell::new(StackWriteVenue {
            prepared: NoopPreparedResolver,
            cow: NoopCowResolver,
            residency: crate::mm_portal::test_support::residency(),
            stack_ipa_base: crate::mm_portal::test_support::IPA,
            bytes: vec![0; stack_len as usize],
        });
        let live_words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
        crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_, address, _, bytes, _| {
                let bytes = bytes?;
                if address.raw() < stack_va || address.raw() >= stack_va + stack_len {
                    return None;
                }
                let handle = portal
                    .admitted_handle(mm_key, u32::from(leader_slot.raw()))
                    .map_err(|err| {
                        NativeProcessError::from_user_write(
                            carrick_core::mm::transaction::UserWriteError::Owner(err),
                        )
                    });
                let handle = match handle {
                    Ok(handle) => handle,
                    Err(err) => return Some(Err(err)),
                };
                Some(
                    portal
                        .write_user_bytes(
                            UserWriteRequest {
                                handle,
                                address,
                                bytes,
                                slot: leader_slot,
                            },
                            live_words,
                            &mut *venue.borrow_mut(),
                        )
                        .map_err(NativeProcessError::from_user_write),
                )
            }));
        });
        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _clear = ClearHook;

        let counters = Box::new(carrick_el1_abi::Counters::new());
        let mut saved = Box::new(Aarch64ParkedContext::ZERO);
        let words = Box::new(Aarch64ParkedContext::from_parts(
            ThreadCtx::ZERO,
            fixture.address,
        ));
        for index in 0..1_000 {
            {
                with_process_entry(
                    source,
                    task,
                    &words.native,
                    ttbr0,
                    fixture.page,
                    fixture.control,
                    &mut service,
                    |entry| {
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
            }

            let mut frame = carrick_el1_abi::TrapFrame {
                esr: 0x5600_0000,
                elr: 0x40_0004,
                slot: u64::from(fixture.slot.raw()),
                ..Default::default()
            };
            loop {
                *saved = Aarch64ParkedContext::ZERO;
                crate::sched::ThreadCpu::save(
                    &mut crate::sched::FakeCpu::default(),
                    &frame,
                    &mut saved,
                    crate::sched::CpuExitCause::Svc,
                );
                saved.native.sp_el0 = sp_top.raw();
                let action = crate::dispatch::arm_signal_user_return_entry(
                    source,
                    task,
                    &saved.native,
                    ttbr0,
                    fixture.page,
                    fixture.control,
                    &mut service,
                    |process| {
                        crate::arm_signal::deliver_on_user_return_at(
                            task,
                            fixture.control,
                            process,
                            &mut frame,
                            |_, _| sp_top,
                        )
                    },
                )
                .unwrap();
                releases.publish();
                match action {
                    carrick_el1_abi::Action::Served => break,
                    carrick_el1_abi::Action::Idle => {
                        let _ = crate::sched::leave_space(
                            fixture.zone,
                            fixture.slot,
                            &mut crate::sched::FakeCpu::default(),
                        );
                        parked_waits.fetch_add(1, Ordering::Relaxed);
                        if let Ok(Some(notice)) = fixture.task.service_notice.take() {
                            let queue = fixture
                                .zone
                                .object_wait(
                                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(
                                        member,
                                    )
                                    .unwrap(),
                                    &carrick_sched_core::ShortLockSpin,
                                    &|owned| {
                                        crate::sched::object_wait::deliver_host_completion(
                                            owned.zone(),
                                            owned,
                                        )
                                    },
                                )
                                .unwrap();
                            let ticket = unsafe {
                                carrick_core_abi::service::ServiceCell::claim_notice(
                                    &fixture.control.service,
                                    notice,
                                    NonZeroU64::MIN,
                                    fixture.zone.record(owner_record).identity(),
                                )
                            }
                            .unwrap();
                            assert!(ticket.complete(true).is_ok());
                            queue
                                .notify_object(fixture.slot, &mut WakeEffects::default())
                                .unwrap();
                            drop(queue);
                        }
                        releases.wait_until(
                            &format!("signal {index} parked on contention was never woken"),
                            |_| {
                                matches!(
                                    fixture.zone.record(owner_record).claim(),
                                    carrick_sched_core::Claim::Queued { .. }
                                )
                            },
                        );
                        let mut cpu = ResumeCpu {
                            inner: crate::sched::FakeCpu {
                                ttbr: (ttbr0, ttbr0),
                                ..Default::default()
                            },
                            runtime: &runtime,
                            registry: registry(),
                            source,
                            task,
                            service: &mut service,
                        };
                        assert_eq!(
                            (Sched {
                                handoff: None,
                                zone: fixture.zone,
                                slot: fixture.slot,
                                task,
                                cpu: &mut cpu,
                                user: &crate::sched::HardwareUserWord,
                                counters: &counters,
                            })
                            .run_next(&mut frame, 0),
                            Served::Returned { switched: true }
                        );
                    }
                    other => panic!("unexpected signal checkpoint action {other:?}"),
                }
            }
            assert_eq!(
                frame.elr, 0x70_0000,
                "signal {index}/1000 forced SIGSEGV (elr={:#x}, x0={}) under concurrent mmap/munmap",
                frame.elr, frame.x[0]
            );
            assert_eq!(frame.x[0], 10);
            assert_ne!(fixture.control.blocked().0 & usr1.bit(), 0);
            fixture
                .control
                .init_blocked(carrick_el1_abi::BlockedMask(0));
        }

        done.store(true, Ordering::Release);
        releases.publish();
        mapper.join().unwrap();
    });
    assert!(mmap_cycles.load(Ordering::Acquire) > 0);
}
