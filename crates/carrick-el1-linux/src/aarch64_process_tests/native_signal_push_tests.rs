use super::*;
use crate::native_process_runtime::host_test_support::{
    Physical, take_signal_copies, take_signal_frames,
};
use carrick_el1_abi::Lifecycle;
use carrick_personality_linux::signal::{
    ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
};
use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

#[test]
fn signal_push_owner_wait_preserves_completed_return_and_suspend_mask() {
    parked_signal_push(false, false, false, false);
}

#[test]
fn synchronous_signal_push_owner_wait_delivers_once() {
    parked_signal_push(true, false, false, false);
}

#[test]
fn refused_signal_frame_fault_settles_once_without_syscall_replay() {
    parked_signal_push(true, true, false, false);
}

#[test]
fn signal_push_second_page_wait_does_not_replay_committed_prefix() {
    parked_signal_push(false, false, true, false);
}

#[test]
fn signal_push_busy_once_preserves_completed_return_and_delivers() {
    parked_signal_push(false, false, false, true);
}

fn parked_signal_push(synchronous: bool, refused_fault: bool, partial: bool, busy: bool) {
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
    let mut owner_record = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap()
        .record
        .id;
    if synchronous {
        let identity = fixture.zone.record(owner_record).identity();
        fixture.zone.discard_unpublished(fixture.slot, owner_record);
        owner_record = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
        let host_reference = fixture.zone.record_ref(owner_record);
        unsafe {
            *fixture.zone.record(owner_record).ctx_mut() = initial;
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
        assert!(!fixture.zone.record(owner_record).is_native_owned());
    }
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
    let signal = if synchronous {
        Signal::SEGV
    } else {
        Signal::PIPE
    };
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
        if !synchronous {
            entry
                .tgkill(
                    SignalThreadSelector::from_abi(41),
                    SignalThreadSelector::from_abi(41),
                    SignalRequest::from_abi(signal.number() as u64).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        }
    }
    control.arm_forwarded_wait_mask(
        carrick_el1_abi::BlockedMask(0),
        carrick_el1_abi::BlockedMask(Signal::PIPE.bit()),
    );
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
    physical.child_copy_error = Some(if refused_fault {
        NativeProcessError::Unsupported
    } else if busy {
        NativeProcessError::Busy
    } else {
        NativeProcessError::OwnerWait(wait)
    });
    let frame_start = (stack.va_at(stack.len()).raw()
        - core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>() as u64)
        & !15;
    if partial {
        physical.child_copy_error_at = Some((frame_start & !4095) + 4096);
    }
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: 0x400004,
        spsr: 0x3c0,
        esr: if synchronous { 0xfffc } else { 0x54000000 },
        ..Default::default()
    };
    // Deliberately different pre-dispatch arg0 and committed return value.
    words.native.x[0] = 0xaaa;
    frame.x[0] = 0xbbb;
    let before = frame;
    if synchronous {
        control.publish_synchronous_fault(signal, carrick_syscall_abi::LINUX_SEGV_MAPERR, 0xdead);
    }
    let _ = take_signal_copies();
    if synchronous {
        SIGNAL_FRAME_WAIT.with(|flag| {
            flag.set(Some(if refused_fault {
                NativeProcessError::Unsupported
            } else {
                NativeProcessError::OwnerWait(wait)
            }))
        });
        SIGNAL_FRAME_SUPPLY_FAULT.with(|flag| flag.set(refused_fault));
        let mut fault_service = fixture.process_service();
        let mut machine = ArmWaitSignalMachine {
            user_sp: stack.va_at(stack.len()),
            backend: ArmWaitSignalBackend,
        };
        assert_eq!(
            crate::dispatch::arm_deliver_declined_fault_signal_with(
                source,
                &fixture.task,
                &words.native,
                fixture_ttbr0(fixture),
                fixture.page,
                control,
                &mut fault_service,
                &mut frame,
                &mut None,
                |process, frame| crate::arm_signal::deliver_on_user_return_with(
                    &fixture.task,
                    control,
                    process,
                    frame,
                    fp.as_bytes(),
                    &mut machine
                )
            )
            .unwrap(),
            carrick_el1_abi::Action::Idle
        );
        assert!(SIGNAL_FRAME_WAIT.with(|flag| flag.get()).is_none());
        SIGNAL_FRAME_SUPPLY_FAULT.with(|flag| flag.set(false));
    } else {
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
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut ArmWaitSignalMachine {
                    user_sp: stack.va_at(stack.len()),
                    backend: ArmWaitSignalBackend
                }
            ),
            Some(carrick_personality_linux::dispatch::CompletionRoute::Suspended)
        );
    }
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(
        fixture.task.linux.has_pending_host_work(),
        refused_fault || busy,
        "a published physical notice owns host work; an internal owner wait does not"
    );
    assert!(
        control.forwarded_wait_mask_armed(),
        "no mask consumption before frame commit"
    );
    assert_eq!(control.blocked().0, 0);
    assert_eq!(frame.elr, before.elr);
    assert_eq!(frame.x, before.x);
    let prefix = take_signal_copies();
    if partial {
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0].0.raw(), frame_start);
        assert_eq!(
            prefix[0].1.len() as u64,
            (frame_start & !4095) + 4096 - frame_start
        );
    } else {
        assert!(prefix.is_empty());
    }
    if synchronous {
        assert!(control.synchronous_fault().is_some());
    }
    assert_eq!(fixture.zone.slot(fixture.slot).current(), None);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        peer.id
    );
    run_as(fixture, 42, 12, 102, peer_control);
    let peer_before = unsafe { *fixture.zone.record(peer.id).ctx_mut() };
    if refused_fault || busy {
        use carrick_core_abi::service::{ServiceCell, ServiceOperation};
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(member.id).identity(),
            )
        }
        .unwrap();
        assert!(if busy {
            matches!(
                ticket.request().operation,
                ServiceOperation::CarrierWork { .. }
            )
        } else {
            matches!(ticket.request().operation, ServiceOperation::Fault(_))
        });
        fixture
            .task
            .linux
            .take_host_work_doorbell()
            .expect("real physical service work")
            .settled();
        assert!(ticket.complete(!refused_fault).is_ok());
        queue
            .notify_object(
                fixture.slot,
                &mut carrick_sched_core::WakeEffects::default(),
            )
            .unwrap();
    }
    drop(editor);
    physical.child_copy_error = None;
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
    let saved = unsafe { *fixture.zone.record(owner_record).ctx_mut() };
    assert_eq!(saved.native.pc, 0x400004);
    assert_eq!(
        saved.native.x[0], 0xbbb,
        "park saves completed return, never old arg0"
    );
    if synchronous {
        let mut service = fixture.process_service();
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
                crate::arm_signal::checkpoint_saved_user_return(&fixture.task, entry)
            })
            .unwrap();
        assert!(matches!(
            result,
            crate::native_process_runtime::NativeResume::Left(None)
        ));
        let peer_after = unsafe { *fixture.zone.record(peer.id).ctx_mut() };
        assert_eq!(peer_before.native.x, peer_after.native.x);
        assert_eq!(peer_before.native.pc, peer_after.native.pc);
        if refused_fault {
            assert!(matches!(
                control.synchronous_fault(),
                Some((Signal::SEGV, _, _, true))
            ));
            assert_eq!(entry.resume_context().native.pc, before.elr);
            assert_eq!(entry.resume_context().native.x[0], before.x[0]);
            assert!(fixture.task.service_notice.take().unwrap().is_none());
            return;
        }
        assert_eq!(entry.resume_context().native.pc, 0x700000);
        assert!(!control.forwarded_wait_mask_armed());
        assert!(control.synchronous_fault().is_none());
        assert!(
            !entry.signal_checkpoint_needed(),
            "no second signal after handler publication"
        );
        let signal_sp = UserVa::new(entry.resume_context().native.sp_el0);
        let offset = usize::try_from(signal_sp.raw() - stack.va().raw()).unwrap();
        let built = carrick_personality_linux::signal::arm::SignalFrame::ref_from_bytes(
            &stack.as_bytes()[offset
                ..offset
                    + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
        )
        .unwrap();
        let mut restored_fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let (mask, restored_sp, _) = crate::arm_signal::restore(
            &mut frame,
            &built.rt,
            restored_fp.as_mut_bytes(),
            signal_sp,
        )
        .unwrap();
        assert_eq!(frame.elr, before.elr);
        assert_eq!(frame.x, before.x);
        assert_eq!(mask, Signal::PIPE.bit());
        assert_eq!(restored_sp, stack.va_at(stack.len()).raw());
        return;
    }
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &saved,
                &mut physical,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            crate::native_process_runtime::NativeResume::NoPending
        ));
    }
    frame.x = saved.native.x;
    frame.elr = saved.native.pc;
    frame.spsr = saved.native.pstate;
    let mut machine = ArmWaitSignalMachine {
        user_sp: stack.va_at(stack.len()),
        backend: ArmWaitSignalBackend,
    };
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &saved,
                &mut physical,
            )
            .unwrap();
        assert!(entry.signal_checkpoint_needed());
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut machine
            ),
            None
        );
        assert_eq!(frame.elr, 0x700000);
        assert!(!control.forwarded_wait_mask_armed());
        assert!(control.synchronous_fault().is_none());
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut machine
            ),
            None
        );
    }
    let mut frames = take_signal_frames();
    if partial {
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].0.raw(),
            prefix[0].0.raw() + prefix[0].1.len() as u64,
            "resumption must begin after the committed prefix"
        );
        let mut prefix = prefix;
        prefix[0].1.extend_from_slice(&frames[0].1);
        frames = prefix;
    }
    assert_eq!(
        frames.len(),
        1,
        "one handler publication across park and resume"
    );
    let (address, bytes) = &frames[0];
    let restored = carrick_personality_linux::signal::arm::decode(bytes, *address, true).unwrap();
    assert_eq!(restored.pc.raw(), 0x400004);
    assert_eq!(restored.regs[0], 0xbbb);
    assert_eq!(restored.sp.raw(), words.native.sp_el0);
    assert_eq!(restored.mask.signals().bits(), Signal::PIPE.bit());
    let built = carrick_personality_linux::signal::arm::SignalFrame::ref_from_bytes(bytes).unwrap();
    let mut restored_fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let (mask, restored_sp, _) =
        crate::arm_signal::restore(&mut frame, &built.rt, restored_fp.as_mut_bytes(), *address)
            .unwrap();
    assert_eq!(frame.elr, before.elr);
    assert_eq!(frame.x, before.x);
    assert_eq!(mask, Signal::PIPE.bit());
    assert_eq!(restored_sp, stack.va_at(stack.len()).raw());
    let peer_after = unsafe { *fixture.zone.record(peer.id).ctx_mut() };
    assert_eq!(peer_before.native.pc, peer_after.native.pc);
    assert_eq!(peer_before.native.x, peer_after.native.x);
}
