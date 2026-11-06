use super::*;
use crate::native_process_runtime::host_test_support::{Physical, take_signal_copies};
use carrick_el1_abi::Lifecycle;
use carrick_personality_linux::signal::{
    ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
};
use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn arm_unblock_resident_null_oldset_delivers_before_work_return() {
    resident_signal_work_return(1, false, None, false, None);
}
#[test]
fn arm_unblock_resident_oldset_delivers_before_work_return() {
    resident_signal_work_return(1, true, None, false, None);
}
#[test]
fn arm_setmask_resident_null_oldset_delivers_before_work_return() {
    resident_signal_work_return(2, false, None, false, None);
}
#[test]
fn arm_setmask_resident_oldset_delivers_before_work_return() {
    resident_signal_work_return(2, true, None, false, None);
}

#[test]
fn arm_completed_carrier_work_delivers_before_user_return() {
    resident_signal_work_return(1, false, Some(false), false, None);
}
#[test]
fn arm_interrupted_crossing_delivers_before_user_return() {
    resident_signal_work_return(1, false, Some(true), false, None);
}

#[test]
fn arm_interrupted_crossing_sa_restart_restores_original_svc() {
    resident_signal_work_return(1, false, Some(true), true, None);
}
#[test]
fn arm_completed_carrier_work_sa_restart_preserves_committed_result() {
    resident_signal_work_return(1, false, Some(false), true, None);
}

#[test]
fn arm_carrier_work_does_not_manufacture_pending_host_work() {
    resident_signal_work_return(1, false, Some(false), false, Some(false));
}

#[test]
fn arm_carrier_work_preserves_real_pending_host_work_and_parks() {
    resident_signal_work_return(1, false, Some(false), false, Some(true));
}

fn resident_signal_work_return(
    how: u64,
    output: bool,
    service: Option<bool>,
    restart: bool,
    pending_only: Option<bool>,
) {
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
    // Adopt the selected record into native execution, as the running owner
    // does before an in-ring service can return directly to user space.
    assert!(fixture.zone.mark_native_owned(peer.id));
    assert!(fixture.zone.record(peer.id).is_native_owned());
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
    let control = peer_control;
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
                    flags: carrick_signal_core::policy::ActionFlags {
                        restart,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            )
            .unwrap();
        entry
            .tgkill(
                SignalThreadSelector::from_abi(41),
                SignalThreadSelector::from_abi(42),
                SignalRequest::from_abi(13).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    // Queue the blocked signal from the other live thread, then select its
    // receiver. No earlier running-lane host request obscures service admission.
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
    let mask =
        carrick_test_support::GuestUserBuffer::from_value(if how == 1 { mask_bits } else { 0 });
    let oldset = carrick_test_support::GuestUserBuffer::from_value(0xdead_beef_u64);
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x54000000,
        elr: words.native.pc,
        ..Default::default()
    };
    frame.x[..4].copy_from_slice(&[how, mask.arg(), if output { oldset.arg() } else { 0 }, 8]);
    frame.x[8] = 135;
    words.native.x = frame.x;
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let route = {
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
        crate::dispatch::dispatch_syscall_with_native(
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
        )
    };
    assert!(take_signal_copies().is_empty());
    if output {
        assert_eq!(oldset.as_bytes(), mask_bits.to_ne_bytes());
    }
    assert_eq!(control.blocked().0 & mask_bits, 0);
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(frame.x[0], 0);
    let action = crate::dispatch::resolve_arm_process_route(
        route,
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        || false,
    );
    let mut completion = service.map(|crossing| {
        assert!(!fixture.task.linux.has_pending_host_work());
        if pending_only == Some(true) {
            fixture.task.linux.mark_pending_host_work();
        }
        let service_action = if crossing {
            frame.x[8] = 63;
            frame.x[0] = 0x44;
            carrick_el1_abi::Action::Forward
        } else {
            if restart {
                frame.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
            }
            action
        };
        let operation = crate::dispatch::native_service_operation(
            &mut frame,
            &fixture.task.linux,
            service_action,
        )
        .unwrap();
        if pending_only == Some(false) {
            assert!(
                !fixture.task.linux.has_pending_host_work(),
                "classifying in-ring CarrierWork cannot manufacture a host wake"
            );
        }
        let mut service_context = words;
        crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut service_context);
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &service_context,
                &mut physical,
            )
            .unwrap();
        if pending_only.is_none() {
            crate::native_process_runtime::host_test_support::set_service_published_hook(
                runtime.as_ref() as *const _ as usize,
                Box::new(move || {
                    let notice = fixture.task.service_notice.take().unwrap().unwrap();
                    let reference = fixture.zone.record_ref(peer.id);
                    let queue = fixture
                        .zone
                        .object_wait(
                            carrick_sched_core::object_wait::ObjectWaitKey::native_service(
                                reference,
                            )
                            .unwrap(),
                            &carrick_sched_core::ShortLockSpin,
                        )
                        .unwrap();
                    // SAFETY: production intake's exact-member queue authenticates
                    // this real published request before issuing its ticket.
                    let ticket = unsafe {
                        carrick_core_abi::service::ServiceCell::claim_notice(
                            &control.service,
                            notice,
                            NonZeroU64::MIN,
                            fixture.zone.record(peer.id).identity(),
                        )
                    }
                    .unwrap();
                    drop(queue);
                    ticket
                        .complete(true)
                        .unwrap_or_else(|_| panic!("real service ACK was refused"));
                }),
            );
        }
        let result = entry.begin_service(operation, None);
        let result = entry.settle_service_exit(
            result,
            if crossing {
                crate::native_process_runtime::NativeServiceExit::Bridge
            } else {
                crate::native_process_runtime::NativeServiceExit::CarrierWork
            },
        );
        let result =
            crate::dispatch::native_service_completion(result, entry.native_service_phase())
                .unwrap();
        if pending_only.is_none() {
            assert!(
                matches!(
                    result,
                    crate::native_process_runtime::NativeResume::Returned(_)
                ),
                "actual pre-park service ACK must return inline through begin_service"
            );
        }
        (operation, result)
    });
    if pending_only == Some(true) {
        assert!(
            fixture.task.linux.has_pending_host_work(),
            "real preexisting host work remains owed"
        );
        assert!(
            matches!(
                completion,
                Some((_, crate::native_process_runtime::NativeResume::Left(None)))
            ),
            "real host work must park rather than cancel before the carrier consumes it"
        );
        assert!(matches!(
            fixture.zone.record(peer.id).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        assert!(fixture.task.service_notice.take().unwrap().is_some());
        assert!(take_signal_copies().is_empty());
        return;
    }
    if pending_only == Some(false) {
        assert!(
            !fixture.task.linux.has_pending_host_work(),
            "in-ring cancelled work cannot manufacture a later host wake"
        );
        return;
    }
    let mut publications = 0;
    let mut published_frames = Vec::new();
    for _ in 0..2 {
        let checkpoint = |frame: &mut carrick_el1_abi::TrapFrame| {
            let mut checkpoint_context = words;
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
            assert_eq!(
                crate::signal_delivery::deliver_signal_on_syscall_return(
                    &fixture.task,
                    control,
                    &mut entry,
                    frame,
                    fp.as_bytes(),
                    &mut ArmWaitSignalMachine {
                        user_sp: stack.va_at(stack.len()),
                        backend: ArmWaitSignalBackend
                    },
                ),
                None
            );
            let copies = take_signal_copies();
            publications += copies.len();
            published_frames.extend(copies);
            carrick_el1_abi::Action::Served
        };
        if let Some((operation, result)) = completion.take() {
            crate::dispatch::native_service_user_return(
                &mut frame,
                Some(operation),
                result,
                checkpoint,
            );
        } else {
            crate::dispatch::final_user_return(&mut frame, action, checkpoint);
        }
        assert_eq!(
            frame.elr, 0x700000,
            "each actual return must publish its handler before any later checkpoint"
        );
        assert_eq!(publications, 1, "the first return publishes exactly once");
    }
    assert_eq!(
        frame.elr, 0x700000,
        "resident sigprocmask must publish handler before returning to EL0"
    );
    assert_eq!(publications, 1, "pending signal must publish exactly once");
    if let Some(crossing) = service {
        let built = carrick_personality_linux::signal::arm::SignalFrame::read_from_bytes(
            &published_frames[0].1,
        )
        .unwrap();
        let pc = built.rt.ucontext.uc_mcontext.pc;
        let x0 = built.rt.ucontext.uc_mcontext.regs[0];
        assert_eq!(
            pc,
            if crossing && restart {
                0x400000
            } else {
                0x400004
            },
            "handler saves the interrupted SVC at the correct restart boundary"
        );
        assert_eq!(
            x0,
            if crossing {
                if restart {
                    0x44
                } else {
                    carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
                }
            } else if restart {
                carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
            } else {
                0
            },
            "handler saves the original crossing argument or committed CarrierWork result"
        );
        assert!(
            !fixture.task.linux.has_pending_host_work(),
            "in-ring cancelled work cannot manufacture a later host wake"
        );
    }
}
