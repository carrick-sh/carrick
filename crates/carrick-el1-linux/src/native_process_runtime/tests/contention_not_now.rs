//! #2306: owner contention is "not now" at every native lifecycle, IPC and
//! signal entry. Each witness enters through the production venue, meets
//! contention once, and must keep its operation (park or retained syscall),
//! never answer an errno or end the run; then it completes.
use super::*;
use carrick_personality_linux::ipc::{IpcOutcome, LinuxSembuf, ProcessIpcVenue};

fn arm_words(address: AddressContext<RootGpa>) -> carrick_sched_core::Aarch64ParkedContext {
    carrick_sched_core::Aarch64ParkedContext::from_parts(carrick_el1_abi::ThreadCtx::ZERO, address)
}

/// Two live threads of one process each block in semop. Each parks its own
/// continuation: the first thread's park is not contention for the second
/// (formerly a process-keyed slot, answered EAGAIN).
fn two_live_threads_park_their_own_semop<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = prepare_signal_sibling(&fixture, true);
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();
    let ops = [LinuxSembuf {
        sem_num: 0,
        sem_op: -1,
        sem_flg: 0,
    }];
    let mut service = fixture.service();
    let sem = {
        let mut leader = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        let sem = leader.semget(0, 1, 0o600).unwrap();
        let parked = leader.semop(sem, &ops, None);
        assert!(matches!(parked, Ok(IpcOutcome::Suspended)), "{parked:?}");
        assert!(leader.take_handoff_receipt().is_some());
        sem
    };
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = sibling.slot;
    let mut worker = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &make_words(fixture.address),
            &mut sibling_service,
        )
        .unwrap();
    let parked = worker.semop(sem, &ops, None);
    assert!(
        matches!(parked, Ok(IpcOutcome::Suspended)),
        "a sibling's parked semop is not contention for this thread: {parked:?}"
    );
    assert!(worker.take_handoff_receipt().is_some());
    assert_eq!(worker.semctl_getncnt(sem, 0), Ok(2));
    drop(worker);
    assert_eq!(fixture.runtime.graph.lock().pending.len(), 2);
}

#[test]
fn two_live_threads_park_their_own_semop_x86() {
    two_live_threads_park_their_own_semop::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn two_live_threads_park_their_own_semop_aarch64() {
    two_live_threads_park_their_own_semop::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// Re-enter the fixture leader after its retained carrier work settled.
fn reenter_leader<C: ProcessContext + 'static>(fixture: &NativeSignalFixture<C>) -> C {
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    // SAFETY: the leader's record was selected just above.
    unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() }
}

/// A fork whose MM preparation meets a Busy carrier lease once keeps the
/// exact syscall, publishes no child, and forks once the carrier settles.
fn fork_preparation_busy_once_then_forks<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let processes = || fixture.runtime.graph.lock().owner.tasks().len();
    let mut service = fixture.service();
    fail_prepare_mm(&[NativeProcessError::Busy]);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        let outcome = entry.fork(ProcessForkChildTid::NONE);
        assert_eq!(
            outcome_kind(&outcome),
            "Transferred",
            "a Busy fork preparation is not now, never EAGAIN"
        );
        assert!(entry.take_run_failure().is_none());
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert_eq!(processes(), 1, "a retained fork publishes no child");
    assert!(matches!(
        complete_carrier_work(fixture.zone, fixture.task, fixture.slot, fixture.record),
        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
    ));
    let saved = reenter_leader(&fixture);
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::RetrySyscall)
    ));
    let outcome = entry.fork(ProcessForkChildTid::NONE);
    assert!(
        matches!(outcome, LifecycleOutcome::Returned { result, .. } if result.raw() > 0),
        "the rerun forks: {}",
        outcome_kind(&outcome)
    );
    drop(entry);
    assert_eq!(processes(), 2);
}

#[test]
fn fork_preparation_busy_once_then_forks_x86() {
    fork_preparation_busy_once_then_forks::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn fork_preparation_busy_once_then_forks_aarch64() {
    fork_preparation_busy_once_then_forks::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// Select the fixture leader's record, letting any queued sibling or child
/// run first.
fn select_leader<C: ProcessContext + 'static>(fixture: &NativeSignalFixture<C>) -> C {
    loop {
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap().record;
        if selected == fixture.record.id {
            // SAFETY: the leader's record was selected just above.
            return unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() };
        }
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, selected)
                .is_queued()
        );
    }
}

/// WNOHANG with a live child consumes nothing: a Busy empty-siginfo copy
/// reruns the call (formerly EAGAIN), which then answers 0 with the copy.
fn waitid_nohang_siginfo_busy_once_then_returns_zero<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_personality_linux::lifecycle::ProcessWaitId;
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let info = UserVa::new(0x3000);
    let options = LinuxWaitOptions::WEXITED | LinuxWaitOptions::WNOHANG;
    let mut service = fixture.service();
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.fork(ProcessForkChildTid::NONE),
            LifecycleOutcome::Returned { result, .. } if result.raw() > 0
        ));
        take_signal_copies();
        fail_signal_copies(&[NativeProcessError::Busy]);
        let outcome = entry.waitid(ProcessWaitId::All, info, options);
        assert_eq!(
            outcome_kind(&outcome),
            "Transferred",
            "a Busy WNOHANG siginfo copy is not now, never EAGAIN"
        );
        assert!(entry.take_run_failure().is_none());
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(take_signal_copies().is_empty());
    assert!(matches!(
        complete_carrier_work(fixture.zone, fixture.task, fixture.slot, fixture.record),
        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
    ));
    let saved = select_leader(&fixture);
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::RetrySyscall)
    ));
    let outcome = entry.waitid(ProcessWaitId::All, info, options);
    assert_eq!(outcome_kind(&outcome), "Returned(0)");
    let empty = carrick_syscall_abi::LinuxSiginfo::empty();
    assert_eq!(
        take_signal_copies(),
        vec![(info, zerocopy::IntoBytes::as_bytes(&empty).to_vec())]
    );
}

#[test]
fn waitid_nohang_siginfo_busy_once_then_returns_zero_x86() {
    waitid_nohang_siginfo_busy_once_then_returns_zero::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn waitid_nohang_siginfo_busy_once_then_returns_zero_aarch64() {
    waitid_nohang_siginfo_busy_once_then_returns_zero::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// A resumed sigtimedwait has already taken its signal when the siginfo
/// copy meets Busy. The copyout owner keeps the answer and the bytes; a
/// rerun (or the former EAGAIN) would lose the signal.
fn sigtimedwait_resumed_siginfo_busy_once_keeps_the_taken_signal<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest, SignalWaitOutcome,
    };
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let info = UserVa::new(0x3000);
    let usr1 = carrick_signal_core::policy::Signal::from_number(10).unwrap();
    let mut service = fixture.service();
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        let pid = fixture.task.visible_pid().unwrap();
        let parked =
            entry.rt_sigtimedwait(carrick_signal_core::SignalSet::EMPTY.with(usr1), None, info);
        assert!(matches!(parked, Ok(SignalWaitOutcome::Pending)));
        assert!(entry.take_handoff_receipt().is_some());
        // A sender publishes the awaited signal while the waiter is parked.
        entry
            .kill(
                SignalProcessSelector::from_abi(u64::from(pid)),
                SignalRequest::from_abi(10).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    take_signal_copies();
    fail_signal_copies(&[NativeProcessError::Busy]);
    let saved = select_leader(&fixture);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(
            matches!(
                entry.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::Left(None))
            ),
            "a Busy siginfo copy keeps the taken signal, never EAGAIN"
        );
        assert!(entry.take_run_failure().is_none());
    }
    assert!(take_signal_copies().is_empty());
    assert!(matches!(
        complete_carrier_work(fixture.zone, fixture.task, fixture.slot, fixture.record),
        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
    ));
    let saved = select_leader(&fixture);
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Returned(result)) if result.raw() == 10
    ));
    let copies = take_signal_copies();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].0, info);
    assert_eq!(i32::from_ne_bytes(copies[0].1[..4].try_into().unwrap()), 10);
}

#[test]
fn sigtimedwait_resumed_siginfo_busy_once_keeps_the_taken_signal_x86() {
    sigtimedwait_resumed_siginfo_busy_once_keeps_the_taken_signal::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigtimedwait_resumed_siginfo_busy_once_keeps_the_taken_signal_aarch64() {
    sigtimedwait_resumed_siginfo_busy_once_keeps_the_taken_signal::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

#[derive(Clone, Copy, Debug)]
enum HostRequestedPark {
    Sleep,
    Semop,
}

/// A host request on the running leader closes park admission (#1467):
/// contention, not a refusal. The sleep or IPC wait keeps its operation and
/// yields (formerly EAGAIN); after the handback its owner entry reparks it.
fn host_request_during_park_yields_then_reparks<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    park: HostRequestedPark,
) {
    use carrick_personality_linux::signal::{ProcessSignals, SignalOutcome};
    use carrick_personality_linux::sleep::{SleepDeadline, SleepRequest};
    use carrick_sched_core::{Claim, Handback, HostClaim, ShortLockSpin};
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let record = fixture.record;
    // Run the leader as a scheduled in-zone record, which a host may request.
    // SAFETY: the fixture's only slot holds the leader's record exclusively.
    unsafe {
        *fixture.zone.record(record.id).ctx_mut() = make_words(fixture.address);
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record.id)
            .is_queued()
    );
    let saved = select_leader(&fixture);
    let mut service = fixture.service();
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let sem = entry.semget(0, 1, 0o600).unwrap();
        // The host requests this exact running leader before it parks.
        assert_eq!(
            fixture.zone.claim_for_host(
                record,
                None,
                Handback::Control,
                &ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            ),
            HostClaim::El1Held { slot: fixture.slot }
        );
        match park {
            HostRequestedPark::Sleep => {
                let outcome = entry.clock_sleep(SleepRequest {
                    deadline: SleepDeadline::Relative(1_000_000_000),
                    remaining: None,
                });
                assert!(
                    matches!(outcome, Ok(SignalOutcome::Transferred { .. })),
                    "a host request during the sleep park must yield, never EAGAIN"
                );
            }
            HostRequestedPark::Semop => {
                let ops = [LinuxSembuf {
                    sem_num: 0,
                    sem_op: -1,
                    sem_flg: 0,
                }];
                let outcome = entry.semop(sem, &ops, None);
                assert!(
                    matches!(outcome, Ok(IpcOutcome::Suspended)),
                    "a host request during the semop park must yield, not {outcome:?}"
                );
            }
        }
        assert!(entry.take_run_failure().is_none());
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    // The native owner, not the host, resumes the retained wait.
    assert_eq!(
        fixture.zone.record(record.id).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(
            carrick_sched_core::object_wait::OwnerEntry::Syscall
        )
    );
    assert!(fixture.zone.record(record.id).needs_native_handback());
    let mut wanted = alloc::vec::Vec::new();
    fixture
        .zone
        .take_host_wanted(fixture.slot, &mut |wanted_record| {
            wanted.push(wanted_record)
        });
    assert_eq!(wanted.as_slice(), &[record]);
    assert!(fixture.zone.place_native_handback(record).is_some());
    // Its next owner entry reruns the retained wait, which now parks.
    let saved = select_leader(&fixture);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(
            matches!(
                entry.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::Left(None))
            ),
            "the retained {park:?} must repark after the handback"
        );
    }
    assert!(matches!(
        fixture.zone.record(record.id).claim(),
        Claim::Parked { .. }
    ));
}

#[test]
fn host_request_during_sleep_park_yields_then_reparks_x86() {
    host_request_during_park_yields_then_reparks::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, HostRequestedPark::Sleep);
}

#[test]
fn host_request_during_sleep_park_yields_then_reparks_aarch64() {
    host_request_during_park_yields_then_reparks::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, HostRequestedPark::Sleep);
}

#[test]
fn host_request_during_semop_park_yields_then_reparks_x86() {
    host_request_during_park_yields_then_reparks::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, HostRequestedPark::Semop);
}

#[test]
fn host_request_during_semop_park_yields_then_reparks_aarch64() {
    host_request_during_park_yields_then_reparks::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, HostRequestedPark::Semop);
}

/// #3003: multi-page `wait_sigreturn_copy_observed` binds `copyout_fault` to the
/// failing second page (never page 0), restarts `rt_sigreturn` on `Supplied` or
/// non-exiting `Cancelled`, and forces `SIGSEGV` (unmasking `SEGV`) on
/// `BackingFault` or `Refused` instead of returning `-EFAULT`. Also verifies
/// `CarrierWork::Work` under `retry_syscall_after_supply` restarts cleanly on
/// `Refused` / `Cancelled`.
fn sigreturn_wait_and_parked_fault_semantics<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::lifecycle::{ProcessNative, SigreturnCopyOutcome};
    use carrick_personality_linux::signal::ProcessSignals;
    use carrick_signal_core::SignalSet;
    use carrick_signal_core::policy::{SigBlockMask, Signal};

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    unsafe {
        *fixture.zone.record(fixture.record.id).ctx_mut() = make_words(fixture.address);
    }
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let request = GuestCopyRequest {
        address: UserVa::new(0x10_f00),
        len: GuestLen::new(512),
        access: Access::Read,
    };
    let mut service = fixture.service();
    let member = fixture.zone.record_ref(fixture.record.id);

    let current_or_select_leader = |fixture: &NativeSignalFixture<C>| -> C {
        if fixture.zone.slot(fixture.slot).current() == Some(fixture.record.id) {
            unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() }
        } else {
            let _ = fixture
                .zone
                .requeue_preempted(fixture.slot, fixture.record.id);
            select_leader(fixture)
        }
    };

    // 1. Multi-page request [0x10f00, 0x11100): page 0 passes, page 1 hits
    // Unsupported -> parked Fault must name 0x11000 (not 0x10f00), and
    // Cancelled (non-exiting) / Supplied must both produce RetrySyscall, while
    // Refused forces SIGSEGV (SI_KERNEL).
    for outcome_idx in 0..3 {
        service.prepare_copy_error = Some(NativeProcessError::Unsupported);
        service.child_copy_error = Some(NativeProcessError::Unsupported);
        PREPARE_READ_ERROR_AT.with(|at| at.set(Some(0x11_000)));
        let saved = current_or_select_leader(&fixture);
        {
            let mut entry = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    source,
                    fixture.task,
                    fixture.address,
                    &saved,
                    &mut service,
                )
                .unwrap();
            let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
            assert!(matches!(
                outcome,
                SigreturnCopyOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
        }
        PREPARE_READ_ERROR_AT.with(|at| at.set(None));
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &fixture.control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(fixture.record.id).identity(),
            )
        }
        .unwrap();
        assert!(matches!(
            ticket.request().operation,
            ServiceOperation::Fault(fault)
                if fault.address == UserVa::new(0x11_000) && fault.access == Access::Read
        ));
        match outcome_idx {
            0 => assert!(ticket.complete(false).is_ok()), // Refused -> force SIGSEGV
            1 => {
                assert_eq!(
                    fixture.control.service.cancel(ticket.request().identity),
                    Ok(false)
                );
                assert!(ticket.complete(false).is_ok());
            }
            _ => {
                FAULT_REPLY_ALLOW_APPLY.with(|allow| allow.set(true));
                assert!(ticket.complete(true).is_ok()); // Supplied -> RetrySyscall
            }
        }
        queue
            .notify_object(fixture.slot, &mut WakeEffects::default())
            .unwrap();
        drop(queue);

        service.prepare_copy_error = None;
        service.child_copy_error = None;
        service.child_copy_error_at = None;
        let saved = current_or_select_leader(&fixture);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let resume = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        assert!(entry.take_run_failure().is_none());
        if outcome_idx == 0 {
            assert!(matches!(resume, NativeResume::NoPending));
            assert_eq!(
                entry.words.saved_syscall_pc(),
                Some(carrick_sched_core::SavedSyscallPc::AfterSyscall),
                "forced SIGSEGV must not rewind saved syscall PC"
            );
            let (sig, info, _) = entry
                .take_deliverable(SigBlockMask::NONE)
                .expect("Refused SigreturnCopyin Fault must force SIGSEGV");
            assert_eq!(sig, Signal::SEGV);
            assert_eq!(info.map(|i| i.si_code), Some(128));
        } else {
            assert!(
                matches!(resume, NativeResume::RetrySyscall),
                "outcome_idx={outcome_idx} must retry rt_sigreturn"
            );
        }
    }

    // 2. BackingFault and Failed(_) on parked SigreturnCopyin Fault unmask SEGV and
    // force SIGSEGV (NoPending), while CarrierWork::Work under SigreturnCopyin restarts on Refused.
    for case in 0..3 {
        let is_fault_op = case < 2;
        fixture.control.init_blocked(carrick_el1_abi::BlockedMask(
            SignalSet::EMPTY.with(Signal::SEGV).bits(),
        ));
        service.prepare_copy_error = Some(if is_fault_op {
            NativeProcessError::Unsupported
        } else {
            NativeProcessError::Busy
        });
        service.child_copy_error = is_fault_op.then_some(NativeProcessError::Unsupported);
        service.child_copy_error_at = None;
        let saved = current_or_select_leader(&fixture);
        {
            let mut entry = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    source,
                    fixture.task,
                    fixture.address,
                    &saved,
                    &mut service,
                )
                .unwrap();
            let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
            assert!(matches!(
                outcome,
                SigreturnCopyOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
        }
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &fixture.control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(fixture.record.id).identity(),
            )
        }
        .unwrap();
        match case {
            0 => assert!(ticket.complete_backing_fault().is_ok()),
            1 => assert!(
                ticket
                    .complete_failure(carrick_core_abi::service::ServiceFailureCode::MINIMUM)
                    .is_ok()
            ),
            _ => assert!(ticket.complete(false).is_ok()),
        }
        queue
            .notify_object(fixture.slot, &mut WakeEffects::default())
            .unwrap();
        drop(queue);

        service.prepare_copy_error = None;
        service.child_copy_error = None;
        let saved = current_or_select_leader(&fixture);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let resume = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        assert!(entry.take_run_failure().is_none());
        if is_fault_op {
            assert!(matches!(resume, NativeResume::NoPending));
            assert_eq!(
                entry.words.saved_syscall_pc(),
                Some(carrick_sched_core::SavedSyscallPc::AfterSyscall),
                "parked BackingFault/Failed SIGSEGV must not rewind saved syscall PC"
            );
            assert_eq!(
                fixture.control.blocked().0 & Signal::SEGV.bit(),
                0,
                "forced SIGSEGV must unmask Signal::SEGV"
            );
            let (sig, info, _) = entry
                .take_deliverable(SigBlockMask::NONE)
                .expect("BackingFault/Failed on SigreturnCopyin must force SIGSEGV");
            assert_eq!(sig, Signal::SEGV);
            assert_eq!(info.map(|i| i.si_code), Some(128));
        } else {
            assert!(
                matches!(resume, NativeResume::RetrySyscall),
                "Refused CarrierWork::Work must retry syscall cleanly"
            );
        }
    }

    // 3. Inline Fault returns Fault (no -EFAULT) and settled pages return RetrySyscall.
    for inline_fault in [true, false] {
        service.prepare_copy_error = inline_fault.then_some(NativeProcessError::Fault);
        let saved = current_or_select_leader(&fixture);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
        if inline_fault {
            assert_eq!(outcome, SigreturnCopyOutcome::Fault);
        } else {
            assert_eq!(outcome, SigreturnCopyOutcome::RetrySyscall);
        }
    }

    // 4. Synchronous pre-park Fault Refused consumes NoPending inside park_service and returns
    // SigreturnCopyOutcome::Settled with forced SIGSEGV (no PC rewind).
    {
        fixture.control.init_blocked(carrick_el1_abi::BlockedMask(
            SignalSet::EMPTY.with(Signal::SEGV).bits(),
        ));
        service.prepare_copy_error = Some(NativeProcessError::Unsupported);
        service.child_copy_error = Some(NativeProcessError::Unsupported);
        let runtime_addr = std::sync::Arc::as_ptr(&fixture.runtime) as usize;
        let record_identity = fixture.zone.record(fixture.record.id).identity();
        set_service_published_hook(
            runtime_addr,
            Box::new(move || {
                let notice = fixture.task.service_notice.take().unwrap().unwrap();
                let ticket = unsafe {
                    ServiceCell::claim_notice(
                        &fixture.control.service,
                        notice,
                        NonZeroU64::MIN,
                        record_identity,
                    )
                }
                .unwrap();
                assert!(ticket.complete(false).is_ok());
            }),
        );
        let saved = current_or_select_leader(&fixture);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
        assert_eq!(outcome, SigreturnCopyOutcome::Settled);
        assert!(entry.take_run_failure().is_none());
        assert_eq!(
            entry.words.saved_syscall_pc(),
            Some(carrick_sched_core::SavedSyscallPc::AfterSyscall),
            "synchronous Fault Refused must not rewind saved syscall PC"
        );
        assert_eq!(fixture.control.blocked().0 & Signal::SEGV.bit(), 0);
        let (sig, info, _) = entry
            .take_deliverable(SigBlockMask::NONE)
            .expect("synchronous Fault Refused must force SIGSEGV");
        assert_eq!(sig, Signal::SEGV);
        assert_eq!(info.map(|i| i.si_code), Some(128));
    }

    // 5. Terminal close cancellation on a parked SigreturnCopyin (both Fault and CarrierWork)
    // settles cleanly as closing-member exit (Left(None)) without forcing SIGSEGV, and
    // synchronous pre-park has_exit settles as Settled.
    for (sync_exit, inject_error) in [
        (false, NativeProcessError::Unsupported),
        (false, NativeProcessError::Busy),
        (true, NativeProcessError::Unsupported),
    ] {
        let term_fixture: &_ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
        let sibling = prepare_signal_sibling(term_fixture, true);
        term_fixture
            .registry
            .register_thread(
                BornInZoneSource {
                    zone: term_fixture.zone,
                    slot: sibling.slot,
                },
                sibling.task,
                term_fixture.address,
                term_fixture.page,
                sibling.control,
            )
            .unwrap();
        let mut term_service = term_fixture.service();
        term_service.prepare_copy_error = Some(inject_error);
        term_service.child_copy_error = Some(inject_error);
        let term_source = BornInZoneSource {
            zone: term_fixture.zone,
            slot: term_fixture.slot,
        };
        let saved = make_words(term_fixture.address);
        if !sync_exit {
            {
                let mut entry = term_fixture
                    .runtime
                    .enter_registered(
                        term_fixture.registry,
                        term_source,
                        term_fixture.task,
                        term_fixture.address,
                        &saved,
                        &mut term_service,
                    )
                    .unwrap();
                let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
                assert!(matches!(outcome, SigreturnCopyOutcome::Transferred { .. }));
            }
            let mut sibling_service = term_fixture.service();
            sibling_service.waker_slot = sibling.slot;
            let mut worker = term_fixture
                .runtime
                .enter_registered(
                    term_fixture.registry,
                    BornInZoneSource {
                        zone: term_fixture.zone,
                        slot: sibling.slot,
                    },
                    sibling.task,
                    term_fixture.address,
                    &saved,
                    &mut sibling_service,
                )
                .unwrap();
            assert!(matches!(
                worker.exit_group(38),
                LifecycleOutcome::Transferred { .. }
            ));
            drop(worker);
            let notice = term_fixture.task.service_notice.take().unwrap().unwrap();
            let term_member = term_fixture.zone.record_ref(term_fixture.record.id);
            let queue = term_fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(term_member)
                        .unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
                .unwrap();
            let ticket = unsafe {
                ServiceCell::claim_notice(
                    &term_fixture.control.service,
                    notice,
                    NonZeroU64::MIN,
                    term_fixture.zone.record(term_fixture.record.id).identity(),
                )
            }
            .unwrap();
            assert!(ticket.complete(false).is_ok());
            queue
                .notify_object(term_fixture.slot, &mut WakeEffects::default())
                .unwrap();
            drop(queue);
            term_service.prepare_copy_error = None;
            term_service.child_copy_error = None;
            let saved = current_or_select_leader(term_fixture);
            let mut entry = term_fixture
                .runtime
                .enter_registered(
                    term_fixture.registry,
                    term_source,
                    term_fixture.task,
                    term_fixture.address,
                    &saved,
                    &mut term_service,
                )
                .unwrap();
            let resume = entry.resume_checkpoint(|_| Ok(None)).unwrap();
            assert!(matches!(resume, NativeResume::Left(None)));
            assert!(entry.take_run_failure().is_none());
            assert!(entry.take_deliverable(SigBlockMask::NONE).is_none());
            assert!(
                term_fixture
                    .zone
                    .slot(term_fixture.slot)
                    .current()
                    .is_none()
            );
        } else {
            let runtime_addr = std::sync::Arc::as_ptr(&term_fixture.runtime) as usize;
            let sibling_task = sibling.task;
            let sibling_slot = sibling.slot;
            let sibling_words = saved;
            let term_identity = term_fixture.zone.record(term_fixture.record.id).identity();
            set_service_published_hook(
                runtime_addr,
                Box::new(move || {
                    let mut sibling_service = term_fixture.service();
                    sibling_service.waker_slot = sibling_slot;
                    let mut worker = term_fixture
                        .runtime
                        .enter_registered(
                            term_fixture.registry,
                            BornInZoneSource {
                                zone: term_fixture.zone,
                                slot: sibling_slot,
                            },
                            sibling_task,
                            term_fixture.address,
                            &sibling_words,
                            &mut sibling_service,
                        )
                        .unwrap();
                    assert!(matches!(
                        worker.exit_group(38),
                        LifecycleOutcome::Transferred { .. }
                    ));
                    drop(worker);
                    let notice = term_fixture.task.service_notice.take().unwrap().unwrap();
                    let ticket = unsafe {
                        ServiceCell::claim_notice(
                            &term_fixture.control.service,
                            notice,
                            NonZeroU64::MIN,
                            term_identity,
                        )
                    }
                    .unwrap();
                    assert!(ticket.complete(false).is_ok());
                }),
            );
            let mut entry = term_fixture
                .runtime
                .enter_registered(
                    term_fixture.registry,
                    term_source,
                    term_fixture.task,
                    term_fixture.address,
                    &saved,
                    &mut term_service,
                )
                .unwrap();
            let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
            assert_eq!(outcome, SigreturnCopyOutcome::Settled);
            assert!(entry.take_run_failure().is_none());
            assert!(entry.take_deliverable(SigBlockMask::NONE).is_none());
            match entry.resume_terminal_user_return() {
                Some(LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }) => {
                    assert!(entry.take_handoff_receipt().is_some());
                }
                Some(LifecycleOutcome::HostCustody) => {
                    let route = entry.user_return_host_custody();
                    assert_eq!(
                        route,
                        carrick_personality_linux::dispatch::CompletionRoute::Served
                    );
                }
                _ => panic!("unexpected terminal user-return outcome"),
            }
            assert!(entry.take_run_failure().is_none());
            assert!(entry.take_deliverable(SigBlockMask::NONE).is_none());
            assert!(
                term_fixture
                    .zone
                    .slot(term_fixture.slot)
                    .current()
                    .is_none()
            );
        }
    }
}

#[test]
fn sigreturn_wait_and_parked_fault_semantics_x86() {
    sigreturn_wait_and_parked_fault_semantics::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigreturn_wait_and_parked_fault_semantics_aarch64() {
    sigreturn_wait_and_parked_fault_semantics::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// #3003: if group exit closes the lifecycle gate between
/// `prepare_owned_read` (which publishes a per-CPU fault selection) and
/// `begin_service_inner` claim admission, retirement must clear that per-CPU
/// slot so subsequent guests on the same CPU never observe a stranded `Busy`.
fn sigreturn_closed_gate_clears_per_cpu_fault_selection<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::lifecycle::SigreturnCopyOutcome;

    let slot = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let _slot_guard = install_portal_fault_slot(slot.clone());

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    unsafe {
        *fixture.zone.record(fixture.record.id).ctx_mut() = make_words(fixture.address);
    }
    let sibling = prepare_signal_sibling(&fixture, true);
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();
    let mut sibling_service = fixture.service();
    sibling_service.waker_slot = sibling.slot;
    let mut worker = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &make_words(fixture.address),
            &mut sibling_service,
        )
        .unwrap();
    assert!(matches!(
        worker.exit_group(38),
        LifecycleOutcome::Transferred { .. }
    ));
    drop(worker);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.prepare_copy_error = Some(NativeProcessError::Unsupported);
    service.child_copy_error = Some(NativeProcessError::Unsupported);
    let saved = make_words(fixture.address);
    let request = GuestCopyRequest {
        address: UserVa::new(0x1000),
        len: GuestLen::new(64),
        access: Access::Read,
    };
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
    assert_eq!(outcome, SigreturnCopyOutcome::Settled);
    assert!(entry.take_run_failure().is_none());
    assert!(matches!(
        entry.resume_terminal_user_return(),
        Some(LifecycleOutcome::HostCustody)
    ));
    assert_eq!(
        entry.user_return_host_custody(),
        carrick_personality_linux::dispatch::CompletionRoute::Served
    );
    drop(entry);

    assert!(
        slot.pending_fault_selection(fixture.address.mm.raw().get(), 0x1000)
            .is_none(),
        "unpublished closing fault must withdraw its per-CPU PortalGrantSlot selection"
    );

    // An unrelated live process running on the same CPU slot must be able to
    // select and park a genuine Fault rather than getting stuck on Busy.
    let live_fixture = native_exec_fixture_for::<C, B>(make_words);
    let live_source = BornInZoneSource {
        zone: live_fixture.zone,
        slot: live_fixture.slot,
    };
    let mut live_service = live_fixture.service();
    live_service.prepare_copy_error = Some(NativeProcessError::Unsupported);
    live_service.child_copy_error = Some(NativeProcessError::Unsupported);
    let live_saved = make_words(live_fixture.address);
    let mut live_entry = live_fixture
        .runtime
        .enter_registered(
            live_fixture.registry,
            live_source,
            live_fixture.task,
            live_fixture.address,
            &live_saved,
            &mut live_service,
        )
        .unwrap();
    let live_outcome = live_entry.wait_sigreturn_copy_observed(request, &mut |_| {});
    assert!(matches!(
        live_outcome,
        SigreturnCopyOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            ..
        }
    ));
    drop(live_entry);
    let notice = live_fixture.task.service_notice.take().unwrap().unwrap();
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &live_fixture.control.service,
            notice,
            NonZeroU64::MIN,
            live_fixture.zone.record(live_fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert!(
        matches!(ticket.request().operation, ServiceOperation::Fault(_)),
        "next guest on same CPU slot must select Fault instead of CarrierWork after stranded Busy"
    );
    assert!(ticket.complete(false).is_ok());
}

#[test]
fn sigreturn_closed_gate_clears_per_cpu_fault_selection_x86() {
    sigreturn_closed_gate_clears_per_cpu_fault_selection::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigreturn_closed_gate_clears_per_cpu_fault_selection_aarch64() {
    sigreturn_closed_gate_clears_per_cpu_fault_selection::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// #3003: if group exit wins between checking `exiting` and forced-SIGSEGV
/// publication for a parked `rt_sigreturn` copy-in fault, signal disposition,
/// pending fault queue, and blocked mask must remain untouched.
fn sigreturn_parked_fault_race_with_exit_group_keeps_signal_state_untouched<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_core_abi::service::ServiceCell;
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::lifecycle::SigreturnCopyOutcome;
    use carrick_personality_linux::signal::ProcessSignals;
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, SigBlockMask, Signal};

    let fixture: &_ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
    unsafe {
        *fixture.zone.record(fixture.record.id).ctx_mut() = make_words(fixture.address);
    }
    let sibling = prepare_signal_sibling(fixture, true);
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.prepare_copy_error = Some(NativeProcessError::Unsupported);
    service.child_copy_error = Some(NativeProcessError::Unsupported);
    let request = GuestCopyRequest {
        address: UserVa::new(0x1000),
        len: GuestLen::new(64),
        access: Access::Read,
    };
    let saved = unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() };
    let handler = HandlerAddress(0x70_0000);
    let task_key = {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let task_key = entry.key;
        {
            let graph = fixture.runtime.graph.lock();
            graph
                .owner
                .task(task_key)
                .unwrap()
                .native()
                .resources()
                .signals()
                .install_action(
                    task_key,
                    Signal::SEGV,
                    Action {
                        disposition: Disposition::Handler(handler),
                        ..Action::default()
                    },
                )
                .unwrap();
        }
        let _ = fixture.control.store_blocked_then_read_pending(
            carrick_personality_linux::abi::thread::BlockedMask(Signal::SEGV.bit()),
            fixture.control.pending(),
        );
        let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
        assert!(matches!(
            outcome,
            SigreturnCopyOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        task_key
    };
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let member = fixture.zone.record_ref(fixture.record.id);
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(member).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert!(ticket.complete(false).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);

    let sibling_slot = sibling.slot;
    let sibling_task = sibling.task;
    let sibling_words = make_words(fixture.address);
    SIGRETURN_FAULT_PRE_FORCE_HOOK.with(|hook| {
        assert!(
            hook.borrow_mut()
                .replace(Box::new(move || {
                    let mut sibling_service = fixture.service();
                    sibling_service.waker_slot = sibling_slot;
                    let mut worker = fixture
                        .runtime
                        .enter_registered(
                            fixture.registry,
                            BornInZoneSource {
                                zone: fixture.zone,
                                slot: sibling_slot,
                            },
                            sibling_task,
                            fixture.address,
                            &sibling_words,
                            &mut sibling_service,
                        )
                        .unwrap();
                    assert!(matches!(
                        worker.exit_group(38),
                        LifecycleOutcome::Transferred { .. }
                    ));
                }))
                .is_none()
        );
    });

    service.prepare_copy_error = None;
    service.child_copy_error = None;
    let saved = if fixture.zone.slot(fixture.slot).current() == Some(fixture.record.id) {
        unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() }
    } else {
        let _ = fixture
            .zone
            .requeue_preempted(fixture.slot, fixture.record.id);
        select_leader(fixture)
    };
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let resume = entry.resume_checkpoint(|_| Ok(None)).unwrap();
    let resume_kind = match resume {
        NativeResume::NoPending => "NoPending",
        NativeResume::RetrySyscall => "RetrySyscall",
        NativeResume::RetrySavedSyscall => "RetrySavedSyscall",
        NativeResume::Returned(_) => "Returned",
        NativeResume::Left(Some(_)) => "Left(Some)",
        NativeResume::Left(None) => "Left(None)",
        NativeResume::Invalid => "Invalid",
    };
    assert!(
        matches!(resume, NativeResume::Left(_)),
        "unexpected resume={resume_kind} run_failure={:?}",
        entry.take_run_failure()
    );
    assert!(entry.take_run_failure().is_none());
    assert_eq!(
        fixture.control.blocked().0 & Signal::SEGV.bit(),
        Signal::SEGV.bit(),
        "group exit winner must keep Signal::SEGV blocked bit untouched"
    );
    assert!(
        entry.take_deliverable(SigBlockMask::NONE).is_none(),
        "group exit winner must not enqueue forced SIGSEGV"
    );
    let action = fixture
        .runtime
        .graph
        .lock()
        .owner
        .task(task_key)
        .unwrap()
        .native()
        .resources()
        .signals()
        .action(Signal::SEGV);
    assert_eq!(
        action.disposition,
        Disposition::Handler(handler),
        "group exit winner must keep caught SIGSEGV disposition untouched"
    );
}

#[test]
fn sigreturn_parked_fault_race_with_exit_group_keeps_signal_state_untouched_x86() {
    sigreturn_parked_fault_race_with_exit_group_keeps_signal_state_untouched::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigreturn_parked_fault_race_with_exit_group_keeps_signal_state_untouched_aarch64() {
    sigreturn_parked_fault_race_with_exit_group_keeps_signal_state_untouched::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// #3003: if group exit cancels an unpublished `rt_sigreturn` fault request
/// while it is in `PreparedService::NoticeWait` (carrier `service_notice` held),
/// `cancel_unpublished_service` must withdraw its per-CPU `PortalGrantSlot`
/// selection so subsequent guests on the same CPU never hit a stranded `Busy`.
fn sigreturn_notice_wait_cancelled_clears_per_cpu_fault_selection<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation, ServiceSelector};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::lifecycle::SigreturnCopyOutcome;

    let slot = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let _slot_guard = install_portal_fault_slot(slot.clone());

    let fixture: &_ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
    unsafe {
        *fixture.zone.record(fixture.record.id).ctx_mut() = make_words(fixture.address);
    }
    let sibling = prepare_signal_sibling(fixture, true);
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();

    // Hold `fixture.task.service_notice` with a bound `native_service` holder so
    // `prepare_service_inner` enters `PreparedService::NoticeWait` and
    // `park_notice_wait` reaches `should_cancel_unpublished` under its queue lock.
    let holder_key =
        carrick_sched_core::object_wait::ObjectWaitKey::native_service(sibling.record).unwrap();
    fixture
        .zone
        .bind_object_wait(holder_key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    let holder = ServiceSelector {
        record: sibling.record,
        execution: carrick_core_abi::SnapshotGeneration::from_raw(
            fixture.zone.record(sibling.record.id).identity().generation,
        ),
        sequence: NonZeroU64::MIN,
    };
    assert!(
        fixture
            .task
            .service_notice
            .publish_or_observe(holder)
            .is_ok()
    );

    let sibling_slot = sibling.slot;
    let sibling_task = sibling.task;
    SERVICE_NOTICE_WAIT_HOOK.with(|hook| {
        assert!(
            hook.borrow_mut()
                .replace(Box::new(move || {
                    let mut sibling_service = fixture.service();
                    sibling_service.waker_slot = sibling_slot;
                    let mut worker = fixture
                        .runtime
                        .enter_registered(
                            fixture.registry,
                            BornInZoneSource {
                                zone: fixture.zone,
                                slot: sibling_slot,
                            },
                            sibling_task,
                            fixture.address,
                            &make_words(fixture.address),
                            &mut sibling_service,
                        )
                        .unwrap();
                    assert!(matches!(
                        worker.exit_group(38),
                        LifecycleOutcome::Transferred { .. }
                    ));
                }))
                .is_none()
        );
    });

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.prepare_copy_error = Some(NativeProcessError::Unsupported);
    service.child_copy_error = Some(NativeProcessError::Unsupported);
    let saved = unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() };
    let request = GuestCopyRequest {
        address: UserVa::new(0x1000),
        len: GuestLen::new(64),
        access: Access::Read,
    };
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let outcome = entry.wait_sigreturn_copy_observed(request, &mut |_| {});
    assert!(
        SERVICE_NOTICE_WAIT_HOOK.with(|hook| hook.borrow().is_none()),
        "SERVICE_NOTICE_WAIT_HOOK must have executed (NoticeWait path)"
    );
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed,
        "gate must be closed after exit_group inside NoticeWait hook"
    );
    assert_eq!(outcome, SigreturnCopyOutcome::Settled);
    assert!(entry.take_run_failure().is_none());
    drop(entry);

    assert!(
        slot.pending_fault_selection(fixture.address.mm.raw().get(), 0x1000)
            .is_none(),
        "cancelled notice-wait fault must withdraw its per-CPU PortalGrantSlot selection"
    );

    // An unrelated live guest on the same CPU slot must select Fault cleanly
    // rather than falling back to CarrierWork after seeing a stranded Busy.
    let live_fixture = native_exec_fixture_for::<C, B>(make_words);
    let live_source = BornInZoneSource {
        zone: live_fixture.zone,
        slot: live_fixture.slot,
    };
    let mut live_service = live_fixture.service();
    live_service.prepare_copy_error = Some(NativeProcessError::Unsupported);
    live_service.child_copy_error = Some(NativeProcessError::Unsupported);
    let live_saved = make_words(live_fixture.address);
    let mut live_entry = live_fixture
        .runtime
        .enter_registered(
            live_fixture.registry,
            live_source,
            live_fixture.task,
            live_fixture.address,
            &live_saved,
            &mut live_service,
        )
        .unwrap();
    let live_outcome = live_entry.wait_sigreturn_copy_observed(request, &mut |_| {});
    assert!(matches!(
        live_outcome,
        SigreturnCopyOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            ..
        }
    ));
    drop(live_entry);
    let notice = live_fixture.task.service_notice.take().unwrap().unwrap();
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &live_fixture.control.service,
            notice,
            NonZeroU64::MIN,
            live_fixture.zone.record(live_fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert!(
        matches!(ticket.request().operation, ServiceOperation::Fault(_)),
        "next guest on same CPU slot must select Fault instead of CarrierWork after notice-wait cancellation"
    );
    assert!(ticket.complete(false).is_ok());
}

#[test]
fn sigreturn_notice_wait_cancelled_clears_per_cpu_fault_selection_x86() {
    sigreturn_notice_wait_cancelled_clears_per_cpu_fault_selection::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigreturn_notice_wait_cancelled_clears_per_cpu_fault_selection_aarch64() {
    sigreturn_notice_wait_cancelled_clears_per_cpu_fault_selection::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// #3003: if group exit wins before inline `rt_sigreturn` fault handling
/// acquires `graph.lock()` (either from `restore_signal_frame` returning `Err`
/// or synchronous `wait_sigreturn_copy` fault), signal disposition, pending fault
/// queue, and blocked mask must remain untouched.
fn sigreturn_inline_fault_race_with_exit_group_keeps_signal_state_untouched<
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_guest_arch::{Access, GuestLen, NativeOrdinal, NativeReturnWord};
    use carrick_personality_linux::crossing::HostCrossingSet;
    use carrick_personality_linux::dispatch::{CompletionRoute, SyscallFrame, dispatch};
    use carrick_personality_linux::signal::{ProcessSignals, SignalFrameRestore};
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, SigBlockMask, Signal};

    struct InlineVenue<'a> {
        page: &'a carrick_el1_abi::ThreadLifecyclePage,
        control: &'a carrick_el1_abi::ThreadControlSlot,
    }
    impl crate::thread_setup::LifecycleVenue for InlineVenue<'_> {
        fn thread<'a>(
            &'a self,
            _: &'a carrick_el1_abi::CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(
            &self,
            _: &carrick_el1_abi::ThreadLifecyclePage,
            _: carrick_el1_abi::EntryRef,
        ) -> Option<&carrick_el1_abi::ThreadControlSlot> {
            None
        }
    }

    struct HookUserCopy(Option<Box<dyn FnOnce()>>);
    impl crate::file::UserCopy for HookUserCopy {
        fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
            if let Some(hook) = self.0.take() {
                hook();
            }
            false
        }
        fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
            false
        }
    }

    struct InlineSigreturnFaultFrame {
        isa: HostCrossingSet,
        slot: SlotId,
        return_not_yet: bool,
    }
    impl SyscallFrame for InlineSigreturnFaultFrame {
        fn canonical_ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
            carrick_syscall_abi::CanonicalNr::new(139)
        }
        fn argument(&self, _: usize) -> Option<u64> {
            Some(0)
        }
        fn result(&self) -> NativeReturnWord {
            NativeReturnWord(0)
        }
        fn set_result(&mut self, _: NativeReturnWord) {}
        fn slot(&self) -> Option<SlotId> {
            Some(self.slot)
        }
        fn task_index(&self) -> usize {
            0
        }
        fn user_sp(&self) -> Option<UserVa> {
            Some(UserVa::new(0x8000))
        }
    }
    impl crate::dispatch::GuestDispatchFrame for InlineSigreturnFaultFrame {
        fn restart_syscall(&mut self) {}
        fn native_number(&self) -> NativeOrdinal {
            NativeOrdinal::new(match self.isa {
                HostCrossingSet::X86 => 15,
                HostCrossingSet::Aarch64 => 139,
            })
        }
        fn crossing_set(&self) -> HostCrossingSet {
            self.isa
        }
        fn arm_frame(&mut self) -> Option<&mut carrick_el1_abi::TrapFrame> {
            None
        }
        fn arm_frame_ref(&self) -> Option<&carrick_el1_abi::TrapFrame> {
            None
        }
        fn arm_scheduler(&self) -> bool {
            false
        }
        fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
            None
        }
        fn restore_signal_frame(
            &mut self,
            copy_in: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
        ) -> Result<SignalFrameRestore, carrick_syscall_abi::LinuxErrno> {
            let mut probe = [0_u8; 8];
            let _ = copy_in.copy_in(&mut probe, UserVa::new(0x1000));
            if self.return_not_yet {
                Ok(SignalFrameRestore::NotYet(GuestCopyRequest {
                    address: UserVa::new(0xffff_ffff_ffff_1000),
                    len: GuestLen::new(64),
                    access: Access::Read,
                }))
            } else {
                Err(carrick_personality_linux::abi::signal::LINUX_EFAULT)
            }
        }
    }

    for return_not_yet in [false, true] {
        let fixture: &_ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
        unsafe {
            *fixture.zone.record(fixture.record.id).ctx_mut() = make_words(fixture.address);
        }
        let sibling = prepare_signal_sibling(fixture, true);
        fixture
            .registry
            .register_thread(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: sibling.slot,
                },
                sibling.task,
                fixture.address,
                fixture.page,
                sibling.control,
            )
            .unwrap();
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut service = fixture.service();
        let saved = unsafe { *fixture.zone.record(fixture.record.id).ctx_mut() };
        let handler = HandlerAddress(0x70_0000);
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let task_key = entry.key;
        {
            let graph = fixture.runtime.graph.lock();
            graph
                .owner
                .task(task_key)
                .unwrap()
                .native()
                .resources()
                .signals()
                .install_action(
                    task_key,
                    Signal::SEGV,
                    Action {
                        disposition: Disposition::Handler(handler),
                        ..Action::default()
                    },
                )
                .unwrap();
        }
        let _ = fixture.control.store_blocked_then_read_pending(
            carrick_personality_linux::abi::thread::BlockedMask(Signal::SEGV.bit()),
            fixture.control.pending(),
        );

        let sibling_slot = sibling.slot;
        let sibling_task = sibling.task;
        let mut copy = HookUserCopy(Some(Box::new(move || {
            let mut sibling_service = fixture.service();
            sibling_service.waker_slot = sibling_slot;
            let mut worker = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource {
                        zone: fixture.zone,
                        slot: sibling_slot,
                    },
                    sibling_task,
                    fixture.address,
                    &make_words(fixture.address),
                    &mut sibling_service,
                )
                .unwrap();
            assert!(matches!(
                worker.exit_group(38),
                LifecycleOutcome::Transferred { .. }
            ));
        })));

        let counters = carrick_el1_abi::Counters::new();
        let names = carrick_el1_abi::InotifyNameCache::new();
        let venue = InlineVenue {
            page: fixture.page,
            control: fixture.control,
        };
        let mut frame = InlineSigreturnFaultFrame {
            isa,
            slot: fixture.slot,
            return_not_yet,
        };
        let canonical_nr = frame.canonical_ordinal().raw();
        let route = {
            let mut pending: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
                handoff: None,
                lifecycle_user: Some(&mut copy),
                frame: &mut frame,
                counters: &counters,
                current_tasks: core::slice::from_ref(fixture.task),
                fd_map: &[],
                object_table: &[],
                open_table: &[],
                inotify_table: &[],
                name_cache: &names,
                zone: None,
                ipc: None,
                lifecycle: Some(&venue),
                process: Some(entry.as_mut()),
                source: Some(source),
                anonymous: None,
                cache_lookup: |_| core::ptr::null_mut(),
            };
            dispatch(canonical_nr, u64::MAX, &mut pending)
        };
        assert!(
            matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
            "inline sigreturn fault race must settle natively without forwarding: {route:?}"
        );
        assert!(entry.take_run_failure().is_none());
        assert_eq!(
            fixture.control.blocked().0 & Signal::SEGV.bit(),
            Signal::SEGV.bit(),
            "group exit winner must keep Signal::SEGV blocked bit untouched (return_not_yet={return_not_yet})"
        );
        assert!(
            entry.take_deliverable(SigBlockMask::NONE).is_none(),
            "group exit winner must not enqueue forced SIGSEGV (return_not_yet={return_not_yet})"
        );
        let action = fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(task_key)
            .unwrap()
            .native()
            .resources()
            .signals()
            .action(Signal::SEGV);
        assert_eq!(
            action.disposition,
            Disposition::Handler(handler),
            "group exit winner must keep caught SIGSEGV disposition untouched (return_not_yet={return_not_yet})"
        );
    }
}

#[test]
fn sigreturn_inline_fault_race_with_exit_group_keeps_signal_state_untouched_x86() {
    sigreturn_inline_fault_race_with_exit_group_keeps_signal_state_untouched::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
}

#[test]
fn sigreturn_inline_fault_race_with_exit_group_keeps_signal_state_untouched_aarch64() {
    sigreturn_inline_fault_race_with_exit_group_keeps_signal_state_untouched::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

/// #3003: if an unhomed `rt_sigreturn` waiter parks in `PreparedService::NoticeWait`
/// on CPU A and later wakes on CPU B:
/// 1) parking on CPU A must withdraw CPU A's per-CPU `PortalGrantSlot` selection
///    before releasing CPU A (so another guest on CPU A can use it immediately);
/// 2) waking on CPU B for supply must re-probe and bind CPU B's `PortalGrantSlot`
///    and publish to CPU B's `service_notice` so carrier intake succeeds;
/// 3) waking on CPU B for group-exit cancellation must settle cleanly without
///    corrupting CPU B's `PortalGrantSlot` or stranding CPU A's slot.
struct MigratedNoticeWaitHarness<C: ProcessContext + 'static> {
    fixture: &'static NativeSignalFixture<C>,
    mm: u64,
    slot_a: SlotId,
    slot_b: SlotId,
    waiter_tid: u32,
    waiter_serial: u64,
    waiter_control: &'static carrick_el1_abi::ThreadControlSlot,
    waiter_record_id: carrick_sched_core::RecordId,
    waiter_record: carrick_sched_core::RecordRef,
    waiter_task_a: &'static carrick_el1_abi::CurrentTask,
    holder_key: carrick_sched_core::object_wait::ObjectWaitKey,
}

impl<C: ProcessContext + 'static> MigratedNoticeWaitHarness<C> {
    fn new_task(
        fixture: &NativeSignalFixture<C>,
        mm: u64,
        waiter_tid: u32,
        waiter_serial: u64,
        waiter_control: &'static carrick_el1_abi::ThreadControlSlot,
    ) -> &'static carrick_el1_abi::CurrentTask {
        use core::sync::atomic::Ordering;
        let task = Box::leak(Box::new(carrick_el1_abi::CurrentTask::new()));
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(waiter_tid as i32),
            carrick_core_abi::SnapshotGeneration::from_raw(waiter_serial),
            5,
        );
        task.mm.key.store(mm, Ordering::Release);
        task.mm
            .thread_generation
            .store(waiter_serial, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_root_generation(fixture.address.generation);
        task.publish_lifecycle(
            fixture.page as *const _ as u64,
            waiter_control as *const _ as u64,
        );
        task
    }

    fn spawn<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        make_words: fn(AddressContext<RootGpa>) -> C,
        slot_a: SlotId,
        slot_b: SlotId,
    ) -> Self {
        use carrick_core_abi::service::ServiceSelector;
        use carrick_el1_abi::{BornRecord, EntryIdentity, ThreadControlSlot, ThreadIdentity};

        let fixture: &'static _ = Box::leak(Box::new(native_exec_fixture_for::<C, B>(make_words)));
        let mm = fixture.address.mm.raw().get();
        let zone = fixture.zone;

        // Spawn an unhomed sibling (`home == None`) running on CPU A (`slot_a`),
        // allowed to wake on either CPU A or CPU B (`slot_b`).
        let waiter_tid = 43_u32;
        let waiter_serial = 103_u64;
        let waiter_affinity = (1_u64 << slot_a.raw()) | (1_u64 << slot_b.raw());
        let waiter_control = Box::leak(Box::new(ThreadControlSlot::new()));
        let waiter_birth = carrick_core_abi::BirthSerial::of_task(
            TaskSerial::from_raw_u64(waiter_serial).unwrap(),
        );
        let waiter_entry = fixture
            .page
            .stock(
                0,
                EntryIdentity {
                    tid: waiter_tid,
                    visible_tid: waiter_tid,
                    thread_serial: waiter_serial,
                    birth: waiter_birth,
                    uid_credit: 0,
                },
            )
            .unwrap();
        fixture
            .page
            .bind_control_address(waiter_entry, waiter_control as *const _ as u64)
            .unwrap();
        waiter_control
            .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, waiter_entry)
            .unwrap();
        assert!(waiter_control.publish_visible_tid(waiter_tid));
        waiter_control.publish_host_birth_identity(
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::EntryTaskKey::from_raw(u64::from(waiter_tid)),
                waiter_birth,
                carrick_core_abi::EntryThreadGeneration::from_raw(waiter_serial),
            )
            .unwrap(),
        );
        let birth_claim = fixture.page.claim(waiter_entry).unwrap();
        fixture
            .page
            .record_born(
                birth_claim,
                BornRecord {
                    caller_task: 41,
                    caller_serial: 101,
                    clone_flags: 0x0001_0000,
                    clear_child_tid: 0,
                    blocked: carrick_el1_abi::BlockedMask(0),
                },
            )
            .unwrap();
        carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
        fixture.page.publish(waiter_entry).unwrap();
        zone.namespace()
            .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
                ns.reserve_exact(waiter_tid as i32, ClaimKind::Thread)
                    .unwrap();
            });

        let waiter_record_id = zone
            .alloc_record(ThreadIdentity {
                tid: u64::from(waiter_tid),
                serial: waiter_serial,
                mm,
                file_table: 5,
                generation: waiter_serial,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: waiter_affinity,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: waiter_control as *const _ as u64,
            })
            .unwrap();
        assert!(zone.mark_native_owned(waiter_record_id));
        unsafe {
            *zone.record(waiter_record_id).ctx_mut() = make_words(fixture.address);
        }
        let waiter_record = zone.record_ref(waiter_record_id);
        waiter_control.bind_zone_record(waiter_record);
        let waiter_task_a = Self::new_task(fixture, mm, waiter_tid, waiter_serial, waiter_control);

        let _ = zone.requeue_preempted(slot_a, fixture.record.id);
        zone.clear_current(slot_a);
        assert!(zone.requeue_preempted(slot_a, waiter_record_id).is_queued());
        let first = zone.switch_in_full(slot_a).unwrap().record;
        if first != waiter_record_id {
            let _ = zone.requeue_preempted(slot_a, first);
            zone.clear_current(slot_a);
            assert_eq!(
                zone.switch_in_full(slot_a).unwrap().record,
                waiter_record_id
            );
        }
        fixture
            .registry
            .register_thread(
                BornInZoneSource { zone, slot: slot_a },
                waiter_task_a,
                fixture.address,
                fixture.page,
                waiter_control,
            )
            .unwrap();

        let holder_control = Box::leak(Box::new(ThreadControlSlot::new()));
        let holder_record_id = zone
            .alloc_record(ThreadIdentity {
                tid: 99,
                serial: 199,
                mm: 99,
                file_table: 5,
                generation: 199,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: holder_control as *const _ as u64,
            })
            .unwrap();
        let holder_record = zone.record_ref(holder_record_id);
        let holder_key =
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(holder_record).unwrap();
        zone.bind_object_wait(holder_key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
        let holder = ServiceSelector {
            record: holder_record,
            execution: carrick_core_abi::SnapshotGeneration::from_raw(199),
            sequence: NonZeroU64::MIN,
        };
        assert!(
            waiter_task_a
                .service_notice
                .publish_or_observe(holder)
                .is_ok()
        );

        Self {
            fixture,
            mm,
            slot_a,
            slot_b,
            waiter_tid,
            waiter_serial,
            waiter_control,
            waiter_record_id,
            waiter_record,
            waiter_task_a,
            holder_key,
        }
    }

    fn saved_ctx(&self) -> C {
        unsafe { *self.fixture.zone.record(self.waiter_record_id).ctx_mut() }
    }

    fn migrate_to_cpu_b(&self) -> (&'static carrick_el1_abi::CurrentTask, C) {
        let zone = self.fixture.zone;
        assert_eq!(
            zone.switch_in_full(self.slot_a).unwrap().record,
            self.fixture.record.id
        );
        zone.drive(self.slot_b, 3);
        zone.publish_slot(self.slot_b, self.mm, Some(2), 1 << self.slot_b.raw());
        zone.enter_guest(self.slot_b);
        zone.install_space(self.slot_b, self.mm).unwrap();

        let holder_queue = zone
            .object_wait(
                self.holder_key,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        holder_queue
            .notify_object(self.slot_b, &mut WakeEffects::default())
            .unwrap();
        drop(holder_queue);

        let selected_b = zone.switch_in_full(self.slot_b).unwrap();
        assert_eq!(
            selected_b.record, self.waiter_record_id,
            "woken unhomed waiter must resume on CPU B when CPU A runs another MM"
        );

        let waiter_task_b = Self::new_task(
            self.fixture,
            self.mm,
            self.waiter_tid,
            self.waiter_serial,
            self.waiter_control,
        );
        (waiter_task_b, self.saved_ctx())
    }
}

fn sigreturn_notice_wait_cpu_migration_withdraws_and_reselects_fault<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    use carrick_core::user_copy::GuestCopyRequest;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::lifecycle::SigreturnCopyOutcome;

    let slot_a = SlotId::new(0);
    let slot_b = SlotId::new(2);
    let grant_a = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let grant_b = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let _slot_guard =
        install_portal_fault_slots(&[(slot_a, grant_a.clone()), (slot_b, grant_b.clone())]);

    let request = GuestCopyRequest {
        address: UserVa::new(0x1000),
        len: GuestLen::new(64),
        access: Access::Read,
    };

    for supply_after_migration in [true, false] {
        let harness = MigratedNoticeWaitHarness::spawn::<B>(make_words, slot_a, slot_b);
        let fixture = harness.fixture;
        let mm = harness.mm;
        let zone = fixture.zone;
        let waiter_control = harness.waiter_control;
        let waiter_record_id = harness.waiter_record_id;
        let waiter_record = harness.waiter_record;
        let waiter_task_a = harness.waiter_task_a;

        // Enter waiter on CPU A (`slot_a`): enters NoticeWait and parks on `holder_key`.
        let saved_a = unsafe { *zone.record(waiter_record_id).ctx_mut() };
        {
            let mut service_a = fixture.service();
            service_a.waker_slot = slot_a;
            service_a.prepare_copy_error = Some(NativeProcessError::Unsupported);
            service_a.child_copy_error = Some(NativeProcessError::Unsupported);
            let mut entry_a = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_a },
                    waiter_task_a,
                    fixture.address,
                    &saved_a,
                    &mut service_a,
                )
                .unwrap();
            let outcome = entry_a.wait_sigreturn_copy_observed(request, &mut |_| {});
            assert!(matches!(
                outcome,
                SigreturnCopyOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
        }
        assert!(
            grant_a.pending_fault_selection(mm, 0x1000).is_none(),
            "parking NoticeWait on CPU A must withdraw CPU A PortalGrantSlot selection immediately"
        );

        // An unrelated guest running on CPU A while waiter is parked must be able
        // to select Fault on `grant_a` instead of hitting a stranded Busy.
        {
            let other = native_exec_fixture_for::<C, B>(make_words);
            let other_source = BornInZoneSource {
                zone: other.zone,
                slot: slot_a,
            };
            let mut other_service = other.service();
            other_service.waker_slot = slot_a;
            other_service.prepare_copy_error = Some(NativeProcessError::Unsupported);
            other_service.child_copy_error = Some(NativeProcessError::Unsupported);
            let mut other_entry = other
                .runtime
                .enter_registered(
                    other.registry,
                    other_source,
                    other.task,
                    other.address,
                    &make_words(other.address),
                    &mut other_service,
                )
                .unwrap();
            assert!(matches!(
                other_entry.wait_sigreturn_copy_observed(request, &mut |_| {}),
                SigreturnCopyOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
            drop(other_entry);
            let notice = other.task.service_notice.take().unwrap().unwrap();
            let mut ticket = unsafe {
                ServiceCell::claim_notice(
                    &other.control.service,
                    notice,
                    NonZeroU64::MIN,
                    other.zone.record(other.record.id).identity(),
                )
            }
            .unwrap();
            assert!(matches!(
                ticket.request().operation,
                ServiceOperation::Fault(_)
            ));
            assert!(ticket.take_fault_selection(&grant_a).is_ok());
            assert!(ticket.complete(false).is_ok());
        }

        let (waiter_task_b, saved_b) = harness.migrate_to_cpu_b();

        if supply_after_migration {
            let mut service_b = fixture.service();
            service_b.waker_slot = slot_b;
            service_b.prepare_copy_error = Some(NativeProcessError::Unsupported);
            service_b.child_copy_error = Some(NativeProcessError::Unsupported);
            {
                let mut entry_b = fixture
                    .runtime
                    .enter_registered(
                        fixture.registry,
                        BornInZoneSource { zone, slot: slot_b },
                        waiter_task_b,
                        fixture.address,
                        &saved_b,
                        &mut service_b,
                    )
                    .unwrap();
                let resumed = entry_b.resume_checkpoint(|_| Ok(None)).unwrap();
                assert!(matches!(resumed, NativeResume::Left(None)));
            }
            assert!(grant_a.pending_fault_selection(mm, 0x1000).is_none());
            assert!(
                grant_b.pending_fault_selection(mm, 0x1000).is_some(),
                "resuming on CPU B must select a fresh PortalGrantSlot entry on CPU B"
            );

            let waiter_queue = zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(waiter_record)
                        .unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
                .unwrap();
            let notice_b = waiter_task_b.service_notice.take().unwrap().unwrap();
            let mut ticket_b = unsafe {
                ServiceCell::claim_notice(
                    &waiter_control.service,
                    notice_b,
                    NonZeroU64::MIN,
                    zone.record(waiter_record_id).identity(),
                )
            }
            .unwrap();
            assert!(
                ticket_b.take_fault_selection(&grant_b).is_ok(),
                "CPU B carrier intake must accept migrated waiter fault selection from CPU B slot"
            );
            assert!(grant_b.pending_fault_selection(mm, 0x1000).is_none());
            FAULT_REPLY_ALLOW_APPLY.with(|allow| allow.set(true));
            assert!(ticket_b.complete(true).is_ok());
            waiter_queue
                .notify_object(slot_b, &mut WakeEffects::default())
                .unwrap();
            drop(waiter_queue);

            assert_eq!(
                zone.switch_in_full(slot_b).unwrap().record,
                waiter_record_id
            );
            service_b.prepare_copy_error = None;
            service_b.child_copy_error = None;
            let saved_b2 = unsafe { *zone.record(waiter_record_id).ctx_mut() };
            let mut entry_b2 = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_b },
                    waiter_task_b,
                    fixture.address,
                    &saved_b2,
                    &mut service_b,
                )
                .unwrap();
            let final_resume = entry_b2.resume_checkpoint(|_| Ok(None)).unwrap();
            assert!(
                matches!(final_resume, NativeResume::RetrySyscall),
                "migrated waiter supplied on CPU B must retry rt_sigreturn cleanly"
            );
            assert!(
                carrick_personality_linux::signal::ProcessSignals::take_deliverable(
                    entry_b2.as_mut(),
                    carrick_signal_core::policy::SigBlockMask::NONE,
                )
                .is_none()
            );
        } else {
            // Prepare a sibling on `SlotId(1)` (sibling helper slot) to close the
            // group before CPU B resumes `waiter`. Also seed an unrelated active
            // selection on `grant_b` to verify CPU B cancellation never disturbs it.
            let sibling = prepare_signal_sibling(fixture, true);
            fixture
                .registry
                .register_thread(
                    BornInZoneSource {
                        zone,
                        slot: sibling.slot,
                    },
                    sibling.task,
                    fixture.address,
                    fixture.page,
                    sibling.control,
                )
                .unwrap();
            let mut sibling_service = fixture.service();
            sibling_service.waker_slot = sibling.slot;
            let mut worker = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource {
                        zone,
                        slot: sibling.slot,
                    },
                    sibling.task,
                    fixture.address,
                    &make_words(fixture.address),
                    &mut sibling_service,
                )
                .unwrap();
            assert!(matches!(
                worker.exit_group(38),
                LifecycleOutcome::Transferred { .. }
            ));
            drop(worker);

            let unrelated_window = carrick_el1_abi::PortalGrantWindow::decode([
                1, 0xface, 1, 77, 1, 0x2000, 0x3000, 3, 0x2000, 0, 0, 0, 0,
            ])
            .unwrap();
            assert!(grant_b.publish_fault_selection(77, unrelated_window));

            let mut service_b = fixture.service();
            service_b.waker_slot = slot_b;
            let mut entry_b = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_b },
                    waiter_task_b,
                    fixture.address,
                    &saved_b,
                    &mut service_b,
                )
                .unwrap();
            let cancelled_resume = entry_b.resume_checkpoint(|_| Ok(None)).unwrap();
            assert!(matches!(cancelled_resume, NativeResume::Left(_)));
            assert!(entry_b.take_run_failure().is_none());
            assert!(grant_a.pending_fault_selection(mm, 0x1000).is_none());
            assert!(
                grant_b.pending_fault_selection(0xface, 0x2000).is_some(),
                "CPU B cancellation of a migrated NoticeWait fault must not disturb unrelated CPU B selection"
            );
            assert!(grant_b.cancel_native_fault_selection(
                0xface,
                0x2000,
                NonZeroU64::new(77).unwrap()
            ));
        }
    }
}

#[test]
fn sigreturn_notice_wait_cpu_migration_withdraws_and_reselects_fault_x86() {
    sigreturn_notice_wait_cpu_migration_withdraws_and_reselects_fault::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words);
}

#[test]
fn sigreturn_notice_wait_cpu_migration_withdraws_and_reselects_fault_aarch64() {
    sigreturn_notice_wait_cpu_migration_withdraws_and_reselects_fault::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
}

/// Migrating an `EntropyPreparation` fault from CPU A to CPU B through
/// `NoticeWait` must preserve the prepared writable prefix (`prepared > 0`),
/// both when CPU B's reprobe hits a hard fault and when CPU B reselects the
/// fault and the host carrier refuses it.
fn entropy_notice_wait_cpu_migration_preserves_prefix<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    reprobe_hard_fault: bool,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation, entropy};
    use carrick_guest_arch::GuestLen;

    let slot_a = SlotId::new(0);
    let slot_b = SlotId::new(2);
    let grant_a = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let grant_b = std::sync::Arc::new(carrick_el1_abi::PortalGrantSlot::new());
    let _slot_guard =
        install_portal_fault_slots(&[(slot_a, grant_a.clone()), (slot_b, grant_b.clone())]);

    let address = UserVa::new(0x10ff8);
    let flags = NativeEntropyFlags::from_bits_retain(0);

    {
        let _ = take_signal_copies();
        let harness = MigratedNoticeWaitHarness::spawn::<B>(make_words, slot_a, slot_b);
        let fixture = harness.fixture;
        let mm = harness.mm;
        let zone = fixture.zone;
        let waiter_control = harness.waiter_control;
        let waiter_record_id = harness.waiter_record_id;
        let waiter_record = harness.waiter_record;

        // CPU A (`slot_a`): page 1 (`0x10ff8..0x11000`, 8 bytes) prepares cleanly;
        // page 2 (`0x11000`) returns `Unsupported`, selects `grant_a`, and parks
        // in `NoticeWait` while CPU A's notice is held.
        let saved_a = harness.saved_ctx();
        {
            let mut service_a = fixture.service();
            service_a.waker_slot = slot_a;
            service_a.child_copy_error = Some(NativeProcessError::Unsupported);
            service_a.child_copy_error_at = Some(0x11000);
            let mut entry_a = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_a },
                    harness.waiter_task_a,
                    fixture.address,
                    &saved_a,
                    &mut service_a,
                )
                .unwrap();
            let resumed_a = entry_a
                .begin_entropy_service(address, 13, flags, GuestLen::new(13))
                .unwrap();
            assert!(matches!(resumed_a, NativeResume::Left(None)));
        }
        assert!(
            grant_a.pending_fault_selection(mm, 0x11000).is_none(),
            "parking NoticeWait on CPU A must withdraw page-2 fault selection"
        );

        let (waiter_task_b, saved_b) = harness.migrate_to_cpu_b();
        let mut service_b = fixture.service();
        service_b.waker_slot = slot_b;

        if reprobe_hard_fault {
            // Case A: on CPU B, page 2 now reprobes as a hard Fault.
            service_b.child_copy_error = Some(NativeProcessError::Fault);
            service_b.child_copy_error_at = Some(0x11000);
            let mut entry_b = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_b },
                    waiter_task_b,
                    fixture.address,
                    &saved_b,
                    &mut service_b,
                )
                .unwrap();
            let resumed_b = entry_b.resume_checkpoint(|_| Ok(None)).unwrap();
            let returned = match resumed_b {
                NativeResume::Returned(r) => Some(r.raw()),
                _ => None,
            };
            assert!(
                matches!(resumed_b, NativeResume::Left(None)),
                "hard fault on second page after NoticeWait migration must still issue Entropy for the 8-byte prefix, returned={returned:?}"
            );
        } else {
            // Case B: on CPU B, page 2 still reprobes Unsupported -> reselects on
            // CPU B (`grant_b`), and the host carrier refuses it.
            service_b.child_copy_error = Some(NativeProcessError::Unsupported);
            service_b.child_copy_error_at = Some(0x11000);
            {
                let mut entry_b = fixture
                    .runtime
                    .enter_registered(
                        fixture.registry,
                        BornInZoneSource { zone, slot: slot_b },
                        waiter_task_b,
                        fixture.address,
                        &saved_b,
                        &mut service_b,
                    )
                    .unwrap();
                let resumed_b = entry_b.resume_checkpoint(|_| Ok(None)).unwrap();
                assert!(matches!(resumed_b, NativeResume::Left(None)));
            }
            assert!(grant_b.pending_fault_selection(mm, 0x11000).is_some());

            let waiter_queue = zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(waiter_record)
                        .unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
                .unwrap();
            let notice_b = waiter_task_b.service_notice.take().unwrap().unwrap();
            let mut ticket_b = unsafe {
                ServiceCell::claim_notice(
                    &waiter_control.service,
                    notice_b,
                    NonZeroU64::MIN,
                    zone.record(waiter_record_id).identity(),
                )
            }
            .unwrap();
            assert!(ticket_b.take_fault_selection(&grant_b).is_ok());
            assert!(ticket_b.complete(false).is_ok());
            waiter_queue
                .notify_object(slot_b, &mut WakeEffects::default())
                .unwrap();
            drop(waiter_queue);

            assert_eq!(
                zone.switch_in_full(slot_b).unwrap().record,
                waiter_record_id
            );
            let saved_b2 = harness.saved_ctx();
            let mut entry_b2 = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource { zone, slot: slot_b },
                    waiter_task_b,
                    fixture.address,
                    &saved_b2,
                    &mut service_b,
                )
                .unwrap();
            let resumed_after_refusal = entry_b2.resume_checkpoint(|_| Ok(None)).unwrap();
            let returned = match resumed_after_refusal {
                NativeResume::Returned(r) => Some(r.raw()),
                _ => None,
            };
            assert!(
                matches!(resumed_after_refusal, NativeResume::Left(None)),
                "carrier refusal after CPU B reselection must still issue Entropy for the 8-byte prefix, returned={returned:?}"
            );
        }

        // Both cases must now publish `ServiceOperation::Entropy` with capacity 8.
        let waiter_queue = zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(waiter_record)
                    .unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        let notice_entropy = waiter_task_b.service_notice.take().unwrap().unwrap();
        let ticket_entropy = unsafe {
            ServiceCell::claim_notice(
                &waiter_control.service,
                notice_entropy,
                NonZeroU64::MIN,
                zone.record(waiter_record_id).identity(),
            )
        }
        .unwrap();
        let ServiceOperation::Entropy { payload } = ticket_entropy.request().operation else {
            panic!("expected Entropy service for preserved prefix");
        };
        let record = unsafe {
            core::slice::from_raw_parts_mut(
                payload.address().raw() as *mut u8,
                payload.length().raw() as usize,
            )
        };
        assert_eq!(
            entropy::request(record).unwrap().capacity,
            8,
            "entropy request after migrated fault must keep the 8-byte prepared prefix"
        );
        carrick_kernel::dispatch::serve_native_entropy(record).unwrap();
        assert!(ticket_entropy.complete(true).is_ok());
        waiter_queue
            .notify_object(slot_b, &mut WakeEffects::default())
            .unwrap();
        drop(waiter_queue);

        assert_eq!(
            zone.switch_in_full(slot_b).unwrap().record,
            waiter_record_id
        );
        let saved_final = harness.saved_ctx();
        let mut entry_final = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource { zone, slot: slot_b },
                waiter_task_b,
                fixture.address,
                &saved_final,
                &mut service_b,
            )
            .unwrap();
        let final_resume = entry_final.resume_checkpoint(|_| Ok(None)).unwrap();
        let returned = match final_resume {
            NativeResume::Returned(r) => Some(r.raw()),
            _ => None,
        };
        assert!(
            matches!(final_resume, NativeResume::Returned(r) if r.raw() == 8),
            "getrandom after migrated second-page fault must return 8 bytes, returned={returned:?}"
        );
        let copied = take_signal_copies();
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].0, address);
        assert_eq!(copied[0].1.len(), 8);
    }
}

#[test]
fn entropy_notice_wait_cpu_migration_refusal_preserves_prefix_x86() {
    entropy_notice_wait_cpu_migration_preserves_prefix::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, false);
}

#[test]
fn entropy_notice_wait_cpu_migration_refusal_preserves_prefix_aarch64() {
    entropy_notice_wait_cpu_migration_preserves_prefix::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, false);
}

#[test]
fn entropy_notice_wait_cpu_migration_hard_reprobe_preserves_prefix_x86() {
    entropy_notice_wait_cpu_migration_preserves_prefix::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, true);
}

#[test]
fn entropy_notice_wait_cpu_migration_hard_reprobe_preserves_prefix_aarch64() {
    entropy_notice_wait_cpu_migration_preserves_prefix::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, true);
}
