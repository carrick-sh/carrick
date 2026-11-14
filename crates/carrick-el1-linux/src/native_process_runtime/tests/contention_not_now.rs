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
