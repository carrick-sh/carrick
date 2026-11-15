//! A process-exit owner retains its exact continuation across host requests.
use super::{add_service_sibling, native_exec_fixture, words};
use crate::native_process_runtime::NativeResume;
use carrick_el1_abi::{BornInZoneSource, ExecutionBinding, Lifecycle};
use carrick_personality_linux::lifecycle::{LifecycleOutcome, LinuxWaitStatus, ProcessNative};

/// Exact native report retained for the VM-free executor adapter.
#[derive(Debug)]
pub struct NativeTerminalFailure {
    pub binding: ExecutionBinding,
    pub reason: carrick_core_abi::NativeRunFailureReason,
}

/// Run two real native members through terminal park, handback and exit.
/// Only physical memory service is substituted by the enclosing host fixture.
pub fn run() -> Result<LinuxWaitStatus, NativeTerminalFailure> {
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert!(sibling.service_ticket.is_none());
    let live_members = fixture.page.live();
    assert_eq!(live_members, 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, fixture.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(fixture.slot),
        Some(fixture.record.id)
    );
    assert!(matches!(
        fixture.zone.claim_for_host(
            fixture.record,
            None,
            carrick_sched_core::Handback::Control,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::El1Held { .. }
    ));
    let mut service = fixture.service();
    let saved = words(fixture.address);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        owner.exit_group(0),
        LifecycleOutcome::Transferred { .. }
    ));
    if let Some(reason) = owner.take_run_failure() {
        return Err(NativeTerminalFailure {
            binding: owner.binding,
            reason,
        });
    }
    let owner_record_exists = fixture.zone.live(fixture.record).is_some();
    assert!(owner_record_exists);
    assert!(owner.take_handoff_receipt().is_some());
    drop(owner);
    let live_members = fixture.page.live();
    assert_eq!(live_members, 1);
    assert!(sibling.control.host_exit_requested());
    // A requested group exit has not yet retired this exact sibling.
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            sibling.control,
            sibling.control.host_birth_identity().unwrap(),
            sibling.control.host_birth_identity(),
            sibling.record,
            sibling.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::InvariantViolation
    );

    let mut sibling_service = fixture.service();
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    assert!(matches!(
        member.exit_group(9),
        LifecycleOutcome::Transferred { .. }
    ));
    if let Some(reason) = member.take_run_failure() {
        return Err(NativeTerminalFailure {
            binding: member.binding,
            reason,
        });
    }
    assert!(member.take_handoff_receipt().is_some());
    drop(member);
    let live_members = fixture.page.live();
    assert_eq!(live_members, 0);
    let sibling_record_retired = fixture.zone.live(sibling.record).is_none();
    assert!(sibling_record_retired);
    use carrick_core::terminal::{MissingContinuationVerdict, missing_zone_continuation};
    let birth = sibling.control.host_birth_identity().unwrap();
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            Some(birth),
            sibling.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::Terminal
    );
    // A recycled/foreign binding cannot borrow this member's terminal receipt.
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            Some(birth),
            fixture.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::InvariantViolation
    );
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            fixture.control.host_birth_identity(),
            sibling.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::InvariantViolation
    );

    // The existing host handback reloads a fresh home record and renews its
    // retained native registry binding before entering the owner checkpoint.
    let record = fixture.zone.take_service_head(fixture.slot).unwrap();
    assert_eq!(record, fixture.record);
    let identity = fixture.zone.record(record.id).identity();
    fixture.zone.free_record(record.id);
    let home = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
    fixture
        .registry
        .rehome_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    assert_ne!(fixture.zone.record_ref(home), record);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let resumed =
        owner
            .resume_checkpoint(|_| Ok(None))
            .map_err(|reason| NativeTerminalFailure {
                binding: owner.binding,
                reason,
            })?;
    assert_eq!(owner.take_run_failure(), None);
    let NativeResume::Left(Some(status)) = resumed else {
        panic!("terminal owner did not publish its status");
    };
    Ok(status)
}

#[cfg(test)]
#[test]
fn exit_group_host_request_before_terminal_park_retains_owner() {
    assert_eq!(run().unwrap(), LinuxWaitStatus::exited(0));
}

#[cfg(test)]
#[test]
fn run_failed_never_mints_terminal_load_authority() {
    let fixture = native_exec_fixture();
    let _sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    let mut service = fixture.service();
    let saved = words(fixture.address);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner.run_failed(carrick_core_abi::NativeRunFailureReason::NativeQuarantined);
    assert_eq!(
        owner.take_run_failure(),
        Some(carrick_core_abi::NativeRunFailureReason::NativeQuarantined)
    );
    assert!(fixture.zone.live(fixture.record).is_none());
    let birth = fixture.control.host_birth_identity().unwrap();
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            fixture.control,
            birth,
            Some(birth),
            fixture.record,
            fixture.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::InvariantViolation,
        "run_failed cleanup must never mint ordinary terminal authority"
    );
}

#[cfg(test)]
#[test]
fn losing_entryless_exit_group_publishes_terminal_before_record_release() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(fixture.control.entry().is_none());
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, fixture.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(fixture.slot),
        Some(fixture.record.id)
    );
    let saved = words(fixture.address);
    let mut sibling_service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let mut service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Exception,
        })
        .unwrap();
    assert!(matches!(
        fixture.zone.claim_for_host(
            fixture.record,
            None,
            carrick_sched_core::Handback::Control,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::El1Held { .. }
    ));
    assert!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap()
            .is_some()
    );
    assert!(fixture.zone.live(fixture.record).is_none());
    let birth = fixture.control.host_birth_identity().unwrap();
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            fixture.control,
            birth,
            Some(birth),
            fixture.record,
            fixture.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::Terminal,
        "losing entry-less caller released its saved continuation without terminal custody"
    );
    assert_eq!(
        fixture.page.live(),
        0,
        "each of the two callers owns one live unit"
    );
}

#[cfg(test)]
#[test]
fn losing_pool_exit_group_does_not_reserve_membership_twice() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(sibling.slot, sibling.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id)
    );
    assert!(fixture.zone.live(sibling.record).is_some());
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let mut sibling_service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    assert_eq!(page.live(), 0);
    assert!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Syscall)
            .unwrap()
            .is_some()
    );
    assert!(fixture.zone.live(sibling.record).is_none());
    let graph_cleanup =
        carrick_core::terminal::reserve_host_thread_exit_membership(page, sibling.control)
            .expect("losing caller already consumed its exact membership");
    graph_cleanup
        .retire_published(
            sibling.control.entry().unwrap(),
            sibling.control,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
    assert_eq!(page.live(), 0);
}

#[cfg(test)]
#[test]
fn losing_exit_group_keeps_host_reserved_membership_and_live_record() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let _ = super::super::host_test_support::take_terminal_vacates();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(sibling.slot, sibling.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id)
    );
    assert!(fixture.zone.live(sibling.record).is_some());
    let installed = fixture.zone.installed_space(sibling.slot);
    assert_ne!(
        installed, 0,
        "the switched-in sibling runs in its process space"
    );
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let host =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sibling.control)
            .unwrap();
    assert_eq!(fixture.page.live(), 0);
    let mut sibling_service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Exception,
        })
        .unwrap();
    assert!(matches!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap(),
        Some(LifecycleOutcome::HostCustody)
    ));
    assert!(fixture.zone.live(sibling.record).is_some());
    assert_eq!(
        super::super::host_test_support::take_terminal_vacates(),
        0,
        "host custody must keep the installed process translation live"
    );
    assert_eq!(
        fixture.zone.installed_space(sibling.slot),
        installed,
        "host custody keeps the slot's space occupancy with its translation"
    );
    assert_eq!(page.live(), 0);
    assert!(
        host.commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
            .retire_published(
                sibling.control.entry().unwrap(),
                sibling.control,
                &carrick_core::lifecycle::RegistryWriteHeld::for_test()
            )
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap(),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert!(fixture.zone.live(sibling.record).is_none());
    assert_eq!(super::super::host_test_support::take_terminal_vacates(), 1);
    assert_eq!(
        fixture.zone.installed_space(sibling.slot),
        0,
        "the released member's slot holds no process space"
    );
    assert_eq!(page.live(), 0);
}

#[cfg(test)]
#[test]
fn retiring_host_issued_sibling_refuses_tgkill_with_esrch() {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
    };
    let fixture = native_exec_fixture();
    let sibling = super::add_signal_sibling(&fixture, None, true);
    assert_eq!(fixture.page.live(), 2);
    let _reserved =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sibling.control)
            .unwrap();
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut sender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(42),
            SignalRequest::Probe,
            SignalInfo::Generated(None),
        ),
        Err(carrick_syscall_abi::LINUX_ESRCH),
    );
}

/// Occupancy invariant only (#1100): a losing exit_group member switched in
/// at the SVC of its pending object operation is vacated to the maintenance
/// root, then its release is refused (`CurrentRelease::Requeued`, #685). Its
/// vCPU no longer runs the process root, so the slot's occupancy word must
/// not name that space either. The refusal itself still fails the run closed
/// (`NativeQuarantined`), so this is not the route of #2374's signed failures:
/// that is `closing_interrupt_hands_a_loaded_members_home_record_to_its_host`.
#[cfg(test)]
#[test]
fn refused_losing_exit_after_vacate_leaves_no_installed_space() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken, OwnerEntry};
    let fixture = native_exec_fixture();
    let _ = super::super::host_test_support::take_terminal_vacates();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    let deliver = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, _>| {
        let _ = owned.into_parts();
    };
    let key = ObjectWaitKey::new(9, 1).unwrap();
    fixture
        .zone
        .bind_object_wait(key, &carrick_sched_core::ShortLockSpin, &deliver)
        .unwrap();
    {
        let guard = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &deliver)
            .unwrap();
        guard
            .park(
                guard.snapshot(),
                sibling.record.id,
                OperationToken::new(42, 9).unwrap(),
            )
            .unwrap();
    }
    fixture.zone.clear_current(sibling.slot);
    {
        let guard = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &deliver)
            .unwrap();
        let mut effects = carrick_sched_core::WakeEffects::default();
        assert_eq!(
            guard
                .notify_object(sibling.slot, &mut effects)
                .unwrap()
                .queued,
            1
        );
    }
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id)
    );
    assert!(
        fixture
            .zone
            .record(sibling.record.id)
            .has_object_operation()
    );
    assert_ne!(
        fixture.zone.installed_space(sibling.slot),
        0,
        "the switched-in sibling runs in its process space"
    );
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let mut sibling_service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let outcome = match loser.exit_group(9) {
        LifecycleOutcome::Redispatch => "redispatch",
        LifecycleOutcome::HostCustody => "host custody",
        LifecycleOutcome::Returned { .. } => "returned",
        LifecycleOutcome::Transferred { .. } => "transferred",
    };
    // The refused release is a broken invariant: the run fails closed.
    assert_eq!(
        loser.take_run_failure(),
        Some(carrick_core_abi::NativeRunFailureReason::NativeQuarantined),
        "{outcome}"
    );
    assert!(
        fixture.zone.live(sibling.record).is_some(),
        "the requeued record keeps its pending operation: {outcome:?}"
    );
    assert!(
        fixture
            .zone
            .record(sibling.record.id)
            .has_object_operation()
    );
    let vacates = super::super::host_test_support::take_terminal_vacates();
    assert_eq!(
        vacates, 1,
        "the losing member left its process root: {outcome:?}"
    );
    assert_eq!(
        fixture.zone.installed_space(sibling.slot),
        0,
        "a vacated root must not leave the slot's occupancy naming the process space: {outcome:?}"
    );
}

/// #2374: a closing group interrupts every member record (#2298). A
/// host-loaded member parked on its home record in an EL1 futex wait is woken
/// with `EINTR` and selected again on its home slot, while its host job stays
/// loaded on that vCPU. Retiring that home record in the ring vacates the
/// vCPU to the maintenance root and clears the slot's host record; the host's
/// zone reconciliation then accepts the vacated slot under the exit request
/// and serves the job's in-flight syscall over the maintenance root. Its next
/// zone save names ASID 0 and the reload is refused ("HVPatch task projection
/// ASID 1 does not match CPU TTBR pair 0x2d001f8000/0x2d001f8000").
///
/// Model of the host's save, from what the ring leaves: while the home record
/// is the slot's host record, settlement rewrites the job's roots from its own
/// stage-1 lease; once the ring cleared it, the job keeps the live roots,
/// which name the maintenance root (ASID 0) if the ring vacated them.
#[cfg(test)]
#[test]
fn closing_interrupt_hands_a_loaded_members_home_record_to_its_host() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    const PROCESS_ASID: u16 = 1;
    const MAINTENANCE_ASID: u16 = 0;
    const FUTEX: u64 = 0x7000;
    let fixture = native_exec_fixture();
    let _ = super::super::host_test_support::take_terminal_vacates();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    // The sibling is host-loaded: its record is its slot's host home, running
    // in its process space, with nothing switched in.
    assert_eq!(fixture.zone.slot(sibling.slot).current(), None);
    assert_eq!(
        fixture.zone.slot(sibling.slot).host_record(),
        Some(sibling.record.id)
    );
    // EL1 serves its futex wait by parking that home record.
    {
        let guard = fixture.zone.short_lock(
            carrick_sched_core::ZoneTables::<carrick_sched_core::ParkedContextWords>::bucket_of_with_context(
                1, FUTEX,
            ),
            &carrick_sched_core::ShortLockSpin,
        );
        let seq = fixture.zone.next_seq(sibling.record.id);
        fixture
            .zone
            .enqueue(&guard, sibling.record.id, seq, 1, FUTEX, u32::MAX, 0)
            .unwrap();
        fixture.zone.publish_park(sibling.record.id, seq);
    }

    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    assert_eq!(owner.take_run_failure(), None);
    drop(owner);
    assert!(sibling.control.host_exit_requested());

    // The interrupted waiter is runnable again on its home slot, where its
    // host job is still loaded.
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id),
        "the closing interrupt must wake the parked home record"
    );
    let mut sibling_service = fixture.service();
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let resumed = match member.resume_checkpoint(|_| Ok(None)) {
        Ok(NativeResume::Left(None)) => "left",
        Ok(NativeResume::Left(Some(_))) => "root exit",
        Ok(NativeResume::NoPending) => "no pending",
        Ok(_) => "resumed",
        Err(_) => "run failure",
    };
    let run_failure = member.take_run_failure();
    drop(member);
    assert_eq!(run_failure, None, "{resumed}");
    assert_eq!(resumed, "left", "the member leaves the ring");

    let vacated = super::super::host_test_support::take_terminal_vacates() != 0;
    let host_settles_own_roots =
        fixture.zone.slot(sibling.slot).host_record() == Some(sibling.record.id);
    let saved_asid = if host_settles_own_roots || !vacated {
        PROCESS_ASID
    } else {
        MAINTENANCE_ASID
    };
    assert_eq!(
        saved_asid,
        PROCESS_ASID,
        "the host job saves this thread over the maintenance root: vacated={vacated} \
         host_record={:?}",
        fixture.zone.slot(sibling.slot).host_record()
    );
    // Its host owner retires it: the live record is handed back to the
    // executor that still holds the thread, not freed in the ring.
    assert_eq!(
        fixture.zone.take_service_head(sibling.slot),
        Some(sibling.record),
        "the home record waits for its own executor"
    );
    assert_eq!(fixture.page.live(), 1, "only the owner's unit was consumed");
}
