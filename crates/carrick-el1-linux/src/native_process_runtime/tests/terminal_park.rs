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
    fixture
        .zone
        .requeue_preempted(fixture.slot, fixture.record.id);
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
    let resumed = owner
        .resume_checkpoint()
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
    fixture
        .zone
        .requeue_preempted(fixture.slot, fixture.record.id);
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
            &carrick_sched_core::ShortLockSpin
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
    fixture
        .zone
        .requeue_preempted(sibling.slot, sibling.record.id);
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
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    fixture
        .zone
        .requeue_preempted(sibling.slot, sibling.record.id);
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
    assert_eq!(page.live(), 0);
}
