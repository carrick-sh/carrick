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
