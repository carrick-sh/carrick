//! The x86 CPL0 switch-in's process binding after another process ran on the
//! slot (#1958). This is a regression guard, not a red witness: the CPL0
//! scheduler (`carrick-x86-cpl0` `native_execution::schedule`) resolves the
//! selected record's owner (`runtime_for_record`), takes the PID and address
//! from that owner's row (`record_binding`), and treats an unregistered
//! record as fatal. So x86 never resumes a record with a foreign binding.
//! The guard checks that this owner-row resolution agrees with the
//! ISA-neutral group lookup that the ARM unhomed resume publishes.
use super::*;

/// The steps of `schedule` from `switch_in_full` to `resume_checkpoint`, run
/// with the production calls in the same order on x86 context words.
/// `leave_space`, `settle_current_work` and the CR3 install are ISA
/// mechanics the host fixture does not have.
#[test]
fn x86_switch_in_after_another_process_admits_under_the_selected_owner() {
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let current = fixture.task;
    let root_key = fixture.runtime.graph.lock().root_key;
    let root_pid = fixture.runtime.process_binding(root_key).unwrap().0;
    // The previous occupant is the root: it forked and then blocked in wait4
    // on this slot, and its binding is still published.
    assert_eq!(current.visible_pid(), Some(root_pid));
    current.publish_root_generation(fixture.address.generation);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    let record = fixture.zone.record_ref(selected.record);
    assert_ne!(record, fixture.record, "the fork child is selected");
    let runtime = fixture
        .registry
        .for_record(fixture.zone, record)
        .expect("runtime_for_record: the selected record is registered");
    // SAFETY: switch_in_full transferred this exact record to this slot.
    let state = unsafe { runtime.record_binding(record) }.unwrap();
    let identity = fixture.zone.record(selected.record).identity();
    fixture
        .zone
        .install_space(fixture.slot, state.address.mm.raw().get())
        .unwrap();
    current.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(i32::try_from(identity.tid).unwrap()),
        carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
        identity.file_table,
    );
    current
        .mm
        .key
        .store(state.address.mm.raw().get(), Ordering::Release);
    current
        .mm
        .thread_generation
        .store(identity.serial, Ordering::Release);
    current.publish_visible_pid(state.visible_pid);
    current.publish_lifecycle(identity.lifecycle_page, identity.control_slot);

    assert_ne!(state.visible_pid, root_pid);
    assert_eq!(current.visible_pid(), Some(state.visible_pid));
    // The owner row the CPL0 switch-in uses agrees with the shared group
    // lookup that the ARM unhomed resume publishes.
    assert_eq!(
        fixture
            .registry
            .group_binding(fixture.zone, identity.mm, identity.lifecycle_page),
        Some(carrick_el1_abi::ProcessBinding {
            visible_pid: core::num::NonZeroU32::new(state.visible_pid).unwrap(),
            root_generation: state.address.generation,
        })
    );

    let mut service = fixture.service();
    let mut entry = runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            current,
            state.address,
            &state.words,
            &mut service,
        )
        .expect("the child's admission under its own owner");
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
}
