//! Production forks, IPC parks and host final-close publication with no guest CPU.
use super::*;
use carrick_el1::substrate::file::UserCopy;
use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
use carrick_sched_core::{Claim, ShortLockSpin};
use std::sync::Arc;

struct NoCopy;
impl UserCopy for NoCopy {
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        panic!("an empty-pipe read must not copy input")
    }
    fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
        panic!("EOF must not publish bytes")
    }
}

#[test]
fn serial_host_two_native_children_pipe_eof_wake_without_a_guest_executor() {
    two_native_children_pipe_eof_wake(false);
}

#[test]
fn serial_host_two_native_children_pipe_eof_wake_with_the_executor_away() {
    two_native_children_pipe_eof_wake(true);
}

fn two_native_children_pipe_eof_wake(away: bool) {
    let fixture = Fixture::new(0x10000, asid(1));
    struct RestoreRegion(usize);
    impl Drop for RestoreRegion {
        fn drop(&mut self) {
            carrick_el1_abi::record_el1_region_host_ptr(self.0);
        }
    }
    let _restore = RestoreRegion(carrick_el1_abi::get_el1_region_host_ptr());
    carrick_el1_abi::record_el1_region_host_ptr(fixture.region.ptr.as_ptr() as usize);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let task = CurrentTask::new();
    let runtime = NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source,
        &fixture.task,
        fixture.page,
        fixture.control,
        fixture.address,
        fixture.address,
        parked,
        crate::aarch64_process::registry().host_exec_waiters(),
    )
    .unwrap();
    let owner = Arc::new(
        HostIpc::with_limits(
            1 << 20,
            IpcLimits {
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
                ..IpcLimits::ZONE
            },
        )
        .unwrap(),
    );
    let table = HostTable::create(Arc::clone(&owner), 64, 64).unwrap();
    let object = owner.create_pipe(65536).unwrap();
    let reader = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    let writer = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Writer,
            }
            .encode(),
            fd::AccessMode::WriteOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    writer.install(table.id(), fd::Fd(4), false).unwrap();
    let region = Box::leak(carrick_test_support::TestEl1Region::zeroed());
    // SAFETY: aligned ABI storage retained for all inherited table bindings.
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.ipc = Some((Arc::clone(&owner), map));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let children: [_; 2] = core::array::from_fn(|_| {
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("native fork must return");
        };
        assert!(result.raw() > 0, "fork errno: {}", -result.raw());
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        runtime.task_binding(child).unwrap()
    });
    assert_ne!(children[0].address.mm, children[1].address.mm);
    let parent_binding = runtime.task_binding(parent).unwrap();
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent_binding.record.id);
    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let call = |cpu: &mut crate::sched::FakeCpu, frame: &mut carrick_el1_abi::TrapFrame| {
        let mut sched = crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &task,
            cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        };
        crate::ipc::serve_ipc(&mut sched, frame, &venue, &mut NoCopy)
    };
    let mut saved = Vec::new();
    for child in &children {
        activate_target(source, &task, child);
        assert!(fixture.zone.record(child.record.id).is_native_owned());
        // Pending boundary work makes the real adapter leave after publishing
        // its park, rather than selecting the still-live parent or sibling.
        task.linux.mark_pending_host_work();
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x4004,
            slot: fixture.slot.raw() as u64,
            ..Default::default()
        };
        frame.x[8] = 63;
        frame.x[0] = 3;
        frame.x[1] = 0x4000;
        frame.x[2] = 8;
        assert_eq!(call(&mut cpu, &mut frame), crate::ipc::IpcServed::Idle);
        assert!(matches!(
            fixture.zone.record(child.record.id).claim(),
            Claim::Parked { .. }
        ));
        assert!(
            fixture.zone.slot(fixture.slot).current().is_none(),
            "park releases execution"
        );
        saved.push(
            fixture
                .zone
                .record(child.record.id)
                .object_wait_census()
                .unwrap(),
        );
    }
    fixture.zone.leave_guest(fixture.slot, &ShortLockSpin);
    if away {
        assert!(fixture.zone.step_away(
            fixture.slot,
            1,
            &mut |record| assert_eq!(record, parent_binding.record),
            &mut |_| panic!("the fixture has no second driver"),
        ));
        assert!(!fixture.zone.slot(fixture.slot).is_live());
    }
    // Every inherited writer is closed in the host venue while both children
    // remain alive. The final close runs the shipping ObjectWakeDelivery path.
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        drop(writer);
        table.close(fd::Fd(4)).unwrap();
        for child in &children {
            let raw = map
                .lookup(fixture.zone.record(child.record.id).identity().file_table)
                .unwrap();
            let child_table = fd::TableId::from_raw(raw);
            if let Some(description) = owner
                .region()
                .fd(ShortLockSpin)
                .close(child_table, fd::Fd(4))
                .unwrap()
            {
                owner.release(description.backing).unwrap();
            }
        }
    });
    for (child, operation) in children.iter().zip(saved) {
        assert!(
            runtime.task_binding(child.key).is_some(),
            "peer stays alive"
        );
        let record = fixture.zone.record(child.record.id);
        assert!(
            matches!(record.claim(), Claim::Queued { .. }),
            "native IPC wake has no host continuation: {:?}",
            record.claim()
        );
        let resumed = record.object_wait_census().unwrap();
        assert_eq!(
            (resumed.operation, resumed.operation_generation),
            (operation.operation, operation.operation_generation),
            "retain exact operation"
        );
        assert_eq!(resumed.queue, 0);
    }
    if away {
        fixture.zone.step_back(fixture.slot, 1);
    }
    fixture.zone.enter_guest(fixture.slot);
    for child in &children {
        activate_target(source, &task, child);
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x4004,
            slot: fixture.slot.raw() as u64,
            ..Default::default()
        };
        frame.x[8] = 63;
        frame.x[0] = 3;
        frame.x[1] = 0x4000;
        frame.x[2] = 8;
        assert_eq!(
            call(&mut cpu, &mut frame),
            crate::ipc::IpcServed::Returned { switched: false }
        );
        assert_eq!(frame.x[0], 0, "the same read completes EOF, never replays");
        assert!(!fixture.zone.record(child.record.id).has_object_operation());
        fixture
            .zone
            .requeue_preempted(fixture.slot, child.record.id);
    }
    assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 2);
}
