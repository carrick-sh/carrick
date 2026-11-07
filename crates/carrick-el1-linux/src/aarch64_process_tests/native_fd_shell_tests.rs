//! Shell descriptor compositions through real native fork and dispatch.
use super::*;

#[test]
fn serial_host_native_child_redirect_restore_stdout_1410() {
    shell_descriptor_composition(false);
}

#[test]
fn serial_host_native_subshell_reads_parent_duplicated_heredoc_1399() {
    shell_descriptor_composition(true);
}

fn shell_descriptor_composition(heredoc: bool) {
    use carrick_abi::{LINUX_F_DUPFD, LINUX_F_GETFD};
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    let fixture = Fixture::new(0x10000, asid(1));
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
    // Initial extent capacity 8 with soft limit 64 forces in-ring table growth
    // when native children dup3/F_DUPFD above descriptor 7.
    let table = HostTable::create(Arc::clone(&owner), 64, 8).unwrap();
    let object = owner.create_pipe(65536).unwrap();
    let reader = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags {
                nonblock: true,
                ..fd::StatusFlags::default()
            },
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
    // Pre-open fd 1 as an alias of reader with FD_CLOEXEC so child 0's dup2(4, 1)
    // replaces a live open target and clears FD_CLOEXEC.
    reader.install(table.id(), fd::Fd(1), true).unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    writer.install(table.id(), fd::Fd(4), true).unwrap();
    let region = Box::leak(carrick_test_support::TestEl1Region::zeroed());
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
    let child_bindings: [_; 2] = core::array::from_fn(|_| {
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("native fork must return");
        };
        assert!(result.raw() > 0, "fork errno number: {}", -result.raw());
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        runtime.task_binding(child).unwrap()
    });
    let children = child_bindings
        .each_ref()
        .map(|binding| fixture.zone.record(binding.record.id).identity().file_table);
    assert_ne!(children[0], children[1]);

    // Only the two live children retain the writer and fd 1 aliases.
    drop(writer);
    table.close(fd::Fd(1)).unwrap();
    table.close(fd::Fd(4)).unwrap();

    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );

    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());

    let run_in_child = |binding: &crate::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
                        nr: u64,
                        args: [u64; 3]|
     -> (CompletionRoute, i64) {
        let mut cpu = crate::sched::FakeCpu::default();
        let mut svc = Aarch64NativeProcessService::with_crossing(
            &task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        let child_ctx = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, binding.address);
        let mut entry = runtime.enter(source, &task, child_ctx, &mut svc).unwrap();
        let mut frame = carrick_el1_abi::TrapFrame {
            slot: fixture.slot.index() as u64,
            elr: 0x4004,
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = args[0];
        frame.x[1] = args[1];
        frame.x[2] = args[2];
        carrick_test_support::assert_guest_args(&args);
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&task),
            crossing.fd_map(),
            &[],
            crossing.open_table(),
            &[],
            &names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            Some(&venue),
            Some(&fixture),
            Some(&mut entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        (route, frame.x[0] as i64)
    };

    use carrick_personality_linux::crossing::nr;
    activate_target(source, &task, &child_bindings[0]);
    let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"shell-fd");
    let output = carrick_test_support::GuestUserBuffer::zeroed(8);
    let invoke = |binding: &crate::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
                  nr: u64,
                  args| {
        let (route, value) = run_in_child(binding, nr, args);
        assert_eq!(
            route,
            CompletionRoute::Served,
            "descriptor operation must stay in ring"
        );
        value
    };
    assert_eq!(
        invoke(
            &child_bindings[0],
            nr::CLOSE_RANGE.raw(),
            [
                3,
                u64::from(u32::MAX),
                u64::from(carrick_abi::LINUX_CLOSE_RANGE_CLOEXEC)
            ]
        ),
        0
    );
    assert_eq!(
        invoke(&child_bindings[0], nr::FCNTL.raw(), [3, LINUX_F_GETFD, 0]),
        1
    );
    assert_eq!(
        invoke(
            &child_bindings[0],
            nr::FCNTL.raw(),
            [3, carrick_abi::LINUX_F_SETFD, 0]
        ),
        0
    );
    assert_eq!(
        invoke(&child_bindings[0], nr::FCNTL.raw(), [3, LINUX_F_GETFD, 0]),
        0
    );
    for args in [[4, 3, 0], [0, 4, 1]] {
        assert_eq!(invoke(&child_bindings[0], nr::CLOSE_RANGE.raw(), args), -22);
    }
    assert_eq!(
        invoke(
            &child_bindings[0],
            nr::CLOSE_RANGE.raw(),
            [
                u64::from(u32::MAX),
                u64::from(u32::MAX),
                u64::from(carrick_abi::LINUX_CLOSE_RANGE_CLOEXEC)
            ]
        ),
        0
    );
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    assert_eq!(
        invoke(&child_bindings[1], nr::FCNTL.raw(), [3, LINUX_F_GETFD, 0]),
        0
    );
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[1].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[0]);
    let mut grandchild_table = None;
    if heredoc {
        // The shell parent duplicates the heredoc reader before forking its
        // subshell. Both steps use the production owner, not a copied test fd.
        assert_eq!(
            invoke(&child_bindings[0], nr::FCNTL.raw(), [3, LINUX_F_DUPFD, 10]),
            10
        );
        assert_eq!(
            invoke(&child_bindings[0], nr::WRITE.raw(), [4, payload.arg(), 8]),
            8
        );
        let mut svc = Aarch64NativeProcessService::with_crossing(
            &task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        let ctx = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[0].address);
        let mut entry = runtime.enter(source, &task, ctx, &mut svc).unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("subshell fork must return");
        };
        assert!(result.raw() > 0, "fork errno {}", -result.raw());
        drop(entry);
        let key = runtime
            .namespace_child_key(child_bindings[0].key, result.raw() as u32)
            .unwrap();
        let grandchild = runtime.task_binding(key).unwrap();
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, child_bindings[0].record.id)
                .is_queued()
        );
        activate_target(source, &task, &grandchild);
        assert_eq!(
            invoke(&grandchild, nr::READ.raw(), [10, output.arg(), 8]),
            8
        );
        assert_eq!(output.as_bytes(), b"shell-fd");
        grandchild_table = Some(
            fixture
                .zone
                .record(grandchild.record.id)
                .identity()
                .file_table,
        );
    } else {
        // stdout -> saved fd -> temporary redirect -> restored stdout.
        assert_eq!(invoke(&child_bindings[0], nr::DUP3.raw(), [4, 1, 0]), 1);
        assert_eq!(
            invoke(&child_bindings[0], nr::FCNTL.raw(), [1, LINUX_F_DUPFD, 10]),
            10
        );
        assert_eq!(invoke(&child_bindings[0], nr::DUP3.raw(), [3, 1, 0]), 1);
        assert_eq!(
            invoke(
                &child_bindings[0],
                nr::DUP3.raw(),
                [10, 1, carrick_syscall_abi::LINUX_O_CLOEXEC]
            ),
            1
        );
        assert_eq!(
            invoke(&child_bindings[0], nr::FCNTL.raw(), [1, LINUX_F_GETFD, 0]),
            1
        );
        assert_eq!(invoke(&child_bindings[0], nr::CLOSE.raw(), [10, 0, 0]), 0);
        assert_eq!(
            invoke(&child_bindings[0], nr::WRITE.raw(), [1, payload.arg(), 8]),
            8
        );
        assert_eq!(
            invoke(&child_bindings[0], nr::READ.raw(), [3, output.arg(), 8]),
            8
        );
        assert_eq!(output.as_bytes(), b"shell-fd");
    }
    if let Some(table) = grandchild_table {
        service.retire_fd_table(table);
    }
    for child in children {
        service.retire_fd_table(child);
    }
    owner.drain_retired_tables().unwrap();
    table.close(fd::Fd(3)).unwrap();
    drop(reader);
}
