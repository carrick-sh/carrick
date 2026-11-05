//! A production native fork and exec retain the same in-zone pipe endpoint.
use super::*;
use crate::native_process_runtime::{NativeResume, NativeServiceCall, host_test_support::Physical};
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
    ServiceCell,
};
use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
use carrick_sched_core::{ShortLockSpin, WakeEffects};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn serial_host_native_fork_exec_pipe_writer_reaches_its_parent() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
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
    let table = Arc::new(HostTable::create(owner.clone(), 64, 64).unwrap());
    let object = owner.create_pipe(65536).unwrap();
    for (number, end, access) in [
        (3, End::Reader, fd::AccessMode::ReadOnly),
        (4, End::Writer, fd::AccessMode::WriteOnly),
    ] {
        owner
            .admit_description(fd::Description::new(
                IpcBacking::Pipe { object, end }.encode(),
                access,
                fd::StatusFlags::default(),
            ))
            .unwrap()
            .install(table.id(), fd::Fd(number), false)
            .unwrap();
    }
    let storage = Box::leak(carrick_test_support::TestEl1Region::zeroed());
    // SAFETY: aligned storage is retained for both inherited table bindings.
    let map = unsafe {
        &*storage
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.ipc = Some((owner.clone(), map));
    let words = fixture.tables.live(&fixture.maintenance);
    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            parked,
        )
        .unwrap(),
    );
    runtime.give_fixture_root_a_cwd();
    let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
    registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let mut fork_service = Aarch64NativeProcessService::with_crossing(
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
    let child = {
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut fork_service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("fork must return");
        };
        assert!(result.raw() > 0);
        runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap()
    };
    let child_binding = runtime.task_binding(child).unwrap();
    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate_target(source, &fixture.task, &child_binding);
    let child_table = fixture.task.linux.file_table.load(Ordering::Acquire);
    assert_ne!(child_table, 5, "production fork owns an inherited table");
    let mut service = Physical {
        zone: fixture.zone,
        page: fixture.page,
        controls: &[],
        copies: Vec::new(),
        tid_words: BTreeMap::new(),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: Some(owner.region()),
        refuse_copy: false,
        on_signal_clock: None,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
    payload.extend_from_slice(b"/bin/pipe-writer\0");
    carrick_core_abi::service::encode_exec_payload_header(
        &mut payload,
        carrick_core_abi::service::ExecCall::Execve,
        b"/bin/pipe-writer\0".len(),
        0,
        0,
    )
    .unwrap();
    {
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                child_binding.address,
                &child_binding.words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.begin_exec_service(
                payload.into_boxed_slice(),
                None,
                NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(221), &counters)
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let selector = fixture.task.service_notice.take().unwrap().unwrap();
    let member = fixture.zone.record(selector.record.id).identity();
    // SAFETY: the production fork's live record retains its control slot.
    let control = unsafe { &*(member.control_slot as *const ThreadControlSlot) };
    // SAFETY: this fixture consumes the exact published service ticket once.
    let ticket =
        unsafe { ServiceCell::claim_notice(&control.service, selector, NonZeroU64::MIN, member) }
            .unwrap();
    let identity = ticket.request().identity;
    // SAFETY: the service owner retains this reply record until acknowledgment.
    let manifest =
        unsafe { &mut *(ticket.reply_address().unwrap().raw() as *mut ExecSuccessorManifest) };
    let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(91).unwrap()).unwrap();
    *manifest = manifest
        .seal(
            identity,
            receipt,
            ExecSuccessorBacking {
                root: RootGpa::page_aligned(FrameGpa::new(0xb00000)).unwrap(),
                asid: asid(103),
                asid_generation: NonZeroU64::new(105).unwrap(),
            },
            ExecSuccessorEntry {
                entry: UserVa::new(0x400000),
                stack_pointer: UserVa::new(0x7ffff000),
            },
        )
        .unwrap();
    assert!(
        ticket
            .publish_exec_prepared(receipt, (), |_, ()| {})
            .is_ok()
    );
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(selector.record)
                .unwrap(),
            &ShortLockSpin,
        )
        .unwrap();
    let mut effects = WakeEffects::default();
    queue.notify_object(fixture.slot, &mut effects).unwrap();
    drop(queue);
    service.wake_effects(effects);
    let selected = activate_target(source, &fixture.task, &child_binding);
    assert_eq!(selected.record, child_binding.record.id);
    // SAFETY: this fixture owns the selected child's exact record.
    let saved = unsafe { runtime.record_binding(child_binding.record) }
        .unwrap()
        .words;
    {
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                child_binding.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint(),
            Ok(NativeResume::NoPending)
        ));
    }
    assert_eq!(
        fixture.task.linux.file_table.load(Ordering::Acquire),
        child_table
    );
    assert_ne!(
        fixture.task.mm.key.load(Ordering::Acquire),
        child_binding.address.mm.raw().get()
    );
    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let mut memory = carrick_test_support::GuestUserBuffer::zeroed(1024);
    memory.as_mut_bytes()[128..130].copy_from_slice(b"1\n");
    memory.as_mut_bytes()[256..260].copy_from_slice(b"2\n3\n");
    for (index, word) in [memory.arg() + 128, 2, memory.arg() + 256, 4]
        .into_iter()
        .enumerate()
    {
        memory.as_mut_bytes()[index * 8..index * 8 + 8].copy_from_slice(&word.to_ne_bytes());
    }
    let mut cpu = crate::sched::FakeCpu::default();
    assert_eq!(fixture.slot.raw(), 0);
    // SAFETY: zero is the valid empty name-cache state; retained by fixture.
    let names = unsafe {
        &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<carrick_el1_abi::InotifyNameCache>())
            .cast::<carrick_el1_abi::InotifyNameCache>()
    };
    let mut call = |nr, fd, address, count| {
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x400004,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = fd;
        frame.x[1] = address;
        frame.x[2] = count;
        let action = crate::dispatch::dispatch_syscall_with_ipc(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            Some(&venue),
            |_| core::ptr::null_mut(),
        );
        assert!(
            matches!(
                action,
                carrick_el1_abi::Action::Served | carrick_el1_abi::Action::ServedWithWork
            ),
            "production IPC dispatch: {action:?}"
        );
        frame.x[0]
    };
    assert_eq!(
        call(64, 4, memory.arg() + 128, 2),
        2,
        "exec successor's scalar write"
    );
    assert_eq!(
        call(66, 4, memory.arg(), 2),
        6,
        "exec successor's vector write"
    );
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_binding.record.id)
            .is_queued()
    );
    activate_target(source, &fixture.task, &parent_binding);
    assert_eq!(call(63, 3, memory.arg() + 512, 8), 8);
    assert_eq!(&memory.as_mut_bytes()[512..520], b"1\n1\n2\n3\n");
    registry.unregister_root_for_test(&runtime);
}
