//! A production native fork and exec retain the same in-zone pipe endpoint.
use super::*;
use crate::native_process_runtime::{NativeResume, NativeServiceCall, host_test_support::Physical};
use crate::sched::LinuxSchedEntry;
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
    // SAFETY: the stopped fixture exclusively owns the parent's current
    // record. Supply the context save normally performed before preemption;
    // the root fixture's default words do not authenticate its address space.
    unsafe {
        *fixture.zone.record(parent_binding.record.id).ctx_mut() = parent_binding.words;
    }
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
            entry.resume_checkpoint(|_| Ok(None)),
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
        let selected = fixture.zone.slot(fixture.slot).current().unwrap();
        // SAFETY: fixture retains this selected live record.
        let binding = unsafe { runtime.record_binding(fixture.zone.record_ref(selected)) }.unwrap();
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                binding.address,
                &binding.words,
                &mut service,
            )
            .unwrap_or_else(|error| panic!("native entry nr={nr}, fd={fd}: {error:?}"));
        let route = crate::dispatch::dispatch_syscall_with_native(
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
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        // Completed in-ring I/O can still owe native return-event work.
        // This fixture checks committed results and pipe bytes below, without
        // modelling the carrier's return transport. Neither route replays I/O.
        assert!(
            matches!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Served
                    | carrick_personality_linux::dispatch::CompletionRoute::WithWork
            ),
            "production native IPC dispatch: {route:?}, nr={nr}"
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
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    for bad in [0, 1u64 << 48, 0x6000_0000] {
        assert_eq!(
            call(66, 4, bad, 1) as i64,
            -14,
            "native child bad iovec {bad:#x} must settle EFAULT in ring"
        );
    }
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
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

#[test]
fn serial_host_parked_pipe_read_resumes_at_saved_svc() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture
        .control
        .initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[1]));
    fixture
        .zone
        .record(fixture.zone.slot(fixture.slot).host_record().unwrap())
        .set_affinity(1);
    fixture.zone.publish_carrier_cpu_count(1);
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
    // SAFETY: the stopped fixture exclusively owns the parent's current
    // record. Supply the context save normally performed before preemption;
    // the root fixture's default words do not authenticate its address space.
    unsafe {
        *fixture.zone.record(parent_binding.record.id).ctx_mut() = parent_binding.words;
    }
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

    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let memory = carrick_test_support::GuestUserBuffer::from_value(*b"q");
    let names = Box::leak(Box::new(carrick_el1_abi::InotifyNameCache::new()));
    let mut cpu = crate::sched::FakeCpu::default();
    // A closure rather than a declarative macro: the CI receipt's test-retirement scan refuses
    // any macro definition in a crate's sources, since one could generate tests it can't see.
    let mut dispatch = |nr: u64, fd: u64| {
        let selected = fixture.zone.slot(fixture.slot).current().unwrap();
        // SAFETY: this stopped fixture exclusively owns the selected live record.
        let binding = unsafe { runtime.record_binding(fixture.zone.record_ref(selected)) }.unwrap();
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                binding.address,
                &binding.words,
                &mut service,
            )
            .unwrap();
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x400004,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = fd;
        frame.x[1] = memory.arg();
        frame.x[2] = 1;
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &*names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            Some(&venue),
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        (route, frame.x[0])
    };
    // Both real fork participants stay alive throughout the reader's park.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_binding.record.id)
            .is_queued()
    );
    activate_target(source, &fixture.task, &parent_binding);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate_target(source, &fixture.task, &child_binding);
    let parked = dispatch(63, 3);
    assert_eq!(
        parked.0,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert!(
        fixture
            .zone
            .record(child_binding.record.id)
            .has_object_operation()
    );
    // SAFETY: the reader is parked and this fixture owns its record.
    assert_eq!(
        unsafe { fixture.zone.record(child_binding.record.id).ctx_mut() }
            .native
            .pc,
        0x400000
    );
    let _ = fixture.task.linux.take_host_work_doorbell();
    activate_target(source, &fixture.task, &parent_binding);
    assert_eq!(dispatch(64, 4).1, 1);
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    // Reload through the production scheduler checkpoint. The object park
    // recorded the SVC itself (0x400000), so adapter completion must not apply
    // the refused-admission rewind a second time.
    let mut resume_cpu = ResumeCpu {
        inner: crate::sched::FakeCpu::default(),
        runtime: &runtime,
        registry,
        source,
        task: &fixture.task,
        service: &mut fork_service,
    };
    let mut resumed_frame = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        (crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut resume_cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .yield_queued(&mut resumed_frame),
        Some(crate::sched::Served::Returned { switched: true })
    );
    assert_eq!(
        fixture.zone.slot(fixture.slot).current(),
        Some(child_binding.record.id),
        "scheduler must reload the parked reader"
    );
    assert_eq!(
        resumed_frame.elr, 0x400000,
        "resume exactly at the parked SVC"
    );
    // A timer IRQ preempts the resumed reader before its SVC executes. This
    // goes through the production IRQ path (`serve_irq` -> `interrupt` ->
    // `preempt` -> `ThreadCpu::save(.., CpuExitCause::Interrupted)`), not the
    // `requeue_preempted` shortcut below, which never saves the context. On
    // the pre-fix `save`, which always wrote `AfterSyscall`, this save
    // replaced the reader's `AtSyscall` position and the next selection
    // rewound it to SVC-4 (#887's double rewind, review P1 on #1799).
    // `yield_queued` requeued the parent when it switched to the reader, so the
    // slot already has another runnable thread for the slice to hand over to.
    assert_ne!(
        fixture.zone.slot(fixture.slot).queued(),
        0,
        "another runnable thread must be queued for the slice to preempt"
    );
    resume_cpu.inner.freq = 1_000_000_000;
    fixture.zone.slot(fixture.slot).restart_slice(1);
    resume_cpu.inner.now = 1 + resume_cpu.inner.freq;
    let irq = (crate::sched::Sched {
        handoff: None,
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut resume_cpu,
        user: &crate::sched::HardwareUserWord,
        counters: &counters,
    })
    .serve_irq(&mut resumed_frame);
    assert_ne!(
        fixture.zone.slot(fixture.slot).current(),
        Some(child_binding.record.id),
        "the expired slice must preempt the reader through the IRQ save ({irq:?})"
    );
    // SAFETY: the IRQ save queued the reader; this stopped fixture owns its
    // record until the scheduler selects it again below.
    let saved = unsafe { fixture.zone.record(child_binding.record.id).ctx_mut() };
    assert_eq!(
        (saved.native.pc, saved.saved_syscall_pc()),
        (
            0x400000,
            Some(carrick_sched_core::SavedSyscallPc::AtSyscall)
        ),
        "an IRQ save before the SVC executes must keep the SVC position"
    );
    let mut after_irq = carrick_el1_abi::TrapFrame::default();
    for _ in 0..2 {
        assert_eq!(
            (crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot: fixture.slot,
                task: &fixture.task,
                cpu: &mut resume_cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            })
            .yield_queued(&mut after_irq),
            Some(crate::sched::Served::Returned { switched: true })
        );
        if fixture.zone.slot(fixture.slot).current() == Some(child_binding.record.id) {
            break;
        }
        let other = fixture.zone.slot(fixture.slot).current().unwrap();
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, other)
                .is_queued()
        );
    }
    assert_eq!(
        fixture.zone.slot(fixture.slot).current(),
        Some(child_binding.record.id),
        "the scheduler must reselect the preempted reader"
    );
    assert_eq!(
        after_irq.elr, 0x400000,
        "a reader preempted by an IRQ before its SVC resumes at the SVC, not SVC-4"
    );
    drop(resume_cpu);

    // Preempt before the SVC executes and select the same reader again. The
    // retry position belongs to the saved context, so selection is idempotent
    // until a later architectural save replaces that context.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_binding.record.id)
            .is_queued()
    );
    let mut resume_cpu = ResumeCpu {
        inner: crate::sched::FakeCpu::default(),
        runtime: &runtime,
        registry,
        source,
        task: &fixture.task,
        service: &mut fork_service,
    };
    let mut selected_again = carrick_el1_abi::TrapFrame::default();
    for _ in 0..2 {
        assert_eq!(
            (crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot: fixture.slot,
                task: &fixture.task,
                cpu: &mut resume_cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            })
            .yield_queued(&mut selected_again),
            Some(crate::sched::Served::Returned { switched: true })
        );
        if fixture.zone.slot(fixture.slot).current() == Some(child_binding.record.id) {
            break;
        }
        let other = fixture.zone.slot(fixture.slot).current().unwrap();
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, other)
                .is_queued()
        );
    }
    assert_eq!(
        fixture.zone.slot(fixture.slot).current(),
        Some(child_binding.record.id)
    );
    assert_eq!(
        selected_again.elr, 0x400000,
        "a second selection before execution must not rewind twice"
    );
    drop(resume_cpu);
    assert_eq!(dispatch(63, 3).1, 1);
    assert!(
        !fixture
            .zone
            .record(child_binding.record.id)
            .has_object_operation(),
        "the completed adapter must consume its record token"
    );
    assert_eq!(
        fixture
            .zone
            .record(child_binding.record.id)
            .resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::UserReturn,
        "the completed adapter must consume its owner continuation"
    );
    let binding = unsafe { runtime.record_binding(child_binding.record) }.unwrap();
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            binding.address,
            &binding.words,
            &mut service,
        )
        .unwrap();
    let next = entry.begin_service(
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(56),
        },
        None,
    );
    assert!(
        matches!(next, Ok(NativeResume::Left(None))),
        "an unrelated native service must park after pipe completion"
    );
    assert!(runtime.task_binding(parent).is_some(), "writer stays alive");
    drop(entry);
    registry.unregister_root_for_test(&runtime);
}
