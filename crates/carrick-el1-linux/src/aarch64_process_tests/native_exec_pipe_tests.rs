//! Production native fork/exec successors retain IPC and memory-wait custody.
use super::*;
use crate::native_process_runtime::{NativeResume, NativeServiceCall, host_test_support::Physical};
use crate::sched::LinuxSchedEntry;
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
    ServiceCell,
};
use carrick_el1_abi::Lifecycle;
use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
use carrick_sched_core::{ShortLockSpin, WakeEffects};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn serial_host_native_fork_exec_pipe_writer_reaches_its_parent() {
    fork_exec_successor(None);
}

#[test]
fn serial_host_native_fork_exec_child_futex_retains_owner_refusal() {
    fork_exec_successor(Some(crate::sched::FUTEX_WAIT_PRIVATE));
}

#[test]
fn serial_host_native_fork_exec_child_realtime_bitset_futex_retains_owner_refusal() {
    // glibc sem_wait: CLOCK_REALTIME is valid even with no timeout.
    fork_exec_successor(Some(128 | 256 | 9));
}

#[test]
fn serial_host_native_fork_exec_child_realtime_bitset_zero_mask_is_einval() {
    fork_exec_successor_with_futex(Some(128 | 256 | 9), 0);
}

fn fork_exec_successor(futex: Option<u64>) {
    fork_exec_successor_with_futex(futex, u32::MAX as u64);
}

/// RED: the exec successor has no retained executable-object capability yet.
/// Keep this failing until the live-dentry design in native-exec-link.md lands.
#[test]
fn serial_host_native_fork_exec_child_readlink_exe() {
    fork_exec_probe(None, u32::MAX as u64, true, false);
}

#[test]
fn serial_host_native_fork_exec_child_timed_futex() {
    fork_exec_probe(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        false,
        true,
    );
}

fn fork_exec_successor_with_futex(futex: Option<u64>, bitset: u64) {
    fork_exec_probe(futex, bitset, false, false);
}

fn fork_exec_probe(futex: Option<u64>, bitset: u64, readlink: bool, timed: bool) {
    fork_exec_probe_with_departure(futex, bitset, readlink, timed, None);
}

#[derive(Clone, Copy)]
enum TimerDeparture {
    CarrierExit,
    SlotReset,
}

#[test]
fn serial_host_native_child_timed_futex_carrier_exit() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        false,
        true,
        Some(TimerDeparture::CarrierExit),
    );
}

#[test]
fn serial_host_native_child_timed_futex_slot_reset() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        false,
        true,
        Some(TimerDeparture::SlotReset),
    );
}

fn fork_exec_probe_with_departure(
    futex: Option<u64>,
    bitset: u64,
    readlink: bool,
    timed: bool,
    departure: Option<TimerDeparture>,
) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let metadata_scope = MetadataScope::new(fixture);
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
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((owner.clone(), map));
    let words = fixture.tables.live(&fixture.maintenance);
    let tables = crate::ipc::MapTables(map);
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
    if futex.is_some() {
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                parent_binding.address,
                &parent_binding.words,
                &mut fork_service,
            )
            .unwrap();
        assert!(matches!(
            entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::MAX),
                UserVa::new(0),
                LinuxWaitOptions::empty(),
                UserVa::new(0)
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_handoff_receipt().is_some());
    } else {
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, parent_binding.record.id)
                .is_queued()
        );
    }
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
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
    if let Some(operation) = futex {
        child_futex(
            fixture,
            registry,
            &runtime,
            &mut service,
            parent,
            child,
            (operation, bitset, timed, departure),
        );
        registry.unregister_root_for_test(&runtime);
        return;
    }
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
    if readlink {
        if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        memory.as_mut_bytes()[..15].copy_from_slice(b"/proc/self/exe\0");
    }
    let mut cpu = crate::sched::FakeCpu::default();
    assert_eq!(fixture.slot.raw(), 0);
    // SAFETY: zero is the valid empty name-cache state; retained by fixture.
    let names = unsafe {
        &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<carrick_el1_abi::InotifyNameCache>())
            .cast::<carrick_el1_abi::InotifyNameCache>()
    };
    let mut call_full = |nr, fd, address, count, extra| {
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x400004,
            esr: 0x15 << 26,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = fd;
        frame.x[1] = address;
        frame.x[2] = count;
        frame.x[3] = extra;
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
        if route == carrick_personality_linux::dispatch::CompletionRoute::Forward {
            let (page, _) = fixture.task.lifecycle_refs().unwrap();
            let owner = registry.thread_group_owner(
                fixture.zone,
                page,
                fixture.task.visible_pid().unwrap(),
            );
            assert_eq!(
                crate::dispatch::native_unstaged_exit(
                    &mut frame,
                    &fixture.task.linux,
                    carrick_el1_abi::Action::Forward,
                    || owner,
                    &counters,
                ),
                crate::dispatch::NativeUnstagedExit::Refused(carrick_el1_abi::Action::Served)
            );
            assert_eq!(
                frame.x[0] as i64, -38,
                "unclaimed native child receives errno 38"
            );
            assert_eq!(counters.refused[nr as usize].load(Ordering::Relaxed), 1);
            assert_eq!(counters.served[nr as usize].load(Ordering::Relaxed), 1);
        }
        // Completed in-ring I/O can still owe native return-event work.
        // This fixture checks committed results and pipe bytes below, without
        // modelling the carrier's return transport. Neither route replays I/O.
        assert!(
            matches!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Served
                    | carrick_personality_linux::dispatch::CompletionRoute::WithWork
            ),
            "production native dispatch: {route:?}, nr={nr}, result={}",
            frame.x[0] as i64
        );
        frame.x[0]
    };
    if readlink {
        assert_eq!(
            call_full(78, (-100i64) as u64, memory.arg(), memory.arg() + 512, 128),
            16
        );
        assert_eq!(&memory.as_mut_bytes()[512..528], b"/bin/pipe-writer");
        assert_eq!(counters.forwarded[78].load(Ordering::Relaxed), 0);
        registry.unregister_root_for_test(&runtime);
        return;
    }
    // Constructors must use the successor's native table after exec, just
    // as they do before exec. Check a usable counter and empty epoll wait.
    use carrick_personality_linux::crossing::nr as sys;
    let event = call_full(
        sys::EVENTFD2.raw(),
        7,
        carrick_syscall_abi::LINUX_O_CLOEXEC | carrick_abi::LINUX_O_NONBLOCK,
        0,
        0,
    );
    assert!(
        (event as i64) >= 0,
        "post-exec eventfd errno {}",
        -(event as i64)
    );
    let epoll = call_full(
        sys::EPOLL_CREATE1.raw(),
        carrick_syscall_abi::LINUX_O_CLOEXEC,
        0,
        0,
        0,
    );
    assert!(
        (epoll as i64) >= 0,
        "post-exec epoll errno {}",
        -(epoll as i64)
    );
    assert_eq!(
        call_full(sys::READ.raw(), event, memory.arg() + 768, 8, 0),
        8
    );
    assert_eq!(
        u64::from_ne_bytes(memory.as_mut_bytes()[768..776].try_into().unwrap()),
        7
    );
    assert_eq!(
        call_full(sys::EPOLL_PWAIT.raw(), epoll, memory.arg() + 800, 1, 0),
        0
    );
    // Go's netpollinit registers its wake eventfd after fork+exec. Exercise
    // that composition on the successor's table, including the ARM event
    // layout and the EPOLLET high bit, rather than only two constructors.
    let cookie = 0x1506_1740_8870_0001u64;
    let interest = memory.arg() + 832;
    memory.as_mut_bytes()[832..836].copy_from_slice(
        &(carrick_el1_abi::ipc::epoll::events::IN | carrick_el1_abi::ipc::epoll::events::ET)
            .to_ne_bytes(),
    );
    memory.as_mut_bytes()[840..848].copy_from_slice(&cookie.to_ne_bytes());
    assert_eq!(
        call_full(sys::EPOLL_CTL.raw(), epoll, 1, event, interest),
        0
    );
    let wake = memory.arg() + 864;
    memory.as_mut_bytes()[864..872].copy_from_slice(&1u64.to_ne_bytes());
    assert_eq!(call_full(sys::WRITE.raw(), event, wake, 8, 0), 8);
    assert_eq!(
        call_full(sys::EPOLL_PWAIT.raw(), epoll, memory.arg() + 800, 1, 0),
        1
    );
    assert_eq!(
        u64::from_ne_bytes(memory.as_mut_bytes()[808..816].try_into().unwrap()),
        cookie
    );
    assert_eq!(
        call_full(sys::READ.raw(), event, memory.arg() + 768, 8, 0),
        8
    );
    assert_eq!(
        call_full(sys::EPOLL_PWAIT.raw(), epoll, memory.arg() + 800, 1, 0),
        0
    );
    assert_eq!(call_full(sys::EPOLL_CTL.raw(), epoll, 2, event, 0), 0);
    assert_eq!(call_full(sys::FCNTL.raw(), event, 1, 0, 0), 1);
    assert_eq!(call_full(sys::FCNTL.raw(), epoll, 1, 0, 0), 1);
    assert_eq!(call_full(sys::CLOSE.raw(), event, 0, 0, 0), 0);
    assert_eq!(call_full(sys::CLOSE.raw(), epoll, 0, 0, 0), 0);
    assert_eq!(
        call_full(64, 4, memory.arg() + 128, 2, 0),
        2,
        "exec successor's scalar write"
    );
    assert_eq!(
        call_full(66, 4, memory.arg(), 2, 0),
        6,
        "exec successor's vector write"
    );
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    for bad in [0, 1u64 << 48, 0x6000_0000] {
        assert_eq!(
            call_full(66, 4, bad, 1, 0) as i64,
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
    assert_eq!(call_full(63, 3, memory.arg() + 512, 8, 0), 8);
    assert_eq!(&memory.as_mut_bytes()[512..520], b"1\n1\n2\n3\n");
    registry.unregister_root_for_test(&runtime);
}

#[test]
fn serial_host_parked_pipe_read_resumes_at_saved_svc() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let metadata_scope = MetadataScope::new(fixture);
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
    // Declared before `runtime`: the dispatch closure's IPC venue borrows it, and the
    // runtime (dropped after it otherwise) holds work that names that venue.
    let tables = crate::ipc::MapTables(map);
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
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
            esr: 0x15 << 26,
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

// Control only physical word supply. Fork, exec, copy preparation, scheduler
// custody and resumption all use the production native owner.
fn child_futex<'a>(
    fixture: &'a Fixture,
    registry: &NativeProcessRegistry<'a, AddressContext<RootGpa>, Aarch64ParkedContext>,
    runtime: &NativeProcessRuntime<'a, AddressContext<RootGpa>, Aarch64ParkedContext>,
    service: &mut Physical<'a, Aarch64ParkedContext>,
    parent: TaskKey,
    child: TaskKey,
    futex: (u64, u64, bool, Option<TimerDeparture>),
) {
    let (operation, bitset, timed, departure) = futex;
    let counters = &carrick_el1_abi::Counters::new();
    use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::dispatch::CompletionRoute;
    struct Word {
        available: core::cell::Cell<bool>,
        reads: core::cell::Cell<u32>,
    }
    impl crate::sched::UserWord for Word {
        fn read_u32(&self, _: &CurrentTask, address: u64) -> Option<u32> {
            assert_eq!(address, VA);
            self.reads.set(self.reads.get() + 1);
            self.available.get().then_some(0)
        }
        fn read_u64(&self, _: &CurrentTask, address: u64) -> Option<u64> {
            Some(if address == VA + 16 { 100 } else { 0 })
        }
    }
    assert!(
        runtime.task_binding(parent).is_some(),
        "parent remains live"
    );
    // Physical acknowledges exec retirement synchronously; settle its return
    // doorbell before issuing the successor's first new syscall.
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let binding = runtime.task_binding(child).unwrap();
    assert_ne!(binding.address.mm, fixture.address.mm);
    let word = Word {
        available: core::cell::Cell::new(false),
        reads: core::cell::Cell::new(0),
    };
    let request = GuestCopyRequest {
        address: UserVa::new(VA),
        len: GuestLen::new(4),
        access: Access::Read,
    };
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let handle = service.service_mm_handle(&binding.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    space
        .admit_notifications(handle.incarnation(), &ShortLockSpin, &|effects| {
            crate::sched::object_wait::deliver_host_completion(fixture.zone, effects);
        })
        .unwrap();
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let installed = fixture
        .zone
        .install_space(fixture.slot, handle.mm().raw())
        .unwrap();
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    access.raise(space.index());
    // SAFETY: this exact live successor owner retains its raised gate.
    service.prepare_copy_error = Some(NativeProcessError::OwnerWait(unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    }));
    let names = carrick_el1_abi::InotifyNameCache::new();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (installed.ttbr0, installed.ttbr1),
        ..Default::default()
    };
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: 0x400004,
        esr: 0x15 << 26,
        ..Default::default()
    };
    frame.x[8] = crate::sched::SYS_FUTEX as u64;
    frame.x[0] = VA;
    frame.x[1] = operation;
    frame.x[5] = bitset;
    frame.x[2] = 1;
    // A relative timeout must preserve its deadline across owner-copy suspension.
    frame.x[3] = if timed { VA + 16 } else { 0 };
    let mut parked = binding.words;
    crate::sched::ThreadCpu::save(
        &mut cpu,
        &frame,
        &mut parked,
        crate::sched::CpuExitCause::Svc,
    );
    {
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                binding.address,
                &parked,
                service,
            )
            .unwrap();
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &word,
            }),
            None,
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        if operation == (128 | 256 | 9) && bitset == 0 {
            assert_eq!(frame.x[0] as i64, -22, "native child receives EINVAL");
        }
        if route == CompletionRoute::Forward {
            // Complete the same unclaimed-syscall capture as the ARM vector.
            // Derive lineage from this real exec successor, not a fabricated
            // ForkChild classification, so the red diagnostic shows the errno
            // libc would receive after opcode refusal.
            let (page, _) = fixture.task.lifecycle_refs().unwrap();
            let owner = registry.thread_group_owner(
                fixture.zone,
                page,
                fixture.task.visible_pid().unwrap(),
            );
            assert_eq!(
                owner,
                crate::native_process_runtime::NativeThreadGroupOwner::ForkChild
            );
            assert_eq!(
                crate::dispatch::native_unstaged_exit(
                    &mut frame,
                    &fixture.task.linux,
                    carrick_el1_abi::Action::Forward,
                    || owner,
                    counters,
                ),
                crate::dispatch::NativeUnstagedExit::Refused(carrick_el1_abi::Action::Served),
            );
            let expected = if operation == (128 | 256 | 9) && bitset == 0 {
                -22
            } else {
                -38
            };
            assert_eq!(frame.x[0] as i64, expected, "native child errno");
            assert_eq!(
                word.reads.get(),
                0,
                "opcode refusal happens before UserCopy"
            );
        }
        let expected_route = if operation == (128 | 256 | 9) && bitset == 0 {
            CompletionRoute::Served
        } else {
            CompletionRoute::Suspended
        };
        assert_eq!(
            route,
            expected_route,
            "fork child futex op={operation} address={VA:#x}, expected {:?}; result={}",
            CopyOutcome::NotYet(request),
            frame.x[0] as i64
        );
        assert!(entry.take_run_failure().is_none());
    }
    if operation == (128 | 256 | 9) && bitset == 0 {
        registry.unregister_root_for_test(runtime);
        return;
    }
    assert_eq!(word.reads.get(), 1, "one refusal transfers to the owner");
    service.prepare_copy_error = None;
    word.available.set(true);
    access.lower(space.index());
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        binding.record.id
    );
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            binding.address,
            &parked,
            service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::RetrySyscall)
    ));
    drop(entry);
    // SAFETY: this fixture exclusively owns the selected child record.
    let retained = unsafe { *fixture.zone.record(binding.record.id).ctx_mut() };
    crate::sched::ThreadCpu::load(&mut cpu, &mut frame, &retained);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            binding.address,
            &retained,
            service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &names,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &word,
        }),
        None,
        None,
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    assert_eq!(
        frame.x[0] as i64, -11,
        "retry compares the original expected value, never EFAULT"
    );
    assert_eq!(
        word.reads.get(),
        2,
        "mismatch consumes one atomic comparison"
    );
    assert!(entry.take_run_failure().is_none());
    assert!(runtime.task_binding(parent).is_some());
    assert!(runtime.task_binding(child).is_some());
    drop(entry);

    struct Venue;
    impl crate::thread_setup::LifecycleVenue for Venue {
        fn thread<'b>(
            &'b self,
            task: &'b CurrentTask,
        ) -> Option<crate::thread_setup::LifecycleThread<'b>> {
            let (page, slot) = task.lifecycle_refs()?;
            Some(crate::thread_setup::LifecycleThread { page, slot })
        }
        fn born_slot(
            &self,
            page: &ThreadLifecyclePage,
            entry: carrick_el1_abi::EntryRef,
        ) -> Option<&ThreadControlSlot> {
            let address = page.control_address(entry)?;
            // SAFETY: the production native stock retains the control allocation.
            Some(unsafe { &*(address as *const ThreadControlSlot) })
        }
    }
    let venue = Venue;
    let memory = carrick_test_support::GuestUserBuffer::zeroed(8192);
    frame.x[8] = 220;
    frame.x[..5].copy_from_slice(&[
        0x003d_0f00,
        memory.arg() + 8192,
        memory.arg(),
        memory.arg() + 128,
        memory.arg() + 4,
    ]);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            binding.address,
            &retained,
            service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &names,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &word,
        }),
        None,
        Some(&venue),
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(
        matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
        "clone route {route:?}, result {}",
        frame.x[0] as i64
    );
    let tid = frame.x[0] as u32;
    assert!(
        tid > 0 && (frame.x[0] as i64) > 0,
        "thread clone result {}",
        frame.x[0] as i64
    );
    drop(entry);
    // Acknowledge the clone's completed Born publication before running again.
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    // A matching WAIT switches from the exec leader to its real clone birth.
    frame.x[8] = crate::sched::SYS_FUTEX as u64;
    frame.x[..6].copy_from_slice(&[
        VA,
        operation,
        0,
        if timed { VA + 16 } else { 0 },
        0,
        u64::from(u32::MAX),
    ]);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            binding.address,
            &retained,
            service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &names,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &word,
        }),
        None,
        Some(&venue),
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    drop(entry);
    assert_eq!(
        word.reads.get(),
        3,
        "matching wait compares under the bucket lock and enrolls once"
    );
    let (page, control) = fixture.task.lifecycle_refs().unwrap();
    assert_eq!(control.visible_tid(), Some(tid));
    assert_eq!(
        page.live(),
        2,
        "exec child's leader and cloned thread remain live"
    );
    registry
        .register_thread(source, &fixture.task, binding.address, page, control)
        .unwrap();
    let selected = fixture.zone.slot(fixture.slot).current().unwrap();
    // SAFETY: the scheduler selected this exact clone birth for execution.
    let worker = unsafe { runtime.record_binding(fixture.zone.record_ref(selected)) }.unwrap();
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            worker.address,
            &worker.words,
            service,
        )
        .unwrap();
    frame.x[8] = 178;
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &names,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &word,
        }),
        None,
        Some(&venue),
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    assert_eq!(
        frame.x[0],
        u64::from(tid),
        "post-exec cloned thread reached its first syscall"
    );
    drop(entry);
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    if let Some(departure) = departure {
        let waiter = fixture.zone.record(binding.record.id);
        let deadline = waiter
            .deadline()
            .expect("matching wait has its original deadline");
        assert_eq!(fixture.zone.timer_node_count(), 1);
        assert!(matches!(
            waiter.claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        assert!(deadline > crate::sched::ThreadCpu::now(&cpu));
        // The sibling has executed gettid while the exec leader is parked.
        // Model the stopped carrier boundary using the same public entry
        // points as reconcile_zone_exit and executor slot reuse.
        fixture.zone.leave_guest(fixture.slot, &ShortLockSpin);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, worker.record.id)
                .is_queued()
        );
        carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
            carrick_kernel::el1_zone::hand_back_foreign_timer(fixture.slot);
        });
        if matches!(departure, TimerDeparture::SlotReset) {
            assert!(
                fixture.zone.reset_slot(fixture.slot),
                "slot reuse must settle timer custody"
            );
        }
        assert_eq!(
            waiter.deadline(),
            Some(deadline),
            "departure cannot restart the deadline"
        );
        assert!(
            !waiter.host_resume_ready(),
            "native timed futex has no host syscall continuation: claim={:?}, handback={:?}, timer nodes={}",
            waiter.claim(),
            waiter.handback(),
            fixture.zone.timer_node_count(),
        );
        // No timeout before the original deadline, then exactly one timeout.
        assert!(
            !fixture
                .zone
                .expire_timer(fixture.slot, deadline - 1, (-110_i64) as u64, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap()
        );
        assert!(
            fixture
                .zone
                .expire_timer(fixture.slot, deadline, (-110_i64) as u64, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap()
        );
        assert!(
            !fixture
                .zone
                .expire_timer(fixture.slot, deadline, (-110_i64) as u64, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap()
        );
        assert_eq!(fixture.zone.timer_node_count(), 0);
        assert_eq!(waiter.result() as i64, -110);
        assert!(!matches!(
            waiter.claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        let selected = activate_target(source, &fixture.task, &binding);
        assert_eq!(selected.result, Some((-110_i64) as u64));
        return;
    }
    frame.x[8] = crate::sched::SYS_FUTEX as u64;
    frame.x[..6].copy_from_slice(&[VA, crate::sched::FUTEX_WAKE_PRIVATE, 1, 0, 0, 0]);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            worker.address,
            &worker.words,
            service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &names,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &word,
        }),
        None,
        Some(&venue),
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    assert_eq!(frame.x[0], 1, "one enrolled waiter, exactly one wake");
    assert_eq!(counters.forwarded[98].load(Ordering::Relaxed), 0);
    assert!(runtime.task_binding(parent).is_some());
}
