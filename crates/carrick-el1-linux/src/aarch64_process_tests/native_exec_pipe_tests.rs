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

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiscardScenario {
    ZeroLength,
    V8CodeRangeAndRootForward,
}

#[test]
fn serial_host_native_fork_exec_madvise_dontneed_returns_zero() {
    fork_exec_probe_with_scenario(
        None,
        u32::MAX as u64,
        false,
        None,
        None,
        Some(DiscardScenario::ZeroLength),
        false,
    );
}

#[test]
fn serial_host_native_fork_exec_v8_code_range_discard_and_root_forward() {
    fork_exec_probe_with_scenario(
        None,
        u32::MAX as u64,
        false,
        None,
        None,
        Some(DiscardScenario::V8CodeRangeAndRootForward),
        false,
    );
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

#[test]
fn serial_host_native_fork_exec_child_timed_futex() {
    fork_exec_probe(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
    );
}

fn fork_exec_successor_with_futex(futex: Option<u64>, bitset: u64) {
    fork_exec_probe(futex, bitset, false, None);
}

pub(super) fn metadata_successor(case: super::pipe_metadata_tests::Case) {
    fork_exec_probe(None, u32::MAX as u64, false, Some(case));
}

fn fork_exec_probe(
    futex: Option<u64>,
    bitset: u64,
    timed: bool,
    metadata: Option<super::pipe_metadata_tests::Case>,
) {
    fork_exec_probe_with_departure(futex, bitset, timed, metadata, None);
}

#[derive(Clone, Copy)]
enum TimerDeparture {
    CarrierExit,
    SlotReset,
    CarrierExitWake,
    SlotResetWake,
    Nanosleep(SleepCase),
}

/// #1808: what a native fork/exec child's sleep must do through production
/// entry while its exec leader stays parked in a timed futex.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SleepCase {
    /// Park, depart the executor, expire once at the original deadline: 0.
    Expiry,
    /// Park, then a terminal SIGINT: EINTR and the unslept interval in rem.
    Interrupted,
    /// SIGINT already pending at entry: EINTR and the whole interval, no park.
    PendingSignal,
    /// forkexecstorm's ready-child shape: an expired absolute deadline is 0.
    ExpiredAbsolute,
    /// A zero relative interval is 0 without a timer lease.
    ZeroRelative,
    /// An unrelated wake publication races enrollment once: the owner
    /// rescans and parks with the same deadline (no errno, no second lease).
    RacedPublication,
    InvalidTimespec,
    /// SIGINT pending at entry and the rem page not yet backed: the owner
    /// prepares it and writes the retained output, EINTR.
    PendingSignalLazyRemainder,
    /// SIGINT pending at entry and the rem copy Busy once: the output and
    /// EINTR stay retained across carrier work, then are written.
    PendingSignalBusyRemainder,
    /// SIGINT pending at entry and the rem copy waits on the mm owner once
    /// (the child's page-table gate is raised): the caller parks on the
    /// owner, the EINTR answer and its rem bytes stay retained across that
    /// park, and the gate's release reruns the copy.
    PendingSignalOwnerWaitRemainder,
    /// Woken before the deadline; the clock passes it between the sleep's
    /// clock read and any later read. It re-parks and returns 0, never EAGAIN.
    DeadlineCrossesChecks,
    /// Woken before the deadline; SIGINT is published right after the
    /// sleep's empty deliverable check. EINTR, with the relative rem written.
    SignalBetweenChecks,
    /// A future absolute CLOCK_MONOTONIC deadline parks and expires: 0.
    FutureAbsolute,
    /// A future absolute deadline interrupted by SIGINT: EINTR, rem untouched.
    FutureAbsoluteInterrupted,
}

#[test]
fn serial_host_native_child_timed_futex_carrier_exit() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::CarrierExit),
    );
}

#[test]
fn serial_host_native_child_timed_futex_slot_reset() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::SlotReset),
    );
}

#[test]
fn serial_host_native_child_timed_futex_carrier_exit_wake() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::CarrierExitWake),
    );
}

#[test]
fn serial_host_native_child_timed_futex_slot_reset_wake() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::SlotResetWake),
    );
}

#[test]
fn serial_host_native_child_nanosleep_is_routed() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::Expiry)),
    );
}

#[test]
fn serial_host_native_child_nanosleep_eintr_writes_remaining() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::Interrupted)),
    );
}

#[test]
fn serial_host_native_child_nanosleep_pending_signal_is_eintr() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::PendingSignal)),
    );
}

#[test]
fn serial_host_native_child_expired_absolute_clock_nanosleep_returns_zero() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::ExpiredAbsolute)),
    );
}

#[test]
fn serial_host_native_child_zero_nanosleep_returns_zero() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::ZeroRelative)),
    );
}

#[test]
fn serial_host_native_child_nanosleep_rescans_a_raced_publication() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::RacedPublication)),
    );
}

#[test]
fn serial_host_native_child_nanosleep_eintr_prepares_a_lazy_remainder() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(
            SleepCase::PendingSignalLazyRemainder,
        )),
    );
}

#[test]
fn serial_host_native_child_nanosleep_eintr_retains_a_busy_remainder() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(
            SleepCase::PendingSignalBusyRemainder,
        )),
    );
}

#[test]
fn serial_host_native_child_nanosleep_eintr_retains_an_owner_wait_remainder() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(
            SleepCase::PendingSignalOwnerWaitRemainder,
        )),
    );
}

#[test]
fn serial_host_native_child_nanosleep_deadline_crossing_between_checks_returns_zero() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::DeadlineCrossesChecks)),
    );
}

#[test]
fn serial_host_native_child_nanosleep_signal_between_checks_writes_remaining() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::SignalBetweenChecks)),
    );
}

#[test]
fn serial_host_native_child_future_absolute_clock_nanosleep_expires_at_deadline() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::FutureAbsolute)),
    );
}

#[test]
fn serial_host_native_child_future_absolute_clock_nanosleep_eintr_leaves_rem() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(
            SleepCase::FutureAbsoluteInterrupted,
        )),
    );
}

#[test]
fn serial_host_native_child_nanosleep_rejects_invalid_timespec() {
    fork_exec_probe_with_departure(
        Some(crate::sched::FUTEX_WAIT_PRIVATE),
        u32::MAX as u64,
        true,
        None,
        Some(TimerDeparture::Nanosleep(SleepCase::InvalidTimespec)),
    );
}

fn fork_exec_probe_with_departure(
    futex: Option<u64>,
    bitset: u64,
    timed: bool,
    metadata: Option<super::pipe_metadata_tests::Case>,
    departure: Option<TimerDeparture>,
) {
    fork_exec_probe_with_scenario(futex, bitset, timed, metadata, departure, None, false);
}

/// #2028: the exec successor of a live-parent fork child reads the run's
/// clock in ring (frozen domain), with no child forward or refusal.
#[test]
fn serial_host_native_fork_exec_successor_clock_reads_the_domain() {
    fork_exec_probe_with_scenario(None, u32::MAX as u64, false, None, None, None, true);
}

fn fork_exec_probe_with_scenario(
    futex: Option<u64>,
    bitset: u64,
    timed: bool,
    metadata: Option<super::pipe_metadata_tests::Case>,
    departure: Option<TimerDeparture>,
    discard: Option<DiscardScenario>,
    successor_clock: bool,
) {
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
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
    let owner: &'static Arc<HostIpc> = Box::leak(Box::new(Arc::new(
        HostIpc::with_limits(
            1 << 20,
            IpcLimits {
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
                ..IpcLimits::ZONE
            },
        )
        .unwrap(),
    )));
    let table = Arc::new(HostTable::create(owner.clone(), 64, 64).unwrap());
    let object = owner.create_pipe(65536).unwrap();
    for (number, end, access) in [
        (3, End::Reader, fd::AccessMode::ReadOnly),
        (4, End::Writer, fd::AccessMode::WriteOnly),
    ] {
        let description = owner
            .admit_description(fd::Description::new(
                IpcBacking::Pipe { object, end }.encode(),
                access,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        description
            .install(table.id(), fd::Fd(number), false)
            .unwrap();
        if metadata.is_some() && number == 3 {
            description.install(table.id(), fd::Fd(6), true).unwrap();
        }
    }
    // Fork, exec and dispatch use the same published table map, just as the
    // carrier does. The fixture registered this retained EL1 region above.
    let map = carrick_el1_abi::ipc_table_map_host().unwrap();
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let crossing: &'static mut TestStockCrossing =
        Box::leak(Box::new(TestStockCrossing::new(&pages)));
    crossing.metadata_in_el1_window = true;
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((owner.clone(), map));
    let crossing: &'static TestStockCrossing = crossing;
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let tables: &'static crate::ipc::MapTables<'static> =
        Box::leak(Box::new(crate::ipc::MapTables(map)));
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
    .with_words(&*words);
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
    let counters: &'static carrick_el1_abi::Counters =
        Box::leak(Box::new(carrick_el1_abi::Counters::new()));
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
    if successor_clock {
        exec_successor_clock_reads(fixture, registry, &runtime, source, counters, parent, child);
        registry.unregister_root_for_test(&runtime);
        return;
    }
    let residency = carrick_el1::cow::test_support::residency_table();
    let successor_tables = crate::mm_portal::test_support::Tables::new(0xb00000, 0xc00000, 0);
    {
        let window = carrick_el1_abi::EL1_COW_COPY_BASE;
        let win_indices = carrick_mmu_core::aarch64::indices(window);
        let set = |address: u64, value| {
            successor_tables.words[((address - 0xb00000) / 8) as usize]
                .store(value, Ordering::Relaxed)
        };
        set(0xb01000 + win_indices[1] as u64 * 8, 0xb04000 | 3);
        set(0xb04000 + win_indices[2] as u64 * 8, 0xb05000 | 3);
        for page in 0..2 {
            let alias = window + page * 4096;
            set(
                0xb05000 + carrick_mmu_core::aarch64::indices(alias)[3] as u64 * 8,
                alias,
            );
        }
    }
    let successor_words = successor_tables.live(&fixture.maintenance);
    let fault_pages = std::cell::RefCell::new(BTreeMap::new());
    let scrubs = std::cell::Cell::new(0usize);
    if discard.is_some() {
        let successor_raw = fixture.task.mm.key.load(Ordering::Acquire);
        let successor_mm = carrick_el1_abi::ReservationMm::new(successor_raw).unwrap();
        let successor_index = fixture.zone.spaces.find(successor_raw).unwrap();
        fixture
            .region
            .table()
            .publish(
                successor_index.index(),
                successor_mm,
                carrick_el1::memory::reservations::Layout {
                    heap: carrick_el1_abi::ReservationRange::new(0x1000, 0x10_0000).unwrap(),
                    arena: carrick_el1_abi::ReservationRange::new(0x4000_0000, 0x6000_0000)
                        .unwrap(),
                    brk: 0x1000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        fixture
            .region
            .table()
            .lock(successor_index.index(), successor_mm)
            .unwrap()
            .finish_import()
            .unwrap();
    }
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
        tables,
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
        if nr == 222 {
            frame.x[4] = u64::MAX;
        }
        let selected = fixture.zone.slot(fixture.slot).current().unwrap();
        // SAFETY: fixture retains this selected live record.
        let binding = unsafe { runtime.record_binding(fixture.zone.record_ref(selected)) }.unwrap();
        // Physical records owner copies rather than writing host memory. Bind
        // this call's live GuestUserBuffer output and apply only the bytes the
        // production owner actually delivered, never a synthesized result.
        let output = metadata.and(match nr {
            59 => Some((fd, 8usize)),
            80 => Some((address, core::mem::size_of::<carrick_abi::LinuxStat>())),
            79 => Some((count, core::mem::size_of::<carrick_abi::LinuxStat>())),
            29 if address == carrick_abi::LINUX_FIONREAD => Some((count, 4)),
            63 => Some((address, count as usize)),
            _ => None,
        });
        if metadata.is_some() {
            let _ = crate::native_process_runtime::host_test_support::take_signal_copies();
        }
        if let Some((address, 4)) = output {
            service
                .tid_words
                .insert((binding.address.mm.raw().get(), address), 0);
        }
        // This schedule's deliberate copy fault means unmapped input, not
        // first-touch backing. Qualify the physical owner too: it must refuse
        // preparation, rather than falsely report these bad iovecs readable.
        service.prepare_copy_error = crate::file::SIMULATE_COPY_FAULT
            .with(|fault| fault.load(Ordering::Relaxed))
            .then_some(NativeProcessError::Fault);
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
        let served_before = counters.served[nr as usize].load(Ordering::Relaxed);
        let is_root_process = entry.is_root_process();
        struct DiscardAnonymousVenue<'a> {
            call: carrick_el1::memory::AnonymousCall,
            fixture: &'static Fixture,
            counters: &'a carrick_el1_abi::Counters,
            is_root_process: bool,
            editor: FixtureDiscardMapping<'a>,
        }
        impl carrick_personality_linux::pending_anonymous::PendingAnonymousVenue
            for DiscardAnonymousVenue<'_>
        {
            fn original_argument0(&self) -> u64 {
                use carrick_el1::memory::AnonymousCallView;
                self.call.arguments()[0]
            }
            fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
                Some(&self.fixture.task.linux)
            }
            fn delegated(&mut self) -> carrick_personality_linux::pending_anonymous::DelegatedStep {
                use carrick_el1::memory::{AnonymousCallView, DelegatedAnonymous};
                use carrick_personality_linux::abi::entry::SyscallResult;
                use carrick_personality_linux::pending_anonymous::DelegatedStep;
                let access =
                    crate::sched::object_wait::space_access(self.fixture.zone, self.fixture.slot);
                let outcome = if carrick_personality_linux::dispatch::AnonymousCall::from_canonical(
                    carrick_syscall_abi::CanonicalNr::new(self.call.canonical().raw()),
                ) == Some(
                    carrick_personality_linux::dispatch::AnonymousCall::Madvise,
                ) {
                    if self.is_root_process {
                        return DelegatedStep::NotDelegated;
                    }
                    carrick_el1::memory::serve_delegated_discard(
                        &mut self.call,
                        self.counters,
                        &self.fixture.task,
                        access,
                        self.fixture.region.table(),
                        &mut self.editor,
                    )
                } else {
                    carrick_el1::memory::serve_delegated_mapping(
                        &mut self.call,
                        self.counters,
                        &self.fixture.task,
                        access,
                        self.fixture.region.table(),
                        &mut self.editor,
                        None,
                    )
                };
                match outcome {
                    DelegatedAnonymous::Contended(cause) => DelegatedStep::Contended(cause),
                    DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
                    DelegatedAnonymous::Served => {
                        DelegatedStep::Served(SyscallResult::new(self.call.result().0 as i64))
                    }
                    DelegatedAnonymous::Forward => DelegatedStep::Forward,
                }
            }
            fn park_prepared(
                &mut self,
            ) -> Option<carrick_personality_linux::dispatch::FamilyCompletion> {
                None
            }
            fn permission(
                &mut self,
            ) -> carrick_personality_linux::pending_anonymous::PermissionStep {
                carrick_personality_linux::pending_anonymous::PermissionStep::Forward
            }
            fn retirement(
                &mut self,
            ) -> carrick_personality_linux::pending_anonymous::RetirementStep {
                carrick_personality_linux::pending_anonymous::RetirementStep::Forward
            }
            fn install_result(&mut self, _: carrick_personality_linux::abi::entry::SyscallResult) {}
        }
        let mut anon_venue = discard.is_some().then(|| DiscardAnonymousVenue {
            call: carrick_el1::memory::AnonymousCall::new(
                carrick_core::CallOrdinal::from_raw(nr),
                [
                    fd,
                    address,
                    count,
                    extra,
                    if nr == 222 { u64::MAX } else { 0 },
                    0,
                ],
                0,
                fixture.slot,
                UserVa::new(0x400004),
            ),
            fixture,
            counters: &counters,
            is_root_process,
            editor: FixtureDiscardMapping {
                mapping: super::native_fault_supply_tests::FixtureMapping {
                    words: if is_root_process {
                        &*words
                    } else {
                        &successor_words
                    },
                    residency: &residency,
                },
                pages: &fault_pages,
                scrubs: &scrubs,
            },
        });
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            if metadata.is_some() {
                crossing.fd_map()
            } else {
                &[]
            },
            &[],
            if metadata.is_some() {
                crossing.open_table()
            } else {
                &[]
            },
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
            anon_venue.as_mut().map(|v| {
                v as &mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue
            }),
            |_| core::ptr::null_mut(),
        );
        drop(entry);
        if discard.is_some() {
            use carrick_personality_linux::dispatch::CompletionRoute;
            assert!(
                runtime.task_binding(parent).is_some(),
                "parent remains alive"
            );
            assert!(
                runtime.task_binding(child).is_some(),
                "exec child remains alive"
            );
            if route == CompletionRoute::Forward {
                let refused_before = counters.refused_child[nr as usize].load(Ordering::Relaxed);
                let identity = fixture.zone.record(binding.record.id).identity();
                // SAFETY: the admitted live record owns its lifecycle page.
                let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
                let owner = registry.thread_group_owner(
                    fixture.zone,
                    page,
                    fixture.task.visible_pid().unwrap(),
                );
                let exit = crate::dispatch::native_unstaged_exit(
                    &mut frame,
                    &fixture.task.linux,
                    carrick_el1_abi::Action::Forward,
                    || owner,
                    &counters,
                );
                if is_root_process {
                    assert_eq!(
                        owner,
                        crate::native_process_runtime::NativeThreadGroupOwner::Root
                    );
                    assert_eq!(
                        exit,
                        crate::dispatch::NativeUnstagedExit::Operation(
                            carrick_core_abi::service::ServiceOperation::Crossing {
                                ordinal: carrick_guest_arch::NativeOrdinal::new(nr),
                            },
                        )
                    );
                    assert_eq!(
                        counters.refused_child[nr as usize].load(Ordering::Relaxed),
                        refused_before
                    );
                    return 0xfeed_face;
                }
                assert_eq!(
                    owner,
                    crate::native_process_runtime::NativeThreadGroupOwner::ForkChild
                );
                assert_eq!(
                    exit,
                    crate::dispatch::NativeUnstagedExit::Refused(carrick_el1_abi::Action::Served),
                );
                assert_eq!(
                    counters.refused_child[nr as usize].load(Ordering::Relaxed),
                    refused_before + 1
                );
                assert_eq!(
                    counters.venue_refused[nr as usize].load(Ordering::Relaxed),
                    0
                );
            } else {
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
            }
            return frame.x[0];
        }
        if metadata.is_some() {
            assert_eq!(
                counters.served[nr as usize].load(Ordering::Relaxed),
                served_before + 1,
                "metadata syscall {nr} must record a completed ring call, route {route:?}"
            );
        }
        if let Some((destination, length)) = output {
            let mut copies = crate::native_process_runtime::host_test_support::take_signal_copies();
            if length == 4 {
                let word = service.tid_words[&(binding.address.mm.raw().get(), destination)];
                copies.push((UserVa::new(destination), word.to_ne_bytes().to_vec()));
            }
            for (at, bytes) in copies {
                assert!(at.raw() >= destination);
                assert!(at.raw() + bytes.len() as u64 <= destination + length as u64);
                // SAFETY: exercise owns this exact live GuestUserBuffer until
                // the call returns, and the assertions bound every copied byte.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        at.raw() as *mut u8,
                        bytes.len(),
                    );
                }
            }
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
    if let Some(scenario) = discard {
        // The fixture has delivered the exec service reply and its wake above.
        // Settle that setup boundary before issuing a fresh syscall, as the
        // carrier does. Otherwise WithWork retains argument 0 for replay;
        // that argument is not a syscall result.
        let settle = || {
            let _ = fixture.task.linux.take_served_boundary();
            if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
                assert_eq!(work.native_terminal_slot(), None);
                work.settled();
            }
        };
        settle();
        match scenario {
            DiscardScenario::ZeroLength => {
                // Zero length isolates admission on the child's admitted successor MM.
                // Linux accepts this aligned no-op.
                let result = call_full(233, 0x400000, 0, 4, 0) as i64;
                registry.unregister_root_for_test(&runtime);
                assert_eq!(
                    result, 0,
                    "exec child madvise(0x400000, 0, MADV_DONTNEED=4)"
                );
            }
            DiscardScenario::V8CodeRangeAndRootForward => {
                use carrick_mmu_core::aarch64::descriptor_txn::{
                    BackingIdentity, DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan,
                    TableGrants, execute_descriptor_op,
                };
                use carrick_mmu_core::aarch64::{
                    GuestLeafPublication, LeafAccess, SubstrateGpa, terminal_descriptor_permits_el0,
                };
                const BASE: u64 = 0x4000_0000;
                // Reserve 4 pages PROT_NONE | MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE.
                assert_eq!(call_full(222, BASE, 4 * 4096, 0, 0x4032), BASE);
                settle();
                // Trim suffix page so BASE + 3*4096 is an unmapped hole.
                assert_eq!(call_full(215, BASE + 3 * 4096, 4096, 0, 0) as i64, 0);
                settle();
                // Promote first 2 pages to RWX, leaving third page PROT_NONE.
                assert_eq!(call_full(226, BASE, 2 * 4096, 7, 0) as i64, 0);
                settle();
                let nz = |v| NonZeroU64::new(v).unwrap();
                assert!(matches!(
                    execute_descriptor_op(
                        &successor_words,
                        SubstrateGpa(0xb00000),
                        DescriptorOp::Prepare {
                            publication: GuestLeafPublication {
                                va: BASE,
                                ipa: 0xc00000,
                                len: 4096,
                                writable: true,
                                executable: true,
                            },
                            resident: PageSpan::new(BASE, 4096),
                            backing: BackingIdentity {
                                frame_id: nz(1),
                                mapping_id: nz(2),
                                owner_generation: nz(3),
                                inventory_revision: nz(4),
                            },
                        },
                        &TableGrants::NONE,
                        &mut InlineJournal::new(),
                    ),
                    DescriptorOutcome::Applied(_)
                ));
                fault_pages.borrow_mut().insert(0xc00000, vec![0x5a; 4096]);
                assert_eq!(
                    call_full(233, BASE, 2 * 4096, 4, 0) as i64,
                    0,
                    "V8 code-range MADV_DONTNEED over resident RWX + lazy page"
                );
                settle();
                assert!(fault_pages.borrow()[&0xc00000].iter().all(|&b| b == 0));
                assert_eq!(scrubs.get(), 1, "lazy second page stays unbacked");
                let rwx_leaf =
                    super::native_fault_supply_tests::leaf(&successor_words, 0xb00000, BASE);
                assert_eq!(rwx_leaf & AARCH64_ROOT_ADDRESS_MASK, 0xc00000);
                assert!(terminal_descriptor_permits_el0(rwx_leaf, LeafAccess::Write));
                assert!(terminal_descriptor_permits_el0(
                    rwx_leaf,
                    LeafAccess::Execute
                ));
                assert_eq!(
                    super::native_fault_supply_tests::leaf(&successor_words, 0xb00000, BASE + 4096),
                    0
                );

                // Spanning into the trimmed hole scrubs the covered prefix then returns -ENOMEM.
                fault_pages.borrow_mut().insert(0xc00000, vec![0xa5; 4096]);
                assert_eq!(call_full(233, BASE, 4 * 4096, 4, 0) as i64, -12);
                settle();
                assert!(fault_pages.borrow()[&0xc00000].iter().all(|&b| b == 0));
                assert_eq!(scrubs.get(), 2);

                // Read-only PROT_READ MADV_DONTNEED (4) still scrubs via the COW write alias.
                assert_eq!(call_full(226, BASE, 4096, 1, 0) as i64, 0);
                settle();
                fault_pages.borrow_mut().insert(0xc00000, vec![0x77; 4096]);
                assert_eq!(call_full(233, BASE, 4096, 4, 0) as i64, 0);
                settle();
                assert!(fault_pages.borrow()[&0xc00000].iter().all(|&b| b == 0));
                assert_eq!(scrubs.get(), 3);
                assert_eq!(call_full(226, BASE, 4096, 7, 0) as i64, 0);
                settle();

                // MADV_FREE (8) and MADV_WILLNEED (3) return 0 without eager scrubbing.
                fault_pages.borrow_mut().insert(0xc00000, vec![0x33; 4096]);
                assert_eq!(call_full(233, BASE, 4096, 8, 0) as i64, 0);
                settle();
                assert_eq!(call_full(233, BASE, 4096, 3, 0) as i64, 0);
                settle();
                assert_eq!(fault_pages.borrow()[&0xc00000][0], 0x33);
                assert_eq!(scrubs.get(), 3);

                // Unaligned start and unsupported advice (999, MADV_COLD=20) return -EINVAL (-22).
                assert_eq!(call_full(233, BASE + 1, 4096, 4, 0) as i64, -22);
                settle();
                assert_eq!(call_full(233, BASE, 4096, 999, 0) as i64, -22);
                settle();
                assert_eq!(call_full(233, BASE, 4096, 20, 0) as i64, -22);
                settle();

                // Host-attribute advice (MADV_DONTDUMP=16) declines to child counted -ENOSYS (-38).
                assert_eq!(call_full(233, BASE, 4096, 16, 0) as i64, -38);
                settle();

                // Shared COW leaf at BASE + 4096 declines to counted -ENOSYS without scrubbing.
                successor_tables.words[1536 + 1].store(
                    0xc01000 | (1 << 55) | (2 << 6) | (1 << 10) | (1 << 11) | 3,
                    Ordering::Relaxed,
                );
                fault_pages.borrow_mut().insert(0xc01000, vec![0x99; 4096]);
                assert_eq!(call_full(233, BASE + 4096, 4096, 4, 0) as i64, -38);
                settle();
                assert_eq!(fault_pages.borrow()[&0xc01000][0], 0x99);

                // Switch to the live ARM root process: madvise forwards to the host VMA venue.
                assert!(
                    fixture
                        .zone
                        .requeue_preempted(fixture.slot, child_binding.record.id)
                        .is_queued()
                );
                activate_target(source, &fixture.task, &parent_binding);
                settle();
                let forwarded_before = counters.forwarded[233].load(Ordering::Relaxed);
                assert_eq!(call_full(233, BASE, 4096, 4, 0), 0xfeed_face);
                assert_eq!(
                    counters.forwarded[233].load(Ordering::Relaxed),
                    forwarded_before + 1
                );
                registry.unregister_root_for_test(&runtime);
            }
        }
        return;
    }
    if let Some(case) = metadata {
        use carrick_personality_linux::crossing::nr as sys;
        for fd in [3, 4] {
            assert_eq!(
                call_full(sys::FCNTL.raw(), fd, carrick_abi::LINUX_F_GETFD, 0, 0),
                0,
                "non-CLOEXEC pipe ends must survive fork and exec"
            );
        }
        assert!(
            runtime.task_binding(parent).is_some(),
            "parent remains live"
        );
        super::pipe_metadata_tests::exercise(case, |nr, args| {
            call_full(nr, args[0], args[1], args[2], args[3]) as i64
        });
        assert!(
            owner
                .region()
                .fd(carrick_sched_core::ShortLockSpin)
                .getfd(table.id(), fd::Fd(6))
                .unwrap()
        );
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

/// Re-enters a woken sleeper's registered thread, as its executor does
/// before consuming the retained operation.
fn reenter_worker<'r, 'a>(
    fixture: &'a Fixture,
    registry: &NativeProcessRegistry<'a, AddressContext<RootGpa>, Aarch64ParkedContext>,
    runtime: &'r NativeProcessRuntime<'a, AddressContext<RootGpa>, Aarch64ParkedContext>,
    source: BornInZoneSource<'a, Aarch64ParkedContext>,
    worker: &crate::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
    service: &'r mut Physical<'a, Aarch64ParkedContext>,
) -> Box<
    crate::native_process_runtime::NativeProcessEntry<
        'r,
        'a,
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
        Physical<'a, Aarch64ParkedContext>,
    >,
> {
    activate_target(source, &fixture.task, worker);
    let identity = fixture.zone.record(worker.record.id).identity();
    fixture.task.set(
        El1TaskId::from_linux_tid(identity.tid as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
        identity.file_table,
    );
    runtime
        .enter_registered(
            registry,
            source,
            &fixture.task,
            worker.address,
            &worker.words,
            service,
        )
        .unwrap()
}

/// The exec successor's clock readings, through the production dispatch owner:
/// dispatch -> ARM staging -> begin body -> host `ClockDomain` service ->
/// ticket acknowledgment -> native resume. The parent stays live throughout.
#[allow(clippy::too_many_arguments)]
fn exec_successor_clock_reads(
    fixture: &'static Fixture,
    registry: &NativeProcessRegistry<'static, AddressContext<RootGpa>, Aarch64ParkedContext>,
    runtime: &NativeProcessRuntime<'static, AddressContext<RootGpa>, Aarch64ParkedContext>,
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    counters: &'static carrick_el1_abi::Counters,
    parent: TaskKey,
    child: TaskKey,
) {
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::time::{Duration, UNIX_EPOCH};
    assert!(
        runtime.task_binding(parent).is_some(),
        "parent remains live"
    );
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let clock = Arc::new(carrick_kernel::kernel::container::ClockDomain::frozen(
        UNIX_EPOCH + Duration::from_secs(777),
    ));
    let names = carrick_el1_abi::InotifyNameCache::new();
    // The successor runs on the production ARM service (the shipping begin
    // body is typed to it); the exec itself was driven above.
    let crossing = Box::leak(Box::new(TestStockCrossing::new(&[
        0x80000, 0x81000, 0x82000, 0x83000, 0x84000, 0x85000, 0x86000, 0x87000,
    ])));
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(&*words);
    let service = &mut service;
    for (nr, x0, x1) in [(113_u64, 0_u64, 1_u64), (169, 1, 0)] {
        let out = carrick_test_support::GuestUserBuffer::from_bytes(&[0xaa; 16]);
        let (x0, x1) = (
            if x0 == 1 { out.arg() } else { x0 },
            if x1 == 1 { out.arg() } else { x1 },
        );
        let binding = runtime.task_binding(child).unwrap();
        assert_ne!(binding.address.mm, fixture.address.mm, "exec successor");
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x400004,
            esr: 0x15 << 26,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = x0;
        frame.x[1] = x1;
        let (page, _) = fixture.task.lifecycle_refs().unwrap();
        let owner =
            registry.thread_group_owner(fixture.zone, page, fixture.task.visible_pid().unwrap());
        assert_eq!(
            owner,
            crate::native_process_runtime::NativeThreadGroupOwner::ForkChild
        );
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                binding.address,
                &binding.words,
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
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(
            route,
            CompletionRoute::NativeService,
            "successor clock {nr}: routed to the clock owner, not forwarded"
        );
        let begin = match crate::dispatch::native_service_decision(
            &mut frame,
            &fixture.task,
            carrick_el1_abi::Action::Forward,
            None,
            counters,
            || owner,
            |_| None,
        ) {
            crate::dispatch::NativeServiceDecision::Begin(begin) => begin,
            _ => panic!("a successor clock reading must publish a clock request"),
        };
        let (result, _) = crate::dispatch::begin_native_service(
            &mut *entry,
            nr,
            begin,
            None,
            counters,
            counters,
            || None,
        );
        assert!(matches!(result.unwrap(), NativeResume::Left(None)));
        drop(entry);
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let member = fixture.zone.record(notice.record.id).identity();
        // SAFETY: the live successor retains its control slot.
        let control = unsafe { &*(member.control_slot as *const ThreadControlSlot) };
        // SAFETY: this fixture consumes the exact published ticket once.
        let ticket = unsafe {
            carrick_core_abi::service::ServiceCell::claim_notice(
                &control.service,
                notice,
                NonZeroU64::MIN,
                member,
            )
        }
        .unwrap();
        let carrick_core_abi::service::ServiceOperation::Clock { payload, .. } =
            ticket.request().operation
        else {
            panic!("a successor clock reading must stage a typed clock request");
        };
        // SAFETY: the pending ring service retains this staging record until
        // the ticket's acknowledgment.
        let record = unsafe {
            &mut *(payload.address().raw()
                as *mut [u8; carrick_core_abi::clock::CLOCK_RECORD_BYTES])
        };
        carrick_kernel::clock_service::ClockResourceService::new(Arc::clone(&clock))
            .serve_record(record)
            .unwrap();
        assert!(ticket.complete(true).is_ok());
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(notice.record)
                    .unwrap(),
                &ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        let mut effects = WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
        drop(queue);
        service.wake_effects(effects);
        let selected = activate_target(source, &fixture.task, &binding);
        assert_eq!(selected.record, binding.record.id);
        // SAFETY: this fixture owns the selected successor's exact record.
        let saved = unsafe { runtime.record_binding(binding.record) }
            .unwrap()
            .words;
        let mut entry = runtime
            .enter_registered(
                registry,
                source,
                &fixture.task,
                binding.address,
                &saved,
                service,
            )
            .unwrap();
        let Ok(NativeResume::Returned(result)) = entry.resume_checkpoint(|_| Ok(None)) else {
            panic!("a completed successor clock reading resumes with its result");
        };
        drop(entry);
        assert_eq!(result.raw(), 0, "successor clock {nr}");
        assert_eq!(
            i64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()),
            777,
            "the frozen ClockDomain's realtime, not the host's"
        );
        assert_eq!(
            counters.refused_child[nr as usize].load(Ordering::Acquire),
            0,
            "no child refusal for {nr}"
        );
    }
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
    let selected = fixture.zone.slot(fixture.slot).current().unwrap();
    // The clone published the birth through its owner (#1958): it is
    // registered before any CPU selected it, never lazily at first entry.
    assert!(
        registry
            .for_record(fixture.zone, fixture.zone.record_ref(selected))
            .is_some_and(|owner| core::ptr::eq(std::sync::Arc::as_ptr(&owner), runtime))
    );
    assert!(matches!(
        registry.register_thread(source, &fixture.task, binding.address, page, control),
        Err(NativeProcessError::Busy)
    ));
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
    if let Some(TimerDeparture::Nanosleep(case)) = departure {
        use crate::native_process_runtime::host_test_support::{
            fail_signal_copies, script_signal_clock, take_signal_copies,
        };
        use carrick_personality_linux::sleep::timespec_bytes;
        // The Physical clock reads 1000 until a timeout is served, then 2000;
        // one tick is one nanosecond. The exec leader stays parked in its
        // timed futex (deadline far beyond 1100), so this is a two-live-thread
        // native child: the sleeping clone and the waiting leader.
        let mut user = carrick_test_support::GuestUserBuffer::zeroed(32);
        let (request, remaining) = (user.arg(), user.arg() + 16);
        let absolute = matches!(
            case,
            SleepCase::ExpiredAbsolute
                | SleepCase::FutureAbsolute
                | SleepCase::FutureAbsoluteInterrupted
        );
        match case {
            SleepCase::InvalidTimespec => {
                user.as_mut_bytes()[8..16].copy_from_slice(&1_000_000_000_i64.to_le_bytes());
            }
            SleepCase::ZeroRelative => {}
            SleepCase::ExpiredAbsolute => {
                user.as_mut_bytes()[..16].copy_from_slice(&timespec_bytes(500));
            }
            SleepCase::FutureAbsolute | SleepCase::FutureAbsoluteInterrupted => {
                user.as_mut_bytes()[..16].copy_from_slice(&timespec_bytes(1100));
            }
            SleepCase::Expiry
            | SleepCase::Interrupted
            | SleepCase::PendingSignal
            | SleepCase::PendingSignalLazyRemainder
            | SleepCase::PendingSignalBusyRemainder
            | SleepCase::PendingSignalOwnerWaitRemainder
            | SleepCase::RacedPublication
            | SleepCase::DeadlineCrossesChecks
            | SleepCase::SignalBetweenChecks => {
                user.as_mut_bytes()[..16].copy_from_slice(&timespec_bytes(100));
            }
        }
        user.as_mut_bytes()[16..].fill(0xa5);
        if absolute {
            // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, request, rem)
            frame.x[8] = 115;
            frame.x[..4].copy_from_slice(&[1, 1, request, remaining]);
        } else {
            frame.x[8] = 101;
            frame.x[..2].copy_from_slice(&[request, remaining]);
        }
        let interrupt = carrick_el1_abi::ExternalSignalRecord::new(
            carrick_core_abi::EntryEventIdentity::from_binding(
                crate::common_entry::execution_binding(&fixture.task),
            ),
            crate::common_entry::execution_binding(&fixture.task),
            worker.record,
            carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::MIN),
            carrick_signal_core::policy::Signal::from_number(2).unwrap(),
            carrick_el1_abi::ExternalSignalSource::Terminal,
        );
        let pending_signal = matches!(
            case,
            SleepCase::PendingSignal
                | SleepCase::PendingSignalLazyRemainder
                | SleepCase::PendingSignalBusyRemainder
                | SleepCase::PendingSignalOwnerWaitRemainder
        );
        if pending_signal {
            assert!(
                registry
                    .admit_external_event(fixture.zone, interrupt, fixture.slot, service)
                    .unwrap()
            );
        }
        let raced = (case == SleepCase::RacedPublication)
            .then(|| runtime.publish_signal_channel_before_next_park(child));
        let _ = take_signal_copies();
        match case {
            // The rem page is not yet backed: the first copy needs the owner
            // to prepare it, then the retained output is written.
            SleepCase::PendingSignalLazyRemainder => {
                fail_signal_copies(&[NativeProcessError::Unsupported]);
            }
            SleepCase::PendingSignalBusyRemainder => {
                fail_signal_copies(&[NativeProcessError::Busy]);
            }
            // The child's page-table gate is raised, so the rem copy's
            // OwnerWait is a live wait on this exact mm's notification.
            SleepCase::PendingSignalOwnerWaitRemainder => {
                let observed = space
                    .notifications(handle.incarnation())
                    .unwrap()
                    .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
                access.raise(space.index());
                // SAFETY: this exact live successor owner retains its raised gate.
                fail_signal_copies(&[NativeProcessError::OwnerWait(unsafe {
                    carrick_core_abi::PortalOwnerWait::from_owner(
                        handle,
                        carrick_core_abi::PortalWaitCause::Gate,
                        observed.revision(),
                    )
                })]);
            }
            _ => {}
        }
        // The busy copy suspends to carrier work; this carrier answers its
        // doorbell at once, as the synchronous CPL0 crossing does.
        let crossings = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        if case == SleepCase::PendingSignalBusyRemainder {
            let counted = crossings.clone();
            let zone = fixture.zone;
            let record = worker.record;
            let task: *const CurrentTask = &fixture.task;
            // SAFETY: the published child control outlives this fixture.
            let control = unsafe {
                &*(zone.record(record.id).identity().control_slot as *const ThreadControlSlot)
            };
            crate::native_process_runtime::host_test_support::on_service_doorbell(Some(Box::new(
                move || {
                    counted.fetch_add(1, Ordering::Relaxed);
                    // SAFETY: the doorbell is cleared before the fixture's task drops.
                    let task = unsafe { &*task };
                    let notice = task.service_notice.take().unwrap().unwrap();
                    let key =
                        carrick_sched_core::object_wait::ObjectWaitKey::native_service(record)
                            .unwrap();
                    let queue = zone
                        .object_wait(key, &ShortLockSpin, &|owned| {
                            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                        })
                        .unwrap();
                    let member = queue.native_service_member(record).unwrap();
                    // SAFETY: the pending service retains this exact member under its queue.
                    let ticket = unsafe {
                        ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, member)
                    }
                    .unwrap();
                    drop(queue);
                    assert!(matches!(
                        ticket.request().operation,
                        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
                    ));
                    let _queue = zone
                        .object_wait(key, &ShortLockSpin, &|owned| {
                            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                        })
                        .unwrap();
                    assert!(ticket.complete(true).is_ok());
                },
            )));
        }
        let nodes = fixture.zone.timer_node_count();
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
        drop(entry);
        crate::native_process_runtime::host_test_support::on_service_doorbell(None);
        assert_ne!(
            route,
            CompletionRoute::Forward,
            "native child nanosleep cannot use a host continuation"
        );
        assert_eq!(
            counters.forwarded[frame.x[8] as usize].load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters.refused[frame.x[8] as usize].load(Ordering::Relaxed),
            0
        );
        let sleeper = fixture.zone.record(worker.record.id);
        // Re-enter the selected sleeper after a wake and consume its retained
        // operation, as its executor does before returning to EL0.
        // The executor departs; the deadline survives on the carrier
        // driver's heap and expires exactly once at its original tick.
        let depart_and_expire = || {
            fixture.zone.leave_guest(fixture.slot, &ShortLockSpin);
            carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                carrick_kernel::el1_zone::hand_back_foreign_timer(fixture.slot);
            });
            assert_eq!(
                sleeper.deadline(),
                Some(1100),
                "departure keeps the deadline"
            );
            let expire = |now| {
                fixture.zone.expire_native_timer(
                    carrick_guest_arch::CounterTick::new(now),
                    &ShortLockSpin,
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
                )
            };
            assert!(expire(1099).is_none(), "no early expiry");
            assert_eq!(expire(1100).map(|record| record.id), Some(worker.record.id));
            assert!(expire(1100).is_none(), "one resolution");
            assert_eq!(fixture.zone.timer_node_count(), nodes);
            carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                carrick_kernel::el1_zone::hand_back(&[worker.record]);
            });
            fixture.zone.enter_guest(fixture.slot);
        };
        // Parked: the clone released its execution lease and its timer lease
        // holds the original deadline.
        let assert_parked = || {
            assert!(fixture.zone.slot(fixture.slot).current().is_none());
            assert!(matches!(
                sleeper.claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            assert_eq!(sleeper.deadline(), Some(1100));
            assert_eq!(fixture.zone.timer_node_count(), nodes + 1);
        };
        if case == SleepCase::PendingSignalBusyRemainder {
            // Busy once: the EINTR answer and its rem bytes stay retained in
            // the service row across the carrier crossing, then the owner's
            // checkpoint writes them and returns EINTR.
            assert_eq!(
                crossings.load(Ordering::Relaxed),
                1,
                "the busy copy suspended to carrier work"
            );
            assert!(take_signal_copies().is_empty(), "nothing written yet");
            assert_eq!(fixture.zone.timer_node_count(), nodes, "no timer lease");
            let resumed = {
                let mut entry =
                    reenter_worker(fixture, registry, runtime, source, &worker, service);
                let resumed = entry.resume_checkpoint(|_| Ok(None));
                drop(entry);
                resumed
            };
            let resumed = match resumed {
                Ok(NativeResume::Returned(result)) => Some(result.raw()),
                _ => None,
            };
            assert_eq!(resumed, Some(-4), "the retained EINTR answer");
            assert_eq!(
                take_signal_copies(),
                [(UserVa::new(remaining), timespec_bytes(100).to_vec())]
            );
            consume_injected_sigint(runtime, &fixture.task, worker.record);
            return;
        }
        if case == SleepCase::PendingSignalOwnerWaitRemainder {
            // OwnerWait once: the caller released its execution lease and
            // parked on the mm owner, with the EINTR answer and its rem bytes
            // retained in the service row. No timer lease: the sleep's
            // decision is already made.
            assert_eq!(route, CompletionRoute::Suspended, "parked on the owner");
            assert!(take_signal_copies().is_empty(), "nothing written yet");
            assert_ne!(
                fixture.zone.slot(fixture.slot).current(),
                Some(worker.record.id),
                "the owner wait released the execution lease"
            );
            assert_eq!(fixture.zone.timer_node_count(), nodes, "no timer lease");
            // The gate's release publishes the owner notification and wakes
            // the parked caller; its checkpoint reruns the retained copy.
            access.lower(space.index());
            let resumed = {
                let mut entry =
                    reenter_worker(fixture, registry, runtime, source, &worker, service);
                let resumed = entry.resume_checkpoint(|_| Ok(None));
                drop(entry);
                resumed
            };
            let resumed = match resumed {
                Ok(NativeResume::Returned(result)) => Some(result.raw()),
                _ => None,
            };
            assert_eq!(resumed, Some(-4), "the retained EINTR answer");
            assert_eq!(
                take_signal_copies(),
                [(UserVa::new(remaining), timespec_bytes(100).to_vec())],
                "the retained rem bytes, written once after the wait"
            );
            consume_injected_sigint(runtime, &fixture.task, worker.record);
            return;
        }
        let immediate = match case {
            SleepCase::ZeroRelative | SleepCase::ExpiredAbsolute => Some(0),
            SleepCase::InvalidTimespec => Some(-22),
            SleepCase::PendingSignal | SleepCase::PendingSignalLazyRemainder => Some(-4),
            _ => None,
        };
        if let Some(result) = immediate {
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(frame.x[0] as i64, result, "{case:?}");
            assert_eq!(
                fixture.zone.slot(fixture.slot).current(),
                Some(worker.record.id),
                "an answered sleep never parks"
            );
            assert_eq!(fixture.zone.timer_node_count(), nodes, "no timer lease");
            let copies = take_signal_copies();
            if pending_signal {
                // A deliverable signal at entry: EINTR with the whole
                // interval; a not-yet-backed rem page is prepared, never a
                // fault.
                assert_eq!(
                    copies,
                    [(UserVa::new(remaining), timespec_bytes(100).to_vec())]
                );
                consume_injected_sigint(runtime, &fixture.task, worker.record);
            } else {
                assert!(copies.is_empty(), "only EINTR writes rem: {copies:?}");
            }
            return;
        }
        if let Some(raced) = raced {
            assert!(
                raced.load(Ordering::Acquire),
                "the publication raced enrollment"
            );
        }
        assert_parked();
        let (expected, copied) = match case {
            SleepCase::Expiry | SleepCase::RacedPublication | SleepCase::FutureAbsolute => {
                depart_and_expire();
                (0, None)
            }
            SleepCase::DeadlineCrossesChecks => {
                depart_and_expire();
                // The woken sleep's first clock read is before the deadline;
                // the clock then passes it (default 2000) before any later
                // read. The sleep must park again on its own deadline, never
                // reach the rt_sigtimedwait EAGAIN answer.
                script_signal_clock(&[1050]);
                let first = {
                    let mut entry =
                        reenter_worker(fixture, registry, runtime, source, &worker, service);
                    let resumed = entry.resume_pending_wait();
                    drop(entry);
                    resumed
                };
                let first = match first {
                    Some(LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        ..
                    }) => Ok(()),
                    Some(LifecycleOutcome::Returned { result, .. }) => Err(result.raw()),
                    _ => Err(i64::MIN),
                };
                assert_eq!(
                    first,
                    Ok(()),
                    "a deadline crossing between the checks re-parks, never returns"
                );
                assert_parked();
                depart_and_expire();
                (0, None)
            }
            SleepCase::SignalBetweenChecks => {
                depart_and_expire();
                // Woken early (the clock still reads 1050), then SIGINT is
                // published right after the sleep's deliverable check found
                // nothing. Enrollment must refuse the stale generation and
                // the rescan answers EINTR with the unslept 50 ns in rem.
                script_signal_clock(&[1050, 1050]);
                let fired = runtime.publish_signal_after_next_empty_check(
                    child,
                    worker.record,
                    carrick_signal_core::policy::Signal::from_number(2).unwrap(),
                );
                let resumed = {
                    let mut entry =
                        reenter_worker(fixture, registry, runtime, source, &worker, service);
                    let resumed = entry.resume_pending_wait();
                    drop(entry);
                    resumed
                };
                assert!(fired.load(Ordering::Acquire), "the publication raced");
                let resumed = match resumed {
                    Some(LifecycleOutcome::Returned { result, .. }) => Some(result.raw()),
                    _ => None,
                };
                assert_eq!(resumed, Some(-4), "{case:?}");
                assert_eq!(
                    take_signal_copies(),
                    [(UserVa::new(remaining), timespec_bytes(50).to_vec())],
                    "EINTR writes the relative rem"
                );
                consume_injected_sigint(runtime, &fixture.task, worker.record);
                return;
            }
            SleepCase::Interrupted | SleepCase::FutureAbsoluteInterrupted => {
                // A terminal SIGINT reaches the parked member through the
                // production ingress owner and wakes it before its deadline.
                assert!(
                    registry
                        .admit_external_event(fixture.zone, interrupt, fixture.slot, service)
                        .unwrap()
                );
                assert!(
                    !matches!(sleeper.claim(), carrick_sched_core::Claim::Parked { .. }),
                    "a deliverable signal wakes the parked sleep"
                );
                assert_eq!(
                    fixture.zone.timer_node_count(),
                    nodes,
                    "wake cancels the timer"
                );
                // An absolute sleep never writes rem.
                (-4, (case == SleepCase::Interrupted).then_some(100))
            }
            _ => unreachable!("{case:?} answers at entry"),
        };
        let mut entry = reenter_worker(fixture, registry, runtime, source, &worker, service);
        let resumed_outcome = entry.resume_pending_wait();
        drop(entry);
        let resumed = match resumed_outcome {
            Some(LifecycleOutcome::Returned { result, .. }) => Some(result.raw()),
            _ => None,
        };
        assert_eq!(resumed, Some(expected), "{case:?}");
        let copies = take_signal_copies();
        match copied {
            Some(nanos) => assert_eq!(
                copies,
                [(UserVa::new(remaining), timespec_bytes(nanos).to_vec())]
            ),
            None => assert!(copies.is_empty(), "only a relative EINTR writes rem"),
        }
        if expected == -4 {
            consume_injected_sigint(runtime, &fixture.task, worker.record);
        }
        return;
    }
    let wake_after_departure = matches!(
        departure,
        Some(TimerDeparture::CarrierExitWake | TimerDeparture::SlotResetWake)
    );
    let original_deadline = fixture.zone.record(binding.record.id).deadline();
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
        // Settle gettid's completed return boundary before rebinding the
        // task, just as the carrier does. Otherwise CurrentTask::set turns
        // that unconsumed boundary into pending work and defers FUTEX_WAKE.
        assert_eq!(
            fixture.task.linux.take_served_boundary(),
            Some(carrick_personality_linux::abi::entry::ServedBoundary::Completed),
        );
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
        if matches!(
            departure,
            TimerDeparture::SlotReset | TimerDeparture::SlotResetWake
        ) {
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
        if wake_after_departure {
            // Resume the already-live sibling through native custody, then
            // use the production FUTEX_WAKE below before the original tick.
            fixture.zone.enter_guest(fixture.slot);
            activate_target(source, &fixture.task, &worker);
            // activate_target's process binding names the leader. This is a
            // non-leader: project its exact execution identity as Sched does.
            let identity = fixture.zone.record(worker.record.id).identity();
            fixture.task.set(
                El1TaskId::from_linux_tid(identity.tid as i32),
                carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
                identity.file_table,
            );
        } else {
            // No timeout before the original deadline, then exactly one timeout.
            assert!(
                fixture
                    .zone
                    .expire_native_timer(
                        carrick_guest_arch::CounterTick::new(deadline - 1),
                        &ShortLockSpin,
                        &|owned| crate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned
                        )
                    )
                    .is_none()
            );
            assert!(
                fixture
                    .zone
                    .expire_native_timer(
                        carrick_guest_arch::CounterTick::new(deadline),
                        &ShortLockSpin,
                        &|owned| crate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned
                        )
                    )
                    .is_some()
            );
            assert!(
                fixture
                    .zone
                    .expire_native_timer(
                        carrick_guest_arch::CounterTick::new(deadline),
                        &ShortLockSpin,
                        &|owned| crate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned
                        )
                    )
                    .is_none()
            );
            assert_eq!(fixture.zone.timer_node_count(), 0);
            assert_eq!(waiter.result() as i64, -110);
            assert_eq!(waiter.entry_count(), 0);
            carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                carrick_kernel::el1_zone::hand_back(&[binding.record]);
            });
            assert!(!matches!(
                waiter.claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            let selected = activate_target(source, &fixture.task, &binding);
            assert_eq!(selected.result, Some((-110_i64) as u64));
            return;
        }
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
    drop(entry);
    if wake_after_departure {
        let deadline = original_deadline.expect("timed native park");
        assert_eq!(fixture.zone.record(binding.record.id).entry_count(), 0);
        assert!(crate::sched::ThreadCpu::now(&cpu) < deadline);
        assert_eq!(fixture.zone.timer_node_count(), 0);
        assert!(
            fixture
                .zone
                .expire_native_timer(
                    carrick_guest_arch::CounterTick::new(deadline),
                    &ShortLockSpin,
                    &|owned| crate::sched::object_wait::deliver_host_completion(
                        owned.zone(),
                        owned
                    )
                )
                .is_none(),
            "the later timeout must not resolve the wake winner again"
        );
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, worker.record.id)
                .is_queued()
        );
        let selected = activate_target(source, &fixture.task, &binding);
        assert_eq!(
            selected.result,
            Some(0),
            "native owner receives FUTEX_WAKE result"
        );
        assert_eq!(fixture.zone.timer_node_count(), 0);
    }
    assert_eq!(counters.forwarded[98].load(Ordering::Relaxed), 0);
    assert!(runtime.task_binding(parent).is_some());
}

/// Consume a SIGINT a sleep witness injected. Pending signals publish a
/// process-global summary word that later tests' empty-checkpoint fast path
/// reads; a leaked fixture must not leave one behind.
fn consume_injected_sigint(
    runtime: &NativeProcessRuntime<'_, AddressContext<RootGpa>, Aarch64ParkedContext>,
    task: &CurrentTask,
    record: carrick_sched_core::RecordRef,
) {
    let signals = runtime
        .current_signals(task)
        .expect("sleeping clone's signal owner");
    let taken = signals.take_deliverable(record, carrick_signal_core::policy::SigBlockMask::NONE);
    assert_eq!(taken.map(|(signal, ..)| signal.number()), Some(2));
}

/// Linux control only: this is not Carrick guest-memory or signed evidence.
#[cfg(all(test, target_os = "linux"))]
#[test]
fn serial_host_linux_exec_child_v8_memory_control() {
    use std::{process::Command, time::Duration};
    use wait_timeout::ChildExt;

    const CHILD: &str = "CARRICK_1846_LINUX_CONTROL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "aarch64_process_tests::native_exec_pipe_tests::serial_host_linux_exec_child_v8_memory_control",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let status = child.wait_timeout(Duration::from_secs(10)).unwrap();
        if status.is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(status.is_some_and(|status| status.success()));
        return;
    }

    // SAFETY: this isolated exec child owns the anonymous reservation. Fixed
    // replacement stays inside it, all pointer accesses are within its RWX
    // subrange, and no slice survives a protection or mapping change.
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let size = 128 * 1024 * 1024;
        let touched = 2 * 1024 * 1024;
        let raw = libc::mmap(
            core::ptr::null_mut(),
            size + 2 * page,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        );
        assert_ne!(raw, libc::MAP_FAILED);
        let base = raw.cast::<u8>().add(page);
        assert_eq!(libc::munmap(raw, page), 0, "prefix trim");
        assert_eq!(libc::munmap(base.add(size).cast(), page), 0, "suffix trim");
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        assert_eq!(libc::mprotect(base.cast(), touched, rwx), 0);
        core::ptr::write_bytes(base, 0x5a, touched);
        assert_eq!(libc::madvise(base.cast(), touched, libc::MADV_DONTNEED), 0);
        assert!(
            core::slice::from_raw_parts(base, touched)
                .iter()
                .all(|byte| *byte == 0)
        );
        // Same admission reduction as the Carrick fork/exec witness.
        assert_eq!(
            libc::madvise(0x400000 as *mut libc::c_void, 0, libc::MADV_DONTNEED),
            0
        );
        for prot in [
            libc::PROT_NONE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::PROT_READ | libc::PROT_EXEC,
            rwx,
        ] {
            assert_eq!(libc::mprotect(base.cast(), touched, prot), 0, "prot={prot}");
        }
        core::ptr::write_bytes(base, 0xa5, touched);
        assert_eq!(
            libc::mmap(
                base.cast(),
                touched,
                libc::PROT_NONE,
                libc::MAP_FIXED | libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0
            ),
            base.cast()
        );
        assert_eq!(libc::mprotect(base.cast(), touched, libc::PROT_READ), 0);
        assert!(
            core::slice::from_raw_parts(base, touched)
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(libc::munmap(base.cast(), size), 0);
        println!(
            "Linux exec child: reserve=128MiB, trim=0, RWX=0, DONTNEED(2MiB)=0, zeros=true, DONTNEED(0x400000,0,4)=0, NONE/RW/RX/RWX=0, fixed-decommit=zeros, unmap=0"
        );
    }
}

struct FixtureDiscardMapping<'a> {
    mapping: super::native_fault_supply_tests::FixtureMapping<'a>,
    pages: &'a std::cell::RefCell<BTreeMap<u64, Vec<u8>>>,
    scrubs: &'a std::cell::Cell<usize>,
}
impl carrick_el1::memory::AnonymousBackingProbe for FixtureDiscardMapping<'_> {
    fn bind_operation(&mut self, sequence: carrick_el1_abi::ReservationSequence) {
        self.mapping.bind_operation(sequence);
    }
    fn backing(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> carrick_el1::memory::Stage1Backing {
        self.mapping.backing(root, va, len)
    }
    fn stock_span(
        &mut self,
        mm: ReservationMm,
        va: UserVa,
    ) -> Option<carrick_guest_arch::UserRange> {
        self.mapping.stock_span(mm, va)
    }
}
impl carrick_el1::memory::AnonymousPermissionEditor for FixtureDiscardMapping<'_> {
    fn bind_resident_edit(&mut self, generation: carrick_el1::memory::AnonymousEditGeneration) {
        self.mapping.bind_resident_edit(generation);
    }
    fn protect_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        edit: carrick_mmu_core::aarch64::GuestPermissionEdit,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
        self.mapping.protect_and_invalidate(root, edit)
    }
}
impl carrick_el1::memory::AnonymousRetirementEditor for FixtureDiscardMapping<'_> {
    fn bind_resident_edit(&mut self, generation: carrick_el1::memory::AnonymousEditGeneration) {
        self.mapping.bind_resident_edit(generation);
    }
    fn retire_and_invalidate(
        &mut self,
        mm: ReservationMm,
        root: carrick_guest_arch::AddressSpaceRegister,
        address: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        self.mapping.retire_and_invalidate(mm, root, address, len)
    }
}
impl carrick_el1::memory::AnonymousDiscardEditor for FixtureDiscardMapping<'_> {
    fn discard_and_scrub(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        steps: &[carrick_el1::memory::AnonymousDiscardStep],
    ) -> Result<(), carrick_el1::memory::AnonymousDiscardError> {
        carrick_el1::memory::discard_aarch64_anonymous_steps(
            self.mapping.words,
            carrick_mmu_core::aarch64::SubstrateGpa(root.raw() & AARCH64_ROOT_ADDRESS_MASK),
            carrick_el1_abi::EL1_COW_COPY_BASE,
            steps,
            |alias_va, _| {
                let to = super::native_fault_supply_tests::leaf(
                    self.mapping.words,
                    root.raw(),
                    alias_va,
                );
                assert_eq!(to & 3, 3);
                assert_eq!(to & (3 << 6), 0);
                assert_ne!(to & ((1 << 54) | (1 << 53)), 0);
                self.pages
                    .borrow_mut()
                    .insert(to & AARCH64_ROOT_ADDRESS_MASK, vec![0; 4096]);
                self.scrubs.set(self.scrubs.get() + 1);
            },
        )
    }
}
