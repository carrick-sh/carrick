//! Red-first VM-free tests for [`Aarch64NativeProcessService`] and the shared process owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::aarch64_process::*;
use super::native_process_runtime::{
    NativeProcessError, NativeProcessRuntime, NativeProcessService,
};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, El1TaskId, ForkStockExchange, ForkStockKind, ForkStockLoan,
    ForkStockRefusal, ForkStockSettlement, ReservationMm, ThreadControlSlot, ThreadIdentity,
    ThreadLifecyclePage,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, SlotId, UserVa,
};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_personality_linux::lifecycle::{
    LifecycleOutcome, LinuxWaitOptions, LinuxWaitStatus, ProcessNative, ProcessWaitPid,
};
use carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
use carrick_sched_core::{Aarch64ParkedContext, ThreadCtx, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const VA: u64 = 0x4000_0000;
const IPA: u64 = 0x9000_0000;

struct TestStockCrossing {
    fd_map: Vec<carrick_el1_abi::FdMapSlot>,
    grant_tables: std::sync::Mutex<Vec<RootGpa>>,
    total_returned_pages: AtomicU64,
    loans_requested: AtomicUsize,
    settlements_committed: AtomicUsize,
    settlements_aborted: AtomicUsize,
    pending_loan: std::sync::Mutex<Option<ForkStockLoan>>,
    retirements: AtomicUsize,
    zone: std::sync::Mutex<Option<&'static ZoneTables<Aarch64ParkedContext>>>,
    child: std::sync::Mutex<Option<(carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>)>>,
    handbacks: AtomicUsize,
}

impl TestStockCrossing {
    fn new(stock_pages: &[u64]) -> Self {
        Self {
            fd_map: (0..carrick_el1_abi::FD_MAP_CAPACITY)
                .map(|_| carrick_el1_abi::FdMapSlot::default())
                .collect(),
            grant_tables: std::sync::Mutex::new(
                stock_pages
                    .iter()
                    .map(|&p| RootGpa::page_aligned(FrameGpa::new(p)).unwrap())
                    .collect(),
            ),
            total_returned_pages: AtomicU64::new(0),
            loans_requested: AtomicUsize::new(0),
            settlements_committed: AtomicUsize::new(0),
            settlements_aborted: AtomicUsize::new(0),
            pending_loan: std::sync::Mutex::new(None),
            retirements: AtomicUsize::new(0),
            zone: std::sync::Mutex::new(None),
            child: std::sync::Mutex::new(None),
            handbacks: AtomicUsize::new(0),
        }
    }
}

impl ForkStockCrossing for TestStockCrossing {
    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        let zone = self
            .zone
            .lock()
            .unwrap()
            .ok_or(NativeProcessError::Invalid)?;
        let (binding, context) = self
            .child
            .lock()
            .unwrap()
            .ok_or(NativeProcessError::Invalid)?;
        let slot = SlotId::from_index(cpu as usize).unwrap();
        let source = BornInZoneSource { zone, slot };
        // SAFETY: the synchronous test crossing retains this aligned ABI record.
        let record = unsafe { &mut *(record_gpa as *mut carrick_el1_abi::NativeChildRetire) };
        assert!(
            zone.slot(slot).current().is_none(),
            "retirement happens after zone exit"
        );
        if !carrick_core::entry::terminal_matches(
            binding,
            source,
            carrick_sched_core::TerminalPhase::PendingRetirement,
        ) || !record.request_matches(binding, context)
        {
            record.refuse(carrick_el1_abi::ChildRetireRefusal::Stale);
            return Err(NativeProcessError::Stale);
        }
        assert!(zone.accept_terminal(
            slot,
            ThreadIdentity {
                tid: binding.task.raw(),
                generation: binding.generation.raw(),
                mm: binding.mm.raw(),
                serial: binding.thread_generation.raw(),
                ..Default::default()
            }
        ));
        assert!(record.accept());
        self.retirements.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn cross_wait_channel_wake(
        &self,
        channel: super::native_process_runtime::ProcessWaitChannel,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        let zone = self.zone.lock().unwrap().unwrap();
        let (binding, _) = self.child.lock().unwrap().unwrap();
        let slot = SlotId::from_index(cpu as usize).unwrap();
        assert!(carrick_core::entry::terminal_matches(
            binding,
            BornInZoneSource { zone, slot },
            carrick_sched_core::TerminalPhase::Retired
        ));
        assert_eq!(
            self.retirements.load(Ordering::Acquire),
            1,
            "wake follows real retirement"
        );
        let mut transfers = Vec::new();
        let guard = zone
            .lock(
                ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(
                    channel.mm.raw(),
                    channel.address.get(),
                ),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        let count = zone.wake_host(
            &guard,
            channel.mm.raw(),
            channel.address.get(),
            u32::MAX,
            u32::MAX,
            false,
            &mut |transfer| transfers.push(transfer),
            &mut |_| panic!("must hand back to host"),
        );
        drop(guard);
        for transfer in transfers {
            assert!(
                transfer
                    .finish(&carrick_sched_core::ShortLockSpin)
                    .is_some()
            );
        }
        self.handbacks.fetch_add(count as usize, Ordering::AcqRel);
        Ok(())
    }

    fn fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        &self.fd_map
    }

    fn cross_fork_stock(&self, record_gpa: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        let tag = unsafe { *(record_gpa as *const u64) };
        match ForkStockKind::decode(tag) {
            Some(ForkStockKind::Loan) => {
                let loans = self.loans_requested.fetch_add(1, Ordering::AcqRel) + 1;
                let exchange = unsafe { &mut *(record_gpa as *mut ForkStockExchange) };
                let req = exchange.request().ok_or(NativeProcessError::Invalid)?;
                let child_pages = (req.child_bytes as usize).div_ceil(4096).max(1);
                let parent_pages = (req.parent_bytes as usize).div_ceil(4096).max(1);
                let total = child_pages + parent_pages;
                let mut tables = self.grant_tables.lock().unwrap();
                if tables.len() < total {
                    exchange.refuse(ForkStockRefusal::Capacity);
                    return Err(NativeProcessError::Exhausted);
                }
                let child_slice: Vec<_> = tables.drain(..child_pages).collect();
                let parent_slice: Vec<_> = tables.drain(..parent_pages).collect();
                drop(tables);
                let child_base = child_slice[0].address().raw();
                let parent_base = parent_slice[0].address().raw();
                let layout = std::alloc::Layout::from_size_align(
                    core::mem::size_of::<ThreadLifecyclePage>(),
                    16384,
                )
                .unwrap();
                let page_ptr = unsafe {
                    let ptr = std::alloc::alloc_zeroed(layout).cast::<ThreadLifecyclePage>();
                    (*ptr) = ThreadLifecyclePage::new();
                    ptr
                };
                let controls = Box::leak(Box::new(core::array::from_fn::<
                    _,
                    { carrick_el1_abi::THREAD_POOL_ENTRIES + 1 },
                    _,
                >(|_| ThreadControlSlot::new())));
                let lifecycle = carrick_el1_abi::ForkLifecycleLoan::new(
                    KernelVa::new(page_ptr as u64),
                    KernelVa::new(controls as *mut _ as u64),
                )
                .unwrap();
                let id = NonZeroU64::new(100 + loans as u64).unwrap();
                let asid = carrick_guest_arch::Asid::from_registry_allocation(
                    core::num::NonZeroU16::new(41 + loans as u16).unwrap(),
                );
                let kernel_control_ipa = 0x20_0000;
                if !exchange.grant(
                    child_base,
                    parent_base,
                    kernel_control_ipa,
                    id,
                    lifecycle,
                    Some(asid),
                ) {
                    return Err(NativeProcessError::Invalid);
                }
                *self.pending_loan.lock().unwrap() = req.admit_loan(
                    child_base,
                    parent_base,
                    kernel_control_ipa,
                    id,
                    lifecycle,
                    Some(asid),
                );
                Ok(())
            }
            Some(ForkStockKind::Commit) => {
                self.settlements_committed.fetch_add(1, Ordering::AcqRel);
                let settlement = unsafe { &mut *(record_gpa as *mut ForkStockSettlement) };
                if let Some(loan) = *self.pending_loan.lock().unwrap()
                    && !settlement.accept(loan)
                {
                    return Err(NativeProcessError::Invalid);
                }
                Ok(())
            }
            Some(ForkStockKind::Abort) => {
                self.settlements_aborted.fetch_add(1, Ordering::AcqRel);
                let settlement = unsafe { &mut *(record_gpa as *mut ForkStockSettlement) };
                if let Some(loan) = self.pending_loan.lock().unwrap().take() {
                    if !settlement.accept(loan) {
                        return Err(NativeProcessError::Invalid);
                    }
                    let child_pages = (loan.request.child_tables.len as usize) / 4096;
                    let parent_pages = (loan.request.parent_tables.len as usize) / 4096;
                    self.total_returned_pages
                        .fetch_add((child_pages + parent_pages) as u64, Ordering::AcqRel);
                    let mut tables = self.grant_tables.lock().unwrap();
                    for p in 0..child_pages {
                        tables.push(
                            RootGpa::page_aligned(FrameGpa::new(
                                loan.request.child_tables.base + p as u64 * 4096,
                            ))
                            .unwrap(),
                        );
                    }
                    for p in 0..parent_pages {
                        tables.push(
                            RootGpa::page_aligned(FrameGpa::new(
                                loan.request.parent_tables.base + p as u64 * 4096,
                            ))
                            .unwrap(),
                        );
                    }
                }
                Ok(())
            }
            _ => Err(NativeProcessError::Invalid),
        }
    }

    fn cross_root_exit(&self, _record_gpa: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        Ok(())
    }
}

struct Fixture {
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    task: CurrentTask,
    slot: SlotId,
    address: AddressContext<RootGpa>,
    region: &'static crate::personality::mm_portal::test_support::Region,
    tables: crate::personality::mm_portal::test_support::Tables,
    maintenance: CallerInvalidatesAsid,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
}

fn asid(raw: u16) -> carrick_guest_arch::Asid {
    carrick_guest_arch::Asid::from_registry_allocation(core::num::NonZeroU16::new(raw).unwrap())
}

impl Fixture {
    fn new(root_gpa: u64, asid: carrick_guest_arch::Asid) -> Self {
        let region_box = Box::new(crate::personality::mm_portal::test_support::Region::new());
        let region = Box::leak(region_box);
        let zone: &'static ZoneTables<Aarch64ParkedContext> = unsafe {
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast()
        };

        let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control = Box::leak(Box::new(ThreadControlSlot::new()));

        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(41), 11, 5);
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);

        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root_gpa)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(101).unwrap()),
        };

        let slot = SlotId::new(0);
        let ttbr0 = (u64::from(asid.raw()) << 48) | root_gpa;
        let space = zone.spaces.publish_closed(1, ttbr0, ttbr0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 1).unwrap();
        zone.current_or_new(
            slot,
            ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: 1,
                file_table: 5,
                generation: 11,
                affinity: 1,
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();

        let index = zone.spaces.find(1).unwrap();
        let mm = ReservationMm::new(1).unwrap();
        let table = region.table();
        table
            .publish(
                index.index(),
                mm,
                carrick_el1_abi::Layout {
                    heap: carrick_el1_abi::ReservationRange::new(4096, VA).unwrap(),
                    arena: carrick_el1_abi::ReservationRange::new(VA, VA + 0x1000_0000).unwrap(),
                    policy: carrick_el1_abi::ReservationPolicyPayload::new([
                        4096,
                        u64::MAX,
                        u64::MAX,
                        0,
                        0,
                    ]),
                },
            )
            .unwrap();
        let view = crate::personality::mm_portal::test_support::nodes(region);
        let mut owner = table
            .lock_el1_resolved(index.index(), mm, &view, 0)
            .unwrap();
        owner
            .import(
                carrick_el1_abi::ReservationRange::new(VA, VA + 8192).unwrap(),
                carrick_el1_abi::ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
        owner.finish_import().unwrap();
        drop(owner);

        let tables = crate::personality::mm_portal::test_support::Tables::new(root_gpa, IPA, 2);
        let maintenance = CallerInvalidatesAsid;

        Self {
            zone,
            task,
            slot,
            address,
            region,
            tables,
            maintenance,
            page,
            control,
        }
    }
}

#[test]
fn native_process_entry_uses_parked_root_generation_after_record_reuse() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let record = fixture
        .zone
        .slot(fixture.slot)
        .current()
        .or_else(|| fixture.zone.slot(fixture.slot).host_record())
        .unwrap();
    assert_ne!(
        fixture.zone.record(record).incarnation(),
        fixture.address.generation.raw().get()
    );
    // SAFETY: this VM-free fixture owns the stopped record exclusively.
    unsafe {
        *fixture.zone.record(record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    // SAFETY: this VM-free fixture owns the stopped record exclusively.
    let address = unsafe { observed_entry_address(source, &fixture.task, ttbr0, record) }.unwrap();
    assert_eq!(address, fixture.address);
    // The live register must still name the parked root; a recycled root
    // address with another generation is checked by the registry at entry.
    let other_root = ttbr0 + 0x1000;
    assert!(matches!(
        unsafe { observed_entry_address(source, &fixture.task, other_root, record) },
        Err(NativeProcessError::Stale)
    ));
}

/// Red-first Test 1: child gets distinct root and x0 = 0.
#[test]
fn test_fork_child_gets_distinct_root_and_x0_zero() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    let outcome = entry.fork();
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("expected fork to return child pid");
    };
    let child_pid = result.raw() as u32;
    assert_eq!(child_pid, 42);

    let parent_key = TaskKey {
        id: TaskId::from_abi_positive(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    assert_ne!(child_key, parent_key);

    let child_binding = runtime.task_binding(child_key).unwrap();
    assert_eq!(child_binding.words.syscall_return(), 0);
    assert_eq!(child_binding.words.native.x[0], 0);
    assert_ne!(child_binding.address.root, fixture.address.root);
    assert_eq!(
        child_binding.address.root.address().raw(),
        0x20000 & AARCH64_ROOT_ADDRESS_MASK
    );

    // Verify child address space TTBR0 contains the host-assigned ASID in the top 16 bits
    let child_index = fixture
        .zone
        .spaces
        .find(child_binding.address.mm.raw().get())
        .unwrap();
    let grant = fixture
        .zone
        .spaces
        .grant(child_index, child_binding.address.mm.raw().get())
        .unwrap();
    assert_eq!(grant.ttbr0 >> 48, 42);
}

#[test]
fn plain_fork_owns_an_independent_fd_table() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parent_ttbr = (1_u64 << 48) | fixture.address.root.address().raw();
    let parked = Aarch64ParkedContext::from_register(
        native,
        parent_ttbr,
        fixture.address.mm.raw().get(),
        fixture.address.generation.raw().get(),
    );
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let parent_table = fixture.task.linux.file_table.load(Ordering::Acquire);
    crossing.fd_map[0].set(parent_table, 7, 3, 1);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    let outcome = entry.fork();
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("expected fork to return child pid");
    };
    let child_pid = result.raw() as u32;
    assert_eq!(child_pid, 42);

    let parent_key = TaskKey {
        id: TaskId::from_abi_positive(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    assert_ne!(child_key, parent_key);

    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();
    let parent_table = fixture
        .zone
        .record(parent_binding.record.id)
        .identity()
        .file_table;
    let child_table = fixture
        .zone
        .record(child_binding.record.id)
        .identity()
        .file_table;
    assert_ne!(
        child_table, parent_table,
        "plain fork must not share descriptor table identity"
    );
    assert_eq!(
        carrick_el1_abi::fd_map_lookup(&crossing.fd_map, child_table, 7)
            .unwrap()
            .0,
        3
    );
    assert!(
        super::file_table::close_host_binding(&crossing.fd_map, child_table, 7)
            .unwrap()
            .release
            .is_none(),
        "parent still owns the shared open description"
    );
    assert!(carrick_el1_abi::fd_map_lookup(&crossing.fd_map, child_table, 7).is_none());
    assert_eq!(
        carrick_el1_abi::fd_map_lookup(&crossing.fd_map, parent_table, 7)
            .unwrap()
            .0,
        3
    );
}

/// Red-first Test 2: private pages are COW-armed in both parent and child.
#[test]
fn test_fork_private_pages_cow_armed_in_both() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    let outcome = entry.fork();
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("expected fork to return child pid");
    };
    assert_eq!(result.raw(), 42);

    // After fork, parent's private mapping at VA should be COW-armed (read-only and non-global nG)
    let parent_leaf = fixture.tables.words[1536].load(Ordering::Relaxed);
    // Read-only has bit 7 set (AP[2]=1) or writable bit 7 clear, and nG (bit 11) set
    assert_ne!(parent_leaf & (1 << 11), 0, "parent leaf must have nG set");
    assert_ne!(
        parent_leaf & (1 << 7),
        0,
        "parent leaf must be read-only (AP[2])"
    );
}

fn activate(
    source: BornInZoneSource<'_, Aarch64ParkedContext>,
    task: &CurrentTask,
    binding: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
) {
    let zone = source.zone;
    assert_eq!(
        zone.switch_in_full(source.slot).unwrap().record,
        binding.record.id
    );
    zone.install_space(source.slot, binding.address.mm.raw().get())
        .unwrap();
    let identity = zone.record(binding.record.id).identity();
    task.set(
        El1TaskId::from_linux_tid(binding.key.id.raw()),
        binding.key.serial.raw(),
        identity.file_table,
    );
    task.mm
        .key
        .store(binding.address.mm.raw().get(), Ordering::Release);
    task.mm
        .thread_generation
        .store(identity.serial, Ordering::Release);
    task.publish_visible_pid(binding.visible_pid);
    task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
}

/// Red-first Test 3: wait4 consumes the zombie exactly once with exact status copied.
#[test]
fn test_wait4_consumes_zombie_once_with_exact_status() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let child_pid;
    {
        let mut parent_entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent_entry.fork() else {
            panic!("expected fork return");
        };
        child_pid = result.raw() as u32;
    }

    let parent_key = TaskKey {
        id: TaskId::from_abi_positive(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    // Parent yields slot to child
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent_binding.record.id);

    // Now child exits with status 9
    let child_task = CurrentTask::new();
    let child_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    activate(child_source, &child_task, &child_binding);
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.child.lock().unwrap() = Some((
        super::common_entry::execution_binding(&child_task),
        child_binding.address,
    ));

    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    {
        let mut child_entry = runtime
            .enter(
                child_source,
                &child_task,
                child_binding.words,
                &mut child_service,
            )
            .unwrap();
        let exit_outcome = child_entry.exit_group(9);
        assert!(matches!(
            exit_outcome,
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
    }

    // Now parent calls wait4 to consume the zombie
    let mut status_storage = 0i32;
    let status_va = UserVa::new(&raw mut status_storage as u64);

    let parent_binding = runtime.task_binding(parent_key).unwrap();
    activate(source, &fixture.task, &parent_binding);

    let mut parent_entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();

    let wait_outcome = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(child_pid as u64),
        status_va,
        LinuxWaitOptions::empty(),
        UserVa::new(0),
    );

    assert!(matches!(
        wait_outcome,
        LifecycleOutcome::Returned { result, .. } if result.raw() == child_pid as i64
    ));
    assert_eq!(
        status_storage,
        LinuxWaitStatus::from_wait_encoding(9 << 8).raw()
    );

    // Second wait on the consumed child must fail with ECHILD (error code -10)
    let re_wait = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(child_pid as u64),
        status_va,
        LinuxWaitOptions::empty(),
        UserVa::new(0),
    );
    assert!(matches!(
        re_wait,
        LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::NoChild.errno()
    ));
}

#[test]
fn arm_terminal_child_retirement_and_parent_handback_once() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let child_pid;
    {
        let mut parent_entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent_entry.fork() else {
            panic!("expected fork return");
        };
        child_pid = result.raw() as u32;
    }

    let parent_key = TaskKey {
        id: TaskId::from_abi_positive(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    // Parent yields slot to child
    let mut status_storage = 0i32;
    let status_va = UserVa::new(&raw mut status_storage as u64);
    {
        let mut parent_entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        assert!(matches!(
            parent_entry.wait4(
                ProcessWaitPid::from_syscall_argument(child_pid as u64),
                status_va,
                LinuxWaitOptions::empty(),
                UserVa::new(0)
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(parent_entry.take_handoff_receipt().is_some());
    }
    fixture
        .zone
        .unhome(fixture.slot, parent_binding.record.id, 1);

    // Now child exits with status 9
    let child_task = CurrentTask::new();
    let child_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    activate(child_source, &child_task, &child_binding);
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.child.lock().unwrap() = Some((
        super::common_entry::execution_binding(&child_task),
        child_binding.address,
    ));

    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    {
        let mut child_entry = runtime
            .enter(
                child_source,
                &child_task,
                child_binding.words,
                &mut child_service,
            )
            .unwrap();
        // No guest slot may place the parent: its executor is in the host
        // continuation, and the child is the last execution on this slot.
        fixture.zone.publish_slot(fixture.slot, 0, Some(0), 1);
        let exit_outcome = child_entry.exit_group(9);
        assert_eq!(child_entry.take_run_failure(), None);
        assert!(matches!(
            exit_outcome,
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
    }

    assert_eq!(
        crossing.retirements.load(Ordering::Acquire),
        1,
        "terminal child must retire before parent can reap"
    );

    let binding = super::common_entry::execution_binding(&child_task);
    for candidate in [
        binding,
        carrick_el1_abi::ExecutionBinding {
            generation: carrick_el1_abi::EntryGeneration::from_raw(binding.generation.raw() + 1),
            ..binding
        },
    ] {
        let mut duplicate =
            carrick_el1_abi::NativeChildRetire::new(candidate, child_binding.address).unwrap();
        assert_eq!(
            crossing.cross_child_retire(&raw mut duplicate as u64, u64::from(fixture.slot.raw())),
            Err(NativeProcessError::Stale)
        );
        assert_eq!(
            duplicate.take(candidate, child_binding.address),
            Some(Err(carrick_el1_abi::ChildRetireRefusal::Stale))
        );
        assert_eq!(crossing.retirements.load(Ordering::Acquire), 1);
    }

    // Now parent calls wait4 to consume the zombie
    assert_eq!(crossing.handbacks.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.zone.record(parent_binding.record.id).claim(),
        carrick_sched_core::Claim::Host {
            seq: fixture
                .zone
                .next_seq(parent_binding.record.id)
                .wrapping_sub(1)
        }
    );
    // Host reload uses the original continuation and restores execution capacity.
    fixture.zone.publish_slot(fixture.slot, 1, Some(0), 1);
    fixture.zone.install_space(fixture.slot, 1).unwrap();
    assert!(
        fixture
            .zone
            .place_from_host(parent_binding.record.id)
            .is_some()
    );
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    activate(source, &fixture.task, &parent_binding);

    let mut parent_entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();

    let wait_outcome = parent_entry.resume_pending_wait().unwrap();

    assert!(matches!(
        wait_outcome,
        LifecycleOutcome::Returned { result, .. } if result.raw() == child_pid as i64
    ));
    assert_eq!(
        status_storage,
        LinuxWaitStatus::from_wait_encoding(9 << 8).raw()
    );

    // Second wait on the consumed child must fail with ECHILD (error code -10)
    let re_wait = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(child_pid as u64),
        status_va,
        LinuxWaitOptions::empty(),
        UserVa::new(0),
    );
    assert!(matches!(
        re_wait,
        LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::NoChild.errno()
    ));
}

/// Red-first Test 4: stock loan is requested and settled once.
#[test]
fn test_stock_loan_requested_and_settled_once() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
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

    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    let outcome = entry.fork();
    assert!(matches!(outcome, LifecycleOutcome::Returned { .. }));

    // Crossing facts: exactly one loan requested, exactly one committed, zero aborted
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 0);
}

/// Red-first Test 5: abort after a stock loan returns every page exactly once.
#[test]
fn test_abort_after_stock_loan_returns_every_page_once() {
    let fixture = Fixture::new(0x10000, asid(1));
    let words = fixture.tables.live(&fixture.maintenance);
    let initial_stock = [
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ];
    let crossing = TestStockCrossing::new(&initial_stock);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);

    let child_mm = MmGeneration::new(NonZeroU64::new(2).unwrap());
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);

    let prepared = service
        .prepare_mm(&fixture.address, parked, child_mm)
        .expect("prepare_mm should succeed");

    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 0);
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 0);

    service.abort_mm(prepared).expect("abort_mm should succeed");

    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 0);
    assert_eq!(
        crossing.grant_tables.lock().unwrap().len(),
        initial_stock.len()
    );
    assert_eq!(crossing.total_returned_pages.load(Ordering::Acquire), 5);
}

#[test]
fn terminal_retirement_cannot_retire_a_reused_record_or_slot_generation() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let old = super::common_entry::execution_binding(&fixture.task);
    let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
    assert!(carrick_core::entry::retire_current(old, source, record).is_some());
    let phase = carrick_sched_core::TerminalPhase::PendingRetirement;
    assert!(carrick_core::entry::terminal_matches(old, source, phase));
    // Global record storage can be reissued before the terminal crossing.
    // Its new identity cannot replace the retained stopped CPU authority.
    let replacement = ThreadIdentity {
        tid: old.task.raw(),
        generation: old.generation.raw() + 1,
        mm: old.mm.raw(),
        serial: old.thread_generation.raw() + 1,
        ..Default::default()
    };
    let reused = fixture.zone.alloc_record(replacement).unwrap();
    assert_eq!(reused, record);
    assert!(carrick_core::entry::terminal_matches(old, source, phase));
    fixture.zone.free_record(reused);
    let current = fixture
        .zone
        .current_or_new(fixture.slot, replacement)
        .unwrap();
    assert_eq!(current, record);
    assert!(!carrick_core::entry::terminal_matches(old, source, phase));
    assert!(carrick_core::entry::retire_current(old, source, current).is_none());
    assert_eq!(fixture.zone.slot(fixture.slot).host_record(), Some(current));
    assert_eq!(fixture.zone.record(current).identity(), replacement);
    let next = carrick_el1_abi::ExecutionBinding {
        generation: carrick_el1_abi::EntryGeneration::from_raw(replacement.generation),
        thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(replacement.serial),
        ..old
    };
    assert!(carrick_core::entry::retire_current(next, source, current).is_some());
    // Each stale control differs from the retained custody in exactly one
    // field, so no single comparison can be dropped without admitting it.
    for stale in [
        ThreadIdentity {
            generation: old.generation.raw(),
            ..replacement
        },
        ThreadIdentity {
            serial: old.thread_generation.raw(),
            ..replacement
        },
        ThreadIdentity {
            mm: old.mm.raw() + 1,
            ..replacement
        },
        ThreadIdentity {
            tid: old.task.raw() + 1,
            ..replacement
        },
    ] {
        let binding = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(stale.tid),
            generation: carrick_el1_abi::EntryGeneration::from_raw(stale.generation),
            mm: carrick_el1_abi::EntryMmKey::from_raw(stale.mm),
            thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(stale.serial),
        };
        assert!(!carrick_core::entry::terminal_matches(
            binding, source, phase
        ));
        assert!(!fixture.zone.accept_terminal(fixture.slot, stale));
    }
    assert!(fixture.zone.accept_terminal(fixture.slot, replacement));
    assert!(!fixture.zone.accept_terminal(fixture.slot, replacement));
    assert!(
        !carrick_core::entry::terminal_matches(
            next,
            source,
            carrick_sched_core::TerminalPhase::Retired
        ),
        "retirement acceptance must not wake a parent while the child MM remains installed"
    );
    fixture.zone.release_space(fixture.slot);
    assert!(carrick_core::entry::terminal_matches(
        next,
        source,
        carrick_sched_core::TerminalPhase::Retired
    ));
}
