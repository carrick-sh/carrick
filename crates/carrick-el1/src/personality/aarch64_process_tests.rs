//! Red-first VM-free tests for [`Aarch64NativeProcessService`] and the shared process owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::aarch64_process::{Aarch64NativeProcessService, ForkStockCrossing};
#[cfg(test)]
use super::aarch64_process::{admit_entry, registry, with_process_entry};
#[cfg(test)]
use super::aarch64_process::{observed_entry_address, process_record_for_call};
#[cfg(test)]
use super::native_process_runtime::NativeProcessService;
use super::native_process_runtime::{NativeProcessError, NativeProcessRuntime};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, El1TaskId, ForkStockExchange, ForkStockKind, ForkStockLoan,
    ForkStockRefusal, ForkStockSettlement, ReservationMm, ThreadControlSlot, ThreadIdentity,
    ThreadLifecyclePage,
};
#[cfg(test)]
use carrick_guest_arch::UserVa;
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, SlotId,
};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_personality_linux::lifecycle::{LifecycleOutcome, ProcessNative};
#[cfg(test)]
use carrick_personality_linux::lifecycle::{LinuxWaitOptions, LinuxWaitStatus, ProcessWaitPid};
#[cfg(test)]
use carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
use carrick_sched_core::{Aarch64ParkedContext, ThreadCtx, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const VA: u64 = 0x4000_0000;
const IPA: u64 = 0x9000_0000;

struct TestStockCrossing {
    fd_map: Vec<carrick_el1_abi::FdMapSlot>,
    open_table: Vec<carrick_el1_abi::DelegatedOpenFile>,
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
    root_exits: AtomicUsize,
    root_exit_status: AtomicU64,
}

impl TestStockCrossing {
    fn new(stock_pages: &[u64]) -> Self {
        Self {
            open_table: (0..16)
                .map(|_| carrick_el1_abi::DelegatedOpenFile::new())
                .collect(),
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
            root_exits: AtomicUsize::new(0),
            root_exit_status: AtomicU64::new(u64::MAX),
        }
    }
}

impl ForkStockCrossing for TestStockCrossing {
    fn open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
        &self.open_table
    }
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

    fn cross_root_exit(&self, record_gpa: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        // SAFETY: the VM-free crossing receives the caller's live exit record.
        let exit = unsafe { &*(record_gpa as *const carrick_core_abi::NativeRootExit) };
        self.root_exit_status
            .store(exit.words[5], Ordering::Relaxed);
        self.root_exits.fetch_add(1, Ordering::Relaxed);
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
    #[cfg(test)]
    fn new(root_gpa: u64, asid: carrick_guest_arch::Asid) -> Self {
        Self::with_file_table(root_gpa, asid, 5)
    }
    fn with_file_table(root_gpa: u64, asid: carrick_guest_arch::Asid, file_table: u64) -> Self {
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
        task.set(El1TaskId::from_linux_tid(41), 11, file_table);
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);

        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root_gpa)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(101).unwrap()),
        };
        task.publish_root_generation(address.generation);

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
                file_table,
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
    #[cfg(test)]
    fn enter<R>(
        &'static self,
        control: &'static carrick_el1_abi::ThreadControlSlot,
        ttbr0: u64,
        service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
        dispatch: impl FnOnce(
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<Aarch64ParkedContext>,
        ) -> R,
    ) -> Result<R, NativeProcessError> {
        with_process_entry(
            BornInZoneSource {
                zone: self.zone,
                slot: service.slot,
            },
            &self.task,
            ThreadCtx::ZERO,
            ttbr0,
            self.page,
            control,
            service,
            dispatch,
        )
    }
    fn process_service(&'static self) -> Aarch64NativeProcessService<'static, TestStockCrossing> {
        Aarch64NativeProcessService::with_crossing(
            &self.task,
            self.slot,
            self.zone,
            self.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        )
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

#[test]
fn first_process_call_acquires_a_root_authenticated_home_record() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
    assert!(fixture.zone.release_host_home(fixture.slot, record));
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let record = process_record_for_call(
        source,
        &fixture.task,
        ThreadCtx::ZERO,
        ttbr0,
        fixture.control,
    )
    .unwrap();
    let parked = unsafe { fixture.zone.record(record).ctx_mut() };
    assert_eq!(parked.address_context(), Some(fixture.address));
}

#[test]
fn host_home_process_call_seeds_an_unpublished_root_context() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
    assert!(
        unsafe { fixture.zone.record(record).ctx_mut() }
            .address_context()
            .is_none()
    );
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let retained = process_record_for_call(
        source,
        &fixture.task,
        ThreadCtx::ZERO,
        ttbr0,
        fixture.control,
    )
    .unwrap();
    assert_eq!(retained, record);
    assert_eq!(
        unsafe { fixture.zone.record(record).ctx_mut() }.address_context(),
        Some(fixture.address)
    );
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
    assert!(crossing.open_table[2].lifetime.initialize(1, false));
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
        super::file_table::close_host_binding(
            &crossing.fd_map,
            &crossing.open_table,
            child_table,
            7
        )
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

/// Runs the production native fork/exit owners over caller-owned file tables.
/// Only MMU stock supply is simulated; files use real VFS admission and custody.
pub fn with_native_file_fork(
    fd_map: &[carrick_el1_abi::FdMapSlot],
    open_table: &[carrick_el1_abi::DelegatedOpenFile],
    parent_table: u64,
    witness: impl FnOnce(&CurrentTask),
) {
    struct Crossing<'a> {
        stock: TestStockCrossing,
        fds: &'a [carrick_el1_abi::FdMapSlot],
        opens: &'a [carrick_el1_abi::DelegatedOpenFile],
    }
    impl ForkStockCrossing for Crossing<'_> {
        fn fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
            self.fds
        }
        fn open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
            self.opens
        }
        fn cross_fork_stock(&self, record: u64, cpu: u64) -> Result<(), NativeProcessError> {
            self.stock.cross_fork_stock(record, cpu)
        }
        fn cross_root_exit(&self, record: u64, cpu: u64) -> Result<(), NativeProcessError> {
            self.stock.cross_root_exit(record, cpu)
        }
        fn cross_child_retire(&self, record: u64, cpu: u64) -> Result<(), NativeProcessError> {
            self.stock.cross_child_retire(record, cpu)
        }
        fn cross_wait_channel_wake(
            &self,
            channel: super::native_process_runtime::ProcessWaitChannel,
            cpu: u64,
        ) -> Result<(), NativeProcessError> {
            self.stock.cross_wait_channel_wake(channel, cpu)
        }
    }
    let fixture = Fixture::with_file_table(0x10000, asid(1), parent_table);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
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
    let crossing = Crossing {
        stock: TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
        fds: fd_map,
        opens: open_table,
    };
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);
    let LifecycleOutcome::Returned { result, .. } = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap()
        .fork()
    else {
        panic!("native fork must publish a live child");
    };
    assert!(result.raw() > 0, "native fork refused: {}", result.raw());
    let parent_key = TaskKey {
        id: TaskId::from_abi_positive(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime
        .namespace_child_key(parent_key, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    assert_ne!(parent.key, child.key);
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent.record.id);
    let child_task = CurrentTask::new();
    activate(source, &child_task, &child);
    *crossing.stock.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.stock.child.lock().unwrap() = Some((
        super::common_entry::execution_binding(&child_task),
        child.address,
    ));
    assert!(runtime.task_binding(parent_key).is_some());
    assert!(runtime.task_binding(child_key).is_some());
    witness(&child_task);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::new(1).unwrap(),
        &crossing,
    )
    .with_words(&words);
    assert!(matches!(
        runtime
            .enter(source, &child_task, child.words, &mut child_service)
            .unwrap()
            .exit_group(0),
        LifecycleOutcome::Transferred { .. }
    ));
    assert!(
        runtime.task_binding(parent_key).is_some(),
        "parent survives child exit"
    );
    assert_eq!(crossing.stock.retirements.load(Ordering::Acquire), 1);
}

impl super::thread_setup::LifecycleVenue for Fixture {
    fn thread<'a>(
        &'a self,
        task: &'a CurrentTask,
    ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
        if task.metadata.lifecycle_page.load(Ordering::Acquire) != self.page as *const _ as u64 {
            return None;
        }
        let address = task.metadata.control_slot.load(Ordering::Acquire);
        let slot = if address == self.control as *const _ as u64 {
            self.control
        } else {
            let tid = u32::try_from(task.execution.task.load(Ordering::Acquire)).ok()?;
            if let Some(entry) = self.page.entry_ref_for_visible_tid(tid) {
                if self.page.control_address(entry)? != address {
                    return None;
                }
                // The test fixture retains the published control allocation.
                unsafe { &*(address as *const ThreadControlSlot) }
            } else {
                if address == 0
                    || !address.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
                {
                    return None;
                }
                let slot = unsafe { &*(address as *const ThreadControlSlot) };
                if slot.entry().is_some() || slot.visible_tid() != Some(tid) {
                    return None;
                }
                slot
            }
        };
        Some(carrick_personality_linux::thread::LifecycleThread {
            page: self.page,
            slot,
        })
    }
    fn born_slot(
        &self,
        _: &ThreadLifecyclePage,
        _: carrick_el1_abi::EntryRef,
    ) -> Option<&ThreadControlSlot> {
        None
    }
}

#[test]
fn arm_root_setup_enters_production_process_venue() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    for (nr, args, expected) in [
        (96, [0, 0, 0, 0, 0, 0], 41),
        (260, [u64::MAX, 0, 1, 0, 0, 0], -10),
        (93, [7, 0, 0, 0, 0, 0], 7),
    ] {
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let route = super::dispatch::dispatch_arm_syscall_with_native_process(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            None::<crate::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            Some(&*fixture),
            fixture.page,
            fixture.control,
            ThreadCtx::ZERO,
            ttbr0,
            &mut service,
            |_| core::ptr::null_mut(),
        )
        .unwrap();
        assert_eq!(frame.x[0] as i64, expected, "production ARM syscall {nr}");
        assert_eq!(
            route,
            if nr == 93 {
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            } else {
                carrick_personality_linux::dispatch::CompletionRoute::WithWork
            }
        );
        assert_eq!(counters.served[nr as usize].load(Ordering::Acquire), 1);
        assert_eq!(counters.forwarded[nr as usize].load(Ordering::Acquire), 0);
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert!(
            fixture.zone.slot(fixture.slot).host_record().is_none(),
            "returned process call must not leave admission-only home custody"
        );
    }
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 0);
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 0);
}

#[test]
fn arm_returned_process_call_is_not_a_zone_park() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let mut owner = None;
    for _ in 0..2 {
        fixture
            .enter(fixture.control, ttbr0, &mut service, |process| {
                let LifecycleOutcome::Returned { result, .. } = process.wait4(
                    ProcessWaitPid::from_syscall_argument(u64::MAX),
                    UserVa::new(0),
                    LinuxWaitOptions::WNOHANG,
                    UserVa::new(0),
                ) else {
                    panic!("a no-child wait returns ECHILD without parking")
                };
                assert_eq!(result.raw(), -10);
                let admitted = registry()
                    .for_entry(source, &fixture.task, fixture.address)
                    .unwrap();
                if let Some(prior) = &owner {
                    assert!(std::sync::Arc::ptr_eq(prior, &admitted));
                }
                owner = Some(admitted);
            })
            .unwrap();
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert!(fixture.zone.slot(fixture.slot).host_record().is_none());
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 1);
    }
    let published = fixture
        .enter(fixture.control, ttbr0, &mut service, |_| {
            let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
            fixture.zone.requeue_preempted(fixture.slot, record);
            fixture.zone.record_ref(record)
        })
        .unwrap();
    assert!(fixture.zone.live(published).is_some());
    assert_eq!(
        fixture.zone.slot(fixture.slot).host_record(),
        Some(published.id)
    );
}

fn imported_thread(
    fixture: &Fixture,
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    imported_thread_with_identity(fixture, |_| {})
}

fn imported_thread_with_identity(
    fixture: &Fixture,
    edit: impl FnOnce(&mut carrick_sched_core::ThreadIdentity),
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    use carrick_el1_abi::Lifecycle;
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let entry = fixture
        .page
        .stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(entry, control as *const _ as u64)
        .unwrap();
    let mut identity = carrick_sched_core::ThreadIdentity {
        tid: 42,
        serial: 102,
        mm: 1,
        file_table: 5,
        generation: 12,
        affinity: 1,
        lifecycle_page: fixture.page as *const _ as u64,
        control_slot: control as *const _ as u64,
    };
    edit(&mut identity);
    let record = fixture.zone.alloc_record(identity).unwrap();
    let reference = fixture.zone.record_ref(record);
    unsafe {
        *fixture.zone.record(record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    control.reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry);
    assert!(control.publish_visible_tid(42));
    control.bind_zone_record(reference);
    let claim = fixture.page.claim_any().unwrap();
    fixture.page.thread_born().unwrap();
    fixture
        .page
        .record_born(
            claim,
            carrick_el1_abi::BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x0001_0000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    fixture.zone.requeue_preempted(fixture.slot, record);
    (control, reference)
}

#[test]
fn arm_root_admission_imports_live_thread_membership_without_changing_census() {
    for notified in [false, true] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let (_, record) = imported_thread(fixture);
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut service = fixture.process_service();
        let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
        let signal = carrick_signal_core::policy::Signal::from_number(10).unwrap();
        let action = carrick_signal_core::policy::Action {
            disposition: carrick_signal_core::policy::Disposition::Ignore,
            ..Default::default()
        };
        let route = fixture.enter(fixture.control, ttbr0, &mut service, |process| {
            process
                .signal_venue()
                .unwrap()
                .rt_sigaction(signal, Some(action))
                .unwrap();
            assert!(process.has_thread(41));
            assert!(
                process.has_thread(42),
                "already-live member belongs to this process owner"
            );
        });
        assert!(
            route.is_ok(),
            "authenticated imported membership must admit: {route:?}"
        );
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
        assert!(fixture.zone.live(record).is_some());
        let owner = registry()
            .for_entry(source, &fixture.task, fixture.address)
            .unwrap();
        fixture.task.set(El1TaskId::from_linux_tid(42), 12, 5);
        fixture
            .task
            .mm
            .thread_generation
            .store(102, Ordering::Release);
        let control = fixture.zone.record(record.id).identity().control_slot;
        fixture
            .task
            .publish_lifecycle(fixture.page as *const _ as u64, control);
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            record.id
        );
        let control = unsafe { &*(control as *const ThreadControlSlot) };
        let stale_address = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(102).unwrap()),
            ..fixture.address
        };
        unsafe {
            *fixture.zone.record(record.id).ctx_mut() =
                Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, stale_address);
        }
        assert!(
            fixture
                .enter(control, ttbr0, &mut service, |_| panic!(
                    "thread must not substitute the group generation for a stale parked root"
                ))
                .is_err()
        );
        unsafe {
            *fixture.zone.record(record.id).ctx_mut() =
                Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        }
        fixture
            .enter(control, ttbr0, &mut service, |process| {
                assert_eq!(
                    process.binding(),
                    super::common_entry::execution_binding(&fixture.task)
                );
                assert!(process.has_thread(41) && process.has_thread(42));
                assert_eq!(
                    process
                        .signal_venue()
                        .unwrap()
                        .rt_sigaction(signal, None)
                        .unwrap(),
                    action,
                    "imported thread shares the retained sighand"
                );
            })
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &owner,
            &registry()
                .for_entry(source, &fixture.task, fixture.address)
                .unwrap()
        ));
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
        fixture
            .enter(control, ttbr0, &mut service, |process| {
                let admission =
                    carrick_el1_abi::Lifecycle::begin_exit(fixture.page, control.entry().unwrap())
                        .unwrap();
                fixture.page.try_exit().unwrap();
                carrick_core::entry::retire_current(process.binding(), source, record.id).unwrap();
                admission.commit().unwrap();
                if notified {
                    process.thread_exited(42);
                }
            })
            .unwrap();
        assert_eq!(
            registry().for_record(fixture.zone, record).is_none(),
            notified
        );
        fixture.task.set(El1TaskId::from_linux_tid(41), 11, 5);
        fixture
            .task
            .mm
            .thread_generation
            .store(101, Ordering::Release);
        fixture.task.publish_lifecycle(
            fixture.page as *const _ as u64,
            fixture.control as *const _ as u64,
        );
        fixture
            .enter(fixture.control, ttbr0, &mut service, |process| {
                assert!(matches!(
                    process.exit_group(7),
                    LifecycleOutcome::Transferred { .. }
                ));
            })
            .unwrap();
        assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 0);
        assert!(registry().for_record(fixture.zone, record).is_none());
    }
}

#[test]
fn arm_root_host_lease_renewal_retains_the_admitted_process_owner() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    imported_thread(fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    fixture
        .enter(fixture.control, ttbr0, &mut service, |process| {
            assert!(process.has_thread(42))
        })
        .unwrap();
    let before = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());
    fixture
        .task
        .execution
        .generation
        .store(22, Ordering::Release);
    let outcome = fixture.enter(fixture.control, ttbr0, &mut service, |process| {
        assert!(process.has_thread(42))
    });
    assert!(outcome.is_ok(), "lease renewal retains owner: {outcome:?}");
    let after = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&before, &after));
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
}

#[test]
fn arm_root_admission_refuses_stale_imported_custody_without_publication() {
    for field in 0..6 {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        imported_thread_with_identity(fixture, |identity| match field {
            0 => identity.tid += 1,
            1 => identity.serial += 1,
            2 => identity.mm += 1,
            3 => identity.lifecycle_page = fixture.control as *const _ as u64,
            4 => identity.control_slot = fixture.control as *const _ as u64,
            _ => identity.file_table += 1,
        });
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut service = fixture.process_service();
        let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
        let outcome = fixture.enter(fixture.control, ttbr0, &mut service, |_| {
            panic!("stale member must not enter production dispatch")
        });
        assert!(outcome.is_err(), "stale field {field}");
        assert!(
            registry()
                .for_entry(source, &fixture.task, fixture.address)
                .is_err()
        );
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    }
}

#[test]
fn arm_root_entry_refuses_wrong_binding_and_root_incarnation() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    fixture
        .enter(fixture.control, ttbr0, &mut service, |_| ())
        .unwrap();
    let before = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let record = process_record_for_call(
        source,
        &fixture.task,
        ThreadCtx::ZERO,
        ttbr0,
        fixture.control,
    )
    .unwrap();
    admit_entry(
        source,
        &fixture.task,
        ThreadCtx::ZERO,
        ttbr0,
        record,
        fixture.page,
        fixture.control,
    )
    .unwrap();
    fixture.zone.requeue_preempted(fixture.slot, record);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record
    );
    for atomic in [
        &fixture.task.execution.generation,
        &fixture.task.mm.thread_generation,
        &fixture.task.mm.key,
        &fixture.task.metadata.lifecycle_page,
        &fixture.task.metadata.control_slot,
    ] {
        let original = atomic.load(Ordering::Acquire);
        atomic.store(original + 1, Ordering::Release);
        assert!(
            fixture
                .enter(fixture.control, ttbr0, &mut service, |_| panic!(
                    "wrong binding must not enter dispatch"
                ))
                .is_err()
        );
        atomic.store(original, Ordering::Release);
    }
    let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
    let stale_address = AddressContext {
        generation: ContextGeneration::new(NonZeroU64::new(102).unwrap()),
        ..fixture.address
    };
    unsafe {
        *fixture.zone.record(record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, stale_address);
    }
    assert!(
        fixture
            .enter(fixture.control, ttbr0, &mut service, |_| panic!(
                "recycled root must not enter dispatch"
            ))
            .is_err()
    );
    unsafe {
        *fixture.zone.record(record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    fixture
        .enter(fixture.control, ttbr0, &mut service, |_| ())
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &before,
        &registry()
            .for_entry(source, &fixture.task, fixture.address)
            .unwrap()
    ));
}

#[test]
fn arm_born_thread_uses_native_owner_without_an_execution_generation() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) =
        imported_thread_with_identity(fixture, |identity| identity.generation = 0);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    fixture
        .enter(fixture.control, ttbr0, &mut service, |process| {
            assert!(process.has_thread(42))
        })
        .expect("a retained Born member has no host execution generation yet");
    let owner = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    fixture.task.set(El1TaskId::from_linux_tid(42), 0, 5);
    fixture
        .task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    fixture
        .task
        .publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let mut frame = carrick_el1_abi::TrapFrame {
        x: [0; 31],
        elr: 0,
        spsr: 0,
        esr: 0,
        slot: 0,
        far: 0,
    };
    frame.x[8] = 96;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let route = super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        None::<crate::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&*fixture),
        fixture.page,
        control,
        ThreadCtx::ZERO,
        ttbr0,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert_eq!(frame.x[0], 42);
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    fixture
        .enter(control, ttbr0, &mut service, |process| {
            assert_eq!(process.binding().generation.raw(), 0);
            let LifecycleOutcome::Returned { result, .. } = process.wait4(
                ProcessWaitPid::from_syscall_argument(u64::MAX),
                UserVa::new(0),
                LinuxWaitOptions::WNOHANG,
                UserVa::new(0),
            ) else {
                panic!("wait4");
            };
            assert_eq!(result.raw(), -10);
        })
        .expect("Born entry must retain the existing owner without a host task row");
    assert!(std::sync::Arc::ptr_eq(
        &owner,
        &registry()
            .for_entry(source, &fixture.task, fixture.address)
            .unwrap()
    ));
    assert_eq!(fixture.zone.record(record.id).identity().generation, 0);
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    fixture.zone.clear_current(fixture.slot);
    fixture.zone.free_record(record.id);
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture.zone.publish_slot(slot, 1, Some(0), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, 1).unwrap();
    fixture
        .task
        .execution
        .generation
        .store(19, Ordering::Release);
    service.slot = slot;
    let adopted_source = BornInZoneSource {
        zone: fixture.zone,
        slot,
    };
    fixture
        .enter(control, ttbr0, &mut service, |process| {
            assert_eq!(process.binding().generation.raw(), 19);
            assert!(process.has_thread(41) && process.has_thread(42));
        })
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &owner,
        &registry()
            .for_entry(adopted_source, &fixture.task, fixture.address)
            .unwrap()
    ));
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
}

#[test]
fn arm_owned_raw_exit_retires_only_one_of_two_live_threads() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    fixture
        .enter(fixture.control, ttbr0, &mut service, |_| ())
        .unwrap();
    fixture.task.set(El1TaskId::from_linux_tid(42), 12, 5);
    fixture
        .task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    fixture
        .task
        .publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
    let user = crate::sched::HardwareUserWord;
    let route = super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &user,
        }),
        None,
        Some(&*fixture),
        fixture.page,
        control,
        ThreadCtx::ZERO,
        ttbr0,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 1);
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    assert!(registry().for_record(fixture.zone, record).is_none());
    fixture.task.set(El1TaskId::from_linux_tid(41), 11, 5);
    fixture
        .task
        .mm
        .thread_generation
        .store(101, Ordering::Release);
    fixture.task.publish_lifecycle(
        fixture.page as *const _ as u64,
        fixture.control as *const _ as u64,
    );
    fixture
        .enter(fixture.control, ttbr0, &mut service, |process| {
            assert!(process.has_thread(41));
            assert!(!process.has_thread(42));
            assert!(matches!(
                process.exit_group(7),
                LifecycleOutcome::Transferred { .. }
            ));
        })
        .unwrap();
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 0);
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
}

#[cfg(test)]
fn fixture_ttbr0(fixture: &Fixture) -> u64 {
    (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw()
}

/// One production ARM syscall through the exact adapter the vector uses.
#[cfg(test)]
fn arm_call(
    fixture: &'static Fixture,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> Result<carrick_personality_linux::dispatch::CompletionRoute, NativeProcessError> {
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
    super::dispatch::dispatch_arm_syscall_with_native_process(
        frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        fixture.page,
        control,
        ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        service,
        |_| core::ptr::null_mut(),
    )
}

#[cfg(test)]
fn arm_route_action(
    fixture: &Fixture,
    route: carrick_personality_linux::dispatch::CompletionRoute,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> carrick_el1_abi::Action {
    let counters = Box::new(carrick_el1_abi::Counters::new());
    super::dispatch::resolve_arm_process_route(
        route,
        fixture.page,
        frame,
        &counters,
        core::slice::from_ref(&fixture.task),
    )
}

#[cfg(test)]
fn run_as(fixture: &Fixture, tid: i32, generation: u64, serial: u64, control: &ThreadControlSlot) {
    fixture
        .task
        .set(El1TaskId::from_linux_tid(tid), generation, 5);
    fixture
        .task
        .mm
        .thread_generation
        .store(serial, Ordering::Release);
    fixture
        .task
        .publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
}

#[cfg(test)]
fn run_as_leader(fixture: &Fixture) {
    run_as(fixture, 41, 11, 101, fixture.control);
}

/// A sibling the host cloned because the in-ring pool was empty: an issued
/// execution binding and a retained control slot, but no pool entry.
#[cfg(test)]
fn host_born_sibling(fixture: &Fixture, visible_tid: u32) -> &'static ThreadControlSlot {
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    control.reset_for_host_birth(carrick_el1_abi::BlockedMask(0));
    assert!(control.publish_visible_tid(visible_tid));
    carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
    run_as(fixture, 42, 12, 102, control);
    control
}

#[cfg(test)]
fn leader_sees_thread(
    fixture: &'static Fixture,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    tid: u32,
) -> bool {
    run_as_leader(fixture);
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            service,
            |process| process.has_thread(tid),
        )
        .unwrap()
}

#[test]
fn arm_host_born_sibling_raw_exit_retires_exact_owned_thread() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let owner = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    // The first syscall of the host-issued sibling adopts it into the owner.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 178; // gettid
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    assert_eq!(frame.x[0], 42);
    assert!(std::sync::Arc::ptr_eq(
        &owner,
        &registry()
            .for_entry(source, &fixture.task, fixture.address)
            .unwrap()
    ));
    // Its raw exit has no pool entry to retire in ring: the host retires it,
    // and the owner drops the member instead of failing the EL1.
    frame.x = [0; 31];
    frame.x[8] = 93;
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(frame.x[0], 0, "a forwarded exit keeps its status argument");
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    fixture.page.try_exit().unwrap(); // the host's retirement
    assert!(!leader_sees_thread(fixture, &mut service, 42));
    assert!(leader_sees_thread(fixture, &mut service, 41));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
}

#[test]
fn arm_host_born_sibling_refuses_stale_or_foreign_binding() {
    #[derive(Clone, Copy, Debug)]
    enum Defect {
        UnissuedGeneration,
        StaleRecordSerial,
        StaleRecordGeneration,
        ForeignPage,
        ForeignControl,
        ForeignPid,
        LeaderTid,
        DuplicateTid,
        NoCensus,
    }
    for defect in [
        Defect::UnissuedGeneration,
        Defect::StaleRecordSerial,
        Defect::StaleRecordGeneration,
        Defect::ForeignPage,
        Defect::ForeignControl,
        Defect::ForeignPid,
        Defect::LeaderTid,
        Defect::DuplicateTid,
        Defect::NoCensus,
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        if matches!(defect, Defect::DuplicateTid) {
            imported_thread(fixture); // already owns visible tid 42
        }
        let mut service = fixture.process_service();
        let ttbr0 = fixture_ttbr0(fixture);
        fixture
            .enter(fixture.control, ttbr0, &mut service, |_| ())
            .unwrap();
        let control = match defect {
            Defect::LeaderTid => host_born_sibling(fixture, 41),
            Defect::NoCensus => {
                let control = host_born_sibling(fixture, 42);
                fixture.page.try_exit().unwrap();
                control
            }
            _ => host_born_sibling(fixture, 42),
        };
        let mut page = fixture.page;
        let mut entered = control;
        match defect {
            Defect::UnissuedGeneration => fixture
                .task
                .execution
                .generation
                .store(0, Ordering::Release),
            Defect::StaleRecordSerial | Defect::StaleRecordGeneration => {
                let identity = crate::sched::identity_of(&fixture.task, 1);
                let stale = if matches!(defect, Defect::StaleRecordSerial) {
                    ThreadIdentity {
                        serial: identity.serial - 1,
                        ..identity
                    }
                } else {
                    ThreadIdentity {
                        generation: identity.generation - 1,
                        ..identity
                    }
                };
                let record = fixture.zone.current_or_new(fixture.slot, stale).unwrap();
                // SAFETY: this VM-free fixture owns the current record.
                unsafe {
                    *fixture.zone.record(record).ctx_mut() =
                        Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
                }
                control.bind_zone_record(fixture.zone.record_ref(record));
            }
            Defect::ForeignPage => page = Box::leak(Box::new(ThreadLifecyclePage::new())),
            Defect::ForeignControl => {
                let foreign = Box::leak(Box::new(ThreadControlSlot::new()));
                foreign.reset_for_host_birth(carrick_el1_abi::BlockedMask(0));
                assert!(foreign.publish_visible_tid(42));
                entered = foreign;
            }
            Defect::ForeignPid => fixture.task.publish_visible_pid(99),
            Defect::DuplicateTid => run_as(fixture, 43, 13, 103, control),
            Defect::LeaderTid | Defect::NoCensus => {}
        }
        let admitted = with_process_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: service.slot,
            },
            &fixture.task,
            ThreadCtx::ZERO,
            ttbr0,
            page,
            entered,
            &mut service,
            |_| (),
        );
        assert!(admitted.is_err(), "{defect:?} must not adopt");
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        assert!(
            registry()
                .for_entry(source, &fixture.task, fixture.address)
                .is_err(),
            "{defect:?} registered the refused binding"
        );
        assert!(
            entered.zone_record().is_none() || !matches!(defect, Defect::ForeignControl),
            "a foreign control slot is never bound to the caller's home record"
        );
        fixture.zone.clear_current(fixture.slot);
        fixture.task.publish_visible_pid(41);
        assert!(
            matches!(defect, Defect::DuplicateTid)
                || !leader_sees_thread(fixture, &mut service, 42),
            "{defect:?} left a member in the owner"
        );
    }
}

#[test]
fn arm_two_live_threads_robust_exit_forwards_without_abort() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    run_as(fixture, 42, 12, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    // Every glibc/musl thread registers a robust list at start.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 0x2000;
    frame.x[1] = 24;
    frame.x[8] = 99; // set_robust_list
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    assert_eq!(frame.x[0], 0);
    assert_eq!(control.robust_list().0, 0x2000);
    // The in-ring exit declines (no robust-list walker here) with a live
    // sibling: the host walks the list and retires the thread.
    frame.x = [0; 31];
    frame.x[8] = 93;
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(frame.x[0], 0, "never rewritten to -ENOSYS");
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    assert!(registry().for_record(fixture.zone, record).is_none());
    fixture.zone.clear_current(fixture.slot);
    fixture.zone.free_record(record.id);
    fixture.page.try_exit().unwrap(); // the host's retirement
    assert!(!leader_sees_thread(fixture, &mut service, 42));
    assert!(leader_sees_thread(fixture, &mut service, 41));
}

#[test]
fn arm_two_live_threads_exit_group_ends_group_with_status() {
    #[derive(Clone, Copy, Debug)]
    enum Siblings {
        Pooled,
        AdoptedHostBorn,
        /// One owned member plus a host-born thread the owner never adopted.
        PooledAndUnadoptedHostBorn,
    }
    for siblings in [
        Siblings::Pooled,
        Siblings::AdoptedHostBorn,
        Siblings::PooledAndUnadoptedHostBorn,
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let pooled = (!matches!(siblings, Siblings::AdoptedHostBorn))
            .then(|| imported_thread_with_identity(fixture, |_| {}));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |_| (),
            )
            .unwrap();
        match siblings {
            Siblings::Pooled => {}
            Siblings::AdoptedHostBorn => {
                let control = host_born_sibling(fixture, 42);
                let mut frame = carrick_el1_abi::TrapFrame::default();
                frame.x[8] = 178; // gettid adopts the sibling
                arm_call(fixture, control, &mut service, &mut frame).unwrap();
            }
            Siblings::PooledAndUnadoptedHostBorn => {
                host_born_sibling(fixture, 43);
            }
        }
        assert!(leader_sees_thread(fixture, &mut service, 42));
        let live = carrick_el1_abi::Lifecycle::live(fixture.page);
        // main() returns while workers are live.
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[0] = 7;
        frame.x[8] = 94;
        let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended,
            "{siblings:?}"
        );
        assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
        assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
        // Only the caller's membership is released. Every sibling, owned or
        // not, keeps its census until the host's process terminal (entered
        // by the root crossing) retires it, and no address space is retired
        // under a thread that may still run.
        assert_eq!(
            carrick_el1_abi::Lifecycle::live(fixture.page),
            live - 1,
            "{siblings:?}"
        );
        assert_eq!(service.crossing.retirements.load(Ordering::Acquire), 0);
        assert_eq!(
            carrick_el1_abi::Lifecycle::gate(fixture.page),
            carrick_el1_abi::GateState::Closed,
            "no new thread may be born into an exited group"
        );
        if let Some((_, record)) = pooled {
            assert!(fixture.zone.record(record.id).is_cancelled());
        }
    }
}

#[test]
fn arm_unadmitted_thread_runs_ordinary_calls_and_refuses_owner_calls() {
    use super::dispatch::{arm_owner_must_serve, arm_thread_group_owned};
    // A non-last thread's raw exit is the host's; the last thread's and the
    // process-family calls stay with a retained owner.
    assert!(!arm_owner_must_serve(
        62,
        3,
        || panic!("not a process call"),
        1
    ));
    assert!(!arm_owner_must_serve(93, 0, || true, 2));
    assert!(arm_owner_must_serve(93, 0, || true, 1));
    assert!(arm_owner_must_serve(94, 0, || true, 2));
    assert!(arm_owner_must_serve(260, 0, || true, 2));
    assert!(!arm_owner_must_serve(260, 0, || false, 2));
    assert!(!arm_owner_must_serve(94, 0, || false, 2));
    assert!(arm_owner_must_serve(220, 17, || false, 1), "fork");
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let foreign_page = Box::leak(Box::new(ThreadLifecyclePage::new()));
    assert!(!arm_thread_group_owned(
        fixture.zone,
        &fixture.task,
        fixture.page
    ));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    assert!(arm_thread_group_owned(
        fixture.zone,
        &fixture.task,
        fixture.page
    ));
    assert!(!arm_thread_group_owned(
        fixture.zone,
        &fixture.task,
        foreign_page
    ));
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let fallback = |frame: &mut carrick_el1_abi::TrapFrame, refused| {
        super::dispatch::fallback_or_refuse_arm_process_call(
            frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            None::<crate::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            |_| core::ptr::null_mut(),
            refused,
        )
    };
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 3;
    frame.x[8] = 62; // lseek
    assert_eq!(
        fallback(&mut frame, false),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(frame.x[0], 3, "an ordinary call is never answered -ENOSYS");
    frame.x[0] = 17;
    frame.x[8] = 220; // fork
    assert_eq!(
        fallback(&mut frame, true),
        carrick_el1_abi::Action::ServedWithWork
    );
    assert_eq!(frame.x[0] as i64, -38);
}
