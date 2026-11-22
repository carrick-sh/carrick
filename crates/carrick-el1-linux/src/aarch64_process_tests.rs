//! Red-first VM-free tests for [`Aarch64NativeProcessService`] and the shared process owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
mod born_thread_entry_tests;
#[cfg(test)]
mod native_child_handoff_tests;
#[cfg(all(test, not(target_os = "macos")))]
mod native_exec_pipe_tests;
#[cfg(all(test, not(target_os = "macos")))]
mod native_exec_poll_tests;
#[cfg(test)]
mod native_fault_supply_tests;
#[cfg(test)]
mod native_host_owned_signal_resume_tests;
#[cfg(all(test, not(target_os = "macos")))]
mod native_ipc_wake_tests;
#[cfg(test)]
mod native_retirement_tests;
#[cfg(test)]
mod native_signal_resume_tests;
#[cfg(test)]
mod native_signal_work_return_tests;
#[cfg(all(test, not(target_os = "macos")))]
mod pipe_metadata_tests;

use super::aarch64_process::{Aarch64NativeProcessService, ForkStockCrossing};
#[cfg(test)]
use super::aarch64_process::{
    Mm, admit_entry, map_resume, observed_entry_address, process_record_for_call, registry,
    resume_selected, with_process_entry,
};
#[cfg(test)]
use super::native_process_runtime::{NativeContention, NativeFailure, NativeServiceQuarantine};
use super::native_process_runtime::{NativeProcessError, NativeProcessRuntime};
#[cfg(test)]
use super::native_process_runtime::{NativeProcessRegistry, NativeProcessService};
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
use carrick_personality_linux::lifecycle::{LifecycleOutcome, ProcessForkChildTid, ProcessNative};
#[cfg(test)]
use carrick_personality_linux::lifecycle::{
    LinuxWaitOptions, LinuxWaitStatus, ProcessWaitId, ProcessWaitPid,
};
#[cfg(test)]
use carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
#[cfg(test)]
use carrick_sched_core::RecordId;
use carrick_sched_core::process::{TaskKey, TaskSerial};
use carrick_sched_core::{Aarch64ParkedContext, ThreadCtx, ZoneTables};
use core::num::{NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(test)]
mod exit_group_hang_tests;

#[cfg(test)]
#[test]
fn arm_native_wake_cross_slot_reaches_reschedule_transport() {
    use carrick_sched_core::WakeEffects;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let other = SlotId::new(4);
    fixture.zone.drive(other, 2);
    fixture.zone.publish_slot(other, 1, Some(0), 1);
    fixture.zone.enter_guest(other);
    let target = 0x8000_0004;
    fixture.zone.slot(other).set_sgi_target(target);
    crate::sched::object_wait::clear_test_wake_trace();
    let mut service = fixture.process_service();
    let mut effects = WakeEffects::default();
    effects.request_reschedule(other);
    NativeProcessService::wake_effects(&mut service, effects);
    assert_eq!(
        crate::sched::object_wait::test_wake_trace(),
        [(other, target)]
    );
}

/// Scheduler CPU with the same owner checkpoint as the production ARM CPU.
#[cfg(test)]
struct ResumeCpu<'a, 'b, X: ForkStockCrossing> {
    inner: crate::sched::FakeCpu,
    runtime: &'a NativeProcessRuntime<'b, Mm, Aarch64ParkedContext>,
    registry: &'a NativeProcessRegistry<'b, Mm, Aarch64ParkedContext>,
    source: BornInZoneSource<'b, Aarch64ParkedContext>,
    task: &'b CurrentTask,
    service: &'a mut Aarch64NativeProcessService<'b, X>,
}

#[cfg(test)]
impl<X: ForkStockCrossing> crate::sched::ThreadCpu for ResumeCpu<'_, '_, X> {
    fn save(
        &mut self,
        frame: &carrick_el1_abi::TrapFrame,
        ctx: &mut Aarch64ParkedContext,
        exit: crate::sched::CpuExitCause,
    ) {
        self.inner.save(frame, ctx, exit);
    }
    fn load(&mut self, frame: &mut carrick_el1_abi::TrapFrame, ctx: &Aarch64ParkedContext) {
        self.inner.load(frame, ctx);
    }
    fn resume_lifecycle(
        &mut self,
        _: &ZoneTables<Aarch64ParkedContext>,
        _: &CurrentTask,
        _: SlotId,
        record: carrick_el1_abi::RecordId,
    ) -> crate::sched::ResumeAction {
        map_resume(
            resume_selected(
                self.runtime,
                self.registry,
                self.source,
                self.task,
                record,
                self.service,
            ),
            self.service,
            self.task,
            self.source.slot,
        )
    }
    fn set_translation(&mut self, a: u64, b: u64) {
        self.inner.set_translation(a, b);
    }
    fn live_ttbr0(&self) -> Option<u64> {
        self.inner.live_ttbr0()
    }
    fn invalidate_asid(&mut self, root: u64) {
        self.inner.invalidate_asid(root);
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn freq(&self) -> u64 {
        self.inner.freq()
    }
    fn set_timer(&mut self, deadline: Option<u64>) {
        self.inner.set_timer(deadline);
    }
    fn send_sgi(&mut self, route: u64) {
        self.inner.send_sgi(route);
    }
    fn ack_irq(&mut self) -> u32 {
        self.inner.ack_irq()
    }
    fn end_irq(&mut self, intid: u32) {
        self.inner.end_irq(intid);
    }
    fn wait_for_interrupt(&mut self) {
        self.inner.wait_for_interrupt();
    }
    fn spin(&mut self) {
        self.inner.spin();
    }
    fn own_sgi_target(&self) -> u64 {
        self.inner.own_sgi_target()
    }
}

const VA: u64 = 0x4000_0000;
const IPA: u64 = 0x9000_0000;

#[cfg(test)]
#[derive(Clone, Copy)]
enum CommitFault {
    None,
    Refusal,
    Crossing,
    MissingReply,
}

type ControlsArray = [ThreadControlSlot; carrick_el1_abi::THREAD_POOL_ENTRIES + 1];

fn metadata_lifecycle_allocation() -> (core::ptr::NonNull<u8>, usize, usize) {
    let page_bytes = core::mem::size_of::<ThreadLifecyclePage>().next_multiple_of(16384);
    let chunk_bytes = (page_bytes + core::mem::size_of::<ControlsArray>()).next_multiple_of(16384);
    // Hosts may ignore a hint this low (macOS 27), and an
    // unrelated host allocation can already occupy part of
    // the window. Scan from the start so dropped fixtures return capacity.
    // Take the next chunk an exact,
    // non-replacing allocation admits.
    /// Map `len` zeroed read-write bytes at exactly `addr`, or `None` when any
    /// part of the range is already mapped. Never replaces an existing mapping.
    fn map_exact_unreplaced(addr: u64, len: usize) -> Option<*mut libc::c_void> {
        #[cfg(target_os = "macos")]
        {
            let mut at = addr as libc::vm_address_t;
            // SAFETY: a fixed allocation in this task fails rather than
            // replacing anything already mapped.
            #[allow(deprecated)]
            let status = unsafe {
                libc::vm_allocate(libc::mach_task_self(), &mut at, len, libc::VM_FLAGS_FIXED)
            };
            (status == libc::KERN_SUCCESS).then_some(at as *mut libc::c_void)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: MAP_FIXED_NOREPLACE fails rather than replacing a mapping.
            let mapped = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            (mapped != libc::MAP_FAILED && mapped as u64 == addr).then_some(mapped)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
        {
            // A plain hint never replaces a mapping; keep it
            // only where the kernel placed it exactly.
            // SAFETY: a fresh anonymous mapping, unmapped
            // again when it landed elsewhere.
            let mapped = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return None;
            }
            if mapped as u64 != addr {
                // SAFETY: unmaps only the mapping made above.
                unsafe { libc::munmap(mapped, len) };
                return None;
            }
            Some(mapped)
        }
    }
    let mut offset = 0x100_0000;
    let mapped = loop {
        assert!(
            offset + chunk_bytes as u64 <= carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE,
            "no free metadata window chunk left"
        );
        let hint = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + offset;
        if let Some(mapped) = map_exact_unreplaced(hint, chunk_bytes) {
            break mapped;
        }
        offset += chunk_bytes as u64;
    };
    let base = mapped as u64;
    assert!(
        base.is_multiple_of(16384)
            && base >= carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
            && base + chunk_bytes as u64
                <= carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE,
        "metadata mmap landed outside EL1_DYNAMIC_METADATA_BASE window: {base:#x}"
    );
    (
        core::ptr::NonNull::new(mapped.cast::<u8>()).unwrap(),
        page_bytes,
        chunk_bytes,
    )
}

// Own the host mapping, even while the fixture lends static aliases to the runtime.
struct MetadataLifecycleAllocation {
    base: u64,
    bytes: usize,
}

impl Drop for MetadataLifecycleAllocation {
    fn drop(&mut self) {
        // SAFETY: this owner retains exactly the mapping allocated by the fixture.
        let result = unsafe { libc::munmap(self.base as *mut libc::c_void, self.bytes) };
        assert_eq!(result, 0, "fixture metadata unmap failed");
    }
}

// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_metadata_window_reuses_released_chunks() {
    let page_bytes = core::mem::size_of::<ThreadLifecyclePage>().next_multiple_of(16384);
    let chunk_bytes = (page_bytes + core::mem::size_of::<ControlsArray>()).next_multiple_of(16384);
    let population = carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE as usize / chunk_bytes + 1;
    for _ in 0..population {
        let (base, _, bytes) = metadata_lifecycle_allocation();
        let allocation = MetadataLifecycleAllocation {
            base: base.as_ptr() as u64,
            bytes,
        };
        drop(allocation);
    }
}

struct TestStockCrossing {
    #[cfg(test)]
    ipc: Option<(
        std::sync::Arc<carrick_kernel::el1_ipc::HostIpc>,
        &'static carrick_el1_abi::ipc_tables::IpcTableMap,
    )>,
    #[cfg(test)]
    physical: Option<std::sync::Mutex<native_retirement_tests::PhysicalStock>>,
    fd_map: Vec<carrick_el1_abi::FdMapSlot>,
    open_table: Vec<carrick_el1_abi::DelegatedOpenFile>,
    grant_tables: std::sync::Mutex<Vec<RootGpa>>,
    total_returned_pages: AtomicU64,
    loans_requested: AtomicUsize,
    settlements_reserved: AtomicUsize,
    settlements_committed: AtomicUsize,
    settlements_aborted: AtomicUsize,
    reserved_custody_rows: AtomicUsize,
    refuse_reserve: std::sync::Mutex<Option<ForkStockRefusal>>,
    /// Runs once inside the next fork's stock loan crossing: the forking
    /// caller still holds its birth reservation, as a real vCPU's synchronous
    /// crossing does while sibling vCPUs keep running.
    on_loan: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Runs once at the next fork's commit crossing, before the host
    /// authenticates the stopped lane: sibling vCPUs keep running between
    /// the guest's MM commit and its custody settlement.
    on_commit: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    commit_fault: std::sync::Mutex<CommitFault>,
    pending_loan: std::sync::Mutex<Option<ForkStockLoan>>,
    retirements: AtomicUsize,
    zone: std::sync::Mutex<Option<&'static ZoneTables<Aarch64ParkedContext>>>,
    child: std::sync::Mutex<Option<(carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>)>>,
    handbacks: AtomicUsize,
    root_exits: AtomicUsize,
    root_exit_status: AtomicU64,
    publish_child_affinity_aliases: bool,
    metadata_in_el1_window: bool,
    metadata_allocations: Arc<std::sync::Mutex<Vec<MetadataLifecycleAllocation>>>,
    exec_adopted: core::sync::atomic::AtomicBool,
    #[cfg(all(test, target_os = "linux"))]
    require_stack_commit: bool,
    /// The host-served root's live cwd, as the root fork seed crossing
    /// reads it, and how many seeds were served.
    root_cwd: std::sync::Mutex<Vec<u8>>,
    root_seeds: AtomicUsize,
    /// Refuse the seed, as the carrier does once the run's exec service
    /// retired.
    refuse_root_seed: core::sync::atomic::AtomicBool,
    /// The one capability the carrier's exec service directory holds, when
    /// a fixture models it: a seed naming any other resolves no service and
    /// is refused, as `service_root_fork_seed` refuses it.
    installed_exec_capability: Option<carrick_core_abi::service::ExecCapabilityId>,
}

#[cfg(all(test, not(target_os = "macos")))]
struct MetadataScope {
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    roots: &'static carrick_el1::memory::reservations::SharedReservations,
    allocations: Arc<std::sync::Mutex<Vec<MetadataLifecycleAllocation>>>,
}

#[cfg(all(test, not(target_os = "macos")))]
impl MetadataScope {
    fn new(fixture: &Fixture) -> Self {
        Self {
            zone: fixture.zone,
            roots: fixture.region.table(),
            allocations: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[cfg(all(test, not(target_os = "macos")))]
impl Drop for MetadataScope {
    fn drop(&mut self) {
        registry().unregister_zone_for_test(self.zone);
        let leftover = super::aarch64_process::drain_and_clear_retired_scope(self.zone, self.roots);
        if !std::thread::panicking() {
            assert_eq!(leftover, 0, "metadata scope has unretired spaces");
        }
    }
}

impl TestStockCrossing {
    fn has_physical(&self) -> bool {
        #[cfg(test)]
        {
            self.physical.is_some()
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn new(stock_pages: &[u64]) -> Self {
        Self {
            #[cfg(test)]
            ipc: None,
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
            #[cfg(test)]
            physical: None,
            total_returned_pages: AtomicU64::new(0),
            loans_requested: AtomicUsize::new(0),
            settlements_reserved: AtomicUsize::new(0),
            settlements_committed: AtomicUsize::new(0),
            settlements_aborted: AtomicUsize::new(0),
            reserved_custody_rows: AtomicUsize::new(0),
            refuse_reserve: std::sync::Mutex::new(None),
            on_loan: std::sync::Mutex::new(None),
            on_commit: std::sync::Mutex::new(None),
            #[cfg(test)]
            commit_fault: std::sync::Mutex::new(CommitFault::None),
            pending_loan: std::sync::Mutex::new(None),
            retirements: AtomicUsize::new(0),
            zone: std::sync::Mutex::new(None),
            child: std::sync::Mutex::new(None),
            handbacks: AtomicUsize::new(0),
            root_exits: AtomicUsize::new(0),
            root_exit_status: AtomicU64::new(u64::MAX),
            publish_child_affinity_aliases: true,
            metadata_in_el1_window: false,
            metadata_allocations: Arc::new(std::sync::Mutex::new(Vec::new())),
            exec_adopted: core::sync::atomic::AtomicBool::new(false),
            #[cfg(all(test, target_os = "linux"))]
            require_stack_commit: false,
            root_cwd: std::sync::Mutex::new(b"/".to_vec()),
            root_seeds: AtomicUsize::new(0),
            refuse_root_seed: core::sync::atomic::AtomicBool::new(false),
            installed_exec_capability: None,
        }
    }
}

impl ForkStockCrossing for TestStockCrossing {
    fn cross_root_fork_seed(&self, record_va: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        // SAFETY: the synchronous crossing retains the ring's boxed record.
        let record = unsafe { &mut *(record_va as *mut carrick_core_abi::service::RootForkSeed) };
        if self.refuse_root_seed.load(Ordering::Acquire)
            || self
                .installed_exec_capability
                .is_some_and(|installed| record.requested() != Some(installed))
        {
            return Err(NativeProcessError::Stale);
        }
        let cwd = self.root_cwd.lock().unwrap().clone();
        if !record.serve(&cwd, None) {
            return Err(NativeProcessError::Stale);
        }
        self.root_seeds.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    #[cfg(test)]
    fn ipc_binding(
        &self,
    ) -> Option<(
        carrick_el1_abi::ipc::IpcRegion<'_>,
        &carrick_el1_abi::ipc_tables::IpcTableMap,
    )> {
        self.ipc.as_ref().map(|(owner, map)| (owner.region(), *map))
    }

    fn cross_child_reclaim(&self, mm: ReservationMm, cpu: u64) -> Result<(), NativeProcessError> {
        let zone = self.zone.lock().unwrap().unwrap();
        let (binding, _) = self.child.lock().unwrap().unwrap();
        let slot = SlotId::from_index(cpu as usize).unwrap();
        assert_eq!(binding.mm.raw(), mm.raw());
        assert!(carrick_core::entry::terminal_matches(
            binding,
            BornInZoneSource { zone, slot },
            carrick_sched_core::TerminalPhase::Retired
        ));
        #[cfg(test)]
        if let Some(physical) = &self.physical {
            physical.lock().unwrap().reclaim(zone);
        }
        Ok(())
    }

    fn cross_exec_adopt(&self, record_gpa: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        // SAFETY: the synchronous fixture owns this aligned stack record.
        let request = unsafe { &mut *(record_gpa as *mut carrick_el1_abi::NativeExecAdoption) };
        let request = request.claim().ok_or(NativeProcessError::Stale)?;
        if self.exec_adopted.swap(true, Ordering::AcqRel) {
            request.refuse();
            return Err(NativeProcessError::Stale);
        }
        request.accept();
        Ok(())
    }

    fn cross_exec_cancel(&self, record_gpa: u64, _cpu: u64) -> Result<(), NativeProcessError> {
        // SAFETY: the synchronous fixture owns this aligned stack record.
        let request = unsafe { &mut *(record_gpa as *mut carrick_el1_abi::NativeExecCancellation) };
        request
            .request()
            .and_then(|_| request.accept().then_some(()))
            .ok_or(NativeProcessError::Stale)
    }

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
        #[cfg(test)]
        if let Some(physical) = &self.physical {
            physical.lock().unwrap().retire(
                zone,
                carrick_hal::fork_stock::GrantExecution::new(
                    carrick_guest_arch::CpuId::new(cpu as u32),
                    binding,
                    context,
                ),
                record,
            );
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
        if !self.has_physical() {
            assert!(record.accept());
        }
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
        #[cfg(test)]
        if let Some(physical) = &self.physical {
            assert!(
                physical
                    .lock()
                    .unwrap()
                    .owner
                    .child_root(ReservationMm::new(binding.mm.raw()).unwrap())
                    .is_none(),
                "terminal wake must authenticate without the reclaimed root"
            );
        }
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
                    .finish(&carrick_sched_core::ShortLockSpin, &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    })
                    .is_some()
            );
        }
        self.handbacks.fetch_add(count as usize, Ordering::AcqRel);
        Ok(())
    }

    fn fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        &self.fd_map
    }

    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(not(test))]
        let _ = cpu;
        let tag = unsafe { *(record_gpa as *const u64) };
        match ForkStockKind::decode(tag) {
            Some(ForkStockKind::Loan) => {
                let on_loan = self.on_loan.lock().unwrap().take();
                if let Some(hook) = on_loan {
                    hook();
                }
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
                #[cfg(test)]
                if let Some(physical) = &self.physical {
                    let mut physical = physical.lock().unwrap();
                    let execution = physical.execution(cpu).inspect_err(|_| {
                        exchange.refuse(ForkStockRefusal::Stale);
                    })?;
                    let loan = physical
                        .loan(execution, exchange, child_slice, parent_slice)
                        .map_err(|_| NativeProcessError::Stale)?;
                    *self.pending_loan.lock().unwrap() = Some(loan);
                    return Ok(());
                }
                type ControlsArray = [ThreadControlSlot; carrick_el1_abi::THREAD_POOL_ENTRIES + 1];
                let (page_ptr, controls): (*mut ThreadLifecyclePage, &'static mut ControlsArray) =
                    if self.metadata_in_el1_window {
                        let (mapped, page_bytes, bytes) = metadata_lifecycle_allocation();
                        self.metadata_allocations.lock().unwrap().push(
                            MetadataLifecycleAllocation {
                                base: mapped.as_ptr() as u64,
                                bytes,
                            },
                        );
                        let mapped = mapped.as_ptr();
                        unsafe {
                            let page_ptr = mapped.cast::<ThreadLifecyclePage>();
                            page_ptr.write(ThreadLifecyclePage::new());
                            let controls_ptr =
                                mapped.cast::<u8>().add(page_bytes).cast::<ControlsArray>();
                            controls_ptr.write(core::array::from_fn(|_| ThreadControlSlot::new()));
                            (page_ptr, &mut *controls_ptr)
                        }
                    } else {
                        let layout = std::alloc::Layout::from_size_align(
                            core::mem::size_of::<ThreadLifecyclePage>(),
                            16384,
                        )
                        .unwrap();
                        let page_ptr = unsafe {
                            let ptr =
                                std::alloc::alloc_zeroed(layout).cast::<ThreadLifecyclePage>();
                            (*ptr) = ThreadLifecyclePage::new();
                            ptr
                        };
                        let controls =
                            Box::leak(Box::new(core::array::from_fn(|_| ThreadControlSlot::new())));
                        (page_ptr, controls)
                    };
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
                if self.publish_child_affinity_aliases {
                    for control in controls.iter() {
                        // SAFETY: these leaked fixture controls share one host/guest alias.
                        unsafe {
                            control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
                                core::ptr::from_ref(control).expose_provenance() as u64,
                            ));
                        }
                    }
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
            Some(ForkStockKind::Reserve) => {
                self.settlements_reserved.fetch_add(1, Ordering::AcqRel);
                let settlement = unsafe { &mut *(record_gpa as *mut ForkStockSettlement) };
                if let Some(refusal) = self.refuse_reserve.lock().unwrap().take() {
                    settlement.refuse(refusal);
                    return Err(NativeProcessError::Fault);
                }
                let Some(loan) = *self.pending_loan.lock().unwrap() else {
                    return Err(NativeProcessError::Invalid);
                };
                let Some((_completion, _address, count)) = settlement.reservation(loan) else {
                    return Err(NativeProcessError::Invalid);
                };
                #[cfg(test)]
                if let Some(physical) = &self.physical {
                    let mut physical = physical.lock().unwrap();
                    let execution = physical.execution(cpu).inspect_err(|_| {
                        settlement.refuse(ForkStockRefusal::Stale);
                    })?;
                    physical
                        .reserve(execution, settlement)
                        .map_err(|_| NativeProcessError::Stale)?;
                }
                if !self.has_physical() && !settlement.accept(loan) {
                    return Err(NativeProcessError::Invalid);
                }
                self.reserved_custody_rows
                    .store(count as usize, Ordering::Release);
                Ok(())
            }
            Some(ForkStockKind::Commit) => {
                #[cfg(all(test, target_os = "linux"))]
                if self.require_stack_commit {
                    native_child_handoff_tests::assert_current_stack_commit(record_gpa);
                }
                self.settlements_committed.fetch_add(1, Ordering::AcqRel);
                let on_commit = self.on_commit.lock().unwrap().take();
                if let Some(hook) = on_commit {
                    hook();
                }
                let settlement = unsafe { &mut *(record_gpa as *mut ForkStockSettlement) };
                #[cfg(test)]
                match *self.commit_fault.lock().unwrap() {
                    CommitFault::Refusal => {
                        settlement.refuse(ForkStockRefusal::Invalid);
                        return Ok(());
                    }
                    CommitFault::Crossing => return Err(NativeProcessError::Fault),
                    CommitFault::MissingReply => return Ok(()),
                    CommitFault::None => {}
                }
                let pending = *self.pending_loan.lock().unwrap();
                if let Some(loan) = pending {
                    #[cfg(test)]
                    if let Some(physical) = &self.physical {
                        let mut physical = physical.lock().unwrap();
                        let execution = physical.execution(cpu).inspect_err(|_| {
                            settlement.refuse(ForkStockRefusal::Stale);
                        })?;
                        physical
                            .commit(execution, settlement)
                            .map_err(|_| NativeProcessError::Stale)?;
                    }
                    if !self.has_physical() && !settlement.accept(loan) {
                        return Err(NativeProcessError::Invalid);
                    }
                    self.pending_loan.lock().unwrap().take();
                }
                Ok(())
            }
            Some(ForkStockKind::Abort) => {
                self.settlements_aborted.fetch_add(1, Ordering::AcqRel);
                self.reserved_custody_rows.store(0, Ordering::Release);
                let settlement = unsafe { &mut *(record_gpa as *mut ForkStockSettlement) };
                #[cfg(test)]
                if let Some(physical) = &self.physical {
                    let mut physical = physical.lock().unwrap();
                    let execution = physical.execution(cpu).inspect_err(|_| {
                        settlement.refuse(ForkStockRefusal::Stale);
                    })?;
                    physical
                        .settle(execution, settlement)
                        .map_err(|_| NativeProcessError::Stale)?;
                    self.pending_loan.lock().unwrap().take();
                    return Ok(());
                }
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
            Some(ForkStockKind::Descriptor) => {
                let settlement = unsafe {
                    &mut *(record_gpa as *mut carrick_el1_abi::NativeDescriptorSettlement)
                };
                #[cfg(test)]
                if let Some(physical) = &self.physical {
                    let (owner, generation, address) = settlement.request().unwrap();
                    // SAFETY: the synchronous fixture retains the ring reply slot.
                    let reply =
                        unsafe { &*(address.raw() as *const carrick_el1_abi::PortalGrantSlot) };
                    let mut physical = physical.lock().unwrap();
                    let execution = physical.execution(cpu).inspect_err(|_| {
                        settlement.refuse();
                    })?;
                    physical
                        .settle_descriptor(execution, owner, generation, reply)
                        .inspect_err(|_| {
                            settlement.refuse();
                        })?;
                }
                settlement
                    .accept()
                    .then_some(())
                    .ok_or(NativeProcessError::Invalid)
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
    #[cfg(test)]
    host_ids: carrick_kernel::kernel::IdRegistry,
    #[cfg(test)]
    _host_root: carrick_kernel::kernel::TaskClaim,
    #[cfg(test)]
    host_threads: std::sync::Mutex<Vec<carrick_kernel::kernel::ThreadClaim>>,
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    task: CurrentTask,
    slot: SlotId,
    address: AddressContext<RootGpa>,
    region: &'static crate::mm_portal::test_support::Region,
    tables: crate::mm_portal::test_support::Tables,
    maintenance: CallerInvalidatesAsid,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    #[cfg(test)]
    leader: ThreadIdentity,
}

fn asid(raw: u16) -> carrick_guest_arch::Asid {
    carrick_guest_arch::Asid::from_registry_allocation(core::num::NonZeroU16::new(raw).unwrap())
}

#[test]
fn arm_unregistered_host_cancel_commits_terminal_intent_before_record_release() {
    use carrick_core::terminal::{MissingContinuationVerdict, missing_zone_continuation};
    use carrick_el1_abi::Lifecycle;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Owner {
        Native,
        HostPreparing,
        HostCommitted,
        Final,
    }
    #[derive(Clone, Copy, Debug)]
    enum Trigger {
        HostExit,
        CancelledRecord,
        HostBirth,
    }
    for trigger in [
        Trigger::HostExit,
        Trigger::CancelledRecord,
        Trigger::HostBirth,
    ] {
        for owner in [
            Owner::Native,
            Owner::HostPreparing,
            Owner::HostCommitted,
            Owner::Final,
        ] {
            let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
            // A second live member owns the same lifecycle page and another slot;
            // neither has been registered with the native process owner yet.
            let sibling = (owner != Owner::Final).then(|| {
                fixture.page.thread_born().unwrap();
                let sibling_control = Box::leak(Box::new(ThreadControlSlot::new()));
                let sibling_slot = SlotId::new(1);
                fixture.zone.drive(sibling_slot, 1);
                fixture.zone.publish_slot(sibling_slot, 1, Some(1), 1);
                fixture.zone.enter_guest(sibling_slot);
                fixture.zone.install_space(sibling_slot, 1).unwrap();
                let sibling_record = fixture
                    .zone
                    .current_or_new(
                        sibling_slot,
                        ThreadIdentity {
                            tid: 42,
                            serial: 102,
                            control_slot: sibling_control as *const _ as u64,
                            ..fixture.leader
                        },
                    )
                    .unwrap();
                assert!(
                    fixture
                        .zone
                        .requeue_preempted(sibling_slot, sibling_record)
                        .is_queued()
                );
                assert_eq!(fixture.zone.switch_in(sibling_slot), Some(sibling_record));
                fixture.zone.record_ref(sibling_record)
            });
            let record = fixture
                .zone
                .current_or_new(fixture.slot, fixture.leader)
                .unwrap();
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, record)
                    .is_queued()
            );
            assert_eq!(fixture.zone.switch_in(fixture.slot), Some(record));
            let reference = fixture.zone.record_ref(record);
            fixture.control.bind_zone_record(reference);
            let birth = fixture.control.host_birth_identity().unwrap();
            let host =
                (owner == Owner::HostPreparing || owner == Owner::HostCommitted).then(|| {
                    carrick_core::terminal::reserve_host_thread_exit_membership(
                        fixture.page,
                        fixture.control,
                    )
                    .unwrap()
                });
            let host = if owner == Owner::HostCommitted {
                host.unwrap()
                    .commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
                    .publish();
                None
            } else {
                host
            };
            match trigger {
                Trigger::HostExit => fixture.control.request_host_exit(),
                Trigger::CancelledRecord => assert_eq!(
                    fixture.zone.claim_for_host(
                        reference,
                        None,
                        carrick_el1_abi::Handback::Cancelled,
                        &carrick_sched_core::ShortLockSpin,
                        &|owned| crate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned
                        )
                    ),
                    carrick_sched_core::HostClaim::El1Held { slot: fixture.slot }
                ),
                Trigger::HostBirth => {
                    let birth_slot = fixture.page.reserve_host_birth().unwrap();
                    assert!(fixture.page.publish_host_birth(birth_slot, birth));
                    assert!(fixture.page.request_host_birth_cancel(birth_slot));
                    assert!(!fixture.control.host_exit_requested());
                    assert!(!fixture.zone.record(record).is_cancelled());
                }
            }
            if owner != Owner::HostCommitted {
                assert_eq!(
                    missing_zone_continuation(
                        fixture.control,
                        birth,
                        Some(birth),
                        reference,
                        fixture.control.zone_record()
                    ),
                    MissingContinuationVerdict::InvariantViolation
                );
            }
            let mut service = fixture.process_service();
            assert_eq!(
                crate::aarch64_process::resume_production_with_service(
                    fixture.zone,
                    &fixture.task,
                    fixture.slot,
                    record,
                    &mut service,
                ),
                crate::sched::ResumeAction::Left
            );
            if owner == Owner::HostPreparing || owner == Owner::Final {
                assert!(
                    fixture.zone.live(reference).is_some(),
                    "{owner:?} must retain its record"
                );
                assert_eq!(
                    fixture.zone.take_service_head(fixture.slot),
                    Some(reference)
                );
                assert_eq!(fixture.page.live(), 1);
                assert_eq!(
                    missing_zone_continuation(
                        fixture.control,
                        birth,
                        Some(birth),
                        reference,
                        fixture.control.zone_record()
                    ),
                    MissingContinuationVerdict::InvariantViolation
                );
                drop(host);
                assert_eq!(
                    fixture.page.live(),
                    if owner == Owner::Final { 1 } else { 2 }
                );
                if owner == Owner::HostPreparing && !matches!(trigger, Trigger::CancelledRecord) {
                    let work = fixture.task.linux.take_host_work_doorbell().unwrap();
                    assert_eq!(work.native_terminal_slot(), None, "Busy did not release");
                    work.settled();
                    fixture.zone.requeue_on(fixture.slot, record).unwrap();
                    assert_eq!(fixture.zone.switch_in(fixture.slot), Some(record));
                    assert_eq!(
                        crate::aarch64_process::resume_production_with_service(
                            fixture.zone,
                            &fixture.task,
                            fixture.slot,
                            record,
                            &mut service,
                        ),
                        crate::sched::ResumeAction::Left
                    );
                    assert!(fixture.zone.live(reference).is_none());
                    assert_eq!(fixture.page.live(), 1, "Busy once, then success");
                    let work = fixture.task.linux.take_host_work_doorbell().unwrap();
                    assert_eq!(work.native_terminal_slot(), Some(fixture.slot));
                    work.settled();
                }
                continue;
            }
            assert!(fixture.zone.live(reference).is_none());
            assert_eq!(
                missing_zone_continuation(
                    fixture.control,
                    birth,
                    Some(birth),
                    reference,
                    fixture.control.zone_record()
                ),
                MissingContinuationVerdict::Terminal,
                "host cancellation must publish terminal intent before freeing its record"
            );
            assert_eq!(
                fixture.page.live(),
                1,
                "native release consumes exactly one live unit"
            );
            assert!(fixture.zone.live(sibling.unwrap()).is_some());
        }
    }
}

// A cancelled adapter operation remains owned by its host endpoint. Neither
// native retirement nor a losing membership claim may free it or panic.
#[test]
fn arm_unregistered_cancel_requeues_adapter_operation_without_retirement() {
    use carrick_el1_abi::Lifecycle;
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Owner {
        Native,
        HostPreparing,
        HostCommitted,
        Final,
        NoLifecycle,
    }
    for owner in [
        Owner::Native,
        Owner::HostPreparing,
        Owner::HostCommitted,
        Owner::Final,
        Owner::NoLifecycle,
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        if owner != Owner::Final {
            fixture.page.thread_born().unwrap();
        }
        let record = if owner == Owner::NoLifecycle {
            fixture.zone.clear_current(fixture.slot);
            fixture
                .zone
                .current_or_new(
                    fixture.slot,
                    ThreadIdentity {
                        lifecycle_page: 0,
                        control_slot: 0,
                        ..fixture.leader
                    },
                )
                .unwrap()
        } else {
            fixture.zone.slot(fixture.slot).host_record().unwrap()
        };
        let reference = fixture.zone.record_ref(record);
        fixture.control.bind_zone_record(reference);
        let key = ObjectWaitKey::new(3, 1).unwrap();
        fixture
            .zone
            .bind_object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        queue
            .park(
                queue.snapshot(),
                record,
                OperationToken::new(77, 19).unwrap(),
            )
            .unwrap();
        let mut effects = carrick_sched_core::WakeEffects::default();
        assert_eq!(
            queue
                .notify_object(fixture.slot, &mut effects)
                .unwrap()
                .visited,
            1
        );
        drop(queue);
        assert_eq!(fixture.zone.switch_in(fixture.slot), Some(record));
        assert_eq!(
            fixture.zone.claim_for_host(
                reference,
                None,
                carrick_el1_abi::Handback::Cancelled,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            ),
            carrick_sched_core::HostClaim::El1Held { slot: fixture.slot }
        );
        let host = matches!(owner, Owner::HostPreparing | Owner::HostCommitted).then(|| {
            carrick_core::terminal::reserve_host_thread_exit_membership(
                fixture.page,
                fixture.control,
            )
            .unwrap()
        });
        let host = if owner == Owner::HostCommitted {
            host.unwrap()
                .commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
                .publish();
            None
        } else {
            host
        };
        let live = fixture.page.live();
        let mut service = fixture.process_service();
        assert_eq!(
            crate::aarch64_process::resume_production_with_service(
                fixture.zone,
                &fixture.task,
                fixture.slot,
                record,
                &mut service
            ),
            crate::sched::ResumeAction::Left,
            "{owner:?}"
        );
        assert_eq!(
            fixture.page.live(),
            live,
            "{owner:?}: requeue must restore its temporary reservation"
        );
        assert!(
            fixture.zone.live(reference).is_some(),
            "{owner:?}: endpoint operation retains its record"
        );
        assert_eq!(fixture.zone.slot(fixture.slot).current(), None);
        assert_eq!(
            fixture.zone.take_service_head(fixture.slot),
            Some(reference),
            "{owner:?}: host takes the exact operation"
        );
        // SAFETY: take_service_head transferred this exact record to the host.
        let operation = unsafe { fixture.zone.record(record).take_object_operation() }.unwrap();
        assert_eq!((operation.index(), operation.generation()), (77, 19));
        // SAFETY: this fixture still owns the host record; the token was taken.
        assert!(unsafe { fixture.zone.record(record).take_object_operation() }.is_none());
        assert!(fixture.task.linux.take_host_work_doorbell().is_some());
        drop(host);
    }
}

#[test]
fn arm_unregistered_cancel_without_lifecycle_retains_record_for_host() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.clear_current(fixture.slot);
    let record = fixture
        .zone
        .current_or_new(
            fixture.slot,
            ThreadIdentity {
                lifecycle_page: 0,
                control_slot: 0,
                ..fixture.leader
            },
        )
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record)
            .is_queued()
    );
    assert_eq!(fixture.zone.switch_in(fixture.slot), Some(record));
    let reference = fixture.zone.record_ref(record);
    assert_eq!(
        fixture.zone.claim_for_host(
            reference,
            None,
            carrick_el1_abi::Handback::Cancelled,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::El1Held { slot: fixture.slot }
    );
    let mut service = fixture.process_service();
    assert_eq!(
        crate::aarch64_process::resume_production_with_service(
            fixture.zone,
            &fixture.task,
            fixture.slot,
            record,
            &mut service
        ),
        crate::sched::ResumeAction::Left
    );
    assert!(fixture.zone.live(reference).is_some());
    assert_eq!(fixture.zone.slot(fixture.slot).current(), None);
    assert_eq!(
        fixture.zone.claim_for_host(
            reference,
            None,
            carrick_el1_abi::Handback::Cancelled,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::Claimed
    );
    assert_eq!(fixture.page.live(), 1);
    assert!(fixture.task.linux.take_host_work_doorbell().is_some());
}

#[test]
fn arm_unregistered_pool_cancel_reaps_entry_before_host_cleanup() {
    use carrick_el1_abi::Lifecycle;
    for closed in [false, true] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let leader = fixture.zone.slot(fixture.slot).host_record().unwrap();
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, leader)
                .is_queued()
        );
        assert_eq!(fixture.zone.switch_in(fixture.slot), Some(leader));
        let slot = SlotId::new(1);
        fixture.zone.drive(slot, 1);
        fixture.zone.publish_slot(slot, 1, Some(1), 1);
        fixture.zone.enter_guest(slot);
        fixture.zone.install_space(slot, 1).unwrap();
        let (control, record) =
            imported_thread_on_slot(fixture, slot, |identity| identity.affinity = 2);
        let entry = control.entry().unwrap();
        assert_eq!(fixture.zone.switch_in(slot), Some(record.id));
        let task = Box::leak(Box::new(CurrentTask::new()));
        task.set(
            El1TaskId::from_linux_tid(42),
            carrick_el1_abi::SnapshotGeneration::from_raw(12),
            5,
        );
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(102, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
        task.publish_root_generation(fixture.address.generation);
        if closed {
            fixture.page.close();
        }
        control.request_host_exit();
        assert!(registry().for_record(fixture.zone, record).is_none());
        let mut service = Aarch64NativeProcessService::with_crossing(
            task,
            slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        assert_eq!(
            crate::aarch64_process::resume_production_with_service(
                fixture.zone,
                task,
                slot,
                record.id,
                &mut service
            ),
            crate::sched::ResumeAction::Left
        );
        if !closed {
            assert!(fixture.zone.live(record).is_some());
            assert_eq!(fixture.zone.take_service_head(slot), Some(record));
            assert_eq!(
                fixture.page.live(),
                2,
                "an open pool gate leaves retirement with the host"
            );
            assert_eq!(
                fixture.page.state(entry.index()),
                Some((entry.generation(), carrick_el1_abi::EntryState::Born))
            );
            continue;
        }
        assert!(fixture.zone.live(record).is_none());
        assert_eq!(
            fixture.page.state(entry.index()),
            Some((entry.generation(), carrick_el1_abi::EntryState::Reaped))
        );
        assert_eq!(fixture.page.live(), 1);
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, control)
            .unwrap()
            .commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
            .publish();
        assert_eq!(
            fixture.page.live(),
            1,
            "host graph cleanup cannot consume the sibling twice"
        );
        assert!(
            fixture.zone.slot(fixture.slot).current().is_some(),
            "leader remains executing on its own lane"
        );
        assert!(task.linux.take_host_work_doorbell().is_some());
    }
}

impl Fixture {
    #[cfg(test)]
    fn new(root_gpa: u64, asid: carrick_guest_arch::Asid) -> Self {
        Self::with_file_table(root_gpa, asid, 5)
    }
    fn with_file_table(root_gpa: u64, asid: carrick_guest_arch::Asid, file_table: u64) -> Self {
        Self::with_page(
            root_gpa,
            asid,
            file_table,
            Box::leak(Box::new(ThreadLifecyclePage::new())),
        )
    }
    fn with_page(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        file_table: u64,
        page: &'static ThreadLifecyclePage,
    ) -> Self {
        Self::with_page_and_arena(root_gpa, asid, file_table, page, 0x1000_0000)
    }

    fn with_page_and_arena(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        file_table: u64,
        page: &'static ThreadLifecyclePage,
        arena_len: u64,
    ) -> Self {
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        Self::with_identity_and_arena(
            root_gpa,
            asid,
            page,
            control,
            ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: 1,
                file_table,
                generation: 11,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
            arena_len,
        )
    }
    #[cfg(test)]
    fn with_identity(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        leader: ThreadIdentity,
    ) -> Self {
        Self::with_identity_and_arena(root_gpa, asid, page, control, leader, 0x1000_0000)
    }
    fn with_identity_and_arena(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        leader: ThreadIdentity,
        arena_len: u64,
    ) -> Self {
        Self::with_identity_arena_and_import(root_gpa, asid, page, control, leader, arena_len, None)
    }
    /// [`Self::new`] whose MM also imports `anonymous` as private anonymous
    /// memory: host memory the VM-free fixture dereferences as user memory,
    /// so its words are both readable here and owned by the MM's mapping.
    #[cfg(test)]
    fn with_private_anonymous(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        anonymous: carrick_el1_abi::ReservationRange,
    ) -> Self {
        let page: &'static ThreadLifecyclePage = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        Self::with_identity_arena_and_import(
            root_gpa,
            asid,
            page,
            control,
            ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: 1,
                file_table: 5,
                generation: 11,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
            0x1000_0000,
            Some(anonymous),
        )
    }
    fn with_identity_arena_and_import(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        leader: ThreadIdentity,
        arena_len: u64,
        anonymous: Option<carrick_el1_abi::ReservationRange>,
    ) -> Self {
        let file_table = leader.file_table;
        // The host records the leader's birth identity when it allocates the
        // control slot. Its process serial is independent of the snapshot.
        if let Some(birth) = control.host_birth_identity() {
            // Kernel-backed fixtures retain the real process incarnation;
            // an execution snapshot generation is not its birth serial.
            assert_eq!(birth.task().raw(), leader.tid);
            assert_eq!(birth.thread().raw(), leader.serial);
        } else {
            control.publish_host_birth_identity(
                carrick_core::terminal::ThreadBirthIdentity::from_parts(
                    carrick_core_abi::EntryTaskKey::from_raw(leader.tid),
                    carrick_core_abi::entry::BirthSerial::of_task(
                        carrick_sched_core::process::TaskSerial::from_raw_u64(leader.generation)
                            .unwrap(),
                    ),
                    carrick_core_abi::EntryThreadGeneration::from_raw(leader.serial),
                )
                .unwrap(),
            );
        }
        control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[
            leader.affinity
        ]));
        // SAFETY: this fixture retains the control at its identity-mapped address.
        unsafe {
            control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
                core::ptr::from_ref(control).expose_provenance() as u64,
            ));
        }

        let region_box = Box::new(crate::mm_portal::test_support::Region::new());
        let region = Box::leak(region_box);
        let zone: &'static ZoneTables<Aarch64ParkedContext> = unsafe {
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast()
        };

        let domain = carrick_sched_core::process::identity_allocator::VisibleNamespace::new(
            NonZeroU32::MIN,
            NonZeroU32::MIN,
        );
        #[cfg(test)]
        let (host_ids, host_root, host_leader) = {
            let root_id =
                carrick_personality_linux::identity::task_id_from_linux_pid(leader.tid as i32)
                    .unwrap();
            let (ids, root) = carrick_kernel::kernel::IdRegistry::with_root(root_id).unwrap();
            let thread = ids.claim_task_leader_thread(root_id).unwrap();
            ids.bind_visible_domain(root_id, domain).unwrap();
            ids.bind_namespace_source(Arc::new(
                carrick_hal::birth_serial::test_support::OwnedBirthZone::from_static(zone),
            ))
            .unwrap();
            (ids, root, thread)
        };
        // Downstream host-test users cannot depend on this crate's dev-only
        // host kernel. Their synthetic root still owns explicit fixture claims.
        #[cfg(not(test))]
        zone.namespace()
            .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
                use carrick_sched_core::process::identity_allocator::ClaimKind;
                ns.reserve_exact(leader.tid as i32, ClaimKind::Task)
                    .unwrap();
                ns.claim_related(leader.tid as i32, ClaimKind::Thread)
                    .unwrap();
                ns.bind_visible_domain(leader.tid as i32, domain).unwrap();
                ns.set_next(leader.tid as i32 + 1);
            });
        zone.namespace().with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            ns.advance_visible_past(domain, carrick_sched_core::process::identity_allocator::VisibleIdentity::from_existing_member(NonZeroU32::new(leader.tid as u32).unwrap())).unwrap();
        });

        // This fixture supplies root births without the host issuer. Account
        // for both identities before native fork allocates from this source.
        zone.serial_issuer()
            .advance_past(NonZeroU64::new(leader.generation).unwrap());
        zone.serial_issuer()
            .advance_past(NonZeroU64::new(leader.serial).unwrap());

        let task = CurrentTask::new();
        task.set(
            El1TaskId::from_linux_tid(leader.tid as i32),
            carrick_el1_abi::SnapshotGeneration::from_raw(leader.generation),
            file_table,
        );
        task.mm.key.store(leader.mm, Ordering::Release);
        task.mm
            .thread_generation
            .store(leader.serial, Ordering::Release);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);

        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root_gpa)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(leader.mm).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(101).unwrap()),
        };
        zone.mm_issuer().observe_existing(address.mm);
        // As the host's load publication (`publish_current_task`).
        task.publish_host_loaded(leader.tid as u32, address.generation);

        let slot = SlotId::new(0);
        let ttbr0 = (u64::from(asid.raw()) << 48) | root_gpa;
        let space = zone.spaces.publish_closed(leader.mm, ttbr0, ttbr0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, leader.mm);
        zone.publish_slot(slot, leader.mm, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, leader.mm).unwrap();
        zone.current_or_new(slot, leader).unwrap();

        let index = zone.spaces.find(leader.mm).unwrap();
        let mm = ReservationMm::new(leader.mm).unwrap();
        let table = region.table();
        table
            .publish(
                index.index(),
                mm,
                carrick_el1_abi::Layout {
                    heap: carrick_el1_abi::ReservationRange::new(4096, VA).unwrap(),
                    arena: carrick_el1_abi::ReservationRange::new(VA, VA + arena_len).unwrap(),
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
        let view = crate::mm_portal::test_support::nodes(region);
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
        if let Some(anonymous) = anonymous {
            owner
                .import(
                    anonymous,
                    carrick_el1_abi::ReservationProtection::READ_WRITE,
                    true,
                )
                .unwrap();
        }
        drop(owner);
        super::aarch64_process::Portal::for_zone(NonZeroU64::MIN, table, zone)
            .root_any(mm, 0)
            .unwrap()
            .finish_import()
            .unwrap();

        let tables = crate::mm_portal::test_support::Tables::new(root_gpa, IPA, 2);
        let maintenance = CallerInvalidatesAsid;

        Self {
            #[cfg(test)]
            host_ids,
            #[cfg(test)]
            _host_root: host_root,
            #[cfg(test)]
            host_threads: std::sync::Mutex::new(vec![host_leader]),
            zone,
            task,
            slot,
            address,
            region,
            tables,
            maintenance,
            page,
            control,
            #[cfg(test)]
            leader,
        }
    }
    #[cfg(test)]
    fn enter<R>(
        &'static self,
        control: &'static carrick_el1_abi::ThreadControlSlot,
        ttbr0: u64,
        service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
        dispatch: impl FnOnce(
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<'_, Aarch64ParkedContext>,
        ) -> R,
    ) -> Result<R, NativeProcessError> {
        with_process_entry(
            BornInZoneSource {
                zone: self.zone,
                slot: service.slot,
            },
            &self.task,
            &ThreadCtx::ZERO,
            ttbr0,
            self.page,
            control,
            service,
            |process| dispatch(process),
        )
    }
    #[cfg(test)]
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

impl Drop for Fixture {
    fn drop(&mut self) {
        let leftover =
            super::aarch64_process::drain_and_clear_retired_scope(self.zone, self.region.table());
        if !std::thread::panicking() {
            assert_eq!(
                leftover, 0,
                "Fixture dropped with {leftover} unretired space(s) still queued in RETIRED_SPACES"
            );
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

#[test]
fn native_exec_adoption_publishes_closed_manifest_before_consuming_receipt() {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceBirth, ServiceIdentity,
    };
    use carrick_core_abi::{El1MmHandle, EntryThreadGeneration, SnapshotGeneration};
    use carrick_sched_core::process::TaskId;
    use core::num::NonZeroI32;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let service = fixture.process_service();
    let identity = ServiceIdentity {
        birth: ServiceBirth {
            origin: carrick_core_abi::service::ServiceOrigin::Initial,
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(7).unwrap()),
                serial: TaskSerial::from_registry_allocation(NonZeroU64::new(11).unwrap()),
            },
            thread: EntryThreadGeneration::from_raw(13),
            record: carrick_sched_core::RecordRef {
                id: RecordId::from_raw(7).unwrap(),
                incarnation: 17,
            },
            mm: unsafe {
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    ReservationMm::new(19).unwrap(),
                    NonZeroU64::new(23).unwrap(),
                )
            },
        },
        execution: SnapshotGeneration::from_raw(29),
        sequence: NonZeroU64::new(31).unwrap(),
    };
    let successor_mm = ReservationMm::new(37).unwrap();
    let slot = service.prepare_exec_successor_slot(successor_mm).unwrap();
    let generation = slot.root_generation();
    let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(41).unwrap()).unwrap();
    let root = RootGpa::page_aligned(FrameGpa::new(0x90_0000)).unwrap();
    let manifest = ExecSuccessorManifest::propose(identity, successor_mm, generation)
        .seal(
            identity,
            receipt,
            ExecSuccessorBacking {
                root,
                asid: asid(47),
                asid_generation: NonZeroU64::new(53).unwrap(),
            },
            ExecSuccessorEntry {
                entry: UserVa::new(0x40_0000),
                stack_pointer: UserVa::new(0x7fff_f000),
            },
        )
        .unwrap();
    let index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
    let ttbr = (u64::from(asid(47).raw()) << 48) | root.address().raw();
    assert!(
        fixture
            .zone
            .spaces
            .bind_initial_root(index, successor_mm.raw(), ttbr, ttbr)
    );

    let adopted = service
        .adopt_exec_successor(identity, receipt, &manifest)
        .unwrap();
    slot.commit();
    assert_eq!(adopted.address.mm.raw().get(), successor_mm.raw());
    assert_eq!(adopted.address.root, root);
    assert!(
        !fixture.zone.spaces.is_open(successor_mm.raw()),
        "successor stays closed until graph publication commits"
    );
    assert!(matches!(
        service.adopt_exec_successor(identity, receipt, &manifest),
        Err(NativeProcessError::Stale)
    ));
}

/// Characterization of ARM's pre-crossing identity (#1093 S4c): the closed
/// successor must carry exactly `(asid << 48) | root` from the sealed
/// manifest. Generalising the hook must not change which bindings ARM
/// adopts, so this pins the accepted binding and three near misses.
#[test]
fn arm_exec_adoption_identity_is_the_sealed_asid_over_the_root() {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceBirth, ServiceIdentity,
    };
    use carrick_core_abi::{El1MmHandle, EntryThreadGeneration, SnapshotGeneration};
    use carrick_sched_core::process::TaskId;
    use core::num::NonZeroI32;

    const SEALED: u64 = 0x002f_0000_0090_0000;
    for (bound, adopted) in [
        (SEALED, true),
        // Another ASID over the same root.
        (0x002e_0000_0090_0000, false),
        // The same ASID over another root.
        (0x002f_0000_0091_0000, false),
        // The untagged root alone, as x86 binds it.
        (0x0000_0000_0090_0000, false),
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let service = fixture.process_service();
        let identity = ServiceIdentity {
            birth: ServiceBirth {
                origin: carrick_core_abi::service::ServiceOrigin::Initial,
                process: TaskKey {
                    id: TaskId::from_registry_allocation(NonZeroI32::new(7).unwrap()),
                    serial: TaskSerial::from_registry_allocation(NonZeroU64::new(11).unwrap()),
                },
                thread: EntryThreadGeneration::from_raw(13),
                record: carrick_sched_core::RecordRef {
                    id: RecordId::from_raw(7).unwrap(),
                    incarnation: 17,
                },
                mm: unsafe {
                    El1MmHandle::from_admitted_owner(
                        NonZeroU64::MIN,
                        ReservationMm::new(19).unwrap(),
                        NonZeroU64::new(23).unwrap(),
                    )
                },
            },
            execution: SnapshotGeneration::from_raw(29),
            sequence: NonZeroU64::new(31).unwrap(),
        };
        let successor_mm = ReservationMm::new(37).unwrap();
        let slot = service.prepare_exec_successor_slot(successor_mm).unwrap();
        let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(41).unwrap()).unwrap();
        let root = RootGpa::page_aligned(FrameGpa::new(0x90_0000)).unwrap();
        let manifest =
            ExecSuccessorManifest::propose(identity, successor_mm, slot.root_generation())
                .seal(
                    identity,
                    receipt,
                    ExecSuccessorBacking {
                        root,
                        asid: asid(47),
                        asid_generation: NonZeroU64::new(53).unwrap(),
                    },
                    ExecSuccessorEntry {
                        entry: UserVa::new(0x40_0000),
                        stack_pointer: UserVa::new(0x7fff_f000),
                    },
                )
                .unwrap();
        let index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
        assert!(
            fixture
                .zone
                .spaces
                .bind_initial_root(index, successor_mm.raw(), bound, bound)
        );
        let result = service.adopt_exec_successor(identity, receipt, &manifest);
        assert_eq!(result.is_ok(), adopted, "binding {bound:#x}");
        if adopted {
            slot.commit();
        } else {
            assert!(matches!(result, Err(NativeProcessError::Stale)));
            drop(slot);
        }
    }
}

#[test]
fn first_exec_after_fork_exit_reuses_the_slot_with_a_fresh_root_incarnation() {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceBirth, ServiceIdentity,
    };
    use carrick_core_abi::{El1MmHandle, EntryThreadGeneration, SnapshotGeneration};
    use carrick_sched_core::process::TaskId;
    use core::num::NonZeroI32;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let service = fixture.process_service();
    let retired_mm = ReservationMm::new(7).unwrap();
    let retired_space = fixture
        .zone
        .spaces
        .publish_closed(retired_mm.raw(), 0x7000, 0x7000)
        .unwrap();
    assert_eq!(retired_space.index(), 7);
    fixture
        .region
        .table()
        .publish(
            retired_space.index(),
            retired_mm,
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
    let view = crate::mm_portal::test_support::nodes(fixture.region);
    fixture
        .region
        .table()
        .lock_el1_resolved(retired_space.index(), retired_mm, &view, 0)
        .unwrap()
        .retire_final()
        .unwrap();
    fixture.zone.spaces.free(retired_space);

    let identity = ServiceIdentity {
        birth: ServiceBirth {
            origin: carrick_core_abi::service::ServiceOrigin::Initial,
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(7).unwrap()),
                serial: TaskSerial::from_registry_allocation(NonZeroU64::new(11).unwrap()),
            },
            thread: EntryThreadGeneration::from_raw(13),
            record: carrick_sched_core::RecordRef {
                id: RecordId::from_raw(7).unwrap(),
                incarnation: 17,
            },
            mm: unsafe {
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    ReservationMm::new(19).unwrap(),
                    NonZeroU64::new(23).unwrap(),
                )
            },
        },
        execution: SnapshotGeneration::from_raw(29),
        sequence: NonZeroU64::new(31).unwrap(),
    };
    // This key hashes to the just-retired slot. Receipt 1 is intentionally
    // distinct from the real next reservation-root incarnation 2.
    let successor_mm = ReservationMm::new(1031).unwrap();
    let slot = service.prepare_exec_successor_slot(successor_mm).unwrap();
    assert_eq!(slot.root_generation(), NonZeroU64::new(2).unwrap());
    let receipt = ExecAdoptionReceipt::checked(NonZeroU64::MIN).unwrap();
    let manifest =
        ExecSuccessorManifest::propose(identity, successor_mm, NonZeroU64::new(2).unwrap())
            .seal(
                identity,
                receipt,
                ExecSuccessorBacking {
                    root: RootGpa::page_aligned(FrameGpa::new(0x90_0000)).unwrap(),
                    asid: asid(47),
                    asid_generation: NonZeroU64::new(53).unwrap(),
                },
                ExecSuccessorEntry {
                    entry: UserVa::new(0x40_0000),
                    stack_pointer: UserVa::new(0x7fff_f000),
                },
            )
            .unwrap();
    let index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
    let root = RootGpa::page_aligned(FrameGpa::new(0x90_0000)).unwrap();
    let ttbr = (u64::from(asid(47).raw()) << 48) | root.address().raw();
    assert!(
        fixture
            .zone
            .spaces
            .bind_initial_root(index, successor_mm.raw(), ttbr, ttbr)
    );

    let admitted = slot.prepare_adoption().unwrap();
    assert_eq!(admitted.incarnation(), NonZeroU64::new(2).unwrap());
    let successor = service
        .adopt_exec_successor(identity, receipt, &manifest)
        .expect("the first exec after a fork/exit must use slot 7 incarnation 2");
    slot.commit();
    let notifications = fixture
        .zone
        .space_entry(NonZeroU64::new(successor_mm.raw()).unwrap())
        .unwrap()
        .notifications(NonZeroU64::new(2).unwrap())
        .unwrap();
    let cause = carrick_sched_core::spaces::notification::SpaceWaitCause::Gate;
    let before = notifications.observe(cause).revision();
    let owner = super::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    );
    drop(
        owner
            .root_any(
                ReservationMm::new(fixture.address.mm.raw().get()).unwrap(),
                0,
            )
            .unwrap(),
    );
    let predecessor_notifications = fixture
        .zone
        .space_entry(fixture.address.mm.raw())
        .unwrap()
        .live_notifications()
        .unwrap();
    // Exercise the production physical switch with the admitted successor's
    // notification source. The test crossing deliberately refuses only the
    // final host settlement, after the real gate and install transitions.
    assert_eq!(
        service.finish_exec_successor(
            fixture.address,
            successor.address,
            carrick_el1_abi::ExecCommitEffects::COMPLETE,
        ),
        Err(NativeProcessError::Unsupported),
    );
    assert!(
        fixture
            .zone
            .space_entry(fixture.address.mm.raw())
            .unwrap()
            .live_notifications()
            .is_err()
    );
    drop(predecessor_notifications);
    assert!(
        fixture
            .zone
            .spaces
            .find(fixture.address.mm.raw().get())
            .is_none()
    );
    assert!(fixture.zone.spaces.is_open(successor_mm.raw()));
    assert_eq!(notifications.observe(cause).revision(), before + 1);
    assert_eq!(
        fixture.zone.installed_space(fixture.slot),
        successor_mm.raw()
    );
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
        &ThreadCtx::ZERO,
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
        &ThreadCtx::ZERO,
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
    let words = fixture.tables.live(&fixture.maintenance);
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
    let outcome = entry.fork(ProcessForkChildTid::NONE);
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("expected fork to return child pid");
    };
    let child_pid = result.raw() as u32;
    assert_eq!(child_pid, 42);

    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
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

/// #1808: a fully published native child must reach time argument validation.
/// Null user pointers deliberately remove clock calibration and MM supply from
/// this first routing witness. This is not yet the successful-read acceptance
/// witness: it isolates ENOSYS before any time handler or copy can run.
#[cfg(test)]
fn native_fork_child_time_handler(number: carrick_abi::CanonicalNr) {
    native_fork_child_time_handler_with_flags(number, 0);
}

#[cfg(test)]
fn native_fork_child_time_handler_with_flags(number: carrick_abi::CanonicalNr, flags: u64) {
    assert_eq!(
        native_fork_child_time_result(number, 0, flags),
        (-14, 0),
        "native child time syscall {}",
        number.raw()
    );
}

/// Route one time call with null user pointers from a production native fork
/// child: `(x0, counted refusals)`. A call the ring leaves unserved reaches
/// the crossing's counted ENOSYS refusal.
#[cfg(test)]
fn native_fork_child_time_result(
    number: carrick_abi::CanonicalNr,
    argument0: u64,
    argument1: u64,
) -> (i64, u64) {
    native_fork_child_time_result_with(number, argument0, argument1, |_| {})
}

/// [`native_fork_child_time_result`] after `prepare` publishes carrier state.
#[cfg(test)]
fn native_fork_child_time_result_with(
    number: carrick_abi::CanonicalNr,
    argument0: u64,
    argument1: u64,
    prepare: impl FnOnce(&Fixture),
) -> (i64, u64) {
    use super::native_process_runtime::NativeThreadGroupOwner;
    use carrick_personality_linux::dispatch::CompletionRoute;

    let fixture = Fixture::new(0x10000, asid(1));
    prepare(&fixture);
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
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let LifecycleOutcome::Returned { result, .. } = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap()
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("native fork must return a child");
    };
    assert!(result.raw() > 0);
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime
        .namespace_child_key(parent_key, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    assert_ne!(parent.key, child.key);
    assert_ne!(parent.address.mm, child.address.mm);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent.record.id)
            .is_queued()
    );
    activate(source, &task, &child);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let mut entry = runtime
        .enter(source, &task, child.words, &mut child_service)
        .unwrap();
    assert!(!entry.is_root_process());
    let owner = if entry.is_root_process() {
        NativeThreadGroupOwner::Root
    } else {
        NativeThreadGroupOwner::ForkChild
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: fixture.slot.index() as u64,
        ..Default::default()
    };
    // All user pointers are null.
    frame.x[8] = number.raw();
    frame.x[0] = argument0;
    frame.x[1] = argument1;
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(&task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&fixture),
        Some(&mut entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    if route == CompletionRoute::Forward {
        assert_eq!(
            super::dispatch::native_unstaged_exit(
                &mut frame,
                &task.linux,
                carrick_el1_abi::Action::Forward,
                || owner,
                &counters,
            ),
            super::dispatch::NativeUnstagedExit::Refused(carrick_el1_abi::Action::Served),
        );
    }
    assert!(runtime.task_binding(parent_key).is_some());
    assert!(runtime.task_binding(child_key).is_some());
    (
        frame.x[0] as i64,
        counters.refused[number.raw() as usize].load(Ordering::Acquire),
    )
}

/// #1808: the routed child `clock_nanosleep` answers each clock and flag
/// class as Linux does (clock_nanosleep(2); errno numbers from a native Linux
/// 6.12 probe), with a null request so no sleep starts. Served clocks reach
/// request validation (EFAULT 14). Clocks the ring cannot measure and
/// absolute deadlines without an epoch authority keep the counted ENOSYS
/// refusal (38), before any user access.
#[test]
fn native_fork_child_clock_nanosleep_clocks_and_flags_match_linux() {
    const SERVED: (i64, u64) = (-14, 0);
    const REFUSED: (i64, u64) = (-38, 1);
    const EOPNOTSUPP: (i64, u64) = (-95, 0);
    const EINVAL: (i64, u64) = (-22, 0);
    let process_cpu = |pid: u32| u64::from((!pid << 3) | 0b010);
    let thread_cpu = |pid: u32| u64::from((!pid << 3) | 0b110);
    let clock_fd = |fd: u32| u64::from((!fd << 3) | 0b011);
    let rows = [
        // (clock, flags, expected)
        (0, 0, SERVED),
        (1, 0, SERVED),
        (7, 0, SERVED),
        (11, 0, SERVED),
        // `clockid_t` is an int: the register's upper half is not read.
        (0x1_0000_0001, 0, SERVED),
        // Linux reads only TIMER_ABSTIME; other flag bits are ignored.
        (1, 2, SERVED),
        (1, 0xffff_fffe, SERVED),
        // Absolute monotonic deadlines on ARM (guest counter epoch).
        (1, 1, SERVED),
        (7, 1, SERVED),
        (1, 3, SERVED),
        // Absolute REALTIME/TAI: no realtime authority yet (#1981).
        (0, 1, REFUSED),
        (11, 1, REFUSED),
        // Linux sleeps on process CPU time and decides ALARM clocks after
        // reading the request; the ring measures neither.
        (2, 0, REFUSED),
        (process_cpu(1), 0, REFUSED),
        // Dynamic per-thread CPU clocks: a raw `clock_nanosleep` reads the
        // request first (EFAULT on NULL) and then answers by the named
        // thread (0 for a live sibling, 22 for the caller).
        (thread_cpu(1), 0, REFUSED),
        (8, 0, REFUSED),
        (9, 0, REFUSED),
        (3, 0, EOPNOTSUPP),
        (4, 0, EOPNOTSUPP),
        (5, 0, EOPNOTSUPP),
        (6, 0, EOPNOTSUPP),
        (0x1_0000_0004, 0, EOPNOTSUPP),
        (clock_fd(3), 0, EOPNOTSUPP),
        (10, 0, EINVAL),
        (12, 0, EINVAL),
        (u64::from(i32::MAX as u32), 0, EINVAL),
    ];
    let mut wrong = Vec::new();
    for (clock, flags, expected) in rows {
        let observed =
            native_fork_child_time_result(carrick_abi::syscall::nr::CLOCK_NANOSLEEP, clock, flags);
        if observed != expected {
            wrong.push((clock, flags, observed, expected));
        }
    }
    assert!(
        wrong.is_empty(),
        "(clock, flags, observed, expected): {wrong:#x?}"
    );
}

#[test]
fn native_fork_child_clock_getres_reaches_time_handler() {
    let number = carrick_abi::syscall::nr::CLOCK_GETRES;
    // A null result is allowed for a valid clock. An invalid id still fails.
    assert_eq!(native_fork_child_time_result(number, 1, 0), (0, 0));
    assert_eq!(native_fork_child_time_result(number, 12, 0), (-22, 0));
}

#[test]
fn native_fork_child_clock_gettime_reaches_time_handler() {
    let number = carrick_abi::syscall::nr::CLOCK_GETTIME;
    assert_eq!(native_fork_child_time_result(number, 1, 0), (-14, 0));
}

#[test]
fn native_fork_child_monotonic_raw_clock_gettime_reaches_time_handler() {
    let number = carrick_abi::syscall::nr::CLOCK_GETTIME;
    let clock = carrick_syscall_abi::LINUX_CLOCK_MONOTONIC_RAW;
    assert_eq!(native_fork_child_time_result(number, clock, 0), (-14, 0));
}

#[test]
fn native_fork_child_gettimeofday_accepts_null_outputs() {
    let number = carrick_abi::syscall::nr::GETTIMEOFDAY;
    assert_eq!(native_fork_child_time_result(number, 0, 0), (0, 0));
}

#[test]
fn native_fork_child_realtime_clocks_reach_time_handler() {
    let number = carrick_abi::syscall::nr::CLOCK_GETTIME;
    for clock in [
        carrick_syscall_abi::LINUX_CLOCK_REALTIME,
        carrick_syscall_abi::LINUX_CLOCK_REALTIME_COARSE,
    ] {
        assert_eq!(native_fork_child_time_result(number, clock, 0), (-14, 0));
    }
}

/// #2618: the syscall realtime clock is the carrier's zone calibration on
/// the ring counter. No vvar is mapped at the guest address here, so a value
/// derived from user memory could not produce this exact result.
#[test]
fn native_fork_child_realtime_reads_the_zone_calibration() {
    use carrick_guest_arch::{CounterFrequency, CounterTick};

    const OFFSET_NS: u64 = 1_700_000_000_123_456_789;
    const TICK: u64 = 7_000_000_000;
    let number = carrick_abi::syscall::nr::CLOCK_GETTIME;
    for clock in [
        carrick_syscall_abi::LINUX_CLOCK_REALTIME,
        carrick_syscall_abi::LINUX_CLOCK_REALTIME_COARSE,
    ] {
        let ts = carrick_test_support::GuestUserValue::new([0u64; 2]);
        let result = native_fork_child_time_result_with(number, clock, ts.arg(), |fixture| {
            fixture
                .zone
                .publish_counter_frequency(CounterFrequency::new(
                    NonZeroU64::new(1_000_000_000).unwrap(),
                ));
            fixture.zone.publish_realtime_offset(OFFSET_NS);
            fixture
                .zone
                .cpu_leave_slot(fixture.slot, CounterTick::new(TICK));
        });
        assert_eq!(result, (0, 0), "native child clock_gettime({clock})");
        let nanos = if clock == carrick_syscall_abi::LINUX_CLOCK_REALTIME {
            123_456_789
        } else {
            123_000_000
        };
        assert_eq!(ts.get(), [1_700_000_007, nanos], "clock {clock}");
    }
}

#[test]
fn native_fork_child_cputime_and_times_reach_time_handler() {
    let clock_gettime = carrick_abi::syscall::nr::CLOCK_GETTIME;
    for clock in [
        carrick_syscall_abi::LINUX_CLOCK_PROCESS_CPUTIME_ID,
        carrick_syscall_abi::LINUX_CLOCK_THREAD_CPUTIME_ID,
    ] {
        assert_eq!(
            native_fork_child_time_result(clock_gettime, clock, 0),
            (-14, 0),
            "native child clock_gettime({clock}, NULL)"
        );
    }
    let times = carrick_abi::syscall::nr::TIMES;
    let (ticks, refusals) = native_fork_child_time_result(times, 0, 0);
    assert!(ticks > 0, "native child times(NULL) returned {ticks}");
    assert_eq!(refusals, 0);
    assert_eq!(
        native_fork_child_time_result(times, carrick_guest_arch::USER_CEILING, 0),
        (-14, 0)
    );
}

#[test]
fn native_fork_child_cputime_and_times_account_user_system_and_children() {
    use carrick_guest_arch::CounterTick;
    use carrick_personality_linux::dispatch::CompletionRoute;

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
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000, 0x28000, 0x29000,
        0x2a000, 0x2b000, 0x2c000, 0x2d000, 0x2e000, 0x2f000,
    ]);
    let mut root_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let LifecycleOutcome::Returned { result, .. } = runtime
        .enter(source, &fixture.task, parked, &mut root_service)
        .unwrap()
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("root fork must return child");
    };
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime
        .namespace_child_key(parent_key, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent.record.id)
            .is_queued()
    );

    // Fork a grandchild from the native child, charge it 40 ms user + 15 ms system,
    // exit it, and reap it so child's children_rusage is populated.
    activate(source, &task, &child);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let LifecycleOutcome::Returned {
        result: grandchild_pid,
        ..
    } = runtime
        .enter(source, &task, child.words, &mut child_service)
        .unwrap()
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("child fork must return grandchild");
    };
    let grandchild_key = runtime
        .namespace_child_key(child_key, grandchild_pid.raw() as u32)
        .unwrap();
    let grandchild = runtime.task_binding(grandchild_key).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child.record.id)
            .is_queued()
    );

    let hz = carrick_guest_arch::CounterFrequency::new(NonZeroU64::new(1_000_000_000).unwrap());
    fixture.zone.publish_counter_frequency(hz);
    let activate_target = |target: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >| {
        loop {
            let switched = fixture.zone.switch_in_full(fixture.slot).unwrap();
            if switched.record == target.record.id {
                break;
            }
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, switched.record)
                    .is_queued()
            );
        }
        fixture
            .zone
            .install_space(fixture.slot, target.address.mm.raw().get())
            .unwrap();
        let identity = fixture.zone.record(target.record.id).identity();
        task.set(
            El1TaskId::from_linux_tid(target.key.id.raw()),
            carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
            identity.file_table,
        );
        task.mm
            .key
            .store(target.address.mm.raw().get(), Ordering::Release);
        task.mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        task.publish_visible_pid(target.visible_pid);
        task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
    };

    activate_target(&grandchild);
    fixture.zone.cpu_enter_user(
        fixture.slot,
        Some(grandchild.record),
        CounterTick::new(100_000_000),
    );
    fixture.zone.cpu_enter_ring(
        fixture.slot,
        Some(grandchild.record),
        CounterTick::new(140_000_000),
    );
    fixture
        .zone
        .cpu_leave_slot(fixture.slot, CounterTick::new(155_000_000));
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.child.lock().unwrap() = Some((
        super::common_entry::execution_binding(&task),
        grandchild.address,
    ));
    let mut grandchild_service = Aarch64NativeProcessService::with_crossing(
        &task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let _ = runtime
        .enter(source, &task, grandchild.words, &mut grandchild_service)
        .unwrap()
        .exit_group(0);

    activate_target(&child);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let reaped = runtime
        .enter(source, &task, child.words, &mut child_service)
        .unwrap()
        .wait4(
            ProcessWaitPid::from_syscall_argument(grandchild_pid.raw() as u64),
            UserVa::new(0),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        );
    assert!(matches!(
        reaped,
        LifecycleOutcome::Returned { result, .. } if result.raw() == grandchild_pid.raw()
    ));

    // Charge child 35 ms user + 22 ms system (57 ms own CPU total).
    fixture.zone.cpu_enter_user(
        fixture.slot,
        Some(child.record),
        CounterTick::new(200_000_000),
    );
    fixture.zone.cpu_enter_ring(
        fixture.slot,
        Some(child.record),
        CounterTick::new(235_000_000),
    );
    fixture.zone.cpu_enter_ring(
        fixture.slot,
        Some(child.record),
        CounterTick::new(257_000_000),
    );

    let mut entry = runtime
        .enter(source, &task, child.words, &mut child_service)
        .unwrap();
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());

    for clock in [
        carrick_syscall_abi::LINUX_CLOCK_PROCESS_CPUTIME_ID,
        carrick_syscall_abi::LINUX_CLOCK_THREAD_CPUTIME_ID,
    ] {
        let ts = carrick_test_support::GuestUserValue::new([0u64; 2]);
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            slot: fixture.slot.index() as u64,
            ..Default::default()
        };
        frame.x[8] = carrick_abi::syscall::nr::CLOCK_GETTIME.raw();
        frame.x[0] = clock;
        frame.x[1] = ts.arg();
        let route = super::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            Some(&fixture),
            Some(&mut entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(frame.x[0], 0);
        assert_eq!(ts.get(), [0, 57_000_000]);
    }

    let tms = carrick_test_support::GuestUserValue::new(carrick_syscall_abi::LinuxTms::zeroed());
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: fixture.slot.index() as u64,
        ..Default::default()
    };
    frame.x[8] = carrick_abi::syscall::nr::TIMES.raw();
    frame.x[0] = tms.arg();
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(&task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&fixture),
        Some(&mut entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    assert_eq!(frame.x[0] as i64, 125);
    let tms = tms.get();
    assert_eq!({ tms.tms_utime }, 3);
    assert_eq!({ tms.tms_stime }, 2);
    assert_eq!({ tms.tms_cutime }, 4);
    assert_eq!({ tms.tms_cstime }, 1);
}

#[test]
#[ignore = "#1808 slice 3: clock_gettime/adjtimex/clock_adjtime routing"]
fn native_fork_child_clock_adjtime_reaches_time_handler() {
    native_fork_child_time_handler(carrick_abi::syscall::nr::CLOCK_ADJTIME);
}

#[test]
#[ignore = "#1808 slice 3: clock_gettime/adjtimex/clock_adjtime routing"]
fn native_fork_child_adjtimex_reaches_time_handler() {
    native_fork_child_time_handler(carrick_abi::syscall::nr::ADJTIMEX);
}

#[test]
fn native_fork_child_nanosleep_reaches_time_handler() {
    native_fork_child_time_handler(carrick_abi::syscall::nr::NANOSLEEP);
}

#[test]
fn native_fork_child_clock_nanosleep_reaches_time_handler() {
    native_fork_child_time_handler(carrick_abi::syscall::nr::CLOCK_NANOSLEEP);
}

#[test]
fn native_fork_child_absolute_clock_nanosleep_reaches_time_handler() {
    // TIMER_ABSTIME on CLOCK_MONOTONIC still requires a readable request
    // timespec. A null request must reach Linux validation rather than
    // child-route refusal.
    assert_eq!(
        native_fork_child_time_result(carrick_abi::syscall::nr::CLOCK_NANOSLEEP, 1, 1),
        (-14, 0)
    );
}

/// #1808: only a process without a host continuation sleeps in ring. The
/// run root keeps its host sleep, which honours a controlled ClockDomain.
#[test]
fn native_root_nanosleep_keeps_its_host_continuation() {
    use carrick_personality_linux::dispatch::CompletionRoute;

    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
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
    let crossing = TestStockCrossing::new(&[0x20000, 0x21000]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    assert!(entry.is_root_process());
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    for number in [
        carrick_abi::syscall::nr::NANOSLEEP,
        carrick_abi::syscall::nr::CLOCK_NANOSLEEP,
    ] {
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            slot: fixture.slot.index() as u64,
            ..Default::default()
        };
        frame.x[8] = number.raw();
        frame.x[0] = 0x55;
        let route = super::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            Some(&fixture),
            Some(&mut entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(route, CompletionRoute::Forward, "root {}", number.raw());
        assert_eq!(
            frame.x[0], 0x55,
            "the root's arguments reach its host sleep"
        );
    }
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
    let words = fixture.tables.live(&fixture.maintenance);
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
    let outcome = entry.fork(ProcessForkChildTid::NONE);
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("expected fork to return child pid");
    };
    let child_pid = result.raw() as u32;
    assert_eq!(child_pid, 42);

    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
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
    let words = fixture.tables.live(&fixture.maintenance);
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
    let outcome = entry.fork(ProcessForkChildTid::NONE);
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
        carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
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

#[cfg(test)]
#[derive(Clone, Copy)]
enum Wait4TerminalCase {
    Exited,
    CoreSignal,
    PipeSignal,
}

/// Red-first Test 3: wait4 consumes an exited zombie exactly once with exact status copied.
#[cfg(test)]
#[test]
fn test_wait4_consumes_zombie_once_with_exact_status() {
    wait4_consumes_zombie_once_with_exact_status(Wait4TerminalCase::Exited);
}

/// A core-class signal without a published core must report CLD_KILLED and
/// no WCOREDUMP bit. The parent publishes SIGSEGV, the child consumes it at
/// the production return checkpoint, and the parent observes and reaps it.
#[cfg(test)]
#[test]
fn arm_wait4_reports_default_core_signal_from_production_delivery() {
    wait4_consumes_zombie_once_with_exact_status(Wait4TerminalCase::CoreSignal);
}

#[cfg(test)]
#[test]
fn arm_wait4_reports_sigpipe_from_native_signal_owner() {
    wait4_consumes_zombie_once_with_exact_status(Wait4TerminalCase::PipeSignal);
}

#[cfg(test)]
fn wait4_consumes_zombie_once_with_exact_status(terminal: Wait4TerminalCase) {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };

    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let child_task = CurrentTask::new();
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
        let LifecycleOutcome::Returned { result, .. } =
            parent_entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("expected fork return");
        };
        child_pid = result.raw() as u32;
        for selector in [u64::from(child_pid), u64::MAX, 0] {
            let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
                ProcessWaitPid::from_syscall_argument(selector),
                UserVa::new(0),
                LinuxWaitOptions::WNOHANG,
                UserVa::new(0),
            ) else {
                panic!("live-child selector must not park");
            };
            assert_eq!(result.raw(), 0, "matching live child returns WNOHANG zero");
        }
        carrick_personality_linux::identity::ProcessIdentityVenue::set_pgid(
            &mut parent_entry,
            child_pid as i32,
            child_pid as i32,
        )
        .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
            ProcessWaitPid::from_syscall_argument(0),
            UserVa::new(0),
            LinuxWaitOptions::WNOHANG,
            UserVa::new(0),
        ) else {
            panic!("empty caller process group must not park");
        };
        assert_eq!(result.raw(), -10, "no matching children returns ECHILD");
        let child_group = (-(i64::from(child_pid))) as u64;
        let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
            ProcessWaitPid::from_syscall_argument(child_group),
            UserVa::new(0),
            LinuxWaitOptions::WNOHANG,
            UserVa::new(0),
        ) else {
            panic!("matching child process group must not park");
        };
        assert_eq!(result.raw(), 0, "-pgid selects the regrouped live child");
        if matches!(terminal, Wait4TerminalCase::CoreSignal) {
            parent_entry
                .kill(
                    SignalProcessSelector::from_abi(u64::from(child_pid)),
                    SignalRequest::from_abi(11).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        }
    }

    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    {
        let mut parent_entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
            ProcessWaitPid::from_syscall_argument(u64::from(child_pid)),
            UserVa::new(0),
            LinuxWaitOptions::WNOHANG,
            UserVa::new(0),
        ) else {
            panic!("WNOHANG must return without parking")
        };
        assert_eq!(result.raw(), 0, "a live native child is not waitable");
        let child_info_user = carrick_test_support::GuestUserBuffer::from_value(
            carrick_syscall_abi::LinuxSiginfo::kill(17, 1, 1, 1),
        );
        let LifecycleOutcome::Returned { result, .. } = parent_entry.waitid(
            ProcessWaitId::pid(child_pid),
            child_info_user.va(),
            LinuxWaitOptions::WEXITED | LinuxWaitOptions::WNOHANG,
        ) else {
            panic!("waitid WNOHANG must return without parking")
        };
        assert_eq!(result.raw(), 0);
        let child_info = child_info_user.get::<carrick_syscall_abi::LinuxSiginfo>(0);
        let si_signo = child_info.si_signo;
        assert_eq!(si_signo, 0, "waitid WNOHANG clears the empty result");
    }

    // Parent yields slot to child
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );

    // Now the child either exits normally or consumes a default core signal
    // through the same production return checkpoint used by native execution.
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
        match terminal {
            Wait4TerminalCase::Exited => {
                let exit_outcome = child_entry.exit_group(9);
                assert!(matches!(
                    exit_outcome,
                    LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        ..
                    }
                ));
            }
            Wait4TerminalCase::CoreSignal | Wait4TerminalCase::PipeSignal => {
                let child_control_address = fixture
                    .zone
                    .record(child_binding.record.id)
                    .identity()
                    .control_slot;
                // SAFETY: `activate` authenticated this exact live record and
                // published its retained lifecycle control immediately above.
                let child_control = unsafe {
                    &*(child_control_address as *const carrick_el1_abi::ThreadControlSlot)
                };
                if matches!(terminal, Wait4TerminalCase::PipeSignal) {
                    child_control
                        .post_in_zone_standard_signal(carrick_signal_core::policy::Signal::PIPE)
                        .unwrap();
                    child_control
                        .post_in_zone_standard_signal(carrick_signal_core::policy::Signal::PIPE)
                        .unwrap();
                    child_entry.import_in_zone_standard_signals().unwrap();
                    assert!(
                        !child_control.has_in_zone_standard_signal(),
                        "the exact-thread handoff moves once into the signal owner"
                    );
                }
                assert!(child_entry.signal_checkpoint_needed());
                let mut frame = carrick_el1_abi::TrapFrame::default();
                frame.x[0] = carrick_syscall_abi::LinuxErrno::new(32).guest_retval() as u64;
                let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
                assert_eq!(
                    super::signal_delivery::deliver_signal_on_syscall_return(
                        &child_task,
                        child_control,
                        &mut child_entry,
                        &mut frame,
                        zerocopy::IntoBytes::as_bytes(&fp),
                        &mut ArmWaitSignalMachine {
                            user_sp: UserVa::new(0),
                            backend: ArmWaitSignalBackend,
                        },
                    ),
                    Some(carrick_personality_linux::dispatch::CompletionRoute::Suspended),
                    "default SIGPIPE owns terminal disposition before EPIPE reaches EL0"
                );
            }
        }
    }

    // Now parent calls wait4 to consume the zombie
    let status_storage = carrick_test_support::GuestUserBuffer::from_value(0i32);
    let status_va = status_storage.va();

    let parent_binding = runtime.task_binding(parent_key).unwrap();
    activate(source, &fixture.task, &parent_binding);

    let mut parent_entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();

    let child_info_user = carrick_test_support::GuestUserBuffer::from_value(
        carrick_syscall_abi::LinuxSiginfo::empty(),
    );
    let waitid_outcome = parent_entry.waitid(
        ProcessWaitId::pid(child_pid),
        child_info_user.va(),
        LinuxWaitOptions::WEXITED | LinuxWaitOptions::WNOWAIT,
    );
    assert!(matches!(
        waitid_outcome,
        LifecycleOutcome::Returned { result, .. } if result.raw() == 0
    ));
    let child_info = child_info_user.get::<carrick_syscall_abi::LinuxSiginfo>(0);
    let si_signo = child_info.si_signo;
    let si_code = child_info.si_code;
    assert_eq!(si_signo, 17);
    let expected_code = match terminal {
        Wait4TerminalCase::Exited => carrick_syscall_abi::LINUX_CLD_EXITED,
        Wait4TerminalCase::CoreSignal => carrick_syscall_abi::LINUX_CLD_KILLED,
        Wait4TerminalCase::PipeSignal => carrick_syscall_abi::LINUX_CLD_KILLED,
    };
    assert_eq!(si_code, expected_code);
    assert_eq!(child_info.si_addr as u32, child_pid);
    assert_eq!(
        i32::from_le_bytes(child_info._pad[0..4].try_into().unwrap()),
        match terminal {
            Wait4TerminalCase::Exited => 9,
            Wait4TerminalCase::CoreSignal => 11,
            Wait4TerminalCase::PipeSignal => 13,
        }
    );

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
    let expected_status = match terminal {
        Wait4TerminalCase::Exited => 9 << 8,
        Wait4TerminalCase::CoreSignal => 11,
        Wait4TerminalCase::PipeSignal => 13,
    };
    let status = status_storage.get::<i32>(0);
    assert_eq!(status, expected_status);
    if matches!(terminal, Wait4TerminalCase::CoreSignal) {
        assert_ne!(status & 0x7f, 0, "WIFSIGNALED");
        assert_ne!(status & 0x7f, 0x7f, "WIFSIGNALED");
        assert_eq!(status & 0x7f, 11, "WTERMSIG");
        assert_eq!(status & 0x80, 0, "no core was published");
    }

    // Second wait on the consumed child must fail with ECHILD (error code -10)
    let re_wait = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(child_pid as u64),
        status_va,
        LinuxWaitOptions::empty(),
        UserVa::new(0),
    );
    assert!(matches!(
        re_wait,
        LifecycleOutcome::Returned { result, .. } if result.raw() == NativeFailure::NoChild.errno()
    ));
    let no_children = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(u64::MAX),
        status_va,
        LinuxWaitOptions::WNOHANG,
        UserVa::new(0),
    );
    assert!(matches!(
        no_children,
        LifecycleOutcome::Returned { result, .. } if result.raw() == -10
    ));
}

#[cfg(test)]
#[test]
fn arm_terminal_child_retirement_places_stopped_slot_waiter() {
    arm_child_wait_wake(false, false);
}

#[cfg(test)]
#[test]
fn arm_in_ring_wait4_wake_resumes_owner_before_eret() {
    arm_child_wait_wake(true, false);
}

#[test]
fn arm_physical_retirement_wait4_wake_resumes_owner_before_eret() {
    arm_child_wait_wake_with_stock(true, false, true);
}

#[test]
fn arm_stopped_slot_physical_retirement_wait4_wake_resumes_owner_before_eret() {
    arm_child_wait_wake_with_stock(false, false, true);
}

#[cfg(test)]
#[test]
fn arm_registered_sibling_wait4_wakes_through_owner_in_ring() {
    arm_child_wait_wake(true, true);
}

#[cfg(test)]
fn arm_child_wait_wake(in_ring: bool, sibling: bool) {
    arm_child_wait_wake_with_stock(in_ring, sibling, false);
}

#[cfg(test)]
fn arm_child_wait_wake_with_stock(in_ring: bool, sibling: bool, physical: bool) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let child_task = CurrentTask::new();
    let runtime = std::sync::Arc::new(
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
    let owner_registry = Box::leak(Box::new(NativeProcessRegistry::new()));
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();

    let mut crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    if physical {
        let mut stock = native_retirement_tests::PhysicalStock::new(&fixture.tables);
        stock.bind_lane(
            &fixture.task,
            fixture.zone,
            carrick_guest_arch::CpuId::new(0),
            fixture.address.root,
        );
        stock.returns = Some(fixture.region.table());
        crossing.physical = Some(std::sync::Mutex::new(stock));
    }
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
        let LifecycleOutcome::Returned { result, .. } =
            parent_entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("expected fork return");
        };
        child_pid = result.raw() as u32;
    }

    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    // A host-issued CLONE_THREAD sibling shares the process owner and can
    // itself park the child wait while the leader remains live.
    let sibling_control = if sibling {
        fixture.zone.clear_current(fixture.slot);
        let control: &'static ThreadControlSlot = Box::leak(Box::new(ThreadControlSlot::new()));
        control
            .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
            .unwrap();
        assert!(control.publish_visible_tid(43));
        control.publish_host_birth_identity(
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_el1_abi::EntryTaskKey::from_raw(43),
                carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(13).unwrap(),
                ),
                carrick_el1_abi::EntryThreadGeneration::from_raw(103),
            )
            .unwrap(),
        );
        let host_slot = fixture.page.reserve_host_birth().unwrap();
        carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
        assert!(
            fixture
                .page
                .publish_host_birth(host_slot, control.host_birth_identity().unwrap())
        );
        run_as(fixture, 43, 13, 103, control);
        let record = fixture
            .zone
            .current_or_new(
                fixture.slot,
                ThreadIdentity {
                    tid: 43,
                    serial: 103,
                    mm: 1,
                    file_table: 5,
                    generation: 13,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: control as *const _ as u64,
                },
            )
            .unwrap();
        control.bind_zone_record(fixture.zone.record_ref(record));
        // SAFETY: this unpublished home record belongs exclusively to the fixture.
        unsafe { *fixture.zone.record(record).ctx_mut() = parked };
        owner_registry
            .register_thread(
                source,
                &fixture.task,
                fixture.address,
                fixture.page,
                control,
            )
            .unwrap();
        Some(control)
    } else {
        None
    };
    let waiter_record = sibling_control
        .and_then(|control| control.zone_record().map(|record| record.id))
        .unwrap_or(parent_binding.record.id);

    // Waiter yields slot to child.
    let status_storage = carrick_test_support::GuestUserBuffer::from_value(0i32);
    let status_va = status_storage.va();
    {
        let mut parent_entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &parked,
                &mut service,
            )
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
    if !in_ring {
        fixture.zone.unhome(fixture.slot, waiter_record, 1);
    }

    // Retain the same counted venue that an admitted anonymous edit borrows.
    // Final exit must close admission now and defer entry reuse until release.
    let child_notifications = (!physical).then(|| {
        fixture
            .zone
            .space_entry(child_binding.address.mm.raw())
            .unwrap()
            .live_notifications()
            .unwrap()
    });

    // Now child exits with status 9
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
        if !in_ring {
            fixture.zone.publish_slot(fixture.slot, 0, Some(0), 1);
            fixture
                .zone
                .leave_guest(fixture.slot, &carrick_sched_core::ShortLockSpin);
        }
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
    if child_notifications.is_some() {
        assert!(
            fixture
                .zone
                .space_entry(child_binding.address.mm.raw())
                .unwrap()
                .live_notifications()
                .is_err(),
            "terminal entry rejects new notification borrowers"
        );
    }
    drop(child_notifications);

    assert!(
        fixture
            .zone
            .spaces
            .find(child_binding.address.mm.raw().get())
            .is_none(),
        "child exit must retire its reservation root without waiting for another fork"
    );

    if let Some(physical) = &crossing.physical {
        assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
        physical.lock().unwrap().shutdown();
    }
    let binding = super::common_entry::execution_binding(&child_task);
    for candidate in [
        binding,
        carrick_el1_abi::ExecutionBinding {
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(binding.generation.raw() + 1),
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
    if in_ring {
        assert_eq!(crossing.handbacks.load(Ordering::Acquire), 0);
        assert_eq!(
            fixture.zone.record(waiter_record).claim(),
            carrick_sched_core::Claim::Queued {
                slot: fixture.slot,
                seq: fixture.zone.next_seq(waiter_record).wrapping_sub(1)
            }
        );
        let mut frame = carrick_el1_abi::TrapFrame::default();
        let mut cpu = ResumeCpu {
            inner: crate::sched::FakeCpu::default(),
            runtime: &runtime,
            registry: owner_registry,
            source,
            task: &fixture.task,
            service: &mut service,
        };
        let counters = carrick_el1_abi::Counters::new();
        assert_eq!(
            (crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot: fixture.slot,
                task: &fixture.task,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            })
            .run_next(&mut frame, 0),
            crate::sched::Served::Returned { switched: true }
        );
        assert_eq!(frame.x[0], u64::from(child_pid));
        assert_eq!(fixture.task.visible_pid(), Some(41));
    } else {
        assert_eq!(crossing.handbacks.load(Ordering::Acquire), 0);
        assert_eq!(
            fixture.zone.record(parent_binding.record.id).claim(),
            carrick_sched_core::Claim::Queued {
                slot: fixture.slot,
                seq: fixture
                    .zone
                    .next_seq(parent_binding.record.id)
                    .wrapping_sub(1)
            }
        );
        assert!(
            fixture
                .zone
                .record(parent_binding.record.id)
                .is_native_owned()
        );
        assert_eq!(
            fixture.zone.record(parent_binding.record.id).identity().mm,
            parent_binding.address.mm.raw().get()
        );
        assert!(!fixture.zone.record(parent_binding.record.id).needs_host());
        assert!(!fixture.zone.head_needs_host(fixture.slot));
        assert!(
            fixture
                .zone
                .spaces
                .is_open(parent_binding.address.mm.raw().get())
        );
        fixture.zone.enter_guest(fixture.slot);
        let mut frame = carrick_el1_abi::TrapFrame::default();
        let mut cpu = ResumeCpu {
            inner: crate::sched::FakeCpu::default(),
            runtime: &runtime,
            registry: owner_registry,
            source,
            task: &fixture.task,
            service: &mut service,
        };
        let counters = carrick_el1_abi::Counters::new();
        assert_eq!(
            (crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot: fixture.slot,
                task: &fixture.task,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            })
            .run_next(&mut frame, 0),
            crate::sched::Served::Returned { switched: true }
        );
        assert_eq!(frame.x[0], u64::from(child_pid));
        assert_eq!(fixture.task.visible_pid(), Some(41));
    }
    assert_eq!(
        status_storage.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(9 << 8).raw()
    );

    // Second wait on the consumed child must fail with ECHILD (error code -10)
    let mut parent_entry = runtime
        .enter_registered(
            owner_registry,
            source,
            &fixture.task,
            fixture.address,
            &parked,
            &mut service,
        )
        .unwrap();
    let re_wait = parent_entry.wait4(
        ProcessWaitPid::from_syscall_argument(child_pid as u64),
        status_va,
        LinuxWaitOptions::empty(),
        UserVa::new(0),
    );
    assert!(matches!(
        re_wait,
        LifecycleOutcome::Returned { result, .. } if result.raw() == NativeFailure::NoChild.errno()
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
    let words = fixture.tables.live(&fixture.maintenance);
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
    let outcome = entry.fork(ProcessForkChildTid::NONE);
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
        .prepare_mm(&fixture.address, &parked, child_mm)
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
fn test_fork_prepared_box_allocation_failure_allows_index_reuse_without_collision() {
    let fixture = Fixture::new(0x10000, asid(1));
    let words = fixture.tables.live(&fixture.maintenance);
    let initial_stock = [
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000, 0x28000, 0x29000,
        0x2a000, 0x2b000, 0x2c000, 0x2d000, 0x2e000, 0x2f000,
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

    // Inject allocation failure for Prepared reservation in first fork attempt.
    // The fork preparation executes synchronously on this test thread, so the
    // RAII guard safely isolates the failure without affecting concurrent tests.
    {
        let _fault_guard = super::native_process_runtime::InjectTryReserveFailure::activate();
        let err = service
            .prepare_mm(&fixture.address, &parked, child_mm)
            .expect_err("prepare_mm must fail when FallibleBox::try_reserve fails");
        assert_eq!(err, NativeProcessError::Exhausted);
    }

    // Second fork reuses the exact same index and must not fail with Collision.
    let prepared = service
        .prepare_mm(&fixture.address, &parked, child_mm)
        .expect("second fork reusing the same index must succeed without Collision");

    service.abort_mm(prepared).expect("abort_mm should succeed");
}

#[test]
fn fork_reservation_refusal_from_concurrent_munmap_rolls_back_without_quarantine() {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native = ThreadCtx::ZERO;
    native.x[0] = 99;
    let parked = Aarch64ParkedContext::from_parts(native, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
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

    let initial_stock = [
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ];
    let crossing = TestStockCrossing::new(&initial_stock);
    *crossing.refuse_reserve.lock().unwrap() = Some(ForkStockRefusal::Inventory);
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
    let refused = entry.fork(ProcessForkChildTid::NONE);
    assert_eq!(
        super::native_process_runtime::host_test_support::outcome_kind(&refused),
        "Transferred",
        "a munmap-during-fork inventory refusal rolls back and retains the fork, never EAGAIN"
    );
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_reserved.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 0);
    assert!(crossing.pending_loan.lock().unwrap().is_none());
    assert_eq!(
        crossing.grant_tables.lock().unwrap().len(),
        initial_stock.len(),
        "aborted reservation must scrub and return every loaned table page"
    );
    assert_eq!(crossing.total_returned_pages.load(Ordering::Acquire), 5);
    assert!(
        fixture.zone.spaces.find(2).is_none(),
        "aborted reservation must free the closed child space"
    );

    // A subsequent fork on the same CPU succeeds using the returned stock.
    let second = entry.fork(ProcessForkChildTid::NONE);
    assert!(
        matches!(second, LifecycleOutcome::Returned { result, .. } if result.raw() > 0),
        "subsequent fork after rolled-back reservation must succeed"
    );
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 2);
    assert_eq!(crossing.settlements_reserved.load(Ordering::Acquire), 2);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 1);
}

#[test]
fn fork_reserve_refusal_retains_diagnostic_stage_and_retryable_errno() {
    let fixture = Fixture::new(0x10000, asid(1));
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    *crossing.refuse_reserve.lock().unwrap() = Some(ForkStockRefusal::Inventory);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let error = service
        .prepare_mm(
            &fixture.address,
            &parked,
            MmGeneration::new(NonZeroU64::new(2).unwrap()),
        )
        .expect_err("reservation refusal must stop preparation");
    // Pool inventory is "not now", never EAGAIN (#2306).
    assert_eq!(error.failure(), Err(NativeContention::BUSY));
    let NativeProcessError::ForkRefused(refusal) = error else {
        panic!("Reserve refusal lost its diagnostic stage: {error:?}");
    };
    assert_eq!(
        refusal.stage,
        super::native_fork_refusal::NativeForkStage::Reserve
    );
    assert_eq!(
        refusal.cause,
        super::native_fork_refusal::NativeForkCause::StockReservation(ForkStockRefusal::Inventory)
    );
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 1);
}

#[test]
fn native_fork_busy_diagnostic_names_parent_space_editor() {
    let fixture = Fixture::new(0x10000, asid(1));
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let owner = super::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    );
    let index = fixture.zone.spaces.find(1).unwrap();
    let access = owner.space_access(0).unwrap();
    let editor = access.try_begin_edit(index, 1, NonZeroU64::MIN).unwrap();
    let error = service
        .prepare_mm(
            &fixture.address,
            &parked,
            MmGeneration::new(NonZeroU64::new(2).unwrap()),
        )
        .expect_err("an outstanding editor must retain its exclusion");
    drop(editor);
    // The fork enrols on the editor's release, never retries a bare Busy.
    assert_eq!(
        error
            .failure()
            .err()
            .and_then(NativeContention::owner_wait)
            .map(|wait| wait.cause()),
        Some(carrick_core_abi::PortalWaitCause::Editor)
    );
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 0);
    let NativeProcessError::ForkRefused(refusal) = error else {
        panic!("space edit refusal lost its site: {error:?}");
    };
    assert_eq!(format!("{:?}", refusal.stage), "ParentSpaceEdit");
}

#[test]
fn native_fork_busy_diagnostic_names_unsettled_parent_fork() {
    let fixture = Fixture::new(0x10000, asid(1));
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let prepared = service
        .prepare_mm(
            &fixture.address,
            &parked,
            MmGeneration::new(NonZeroU64::new(2).unwrap()),
        )
        .unwrap();
    let error = service
        .prepare_mm(
            &fixture.address,
            &parked,
            MmGeneration::new(NonZeroU64::new(3).unwrap()),
        )
        .expect_err("a prepared fork must retain parent publication custody");
    service.abort_mm(prepared).unwrap();
    assert_eq!(error.failure(), Err(NativeContention::BUSY));
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 1);
    let NativeProcessError::ForkRefused(refusal) = error else {
        panic!("parent readiness refusal lost its site: {error:?}");
    };
    assert_eq!(format!("{:?}", refusal.stage), "ParentForkReady");
}

#[test]
fn fork_commit_refusal_after_admitted_reservation_fails_closed_without_opening_child_space() {
    assert_commit_fault_keeps_child_closed(CommitFault::Refusal);
}

#[test]
fn fork_commit_crossing_failure_keeps_child_closed() {
    assert_commit_fault_keeps_child_closed(CommitFault::Crossing);
}

#[test]
fn fork_commit_missing_reply_keeps_child_closed() {
    assert_commit_fault_keeps_child_closed(CommitFault::MissingReply);
}

#[cfg(test)]
fn assert_commit_fault_keeps_child_closed(fault: CommitFault) {
    let fixture = Fixture::new(0x10000, asid(1));
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let initial_stock = [
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ];
    let crossing = TestStockCrossing::new(&initial_stock);
    *crossing.commit_fault.lock().unwrap() = fault;
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
    let prepared = service
        .prepare_mm(&fixture.address, &parked, child_mm)
        .unwrap();
    let born = service.commit_mm(prepared).unwrap();
    let (error, born) = service
        .settle_mm(born)
        .expect_err("unacknowledged Commit must not settle a published child");
    assert_eq!(
        error,
        NativeProcessError::ServiceQuarantined(NativeServiceQuarantine::ForkSettleCustody)
    );
    assert_eq!(crossing.settlements_reserved.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_committed.load(Ordering::Acquire), 1);
    assert_eq!(crossing.settlements_aborted.load(Ordering::Acquire), 0);
    assert!(
        fixture.zone.spaces.find(2).is_some(),
        "closed child space was published during prepare"
    );
    assert!(
        !fixture.zone.spaces.is_open(2),
        "refused Commit must never open the child's space gate"
    );
    drop(born);
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
        generation: carrick_el1_abi::SnapshotGeneration::from_raw(replacement.generation),
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
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(stale.generation),
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

/// Hand a real pending terminal owner back to the host after its sibling retires.
/// The callback exercises the host's register materialization on that exact record.
pub fn with_native_terminal_host_handback(
    native: ThreadCtx,
    witness: impl FnOnce(&ZoneTables<Aarch64ParkedContext>, carrick_el1_abi::RecordRef) -> ThreadCtx,
) {
    use carrick_el1_abi::Lifecycle;
    let fixture = Fixture::with_file_table(0x10000, asid(1), 5);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
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
    let sibling = ThreadControlSlot::new();
    sibling
        .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
        .unwrap();
    assert!(sibling.publish_visible_tid(42));
    sibling.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_el1_abi::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
            ),
            carrick_el1_abi::EntryThreadGeneration::from_raw(102),
        )
        .unwrap(),
    );
    let birth = fixture.page.reserve_host_birth().unwrap();
    fixture.page.thread_born().unwrap();
    assert!(
        fixture
            .page
            .publish_host_birth(birth, sibling.host_birth_identity().unwrap())
    );
    ::core::assert_eq!(fixture.page.live(), 2);
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    assert!(matches!(
        entry.exit_group(7),
        LifecycleOutcome::Transferred { .. }
    ));
    let (mm, address) = fixture.page.exit_wait().unwrap();
    fixture
        .page
        .reserve_cancelled_member_exit()
        .unwrap()
        .publish();
    fixture.page.publish_exact_host_retirement(
        &sibling,
        sibling.host_birth_identity().unwrap().retirement(),
    );
    ::core::assert_eq!(fixture.page.live(), 0);
    let guard = fixture
        .zone
        .lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm.raw(), address),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    let mut transfers = Vec::new();
    assert_eq!(
        fixture.zone.wake_host(
            &guard,
            mm.raw(),
            address,
            u32::MAX,
            1,
            false,
            &mut |transfer| transfers.push(transfer),
            &mut |_| panic!("host handback requested"),
        ),
        1
    );
    drop(guard);
    let record = transfers
        .pop()
        .unwrap()
        .finish(&carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    assert!(transfers.is_empty());
    assert!(matches!(
        fixture.zone.record(record.id).claim(),
        carrick_el1_abi::Claim::Host { .. }
    ));
    drop(entry);
    let mut resumed = witness(fixture.zone, record);
    assert_eq!(
        resumed.pc + 4,
        native.pc,
        "host re-enters the same native instruction"
    );
    assert_eq!(
        resumed.x[0], 7,
        "readiness does not replace the retained status"
    );
    let identity = fixture.zone.record(record.id).identity();
    fixture.zone.free_record(record.id);
    let replacement = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
    assert_eq!(
        fixture.zone.record(replacement).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::UserReturn
    );
    // Execute the re-entry SVC: its architectural return PC is post-instruction.
    resumed.pc += 4;
    let words = Aarch64ParkedContext::from_parts(resumed, fixture.address);
    let mut entry = runtime
        .enter(source, &fixture.task, words, &mut service)
        .unwrap();
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut frame = carrick_el1_abi::TrapFrame {
        x: resumed.x,
        elr: resumed.pc,
        slot: fixture.slot.index() as u64,
        ..Default::default()
    };
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&fixture),
        Some(&mut entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        entry.take_root_exit(),
        Some(carrick_personality_linux::lifecycle::LinuxWaitStatus::exited(7))
    );
    assert!(
        entry.resume_owned_continuation().is_none(),
        "terminal custody is consumed once"
    );
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
        fn cross_root_fork_seed(&self, record_va: u64, cpu: u64) -> Result<(), NativeProcessError> {
            self.stock.cross_root_fork_seed(record_va, cpu)
        }
        fn cross_child_reclaim(
            &self,
            mm: ReservationMm,
            cpu: u64,
        ) -> Result<(), NativeProcessError> {
            self.stock.cross_child_reclaim(mm, cpu)
        }
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
    let words = fixture.tables.live(&fixture.maintenance);
    let child_task = CurrentTask::new();
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
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("native fork must publish a live child");
    };
    assert!(result.raw() > 0, "native fork refused: {}", result.raw());
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime
        .namespace_child_key(parent_key, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    assert_ne!(parent.key, child.key);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent.record.id)
            .is_queued()
    );
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
        page: &ThreadLifecyclePage,
        entry: carrick_el1_abi::EntryRef,
    ) -> Option<&ThreadControlSlot> {
        let address = page.control_address(entry)?;
        if address == 0
            || !address.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
        {
            return None;
        }
        Some(unsafe { &*(address as *const ThreadControlSlot) })
    }
}

#[test]
fn arm_root_setup_enters_production_process_venue() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    #[cfg(test)]
    let physical = native_retirement_tests::PhysicalStock::new(&fixture.tables);
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
        carrick_test_support::assert_guest_args(&frame.x[..6]);
        let route =
            super::dispatch::dispatch_arm_syscall_with_native_process(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                &[],
                &[],
                &[],
                &[],
                &cache,
                None::<
                    crate::dispatch::Zone<
                        '_,
                        crate::sched::FakeCpu,
                        crate::sched::HardwareUserWord,
                    >,
                >,
                None,
                Some(&*fixture),
                fixture.page,
                fixture.control,
                &ThreadCtx::ZERO,
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
    #[cfg(test)]
    physical.shutdown_without_child();
}

// These witnesses retain two live processes through staging, host service,
// ticket acknowledgment and native resume.
#[test]
fn arm_native_fork_child_getrandom_default_returns_eight_bytes() {
    native_fork_child_getrandom(0);
}

#[test]
fn arm_native_fork_child_getrandom_nonblock_returns_eight_bytes() {
    native_fork_child_getrandom(1);
}

#[cfg(test)]
fn native_fork_child_getrandom(flags: u64) {
    use crate::native_process_runtime::NativeThreadGroupOwner;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let crossing = Box::leak(Box::new(TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ])));
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let child_task: &CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
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
    registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(&*words);
    let LifecycleOutcome::Returned { result, .. } = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap()
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("production fork must publish a child");
    };
    assert!(result.raw() > 0);
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime
        .namespace_child_key(parent, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate(source, child_task, &child);
    // SAFETY: the live child owner retains this published lifecycle page.
    // VM-free stock is host storage, outside the hardware metadata VA window.
    let page = unsafe {
        &*(child_task.metadata.lifecycle_page.load(Ordering::Acquire) as *const ThreadLifecyclePage)
    };
    assert_eq!(
        registry.thread_group_owner(fixture.zone, page, child_task.visible_pid().unwrap()),
        NativeThreadGroupOwner::ForkChild,
    );
    assert!(
        runtime.task_binding(parent).is_some(),
        "parent remains live"
    );
    let counters = carrick_el1_abi::Counters::new();
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let output = carrick_test_support::GuestUserBuffer::zeroed(8);
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        elr: 0x400004,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    frame.x[8] = carrick_personality_linux::crossing::nr::GETRANDOM.raw();
    frame.x[..3].copy_from_slice(&[output.arg(), 8, flags]);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(&*words);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            child_task,
            child.address,
            &child.words,
            &mut child_service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(child_task),
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
    assert_eq!(route, CompletionRoute::NativeService);
    let (address, capacity, flags, requested) = crate::dispatch::native_entropy_stage(&frame);
    assert!(matches!(
        entry
            .begin_entropy_service(address, capacity, flags, requested)
            .unwrap(),
        crate::native_process_runtime::NativeResume::Left(None)
    ));
    assert!(entry.take_handoff_receipt().is_some());
    drop(entry);
    let notice = child_task.service_notice.take().unwrap().unwrap();
    // SAFETY: the live child retains this control slot in fixture-owned stock.
    let child_control = unsafe {
        &*(child_task.metadata.control_slot.load(Ordering::Acquire) as *const ThreadControlSlot)
    };
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(child.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: this fixture owns the parked member and its service queue.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &child_control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(child.record.id).identity(),
        )
    }
    .unwrap();
    let carrick_core_abi::service::ServiceOperation::Entropy { payload } =
        ticket.request().operation
    else {
        panic!("ARM child must stage entropy, not an ordinal crossing");
    };
    // SAFETY: the pending ring service retains this exact staging allocation
    // through the ticket's acknowledgment; the member remains parked.
    let record = unsafe {
        core::slice::from_raw_parts_mut(
            payload.address().raw() as *mut u8,
            payload.length().raw() as usize,
        )
    };
    carrick_kernel::dispatch::serve_native_entropy(record).unwrap();
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(
            fixture.slot,
            &mut carrick_sched_core::WakeEffects::default(),
        )
        .unwrap();
    drop(queue);
    // The still-live parent is also runnable; keep its queue custody while
    // selecting the completed child's service continuation.
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    if selected.record != child.record.id {
        assert_eq!(selected.record, parent_binding.record.id);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, selected.record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            child.record.id
        );
    }
    let saved = unsafe { runtime.record_binding(child.record) }
        .unwrap()
        .words;
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            child_task,
            child.address,
            &saved,
            &mut child_service,
        )
        .unwrap();
    let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
    assert!(
        matches!(resumed, crate::native_process_runtime::NativeResume::Returned(result) if result.raw() == 8),
        "native child getrandom(flags={flags:?}) must return eight only after completion and resume"
    );
    assert_eq!(counters.refused_child[278].load(Ordering::Acquire), 0);
}

#[test]
fn arm_signal_setup_then_plain_fork_returns_one_child() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let crossing = Box::leak(Box::new(TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
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
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mask = carrick_test_support::GuestUserBuffer::from_value(u64::MAX);
    let old_mask = carrick_test_support::GuestUserBuffer::from_value(0xdead_beef_u64);
    for (nr, args, expected) in [
        (135, [0, mask.arg(), old_mask.arg(), 8, 0, 0], 0),
        // musl's _Fork sets only x0/x1. Linux ignores x2..x5 without their
        // matching CLONE_* flags; the preceding sigprocmask leaves them live.
        (220, [17, 0, 0xdead_beef, 8, 0x1234, 0x5678], 42),
    ] {
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        carrick_test_support::assert_guest_args(&frame.x[..6]);
        let route =
            super::dispatch::dispatch_arm_syscall_with_native_process(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                &[],
                &[],
                &[],
                &[],
                &cache,
                None::<
                    crate::dispatch::Zone<
                        '_,
                        crate::sched::FakeCpu,
                        crate::sched::HardwareUserWord,
                    >,
                >,
                None,
                Some(&*fixture),
                fixture.page,
                fixture.control,
                &ThreadCtx::ZERO,
                ttbr0,
                &mut service,
                |_| core::ptr::null_mut(),
            )
            .unwrap();
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::WithWork
        );
        assert_eq!(frame.x[0] as i64, expected, "syscall {nr}");
    }
    assert_eq!(old_mask.get::<u64>(0), 0);
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 1);
}

#[test]
fn arm_sigprocmask_nonresident_input_is_not_efault() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let crossing = Box::leak(Box::new(TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
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
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mask = carrick_test_support::GuestUserBuffer::from_value(u64::MAX);
    let old_mask = carrick_test_support::GuestUserBuffer::from_value(0xdead_beef_u64);
    // The physical user-copy boundary refuses the first read, as it does
    // for an absent stage-1 leaf. Both addresses remain valid user buffers.
    for attempt in 0..2 {
        crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(attempt == 0, Ordering::Relaxed));
        let (nr, args) = (135, [0, mask.arg(), old_mask.arg(), 8, 0, 0]);
        let pc = frame.elr;
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        carrick_test_support::assert_guest_args(&frame.x[..6]);
        let route =
            super::dispatch::dispatch_arm_syscall_with_native_process(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                &[],
                &[],
                &[],
                &[],
                &cache,
                None::<
                    crate::dispatch::Zone<
                        '_,
                        crate::sched::FakeCpu,
                        crate::sched::HardwareUserWord,
                    >,
                >,
                None,
                Some(&*fixture),
                fixture.page,
                fixture.control,
                &ThreadCtx::ZERO,
                ttbr0,
                &mut service,
                |_| core::ptr::null_mut(),
            )
            .unwrap();
        crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
        assert_eq!(
            route,
            if attempt == 0 {
                carrick_personality_linux::dispatch::CompletionRoute::Served
            } else {
                carrick_personality_linux::dispatch::CompletionRoute::WithWork
            }
        );
        assert_eq!(frame.x[0] as i64, 0, "syscall {nr}");
        if attempt == 0 {
            assert_eq!(
                frame.elr,
                pc.wrapping_sub(4),
                "redispatch the input before effects"
            );
            assert_eq!(old_mask.get::<u64>(0), 0xdead_beef);
            assert_eq!(fixture.control.blocked().0, 0);
        }
    }
    assert_eq!(old_mask.get::<u64>(0), 0);
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 0);
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
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, record)
                    .is_queued()
            );
            fixture.zone.record_ref(record)
        })
        .unwrap();
    assert!(fixture.zone.live(published).is_some());
    assert_eq!(
        fixture.zone.slot(fixture.slot).host_record(),
        Some(published.id)
    );
}

#[cfg(test)]
fn imported_thread(
    fixture: &Fixture,
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    imported_thread_with_identity(fixture, |_| {})
}

#[cfg(test)]
fn imported_thread_with_identity(
    fixture: &Fixture,
    edit: impl FnOnce(&mut carrick_sched_core::ThreadIdentity),
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    imported_thread_on_control(fixture, Box::leak(Box::new(ThreadControlSlot::new())), edit)
}

#[cfg(test)]
fn imported_thread_on_slot(
    fixture: &Fixture,
    slot: SlotId,
    edit: impl FnOnce(&mut carrick_sched_core::ThreadIdentity),
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    imported_thread_on_control_and_slot(
        fixture,
        Box::leak(Box::new(ThreadControlSlot::new())),
        slot,
        edit,
    )
}

#[cfg(test)]
fn imported_thread_on_control(
    fixture: &Fixture,
    control: &'static ThreadControlSlot,
    edit: impl FnOnce(&mut carrick_sched_core::ThreadIdentity),
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    imported_thread_on_control_and_slot(fixture, control, fixture.slot, edit)
}

#[cfg(test)]
fn imported_thread_on_control_and_slot(
    fixture: &Fixture,
    control: &'static ThreadControlSlot,
    slot: SlotId,
    edit: impl FnOnce(&mut carrick_sched_core::ThreadIdentity),
) -> (&'static ThreadControlSlot, carrick_sched_core::RecordRef) {
    use carrick_el1_abi::Lifecycle;
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            use carrick_sched_core::process::identity_allocator::*;
            if !ns.is_reserved_number(42) {
                ns.reserve_exact(42, ClaimKind::Thread).unwrap();
            }
            let domain = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
            ns.bind_visible_domain(42, domain).unwrap();
            ns.advance_visible_past(
                domain,
                VisibleIdentity::from_existing_member(NonZeroU32::new(42).unwrap()),
            )
            .unwrap();
        });
    let entry = fixture
        .page
        .stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
                ),
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
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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
    control
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
        .unwrap();
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
    assert!(fixture.zone.requeue_preempted(slot, record).is_queued());
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
        fixture.task.set(
            El1TaskId::from_linux_tid(42),
            carrick_el1_abi::SnapshotGeneration::from_raw(12),
            5,
        );
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
                let terminal_entry = control.entry();
                fixture.page.try_exit().unwrap();
                carrick_core::entry::retire_current(process.binding(), source, record.id).unwrap();
                admission.commit_with_member(control).unwrap();
                if notified {
                    let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
                        process.binding(),
                        terminal_entry,
                        carrick_sched_core::process::TerminationStatus::exited(0),
                    )
                    .unwrap();
                    process.retire_thread_verdict(
                        carrick_core::terminal::RetirementVerdict::RetireThread {
                            identity,
                            requires_slot_absence: true,
                            notification: None,
                        },
                    );
                }
            })
            .unwrap();
        assert_eq!(
            registry().for_record(fixture.zone, record).is_none(),
            notified
        );
        fixture.task.set(
            El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            5,
        );
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
        // An exact ExitedInZone member owes no host receipt even when its
        // registry row has not yet been unregistered.
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
    fixture.task.execution.generation.store(
        carrick_el1_abi::SnapshotGeneration::from_raw(22),
        Ordering::Release,
    );
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
        &ThreadCtx::ZERO,
        ttbr0,
        fixture.control,
    )
    .unwrap();
    admit_entry(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        ttbr0,
        record,
        fixture.page,
        fixture.control,
    )
    .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record
    );
    let generation = fixture.task.execution.generation.load(Ordering::Acquire);
    fixture.task.execution.generation.store(
        carrick_el1_abi::SnapshotGeneration::from_raw(generation.raw() + 1),
        Ordering::Release,
    );
    assert!(
        fixture
            .enter(fixture.control, ttbr0, &mut service, |_| panic!(
                "wrong binding must not enter dispatch"
            ))
            .is_err()
    );
    fixture
        .task
        .execution
        .generation
        .store(generation, Ordering::Release);
    for atomic in [
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
    fixture.task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(0),
        5,
    );
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
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&*fixture),
        fixture.page,
        control,
        &ThreadCtx::ZERO,
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
    fixture.task.execution.generation.store(
        carrick_el1_abi::SnapshotGeneration::from_raw(19),
        Ordering::Release,
    );
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
    fixture.task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        5,
    );
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
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &user,
        }),
        None,
        Some(&*fixture),
        fixture.page,
        control,
        &ThreadCtx::ZERO,
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
    fixture.task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(11),
        5,
    );
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
    arm_call_with_cpu(
        fixture,
        control,
        service,
        frame,
        &mut crate::sched::FakeCpu::default(),
    )
}

#[cfg(test)]
fn arm_call_with_cpu<X: ForkStockCrossing>(
    fixture: &'static Fixture,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, X>,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
) -> Result<carrick_personality_linux::dispatch::CompletionRoute, NativeProcessError> {
    carrick_test_support::assert_guest_args(&frame.x[..6]);
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    super::dispatch::dispatch_arm_syscall_with_native_process(
        frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        fixture.page,
        control,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        service,
        |_| core::ptr::null_mut(),
    )
}

#[test]
fn arm_signal_setup_then_timed_futex_keeps_its_deadline() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let mut setup = carrick_el1_abi::TrapFrame::default();
    setup.x[8] = 134;
    setup.x[0] = 13;
    setup.x[3] = 8;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut setup, &mut cpu).unwrap();
    assert_eq!(setup.x[0], 0);

    let word = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let timeout = carrick_test_support::GuestUserBuffer::from_values(&[0_u64, 1_000_000]);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 98;
    frame.x[0] = word.arg();
    frame.x[1] = 128;
    frame.x[3] = timeout.arg();
    let route =
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
    );
    assert_eq!(frame.x[0] as i64, -110);
    assert_eq!(
        fixture.zone.counters.el1_timeouts.load(Ordering::Acquire),
        1
    );
}

#[test]
fn arm_permission_fault_keeps_signal_owner_after_admission_home_release() {
    use carrick_el1::fault::{
        GrantMailboxes, NoopCowResolver, NoopPreparedResolver, OwnerFaultSupply,
        OwnerFaultSupplyOutcome, PreparedFaultPath,
    };
    use carrick_el1::substrate::sched::NativeEntryVenue;
    use carrick_el1_abi::Lifecycle;
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use zerocopy::{FromBytes, IntoBytes};

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let action = Action {
        disposition: Disposition::Handler(HandlerAddress(0x40_0100)),
        ..Default::default()
    };
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(Signal::SEGV, Some(action))
                    .unwrap();
            },
        )
        .unwrap();
    assert!(fixture.control.native_signal_owner());
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    // Plain signal setup owns no scheduler park. Its temporary home was
    // correctly released; the action remains in the registered process graph.
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(fixture.zone.slot(fixture.slot).host_record().is_none());
    assert_eq!(
        NativeEntryVenue::select_with_lifecycle(
            fixture.zone,
            fixture.slot,
            &fixture.task,
            fixture.page,
            fixture.control,
        ),
        NativeEntryVenue::SignalOwner,
        "root thread with native_signal_owner must select SignalOwner after AdmissionHome::drop"
    );
    assert_eq!(
        NativeEntryVenue::select_with_lifecycle(
            fixture.zone,
            SlotId::new(1),
            &fixture.task,
            fixture.page,
            fixture.control,
        ),
        NativeEntryVenue::Host,
        "another execution lane cannot borrow this member's MM"
    );
    assert!(
        !super::native_process_runtime::native_entry_owned(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            carrick_sched_core::object_wait::OwnerEntry::Syscall,
        ),
        "signal ownership alone must not transfer the host-loaded syscall venue"
    );
    assert!(
        !super::native_process_runtime::native_entry_owned(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            carrick_sched_core::object_wait::OwnerEntry::Exception,
        ),
        "signal ownership alone must not route non-declined root exceptions into native service"
    );

    // P1-b: a HostOnly or Closed lifecycle gate must fall back to Host instead
    // of entering native admission and fail-stopping.
    let host_only_page = ThreadLifecyclePage::new();
    host_only_page.decline_to_host();
    fixture.task.publish_lifecycle(
        &host_only_page as *const _ as u64,
        fixture.control as *const _ as u64,
    );
    assert_eq!(
        NativeEntryVenue::select_with_lifecycle(
            fixture.zone,
            fixture.slot,
            &fixture.task,
            &host_only_page,
            fixture.control,
        ),
        NativeEntryVenue::Host,
        "HostOnly lifecycle gate must fall back to Host venue"
    );
    fixture.task.publish_lifecycle(
        fixture.page as *const _ as u64,
        fixture.control as *const _ as u64,
    );

    // Director witness: a root process with native_signal_owner and an IRQ
    // host-work exit (esr == 0) must still take the direct host Action::Forward
    // path instead of entering host_work_boundary.
    fixture.task.linux.mark_pending_host_work();
    let counters = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    let mut irq_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let mut cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        crate::dispatch::dispatch_irq_with_regions(
            &mut irq_frame,
            counters,
            core::slice::from_ref(&fixture.task),
            crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            },
        ),
        carrick_el1_abi::Action::Forward,
        "root SignalOwner IRQ host-work exit must remain on the host forward path"
    );
    assert!(
        cpu.host_work_boundaries.is_empty(),
        "root SignalOwner must not enter native host_work_boundary on IRQ host work"
    );
    fixture
        .task
        .linux
        .take_host_work_doorbell()
        .unwrap()
        .settled();

    // Production fault path: mprotect [VA, VA + 4096) to PROT_READ, take a
    // write permission fault (ESR 0x9200004f) on the SignalOwner root after
    // AdmissionHome::drop, and verify dispatch_fault_with_prepared +
    // settle_declined_owner_fault + deliver_declined_fault_signal builds the
    // user handler frame in-ring.
    let mm = carrick_el1_abi::ReservationMm::new(fixture.address.mm.raw().get()).unwrap();
    let decision = super::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    )
    .root_any(mm, 0)
    .unwrap()
    .mprotect(
        carrick_el1_abi::ReservationRange::new(
            crate::mm_portal::test_support::VA,
            crate::mm_portal::test_support::VA + 4096,
        )
        .unwrap(),
        carrick_el1_abi::ReservationProtection::READ,
    )
    .unwrap();
    let carrick_el1::memory::reservations::Decision::Work(request) = decision else {
        panic!("mprotect must stage a protection proposal")
    };
    let receipt = unsafe {
        carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            carrick_el1_abi::ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .unwrap();
    super::aarch64_process::Portal::for_zone(NonZeroU64::MIN, fixture.region.table(), fixture.zone)
        .root_any(mm, 0)
        .unwrap()
        .complete(receipt)
        .unwrap();
    let portal = unsafe {
        &*fixture
            .region
            .ptr
            .as_ptr()
            .add(carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
            .cast::<carrick_el1_abi::MmPortalSlots>()
    };
    let residency = unsafe {
        &*fixture
            .region
            .ptr
            .as_ptr()
            .add(carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET as usize)
            .cast::<carrick_el1_abi::FrameGrantResidencyTable>()
    };
    let handle = crate::cow_resolver::admitted_fault_mm_handle(
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        fixture.slot,
        &fixture.task,
    )
    .unwrap();
    let mailbox = carrick_el1_abi::FrameGrantMailbox::new();

    // Unmapped fault (first-touch / growsdown / SIGBUS candidate) must NOT be
    // marked PolicyDeclined on Mailbox supply and must forward to the host.
    let unmapped_supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let mut unmapped_frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x9200_004f,
        far: crate::mm_portal::test_support::VA + 0x20000,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let unmapped_action = carrick_el1::fault::dispatch_fault_with_prepared(
        &mut unmapped_frame,
        counters,
        core::slice::from_ref(&fixture.task),
        crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
        crate::cow_resolver::native_fault_supply(
            false,
            GrantMailboxes::own(&mailbox),
            &unmapped_supply,
        ),
        Some(PreparedFaultPath {
            residency,
            resolver: &mut NoopPreparedResolver,
            roots: Some(fixture.region.table()),
            file_slots: Some(portal),
        }),
        &mut NoopCowResolver,
    );
    assert_eq!(unmapped_action, carrick_el1_abi::Action::Forward);
    assert_eq!(
        unmapped_supply.outcome(),
        OwnerFaultSupplyOutcome::Unavailable
    );
    assert_eq!(
        crate::cow_resolver::settle_declined_owner_fault(
            NativeEntryVenue::select_with_lifecycle(
                fixture.zone,
                fixture.slot,
                &fixture.task,
                fixture.page,
                fixture.control,
            ),
            &fixture.task,
            unmapped_action,
            unmapped_supply.outcome(),
            || panic!("unmapped fault must forward to host"),
        ),
        carrick_el1_abi::Action::Forward,
    );

    // Declined write permission fault on PROT_READ anonymous mapping:
    let supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x9200_004f,
        far: crate::mm_portal::test_support::VA,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let fault_action = carrick_el1::fault::dispatch_fault_with_prepared(
        &mut frame,
        counters,
        core::slice::from_ref(&fixture.task),
        crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
        crate::cow_resolver::native_fault_supply(false, GrantMailboxes::own(&mailbox), &supply),
        Some(PreparedFaultPath {
            residency,
            resolver: &mut NoopPreparedResolver,
            roots: Some(fixture.region.table()),
            file_slots: Some(portal),
        }),
        &mut NoopCowResolver,
    );
    assert_eq!(fault_action, carrick_el1_abi::Action::Forward);
    assert_eq!(
        supply.outcome(),
        OwnerFaultSupplyOutcome::PolicyDeclined,
        "mapped anonymous PROT_READ write fault must record PolicyDeclined on Mailbox owner supply"
    );

    // Ptrace-traced root task must still forward to the host ptrace fault stop.
    fixture.task.publish_ptrace_traced(true);
    assert_eq!(
        crate::cow_resolver::settle_declined_owner_fault(
            NativeEntryVenue::select_with_lifecycle(
                fixture.zone,
                fixture.slot,
                &fixture.task,
                fixture.page,
                fixture.control,
            ),
            &fixture.task,
            fault_action,
            supply.outcome(),
            || panic!("ptrace-traced fault must forward to host ptrace stop"),
        ),
        carrick_el1_abi::Action::Forward,
    );
    fixture.task.publish_ptrace_traced(false);

    // A previous home is still retained by another executor. Rehoming the
    // signal owner must refuse transiently, before publishing a forced signal.
    let other = SlotId::new(1);
    fixture
        .zone
        .publish_slot(other, fixture.address.mm.raw().get(), Some(1), 1);
    fixture
        .zone
        .install_space(other, fixture.address.mm.raw().get())
        .unwrap();
    let retained_source = BornInZoneSource {
        zone: fixture.zone,
        slot: other,
    };
    let retained = process_record_for_call(
        retained_source,
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        fixture.control,
    )
    .unwrap();
    registry()
        .rehome_entry(
            retained_source,
            &fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    fixture
        .control
        .publish_synchronous_fault(Signal::SEGV, 2, frame.far);
    let refused = super::dispatch::arm_deliver_declined_fault_signal_with(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        fixture.page,
        fixture.control,
        &mut service,
        &mut frame,
        &mut None,
        |_, _| panic!("Busy admission must not publish or deliver a signal"),
    );
    assert_eq!(refused, Ok(carrick_el1_abi::Action::Forward));
    assert_eq!(
        fixture.control.synchronous_fault(),
        Some((Signal::SEGV, 2, frame.far, false))
    );
    assert_eq!(frame.elr, 0x40_0200);
    assert!(fixture.zone.release_host_home(other, retained));

    // Untraced SignalOwner delivers SIGSEGV/SEGV_ACCERR in-ring and builds the
    // user signal frame.
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let sp = stack.va_at(stack.len());
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let mut machine = ArmWaitSignalMachine {
        user_sp: sp,
        backend: ArmWaitSignalBackend,
    };
    let settled = crate::cow_resolver::settle_declined_owner_fault(
        NativeEntryVenue::select_with_lifecycle(
            fixture.zone,
            fixture.slot,
            &fixture.task,
            fixture.page,
            fixture.control,
        ),
        &fixture.task,
        fault_action,
        supply.outcome(),
        || {
            super::dispatch::arm_deliver_declined_fault_signal_with(
                source,
                &fixture.task,
                &ThreadCtx::ZERO,
                fixture_ttbr0(fixture),
                fixture.page,
                fixture.control,
                &mut service,
                &mut frame,
                &mut None,
                |process, frame| {
                    super::arm_signal::deliver_on_user_return_with(
                        &fixture.task,
                        fixture.control,
                        process,
                        frame,
                        fp.as_bytes(),
                        &mut machine,
                    )
                },
            )
            .unwrap()
        },
    );
    assert_eq!(settled, carrick_el1_abi::Action::Served);
    assert!(
        fixture.control.synchronous_fault().is_none(),
        "Busy once, then success must consume the retained fault"
    );
    assert!(
        fixture.zone.slot(fixture.slot).current().is_none(),
        "AdmissionHome::drop must leave the root slot without a lingering zone record"
    );
    assert_eq!(
        frame.elr, 0x40_0100,
        "installed handler must run instead of default termination"
    );
    let offset = (frame.x[1] - stack.va().raw()) as usize;
    let signal = carrick_personality_linux::signal::arm::SignalFrame::ref_from_bytes(
        &stack.as_bytes()[offset
            ..offset + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
    )
    .unwrap();
    let info = signal.rt.siginfo;
    let (signum, code, address) = (info.si_signo, info.si_code, info.si_addr);
    assert_eq!(
        (signum, code, address),
        (11, 2, crate::mm_portal::test_support::VA)
    );
}

#[test]
fn arm_permission_fault_sig_dfl_terminates_through_native_owner() {
    use carrick_signal_core::policy::{Action, Disposition, Signal};
    use zerocopy::IntoBytes;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let ignore = Action {
        disposition: Disposition::Ignore,
        ..Default::default()
    };
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(Signal::PIPE, Some(ignore))
                    .unwrap();
            },
        )
        .unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x9200_004f,
        far: crate::mm_portal::test_support::VA,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let mut machine = ArmWaitSignalMachine {
        user_sp: UserVa::new(0x7000),
        backend: ArmWaitSignalBackend,
    };
    assert_eq!(
        super::dispatch::arm_deliver_declined_fault_signal_with(
            source,
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut None,
            |process, frame| super::arm_signal::deliver_on_user_return_with(
                &fixture.task,
                fixture.control,
                process,
                frame,
                fp.as_bytes(),
                &mut machine,
            ),
        )
        .unwrap(),
        carrick_el1_abi::Action::Idle,
    );
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        service.crossing.root_exit_status.load(Ordering::Acquire),
        11
    );
}

#[test]
fn arm_permission_fault_two_live_threads_delivers_handler_and_sig_dfl_parks_group_exit() {
    use carrick_el1_abi::Lifecycle;
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use zerocopy::IntoBytes;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let handler = Action {
        disposition: Disposition::Handler(HandlerAddress(0x40_0100)),
        ..Default::default()
    };
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(Signal::SEGV, Some(handler))
                    .unwrap();
            },
        )
        .unwrap();
    let (_sibling_control, _) = imported_thread(fixture);
    assert_eq!(fixture.page.live(), 2);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let sp = stack.va_at(stack.len());
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x9200_004f,
        far: crate::mm_portal::test_support::VA,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let mut machine = ArmWaitSignalMachine {
        user_sp: sp,
        backend: ArmWaitSignalBackend,
    };
    assert_eq!(
        super::dispatch::arm_deliver_declined_fault_signal_with(
            source,
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut None,
            |process, frame| super::arm_signal::deliver_on_user_return_with(
                &fixture.task,
                fixture.control,
                process,
                frame,
                fp.as_bytes(),
                &mut machine,
            ),
        )
        .unwrap(),
        carrick_el1_abi::Action::Served,
    );
    assert_eq!(frame.elr, 0x40_0100);
    assert_eq!(fixture.page.live(), 2);

    // Reset SIGSEGV to SIG_DFL with two live threads: declined fault initiates
    // group exit and parks the caller until the sibling retires.
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(Signal::SEGV, Some(Action::default()))
                    .unwrap();
            },
        )
        .unwrap();
    assert_eq!(
        super::dispatch::arm_deliver_declined_fault_signal_with(
            source,
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut None,
            |process, frame| super::arm_signal::deliver_on_user_return_with(
                &fixture.task,
                fixture.control,
                process,
                frame,
                fp.as_bytes(),
                &mut machine,
            ),
        )
        .unwrap(),
        carrick_el1_abi::Action::Idle,
    );
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
    assert!(fixture.task.linux.has_pending_host_work());
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
}

#[test]
fn arm_signal_setup_uses_one_native_owner() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let signal = carrick_signal_core::policy::Signal::from_number(13).unwrap();
    let action = carrick_signal_core::policy::Action {
        disposition: carrick_signal_core::policy::Disposition::Ignore,
        ..Default::default()
    };
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(signal, Some(action))
                    .unwrap();
            },
        )
        .unwrap();
    for (nr, args, expected) in [
        (134, [13, 0, 0, 8, 0, 0], 0),
        (135, [0, 0, 0, 8, 0, 0], 0),
        (132, [0, 0, 0, 0, 0, 0], 0),
    ] {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
        assert_ne!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Forward,
            "ARM signal syscall {nr} escaped to the carrier"
        );
        assert_eq!(frame.x[0] as i64, expected, "ARM signal syscall {nr}");
    }
}

#[test]
fn arm_native_signal_calls_route_to_shared_owner() {
    use carrick_personality_linux::dispatch::{Family, route_aarch64};
    use carrick_personality_linux::signal::SignalCall;

    for (ordinal, call) in [
        (129, SignalCall::Kill),
        (130, SignalCall::Tkill),
        (131, SignalCall::Tgkill),
        (133, SignalCall::RtSigsuspend),
        (136, SignalCall::RtSigpending),
        (137, SignalCall::RtSigtimedwait),
        (138, SignalCall::RtSigqueueinfo),
        (240, SignalCall::RtTgsigqueueinfo),
    ] {
        assert_eq!(
            route_aarch64(ordinal, u64::MAX),
            Family::Signal(call),
            "ARM signal syscall {ordinal} must use the shared process owner"
        );
    }
}

#[test]
fn arm_native_sigsuspend_dispatches_to_owned_continuation() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let mask = carrick_test_support::GuestUserBuffer::from_value(0u64);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = mask.arg();
    frame.x[1] = 8;
    frame.x[8] = 133;

    let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended,
        "rt_sigsuspend must park its owned continuation instead of forwarding"
    );
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
}

#[test]
fn native_child_sigsuspend_wakes_from_parent_signal() {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, SigBlockMask, Signal};

    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let child_task = CurrentTask::new();
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
    let crossing = TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ]);
    let mut parent_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);

    let child_pid = {
        let mut parent = runtime
            .enter(source, &fixture.task, parked, &mut parent_service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent.fork(ProcessForkChildTid::NONE)
        else {
            panic!("fork must return the native child pid")
        };
        result.raw() as u32
    };
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate(source, &child_task, &child_binding);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    {
        let mut child = runtime
            .enter(source, &child_task, child_binding.words, &mut child_service)
            .unwrap();
        child
            .rt_sigaction(
                Signal::from_number(10).unwrap(),
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x700000)),
                    ..Action::default()
                }),
            )
            .unwrap();
        assert_eq!(
            child.rt_sigsuspend(SigBlockMask::NONE, SigBlockMask::NONE),
            Ok(true)
        );
        assert!(child.take_handoff_receipt().is_some());
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());

    activate(source, &fixture.task, &parent_binding);
    {
        let mut parent = runtime
            .enter(
                source,
                &fixture.task,
                parent_binding.words,
                &mut parent_service,
            )
            .unwrap();
        parent
            .kill(
                SignalProcessSelector::from_abi(u64::from(child_pid)),
                SignalRequest::from_abi(10).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate(source, &child_task, &child_binding);
    let mut child = runtime
        .enter(source, &child_task, child_binding.words, &mut child_service)
        .unwrap();
    assert!(
        matches!(child.resume_pending_wait(), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == carrick_syscall_abi::LINUX_EINTR.guest_retval())
    );
    assert_eq!(child.take_suspend_mask(), Some(SigBlockMask::NONE));
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
        frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        || false,
    )
}

#[cfg(test)]
fn run_as(fixture: &Fixture, tid: i32, generation: u64, serial: u64, control: &ThreadControlSlot) {
    // This low-level fixture publishes an already-issued member directly.
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            use carrick_sched_core::process::identity_allocator::{
                ClaimKind, VisibleIdentity, VisibleNamespace,
            };
            if !ns.is_reserved_number(tid) {
                ns.reserve_exact(tid, ClaimKind::Thread).unwrap();
            }
            let domain = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
            ns.bind_visible_domain(tid, domain).unwrap();
            if let Some(visible) = control.visible_tid().and_then(NonZeroU32::new) {
                ns.advance_visible_past(domain, VisibleIdentity::from_existing_member(visible))
                    .unwrap();
            }
        });
    // Between two threads' calls the host boundary consumes both owed-work
    // flags (`settle_el1_boundary`) before it binds the next thread.
    let _ = fixture.task.linux.take_served_boundary();
    if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }
    fixture.task.set(
        El1TaskId::from_linux_tid(tid),
        carrick_el1_abi::SnapshotGeneration::from_raw(generation),
        fixture.leader.file_table,
    );
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
    run_as(
        fixture,
        fixture.leader.tid as i32,
        fixture.leader.generation,
        fixture.leader.serial,
        fixture.control,
    );
}

/// A sibling the host cloned because the in-ring pool was empty: an issued
/// execution binding and a retained control slot, but no pool entry.
#[cfg(test)]
fn host_born_sibling(fixture: &Fixture, visible_tid: u32) -> &'static ThreadControlSlot {
    let mut binding_tid = 0;
    for _ in 0..64 {
        let (issued_tid, reservation) = fixture.host_ids.reserve_thread().unwrap();
        fixture
            .host_threads
            .lock()
            .unwrap()
            .push(reservation.commit());
        binding_tid = issued_tid.raw() as u32;
        if binding_tid >= visible_tid {
            break;
        }
    }
    assert!(binding_tid >= visible_tid);
    let generation = u64::from(binding_tid - 30);
    let thread_generation = u64::from(binding_tid + 60);
    fixture.zone.namespace().with_view(&carrick_sched_core::ShortLockSpin, |ns| {
        ns.advance_visible_past(carrick_sched_core::process::identity_allocator::VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN), carrick_sched_core::process::identity_allocator::VisibleIdentity::from_existing_member(NonZeroU32::new(visible_tid).unwrap())).unwrap();
    });
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    control
        .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
        .unwrap();
    assert!(control.publish_visible_tid(visible_tid));
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_el1_abi::EntryTaskKey::from_raw(u64::from(binding_tid)),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(generation).unwrap(),
            ),
            carrick_el1_abi::EntryThreadGeneration::from_raw(thread_generation),
        )
        .unwrap(),
    );
    let birth_slot = fixture.page.reserve_host_birth().expect("host birth slot");
    carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
    assert!(
        fixture
            .page
            .publish_host_birth(birth_slot, control.host_birth_identity().unwrap())
    );
    run_as(
        fixture,
        binding_tid as i32,
        generation,
        thread_generation,
        control,
    );
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

/// The tgkill-after-clone fixture's peer probes a nonleader tid with kill(2).
/// Linux accepts that tid even though it is not a process group leader.
#[test]
fn arm_kill_probe_resolves_a_live_nonleader_tid() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    // Adopt the host-issued sibling through its real first syscall entry.
    let mut first = carrick_el1_abi::TrapFrame::default();
    first.x[8] = 178;
    arm_call(fixture, control, &mut service, &mut first).unwrap();
    assert_eq!(first.x[0], 42);
    let live_members = carrick_el1_abi::Lifecycle::live(fixture.page);
    assert_eq!(live_members, 2);
    assert!(leader_sees_thread(fixture, &mut service, 42));
    let mut probe = carrick_el1_abi::TrapFrame::default();
    probe.x[8] = 129; // kill(nonleader_tid, 0)
    probe.x[0] = 42;
    arm_call(fixture, fixture.control, &mut service, &mut probe).unwrap();
    assert_eq!(
        probe.x[0] as i64, 0,
        "kill must resolve a live nonleader tid"
    );
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
    // Its raw exit has no pool entry to retire in ring: host custody returns
    // an exact receipt before the owner drops the member.
    frame.x = [0; 31];
    frame.x[8] = 93;
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::HostCustody
    );
    assert_eq!(frame.x[0], 0, "host custody keeps its status argument");
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    assert!(leader_sees_thread(fixture, &mut service, 42));
    let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
        carrick_core_abi::entry::EntryTaskKey::from_raw(42),
        carrick_core_abi::entry::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
        ),
        carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
    )
    .unwrap();
    carrick_el1_abi::Lifecycle::reserve_nonfinal_exit(fixture.page)
        .unwrap()
        .publish();
    fixture
        .page
        .publish_exact_host_retirement(control, receipt.retirement());
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    assert!(!leader_sees_thread(fixture, &mut service, 42));
    assert!(leader_sees_thread(fixture, &mut service, 41));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
}

#[test]
fn arm_host_birth_first_syscall_adopts_during_fork_and_exec_gate() {
    use carrick_el1_abi::Lifecycle;
    for awaiting_exec in [false, true] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |_| (),
            )
            .unwrap();
        let control = host_born_sibling(fixture, 42);
        fixture.page.close_for_fork().unwrap();
        if awaiting_exec {
            fixture.page.await_exec_binding().unwrap();
        }
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 178; // gettid is the host-born thread's first syscall.
        assert_eq!(
            arm_call(fixture, control, &mut service, &mut frame).unwrap(),
            carrick_personality_linux::dispatch::CompletionRoute::WithWork,
            "awaiting_exec={awaiting_exec}"
        );
        assert_eq!(frame.x[0], 42);
        assert!(
            (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
                .all(|index| fixture.page.host_birth_identity(index).is_none())
        );
        if awaiting_exec {
            fixture.page.reopen_after_exec_binding().unwrap();
        } else {
            fixture.page.reopen_after_fork().unwrap();
        }
    }
}

#[cfg(test)]
#[test]
fn arm_registered_sibling_switch_in_without_pending_owner_work() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
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
    let sibling = host_born_sibling(fixture, 42);
    let mut syscall = carrick_el1_abi::TrapFrame::default();
    syscall.x[8] = 178;
    arm_call(fixture, sibling, &mut service, &mut syscall).unwrap();
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let record = sibling.zone_record().unwrap().id;
    // SAFETY: the fixture owns the stopped sibling record.
    unsafe {
        *fixture.zone.record(record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record)
            .is_queued()
    );
    let mut cpu = ResumeCpu {
        inner: crate::sched::FakeCpu::default(),
        runtime: &runtime,
        registry: registry(),
        source,
        task: &fixture.task,
        service: &mut service,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        (crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .run_next(&mut frame, 0),
        crate::sched::Served::Returned { switched: true }
    );
    assert_eq!(fixture.task.visible_pid(), Some(41));
}

#[test]
#[should_panic(expected = "native aarch64 process service failure")]
fn arm_invalid_resume_fails_closed_in_production_mapping() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let _ = map_resume(
        super::native_process_runtime::NativeResume::Invalid,
        &mut service,
        &fixture.task,
        fixture.slot,
    );
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
            Defect::UnissuedGeneration => fixture.task.execution.generation.store(
                carrick_el1_abi::SnapshotGeneration::UNISSUED,
                Ordering::Release,
            ),
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
                foreign
                    .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
                    .unwrap();
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
            &ThreadCtx::ZERO,
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
fn arm_two_live_threads_robust_exit_retires_in_ring() {
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
    // Every glibc thread registers a robust list at start.
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
    // No lane walks a robust list yet, so it is no reason to leave the ring
    // (#2109): with a live sibling the raw exit retires only this thread, in
    // ring, exactly as an exit without a list does.
    frame.x = [0; 31];
    frame.x[8] = 93;
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert!(!control.host_exit_requested());
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 1);
    assert!(registry().for_record(fixture.zone, record).is_none());
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    run_as_leader(fixture);
    assert!(!leader_sees_thread(fixture, &mut service, 42));
    assert!(leader_sees_thread(fixture, &mut service, 41));
}

#[test]
fn arm_raw_exit_refused_copy_after_membership_reservation_restores_live() {
    use carrick_el1_abi::Lifecycle;
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
    // A refused clear_child_tid copy is checked only after the nonfinal
    // membership reservation. The exit keeps its call (#2359), and the page
    // must still see both memberships until it reruns. The word is guest
    // user memory: a host stack address lies above the guest ceiling on an
    // ARM64 Linux host and would refuse as a real fault.
    let child_tid = carrick_test_support::GuestUserValue::new(42_u32);
    control.set_clear_child_tid(child_tid.arg());
    let live = fixture.page.live();
    let entry = control.entry().unwrap();
    let state = fixture.page.state(entry.index());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let route = arm_call(fixture, control, &mut service, &mut frame);
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    let route = route.unwrap();
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody
    );
    assert_ne!(
        frame.x[0] as i64,
        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
        "an exit never returns EFAULT"
    );
    assert_eq!(frame.x[8], 93, "the rerun is the same exit");
    assert_eq!(fixture.page.live(), live);
    assert_eq!(child_tid.get(), 42);
    fixture.zone.clear_current(fixture.slot);
    assert_eq!(fixture.page.state(entry.index()), state);
    assert!(leader_sees_thread(fixture, &mut service, 42));
}

/// #2359 on ARM: a clone thread's raw `exit` whose clear-child-tid copy-out
/// is refused "not now" (the word's page is not yet writable through the
/// hardware copy; the owner can make it so) keeps its owned call. Its
/// membership and admission are restored, the owner prepares the word for
/// writing, and the exit reruns in ring, where it clears the word. Before,
/// the refusal declined to `HostCustody`: a ring-born member has no host
/// task to take that exit.
#[test]
fn arm_raw_exit_refused_clear_tid_copy_reruns_in_ring() {
    use carrick_el1_abi::Lifecycle;
    let words = Box::leak(Box::new(carrick_test_support::GuestUserBuffer::zeroed(
        0x4000,
    )));
    let tid_word = words.arg();
    let fixture = Box::leak(Box::new(Fixture::with_private_anonymous(
        0x10000,
        asid(1),
        carrick_el1_abi::ReservationRange::new(tid_word, tid_word + 0x4000).unwrap(),
    )));
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
    words.set::<u32>(0, 42);
    control.set_clear_child_tid(tid_word);
    let live = fixture.page.live();
    let entry = control.entry().unwrap();
    let state = fixture.page.state(entry.index());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let route = arm_call(fixture, control, &mut service, &mut frame);
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    let route = route.unwrap();
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody,
        "a refused clear-tid copy-out is not now, never a host exit"
    );
    // Nothing was committed: the call reruns from a live member.
    assert_eq!(words.get::<u32>(0), 42);
    assert_eq!(fixture.page.live(), live);
    assert_eq!(fixture.page.state(entry.index()), state);
    assert_eq!(frame.x[8], 93, "the rerun is the same exit");

    // The rerun finds the word writable and retires the thread in ring.
    let route = arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody
    );
    assert_eq!(words.get::<u32>(0), 0, "exit cleared the CLEARTID word");
    assert_eq!(fixture.page.live(), live - 1);
    assert!(!leader_sees_thread(fixture, &mut service, 42));
}

/// glibc's `pthread_join` (#2124), on the production AArch64 entry with the
/// ARM scheduler: the joiner waits on the child's CLEARTID word with shared
/// `FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME` (op 265), NULL timeout and
/// `FUTEX_BITSET_MATCH_ANY`, as the Docker oracle traced it. The child's raw
/// `exit` clears the word and its clear-child-tid wake must release the
/// joiner with 0. Before the fix, op 265 was not admitted on ARM: it was
/// forwarded and answered ENOSYS, which glibc treats as fatal.
#[test]
fn arm_glibc_pthread_join_shared_bitset_wait_wakes_on_child_exit() {
    // The joined CLEARTID word lives in private anonymous memory (glibc's
    // thread descriptor sits in the mmap'd thread stack).
    let words = Box::leak(Box::new(carrick_test_support::GuestUserBuffer::zeroed(
        0x4000,
    )));
    let tid_word = words.arg();
    let fixture = Box::leak(Box::new(Fixture::with_private_anonymous(
        0x10000,
        asid(1),
        carrick_el1_abi::ReservationRange::new(tid_word, tid_word + 0x4000).unwrap(),
    )));
    let (control, child) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    // CLONE_CHILD_SETTID published the child's tid in the joined word.
    words.set::<u32>(0, 42);
    let mut join = carrick_el1_abi::TrapFrame::default();
    join.x[8] = crate::sched::SYS_FUTEX as u64;
    join.x[0] = tid_word;
    join.x[1] = 265;
    join.x[2] = 42;
    join.x[5] = 0xffff_ffff;
    let route =
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut join, &mut cpu).unwrap();
    assert_ne!(
        join.x[0] as i64, -38,
        "ENOSYS aborts glibc: the futex facility returned an unexpected error code"
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served,
        "the join parks in ring; it is never forwarded"
    );
    // The joiner's own record (the leader, tid 41) parked on the word.
    let leader = (1..carrick_sched_core::ZONE_RECORDS as u32)
        .filter_map(carrick_sched_core::RecordId::from_raw)
        .find(|&id| {
            fixture.zone.record(id).identity().tid == 41
                && matches!(
                    fixture.zone.record(id).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                )
        })
        .expect("the joiner is parked on the CLEARTID word");
    // The park ran the queued child on this slot.
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child.id));

    run_as(fixture, 42, 12, 102, control);
    control.set_clear_child_tid(tid_word);
    let mut exit = carrick_el1_abi::TrapFrame::default();
    exit.x[8] = 93;
    arm_call_with_cpu(fixture, control, &mut service, &mut exit, &mut cpu).unwrap();
    assert_eq!(words.get::<u32>(0), 0, "exit cleared the CLEARTID word");
    assert!(
        matches!(
            fixture.zone.record(leader).claim(),
            carrick_sched_core::Claim::Queued { .. }
        ),
        "the clear-child-tid wake released the joiner, found {:?}",
        fixture.zone.record(leader).claim()
    );
    // The slot runs the woken joiner next, with the futex's completion.
    run_as_leader(fixture);
    let counters = carrick_el1_abi::Counters::new();
    let mut resumed = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        }
        .run_ready(&mut resumed),
        Some(crate::sched::Served::Returned { switched: true })
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(leader));
    assert_eq!(resumed.x[0], 0, "pthread_join's futex returns 0");
}

/// A joiner parked on a private-anonymous CLEARTID word with `wait_op`
/// (`FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME` when 265), then the child
/// issues `wake_op` through the production AArch64 entry. Returns whether
/// the wake released the joiner, and the wake's count; a still-parked joiner
/// is cleaned up with a private wake that must find it.
#[cfg(test)]
fn shared_wake_meets_wait(wait_op: u64, wake_op: u64) -> (bool, i64) {
    let words = Box::leak(Box::new(carrick_test_support::GuestUserBuffer::zeroed(
        0x4000,
    )));
    let tid_word = words.arg();
    let fixture = Box::leak(Box::new(Fixture::with_private_anonymous(
        0x10000,
        asid(1),
        carrick_el1_abi::ReservationRange::new(tid_word, tid_word + 0x4000).unwrap(),
    )));
    let (control, child) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    words.set::<u32>(0, 42);
    let mut wait = carrick_el1_abi::TrapFrame::default();
    wait.x[8] = crate::sched::SYS_FUTEX as u64;
    wait.x[0] = tid_word;
    wait.x[1] = wait_op;
    wait.x[2] = 42;
    wait.x[5] = 0xffff_ffff;
    let route =
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut wait, &mut cpu).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served,
        "the wait parks in ring; it is never forwarded"
    );
    let waiter = (1..carrick_sched_core::ZONE_RECORDS as u32)
        .filter_map(carrick_sched_core::RecordId::from_raw)
        .find(|&id| {
            fixture.zone.record(id).identity().tid == 41
                && matches!(
                    fixture.zone.record(id).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                )
        })
        .expect("the waiter is parked on the word");
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child.id));

    run_as(fixture, 42, 12, 102, control);
    let mut wake = carrick_el1_abi::TrapFrame::default();
    wake.x[8] = crate::sched::SYS_FUTEX as u64;
    wake.x[0] = tid_word;
    wake.x[1] = wake_op;
    wake.x[2] = 1;
    wake.x[5] = 0xffff_ffff;
    arm_call_with_cpu(fixture, control, &mut service, &mut wake, &mut cpu).unwrap();
    let count = wake.x[0] as i64;
    let released = matches!(
        fixture.zone.record(waiter).claim(),
        carrick_sched_core::Claim::Queued { .. }
    );
    if !released {
        assert!(
            matches!(
                fixture.zone.record(waiter).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ),
            "found {:?}",
            fixture.zone.record(waiter).claim()
        );
        // Clean up: the private wake meets the private waiter.
        let mut cleanup = carrick_el1_abi::TrapFrame::default();
        cleanup.x[8] = crate::sched::SYS_FUTEX as u64;
        cleanup.x[0] = tid_word;
        cleanup.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
        cleanup.x[2] = 1;
        arm_call_with_cpu(fixture, control, &mut service, &mut cleanup, &mut cpu).unwrap();
        assert_eq!(cleanup.x[0], 1, "the private wake finds the private waiter");
        assert!(matches!(
            fixture.zone.record(waiter).claim(),
            carrick_sched_core::Claim::Queued { .. }
        ));
    }
    (released, count)
}

/// A shared `FUTEX_WAKE` (op 1) releases a shared waiter on the same word of
/// private anonymous memory, through the production AArch64 entry (#2124).
#[test]
fn arm_shared_futex_wake_releases_a_shared_waiter() {
    for wait_op in [0, 265] {
        assert_eq!(
            shared_wake_meets_wait(wait_op, 1),
            (true, 1),
            "shared wait op {wait_op}"
        );
    }
    // FUTEX_WAKE_BITSET (op 10) with MATCH_ANY is the same shared key.
    assert_eq!(shared_wake_meets_wait(265, 10), (true, 1));
}

/// Linux keeps private and shared keys distinct: a shared wake never finds a
/// private waiter on the same word.
#[test]
fn arm_shared_futex_wake_does_not_release_a_private_waiter() {
    assert_eq!(
        shared_wake_meets_wait(crate::sched::FUTEX_WAIT_PRIVATE, 1),
        (false, 0)
    );
}

/// How the joined thread's raw `exit` leaves in the pthread_join witnesses.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinedExit {
    /// A thread-directed pending signal declines the exit to host custody:
    /// the host's retirement clears the CLEARTID word and wakes the join.
    HostRetirement,
    /// glibc's robust list is registered and the exit retires in ring, whose
    /// own clear-child-tid wake releases the join (#2109).
    RobustInRing,
}

// Host queue completion of an in-ring join (#2124): a raw exit that leaves for
// host custody, whose retirement's clear-child-tid wake must meet the
// in-ring waiter's key. Before #2109 the robust list was the decline that
// took glibc's exit there; a pending signal still does.
#[test]
fn arm_glibc_pthread_join_host_retirement_wake_meets_ring_wait() {
    glibc_pthread_join_meets_ring_wait(JoinedExit::HostRetirement);
}

/// #2109: glibc's robust-registered thread exit retires in ring, and its
/// clear-child-tid wake releases the in-ring join.
#[test]
fn arm_glibc_pthread_join_robust_exit_in_ring_wakes_ring_wait() {
    glibc_pthread_join_meets_ring_wait(JoinedExit::RobustInRing);
}

#[cfg(test)]
fn glibc_pthread_join_meets_ring_wait(how: JoinedExit) {
    // The joined CLEARTID word lives in private anonymous memory (glibc's
    // thread descriptor sits in the mmap'd thread stack).
    let words = Box::leak(Box::new(carrick_test_support::GuestUserBuffer::zeroed(
        0x4000,
    )));
    let tid_word = words.arg();
    let fixture = Box::leak(Box::new(Fixture::with_private_anonymous(
        0x10000,
        asid(1),
        carrick_el1_abi::ReservationRange::new(tid_word, tid_word + 0x4000).unwrap(),
    )));
    let (control, child) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    // CLONE_CHILD_SETTID published the child's tid in the joined word.
    words.set::<u32>(0, 42);
    let mut join = carrick_el1_abi::TrapFrame::default();
    join.x[8] = crate::sched::SYS_FUTEX as u64;
    join.x[0] = tid_word;
    join.x[1] = 265;
    join.x[2] = 42;
    join.x[5] = 0xffff_ffff;
    let route =
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut join, &mut cpu).unwrap();
    assert_ne!(
        join.x[0] as i64, -38,
        "ENOSYS aborts glibc: the futex facility returned an unexpected error code"
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served,
        "the join parks in ring; it is never forwarded"
    );
    // The joiner's own record (the leader, tid 41) parked on the word.
    let leader = (1..carrick_sched_core::ZONE_RECORDS as u32)
        .filter_map(carrick_sched_core::RecordId::from_raw)
        .find(|&id| {
            fixture.zone.record(id).identity().tid == 41
                && matches!(
                    fixture.zone.record(id).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                )
        })
        .expect("the joiner is parked on the CLEARTID word");
    // The park ran the queued child on this slot.
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child.id));

    run_as(fixture, 42, 12, 102, control);
    control.set_clear_child_tid(tid_word);
    // glibc's thread start registers its robust list.
    let mut robust = carrick_el1_abi::TrapFrame::default();
    robust.x[8] = 99;
    robust.x[0] = tid_word + 0x100;
    robust.x[1] = 24;
    arm_call_with_cpu(fixture, control, &mut service, &mut robust, &mut cpu).unwrap();
    assert_eq!(robust.x[0], 0);
    assert_ne!(control.robust_list().0, 0);
    if how == JoinedExit::HostRetirement {
        let _ = control
            .carrier_pending()
            .post_then_read_blocked(carrick_el1_abi::PendingSignals(1 << 9), control);
    }
    let mut exit = carrick_el1_abi::TrapFrame::default();
    exit.x[8] = 93;
    let route = arm_call_with_cpu(fixture, control, &mut service, &mut exit, &mut cpu).unwrap();
    match how {
        JoinedExit::HostRetirement => {
            assert_eq!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::HostCustody,
            );
            // Host retirement's clear-child-tid copyout and raw-address queue wake.
            words.set::<u32>(0, 0);
            let wake = carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                carrick_kernel::el1_zone::FutexQueueAuthority::of_mm(
                    carrick_kernel::kernel::MmId::from_raw_u64(1).unwrap(),
                )
                .wake_child_tid(&carrick_kernel::thread::FutexTable::new(), tid_word)
            });
            assert_eq!(
                wake.count, 1,
                "host retirement must meet the in-ring join key"
            );
            assert!(
                wake.handed.is_empty(),
                "native completion keeps ring custody"
            );
        }
        JoinedExit::RobustInRing => {
            assert_eq!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Suspended,
                "a registered robust list is no reason to leave the ring"
            );
            assert!(!control.host_exit_requested());
        }
    }
    assert_eq!(words.get::<u32>(0), 0, "exit cleared the CLEARTID word");
    assert!(
        matches!(
            fixture.zone.record(leader).claim(),
            carrick_sched_core::Claim::Queued { .. }
        ),
        "the clear-child-tid wake released the joiner, found {:?}",
        fixture.zone.record(leader).claim()
    );
    // The slot runs the woken joiner next, with the futex's completion.
    run_as_leader(fixture);
    let counters = carrick_el1_abi::Counters::new();
    let mut resumed = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        }
        .run_ready(&mut resumed),
        Some(crate::sched::Served::Returned { switched: true })
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(leader));
    assert_eq!(resumed.x[0], 0, "pthread_join's futex returns 0");
}

/// A shared futex on an owned word while another lane holds the MM root:
/// authenticating the word's mapping is contention, never an errno and
/// never a wait or wake on an unauthenticated key. The syscall retries on
/// the holder's release with its registers intact (`Suspended`); the
/// futex-entry owner-wait episodes cover the resumed rerun. glibc's join
/// wait (op 265) authenticates after policy decodes it, a shared
/// `FUTEX_WAKE` (op 1) before policy, since a wake always finishes once
/// served.
#[test]
fn arm_shared_futex_mapping_owner_held_retries_the_syscall() {
    shared_futex_mapping_owner_held([0, 265, 42, 0, 0, 0xffff_ffff]);
    shared_futex_mapping_owner_held([0, 1, 1, 0, 0, 0]);
}

#[cfg(test)]
fn shared_futex_mapping_owner_held(args: [u64; 6]) {
    let words = Box::leak(Box::new(carrick_test_support::GuestUserBuffer::zeroed(
        0x4000,
    )));
    let tid_word = words.arg();
    let fixture = Box::leak(Box::new(Fixture::with_private_anonymous(
        0x10000,
        asid(1),
        carrick_el1_abi::ReservationRange::new(tid_word, tid_word + 0x4000).unwrap(),
    )));
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    words.set::<u32>(0, 42);
    let mut call = carrick_el1_abi::TrapFrame::default();
    call.x[8] = crate::sched::SYS_FUTEX as u64;
    call.x[..6].copy_from_slice(&args);
    call.x[0] = tid_word;
    // A word outside private anonymous memory has no shared-private key: the
    // shared op stays unrouted, as before.
    let unowned = carrick_test_support::GuestUserBuffer::from_value(42_u32);
    let mut elsewhere = call;
    elsewhere.x[0] = unowned.arg();
    assert_eq!(
        arm_call_with_cpu(
            fixture,
            fixture.control,
            &mut service,
            &mut elsewhere,
            &mut cpu
        )
        .unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "op {}",
        args[1]
    );
    if args[1] == 1 {
        // An owned word with no waiter: served in ring, waking nobody.
        let mut wake = call;
        assert_eq!(
            arm_call_with_cpu(fixture, fixture.control, &mut service, &mut wake, &mut cpu).unwrap(),
            carrick_personality_linux::dispatch::CompletionRoute::Served
        );
        assert_eq!(wake.x[0], 0);
    }
    let saved = call;
    let portal = super::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    );
    let held = portal.root_any(ReservationMm::new(1).unwrap(), 1).unwrap();
    let route =
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut call, &mut cpu).unwrap();
    drop(held);
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended,
        "a held mapping owner retries op {}",
        args[1]
    );
    assert_eq!(call.x, saved.x, "no errno: the retry reruns the same call");
    assert!(
        (1..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(carrick_sched_core::RecordId::from_raw)
            .all(|id| !matches!(
                fixture.zone.record(id).claim(),
                carrick_sched_core::Claim::Parked { .. }
            )),
        "nothing enrols before the mapping is authenticated"
    );
}

#[test]
fn arm_two_live_threads_exit_group_ends_group_with_status() {
    use carrick_el1_abi::Lifecycle;
    #[derive(Clone, Copy, Debug)]
    enum Siblings {
        Pooled,
        PooledDifferentExecutionGeneration,
        AdoptedHostBorn,
        /// One owned member plus a host-born thread the owner never adopted.
        PooledAndUnadoptedHostBorn,
    }
    for siblings in [
        Siblings::Pooled,
        Siblings::PooledDifferentExecutionGeneration,
        Siblings::AdoptedHostBorn,
        Siblings::PooledAndUnadoptedHostBorn,
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let pooled = (!matches!(siblings, Siblings::AdoptedHostBorn)).then(|| {
            imported_thread_with_identity(fixture, |identity| {
                if matches!(siblings, Siblings::PooledDifferentExecutionGeneration) {
                    // Host snapshot generations and process incarnations are
                    // independent in production. The pool receipt remains 12.
                    identity.generation = 1;
                }
            })
        });
        let mut adopted_control = None;
        let mut unadopted_control = None;
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
            Siblings::Pooled | Siblings::PooledDifferentExecutionGeneration => {}
            Siblings::AdoptedHostBorn => {
                let control = host_born_sibling(fixture, 42);
                adopted_control = Some(control);
                let mut frame = carrick_el1_abi::TrapFrame::default();
                frame.x[8] = 178; // gettid adopts the sibling
                arm_call(fixture, control, &mut service, &mut frame).unwrap();
            }
            Siblings::PooledAndUnadoptedHostBorn => {
                unadopted_control = Some(host_born_sibling(fixture, 43));
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
        assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
        assert_eq!(
            service.crossing.root_exit_status.load(Ordering::Acquire),
            u64::MAX
        );
        assert_eq!(
            carrick_el1_abi::Lifecycle::live(fixture.page),
            live - 1,
            "{siblings:?}"
        );
        assert_eq!(service.crossing.retirements.load(Ordering::Acquire), 0);
        if matches!(siblings, Siblings::AdoptedHostBorn) {
            let control = adopted_control.unwrap();
            assert!(
                control.host_exit_requested(),
                "Closing must request host retirement even after the sibling's admission record was released"
            );
            let identity = control.host_birth_identity().unwrap();
            assert!(
                (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
                    .all(|index| fixture.page.host_birth_identity(index) != Some(identity))
            );
            assert!(!fixture.page.release_adopted_host_birth(identity));
        }
        assert_eq!(
            carrick_el1_abi::Lifecycle::gate(fixture.page),
            carrick_el1_abi::GateState::Closed,
            "no new thread may be born into an exited group"
        );
        if let Some((control, record)) = pooled {
            assert!(control.host_exit_requested());
            assert!(fixture.zone.live(record).is_some());
            assert!(!fixture.zone.record(record.id).is_cancelled());
            let retirement = fixture.page.reserve_cancelled_member_exit().unwrap();
            if matches!(
                fixture.page.state(control.entry().unwrap().index()),
                Some((_, carrick_el1_abi::EntryState::Born))
            ) {
                fixture.page.publish(control.entry().unwrap()).unwrap();
            }
            fixture
                .page
                .retire_published_host_member(
                    control.entry().unwrap(),
                    control,
                    retirement,
                    &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
                )
                .unwrap();
            let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::entry::EntryTaskKey::from_raw(42),
                carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
                ),
                carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
            )
            .unwrap();
            fixture
                .page
                .publish_exact_host_retirement(control, receipt.retirement());
            let _ = fixture.zone.claim_for_host(
                record,
                None,
                carrick_el1_abi::Handback::Cancelled,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            );
            assert!(fixture.zone.record(record.id).is_cancelled());
        }
        if let Some(control) = adopted_control {
            let stale = carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::entry::EntryTaskKey::from_raw(42),
                carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
                ),
                carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
            )
            .unwrap();
            control.publish_host_retirement(stale.retirement());
            fixture
                .page
                .reserve_cancelled_member_exit()
                .unwrap()
                .publish();
            assert!(matches!(
                wake_closing_root(fixture, &mut service),
                crate::sched::ResumeAction::Left
            ));
            assert_eq!(
                service.crossing.root_exits.load(Ordering::Acquire),
                0,
                "stale adopted receipt must not settle Closing"
            );
            let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::entry::EntryTaskKey::from_raw(42),
                carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
                ),
                carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
            )
            .unwrap();
            fixture
                .page
                .publish_exact_host_retirement(control, receipt.retirement());
        }
        if matches!(siblings, Siblings::PooledAndUnadoptedHostBorn) {
            let control = unadopted_control.expect("unadopted control");
            let identity = control.host_birth_identity().unwrap();
            assert!(
                (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
                    .any(|index| fixture.page.host_birth_identity(index) == Some(identity))
            );
            assert!(!fixture.page.release_adopted_host_birth(identity));
            assert!(fixture.page.host_birth_requested(identity));
            assert!(matches!(
                wake_closing_root(fixture, &mut service),
                crate::sched::ResumeAction::Left
            ));
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
            fixture
                .page
                .reserve_cancelled_member_exit()
                .unwrap()
                .publish();
            fixture
                .page
                .publish_exact_host_retirement(control, identity.retirement());
        }
        assert_eq!(fixture.page.live(), 0);
        assert!(matches!(
            wake_closing_root(fixture, &mut service),
            crate::sched::ResumeAction::Left
        ));
        assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
        assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
    }
}

/// #680: a host-born member's first execution can carry any snapshot
/// generation; its birth identity is fixed in its control slot. Adoption must
/// authenticate the birth identity, not a coincidence between the snapshot
/// generation and the process serial, and Closing must owe the birth receipt.
#[test]
fn arm_host_born_member_adopts_and_settles_at_an_unrelated_execution_generation() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    let birth = control.host_birth_identity().unwrap();
    // The host's first published snapshot of the sibling is unrelated to its
    // birth serial (production: ExecutionGeneration::INITIAL vs task serial).
    let first = birth.birth().raw() + 4221;
    run_as(fixture, 42, first, birth.thread().raw(), control);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 178; // gettid adopts the sibling at its first execution
    arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(frame.x[0], 42);
    assert!(
        (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
            .all(|index| fixture.page.host_birth_identity(index) != Some(birth)),
        "adoption consumed the exact host-birth slot"
    );
    // A later settlement republishes it at yet another snapshot generation.
    run_as(fixture, 42, first + 7, birth.thread().raw(), control);
    frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 178;
    arm_call(fixture, control, &mut service, &mut frame).unwrap();
    assert_eq!(frame.x[0], 42, "renewed execution retains its owner");
    assert!(leader_sees_thread(fixture, &mut service, 42));
    run_as_leader(fixture);
    frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94; // exit_group while the adopted sibling is live
    let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    fixture
        .page
        .reserve_cancelled_member_exit()
        .unwrap()
        .publish();
    fixture
        .page
        .publish_exact_host_retirement(control, birth.retirement());
    assert_eq!(fixture.page.live(), 0);
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        1,
        "the birth receipt settles Closing"
    );
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[cfg(test)]
fn arm_pool_raw_exit_closing_at_commit_boundary(
    recycle_entry: bool,
    recycle_control: Option<bool>,
) {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let arena: &'static carrick_kernel::kernel::objects::TestThreadControlArena = Box::leak(
        Box::new(carrick_kernel::kernel::objects::TestThreadControlArena::try_new().unwrap()),
    );
    let lease = arena.allocate(42).unwrap();
    // SAFETY: the arena and fixture outlive the call; the allocator owns the
    // backing even when its final host lease returns the slot to the free list.
    let control = unsafe { &*(lease.slot_address().raw() as *const ThreadControlSlot) };
    let (control, record) = imported_thread_on_control(fixture, control, |_| {});
    let mut worker_service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut worker_service,
            |_| (),
        )
        .unwrap();
    run_as(fixture, 42, 12, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let owner = registry()
        .register_thread(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();
    let root_service: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(fixture.process_service()));
    let root_service_address = root_service as *mut _ as usize;
    let fixture_address = fixture as *const Fixture as usize;
    let closing = Box::new(move || {
        // SAFETY: both allocations are leaked for this test, and the hook
        // completes before the outer raw-exit call uses either again.
        let fixture = unsafe { &*(fixture_address as *const Fixture) };
        let service = unsafe {
            &mut *(root_service_address
                as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
        };
        assert_eq!(
            fixture.page.expected_exit_receipt(control, control.entry()),
            carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
        );
        assert!(registry().for_record(fixture.zone, record).is_some());
        if recycle_entry {
            let entry = control.entry().unwrap();
            fixture.page.reap(entry).unwrap();
            let replacement = fixture
                .page
                .stock(
                    entry.index(),
                    carrick_el1_abi::EntryIdentity {
                        tid: 99,
                        visible_tid: 99,
                        thread_serial: 199,
                        birth: carrick_core_abi::entry::BirthSerial::of_task(
                            carrick_sched_core::process::TaskSerial::from_raw_u64(1).unwrap(),
                        ),
                        uid_credit: 0,
                    },
                )
                .unwrap();
            assert_ne!(replacement.generation(), entry.generation());
        }
        if let Some(rebind) = recycle_control {
            drop(lease);
            let replacement = arena.allocate(99).unwrap();
            if rebind {
                // E2 belongs to the new allocation's unpublished birth, not
                // the old member's lifecycle publication in this graph.
                replacement
                    .reset_for_birth(
                        carrick_el1_abi::BlockedMask(0),
                        0,
                        carrick_el1_abi::EntryRef::new(1, 1),
                    )
                    .unwrap();
            }
            // Keep the newly allocated incarnation live through exit_group.
            core::mem::forget(replacement);
        }
        fixture.zone.clear_current(fixture.slot);
        run_as_leader(fixture);
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[0] = 7;
        frame.x[8] = 94;
        assert_eq!(
            arm_call(fixture, fixture.control, service, &mut frame).unwrap(),
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
        assert_eq!(
            service.crossing.root_exits.load(Ordering::Acquire),
            1,
            "exit_group must settle before the old member unregisters"
        );
        run_as(fixture, 42, 12, 102, control);
    });
    owner.install_raw_exit_after_commit_hook(closing);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    assert_eq!(
        arm_call(fixture, control, &mut worker_service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    if recycle_control.is_some() {
        let recycled = arena.allocate(100).unwrap();
        assert_eq!(
            recycled.slot_address().raw(),
            control as *const _ as usize,
            "unregister must return the old slot to allocation"
        );
        assert!(recycled.entry().is_none());
    }
    assert!(registry().for_record(fixture.zone, record).is_none());
    assert_eq!(root_service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        root_service
            .crossing
            .root_exit_status
            .load(Ordering::Acquire),
        7
    );
}

#[test]
fn arm_pool_raw_exit_committed_before_unregister_owes_no_host_receipt() {
    arm_pool_raw_exit_closing_at_commit_boundary(false, None);
}

#[test]
fn arm_raw_exit_reaped_and_replenished_before_closing_owes_no_host_receipt() {
    arm_pool_raw_exit_closing_at_commit_boundary(true, None);
}

#[cfg(test)]
fn arm_non_graph_retired_pool_member(reallocate: bool, resetting: bool) {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    // This birth happens after the root graph snapshot and never enters ring.
    let arena = Box::leak(Box::new(
        carrick_kernel::kernel::objects::TestThreadControlArena::try_new().unwrap(),
    ));
    let lease = arena.allocate(42).unwrap();
    let address = lease.slot_address();
    // SAFETY: the leaked arena retains the free-list backing after lease drop.
    let control = unsafe { &*(address.raw() as *const ThreadControlSlot) };
    let (_, record) = imported_thread_on_control(fixture, control, |_| {});
    assert!(registry().for_record(fixture.zone, record).is_none());
    let entry = control.entry().unwrap();
    fixture.page.publish(entry).unwrap();
    let membership = fixture.page.reserve_nonfinal_exit().unwrap();
    fixture
        .page
        .retire_published_host_member(
            entry,
            control,
            membership,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
    let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
        carrick_core_abi::EntryTaskKey::from_raw(42),
        carrick_core_abi::entry::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
        ),
        carrick_core_abi::EntryThreadGeneration::from_raw(102),
    )
    .unwrap();
    fixture
        .page
        .publish_exact_host_retirement(control, receipt.retirement());
    fixture.zone.free_record(record.id);
    drop(lease);
    let reset = resetting.then(|| control.reserve_reset_for_test().unwrap());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        arm_call(fixture, fixture.control, &mut service, &mut frame)
    }));
    if outcome.is_err() {
        assert_eq!(
            fixture.page.live(),
            1,
            "fallible retention must precede begin_exit"
        );
        assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
    }
    assert_eq!(
        outcome
            .expect("Reaped reset must not quarantine exit_group")
            .unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    drop(reset);
    if reallocate {
        let replacement = arena.allocate(99).unwrap();
        assert_eq!(
            replacement.slot_address(),
            address,
            "Closing must not retain a Reaped free-list slot"
        );
    }
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        1,
        "a non-graph host-retired member must not strand Closing"
    );
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_non_graph_pool_member_host_retires_before_exit_group() {
    arm_non_graph_retired_pool_member(false, false);
}

#[test]
fn arm_reaped_free_list_slot_is_not_retained_by_closing() {
    arm_non_graph_retired_pool_member(true, false);
}

#[test]
fn arm_reaped_slot_reset_cannot_leave_partially_begun_exit() {
    arm_non_graph_retired_pool_member(false, true);
}

#[test]
fn arm_host_retirement_between_page_scan_and_retain_does_not_quarantine() {
    arm_pool_retirement_during_scan(false);
}

#[test]
fn arm_pool_restock_between_scan_and_retain_settles() {
    arm_pool_retirement_during_scan(true);
}

#[cfg(test)]
fn arm_pool_retirement_during_scan(restock: bool) {
    use carrick_el1_abi::Lifecycle;
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let arena = Box::leak(Box::new(
        carrick_kernel::kernel::objects::TestThreadControlArena::try_new().unwrap(),
    ));
    let lease = arena.allocate(42).unwrap();
    let address = lease.slot_address();
    // SAFETY: the leaked arena retains this backing through the controlled race.
    let control = unsafe { &*(address.raw() as *const ThreadControlSlot) };
    let (_, record) = imported_thread_on_control(fixture, control, |_| {});
    let entry = control.entry().unwrap();
    fixture.page.publish(entry).unwrap();
    let reset = std::sync::Arc::new(std::sync::Mutex::new(None));
    let held_reset = reset.clone();
    let runtime = registry()
        .for_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            fixture.address,
        )
        .unwrap();
    let page = fixture.page;
    let zone = fixture.zone;
    let retirement: Box<dyn FnOnce() + Send> = Box::new(move || {
        let membership = page.reserve_nonfinal_exit().unwrap();
        page.retire_published_host_member(
            entry,
            control,
            membership,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
        let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
            ),
            carrick_core_abi::EntryThreadGeneration::from_raw(102),
        )
        .unwrap();
        page.publish_exact_host_retirement(control, receipt.retirement());
        zone.free_record(record.id);
        drop(lease);
        if restock {
            page.stock(
                entry.index(),
                carrick_el1_abi::EntryIdentity {
                    tid: 99,
                    visible_tid: 99,
                    thread_serial: 199,
                    birth: carrick_core_abi::entry::BirthSerial::of_task(
                        carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
                    ),
                    uid_credit: 0,
                },
            )
            .unwrap();
        } else {
            *held_reset.lock().unwrap() = Some(control.reserve_reset_for_test().unwrap());
        }
    });
    if restock {
        runtime.install_pool_retained_hook(retirement);
    } else {
        runtime.install_pool_control_hook(retirement);
    }
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    drop(reset.lock().unwrap().take());
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
    assert_eq!(arena.allocate(99).unwrap().slot_address(), address);
}

#[test]
fn arm_host_birth_after_snapshot_is_cancelled_and_settles() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let runtime = registry()
        .for_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            fixture.address,
        )
        .unwrap();
    let control: &'static ThreadControlSlot = Box::leak(Box::new(ThreadControlSlot::new()));
    control
        .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
        .unwrap();
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
            ),
            carrick_core_abi::EntryThreadGeneration::from_raw(102),
        )
        .unwrap(),
    );
    let receipt = control.host_birth_identity().unwrap();
    let page = fixture.page;
    let slot = page.reserve_host_birth().unwrap();
    runtime.install_pool_control_hook(Box::new(move || {
        // Complete a host birth admitted before exit, using the publication
        // order in Kernel::thread_spawned: live, receipt slot, gate check.
        page.thread_born().unwrap();
        assert!(page.publish_host_birth(slot, receipt));
        if page.gate() == carrick_el1_abi::GateState::Closed {
            control.request_host_exit();
        }
    }));
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert!(
        control.host_exit_requested(),
        "a host birth published after the snapshot must see terminal cancellation"
    );
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    page.reserve_cancelled_member_exit().unwrap().publish();
    page.publish_exact_host_retirement(control, receipt.retirement());
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_reserved_pool_control_is_not_transiently_registered() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let entry = fixture
        .page
        .stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
                ),
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(entry, control as *const _ as u64)
        .unwrap();
    control
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
        .unwrap();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert!(
        !control.graph_referenced(),
        "a Reserved control must not acquire a graph reference"
    );
    assert!(
        !control.graph_unregister_receipt(),
        "a skipped control must not acquire GRAPH_REGISTERED"
    );
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_non_graph_pool_member_uses_page_identity_after_zone_release() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let (control, record) = imported_thread(fixture);
    let entry = control.entry().unwrap();
    fixture.page.publish(entry).unwrap();
    fixture.zone.free_record(record.id);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    let membership = fixture.page.reserve_cancelled_member_exit().unwrap();
    fixture
        .page
        .retire_published_host_member(
            entry,
            control,
            membership,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
    let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
        carrick_core_abi::EntryTaskKey::from_raw(42),
        carrick_core_abi::entry::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
        ),
        carrick_core_abi::EntryThreadGeneration::from_raw(102),
    )
    .unwrap();
    fixture
        .page
        .publish_exact_host_retirement(control, receipt.retirement());
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        1,
        "the page identity must survive release of the zone record"
    );
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_failed_member_retain_leaves_terminal_admission_unbegun() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let (control, _) = imported_thread(fixture);
    fixture.page.publish(control.entry().unwrap()).unwrap();
    let reset = control.reserve_reset_for_test().unwrap();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        arm_call(fixture, fixture.control, &mut service, &mut frame)
    }));
    assert!(
        refused.is_err(),
        "the controlled reset window must refuse retention"
    );
    assert_eq!(
        fixture.page.live(),
        2,
        "failed retain must not consume caller membership"
    );
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
    drop(reset);
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        fixture.page.live(),
        1,
        "the first successful admission consumes exactly one member"
    );
}

#[test]
fn arm_host_retired_pool_member_waits_for_exact_host_receipt() {
    arm_graph_pool_host_retirement(false);
}

#[test]
fn arm_graph_pool_member_without_execution_binding_uses_page_identity() {
    arm_graph_pool_host_retirement(true);
}

#[cfg(test)]
fn arm_graph_pool_host_retirement(unbound: bool) {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) = imported_thread_with_identity(fixture, |identity| {
        if unbound {
            identity.generation = 0;
        }
    });
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let entry = control.entry().unwrap();
    fixture.page.publish(entry).unwrap();
    let retirement = fixture.page.reserve_nonfinal_exit().unwrap();
    fixture
        .page
        .retire_published_host_member(
            entry,
            control,
            retirement,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
    let _ = fixture.zone.claim_for_host(
        record,
        None,
        carrick_el1_abi::Handback::Cancelled,
        &carrick_sched_core::ShortLockSpin,
        &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
    );
    assert!(fixture.zone.record(record.id).is_cancelled());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        0,
        "host retirement before Closing still owes its exact receipt"
    );
    assert_eq!(fixture.page.live(), 0);
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        0,
        "host retirement must wait for the exact receipt after Reaped"
    );
    let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
        carrick_core_abi::entry::EntryTaskKey::from_raw(42),
        carrick_core_abi::entry::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
        ),
        carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
    )
    .unwrap();
    fixture
        .page
        .publish_exact_host_retirement(control, receipt.retirement());
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_closing_during_raw_exit_admission_settles_after_commit() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) = imported_thread(fixture);
    let mut worker_service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut worker_service,
            |_| (),
        )
        .unwrap();
    run_as(fixture, 42, 12, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    registry()
        .register_thread(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();
    let root_service: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(fixture.process_service()));
    let root_service_address = root_service as *mut _ as usize;
    let fixture_address = fixture as *const Fixture as usize;
    super::lifecycle::install_raw_exit_before_commit_hook(
        fixture.page,
        Box::new(move || {
            // SAFETY: both allocations are leaked for this test and used
            // sequentially while the outer raw-exit call owns this hook.
            let fixture = unsafe { &*(fixture_address as *const Fixture) };
            let service = unsafe {
                &mut *(root_service_address
                    as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
            };
            assert!(matches!(
                fixture.page.state(control.entry().unwrap().index()),
                Some((generation, carrick_el1_abi::EntryState::ExitingBorn
                    | carrick_el1_abi::EntryState::ExitingPublished))
                    if generation == control.entry().unwrap().generation()
            ));
            assert_eq!(
                control.recorded_exit_kind(control.entry()),
                carrick_core::lifecycle::MemberExitKind::Active
            );
            fixture.zone.clear_current(fixture.slot);
            run_as_leader(fixture);
            let mut frame = carrick_el1_abi::TrapFrame::default();
            frame.x[0] = 7;
            frame.x[8] = 94;
            assert_eq!(
                arm_call(fixture, fixture.control, service, &mut frame).unwrap(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
            run_as(fixture, 42, 12, 102, control);
        }),
    );
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    assert_eq!(
        arm_call(fixture, control, &mut worker_service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        control.recorded_exit_kind(control.entry()),
        carrick_core::lifecycle::MemberExitKind::InZone
    );
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    run_as_leader(fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let resumed = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        selected.record,
        root_service,
    );
    assert!(matches!(
        super::aarch64_process::map_resume(resumed, root_service, &fixture.task, fixture.slot),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(root_service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        root_service
            .crossing
            .root_exit_status
            .load(Ordering::Acquire),
        7
    );
}

#[test]
fn arm_unadopted_exit_wakes_closing_owner_without_process_venue() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) =
        imported_thread_with_identity(fixture, |identity| identity.generation = 0);
    let mut worker_service = fixture.process_service();
    run_as(fixture, 42, 0, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let mut failed_frame = carrick_el1_abi::TrapFrame::default();
    failed_frame.x[8] = 93;
    assert!(
        matches!(
            arm_call_with_cpu(
                fixture,
                control,
                &mut worker_service,
                &mut failed_frame,
                &mut crate::sched::FakeCpu {
                    ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
                    ..Default::default()
                }
            ),
            Err(NativeProcessError::Stale)
        ),
        "a Born sibling cannot register a group before its root owner exists"
    );
    fixture.zone.unswitch(fixture.slot, record.id);
    run_as_leader(fixture);
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut worker_service,
            |_| (),
        )
        .unwrap();
    run_as(fixture, 42, 0, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let root_service: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(fixture.process_service()));
    let root_service_address = root_service as *mut _ as usize;
    let fixture_address = fixture as *const Fixture as usize;
    super::lifecycle::install_raw_exit_before_commit_hook(
        fixture.page,
        Box::new(move || {
            // SAFETY: both allocations are leaked for this test and used
            // sequentially while the outer raw-exit call owns this hook.
            let fixture = unsafe { &*(fixture_address as *const Fixture) };
            let service = unsafe {
                &mut *(root_service_address
                    as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
            };
            assert!(matches!(
                fixture.page.state(control.entry().unwrap().index()),
                Some((generation, carrick_el1_abi::EntryState::ExitingBorn
                    | carrick_el1_abi::EntryState::ExitingPublished))
                    if generation == control.entry().unwrap().generation()
            ));
            assert_eq!(
                control.recorded_exit_kind(control.entry()),
                carrick_core::lifecycle::MemberExitKind::Active
            );
            fixture.zone.clear_current(fixture.slot);
            run_as_leader(fixture);
            let mut frame = carrick_el1_abi::TrapFrame::default();
            frame.x[0] = 7;
            frame.x[8] = 94;
            assert_eq!(
                arm_call_with_cpu(
                    fixture,
                    fixture.control,
                    service,
                    &mut frame,
                    &mut crate::sched::FakeCpu {
                        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
                        ..Default::default()
                    }
                )
                .unwrap(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
            run_as(fixture, 42, 0, 102, control);
        }),
    );
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        None::<
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<'_, Aarch64ParkedContext>,
        >,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
            | carrick_personality_linux::dispatch::CompletionRoute::Served
    ));
    assert_eq!(
        control.recorded_exit_kind(control.entry()),
        carrick_core::lifecycle::MemberExitKind::InZone
    );
    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 1);
    let selected = fixture
        .zone
        .slot(fixture.slot)
        .current()
        .expect("the closing root is runnable");
    run_as_leader(fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let resumed = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        selected,
        root_service,
    );
    assert!(matches!(
        super::aarch64_process::map_resume(resumed, root_service, &fixture.task, fixture.slot),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(root_service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(
        root_service
            .crossing
            .root_exit_status
            .load(Ordering::Acquire),
        7
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // VM-free two-actor admission witness.
fn arm_host_birth_adoption_racing_closing_has_one_cancel_owner() {
    use carrick_el1_abi::Lifecycle;
    use std::sync::mpsc;
    use std::time::Duration;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
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
        .for_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            fixture.address,
        )
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    let birth_identity = control.host_birth_identity().unwrap();
    let sibling_task = Box::leak(Box::new(CurrentTask::new()));
    sibling_task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        5,
    );
    sibling_task.mm.key.store(
        fixture.task.mm.key.load(Ordering::Acquire),
        Ordering::Release,
    );
    sibling_task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    sibling_task.publish_visible_pid(41);
    sibling_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    sibling_task.publish_root_generation(fixture.address.generation);
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture.zone.publish_slot(slot, 1, Some(1), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, 1).unwrap();
    let record = fixture
        .zone
        .current_or_new(
            slot,
            ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: fixture.task.mm.key.load(Ordering::Acquire),
                file_table: 5,
                generation: 12,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
    control.bind_zone_record(fixture.zone.record_ref(record));
    let (start_tx, start_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let fixture_address = fixture as *const Fixture as usize;
    let worker = std::thread::spawn(move || {
        start_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // SAFETY: this leaked fixture outlives the joined worker; the worker
        // uses only the zone's atomic/locked registry entry path.
        let fixture = unsafe { &*(fixture_address as *const Fixture) };
        let adopted = registry()
            .register_thread(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot,
                },
                sibling_task,
                fixture.address,
                fixture.page,
                control,
            )
            .is_ok();
        let _ = done_tx.send(adopted);
        adopted
    });
    owner.install_closing_race_hook(Box::new(move || {
        start_tx.send(()).unwrap();
        // On the old ordering adoption completes in the snapshot/close gap.
        // On the corrected ordering it waits for the registry lock and Closed.
        let _ = done_rx.recv_timeout(Duration::from_millis(250));
    }));
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    let adopted = worker.join().unwrap();
    let cancelled = if adopted {
        control.host_exit_requested()
    } else {
        fixture.page.host_birth_requested(birth_identity)
    };
    assert!(
        cancelled,
        "adopted={adopted}: Closing must cancel the sibling"
    );
    assert_eq!(fixture.page.live(), 1);
    fixture
        .page
        .reserve_cancelled_member_exit()
        .unwrap()
        .publish();
    fixture
        .page
        .publish_exact_host_retirement(control, birth_identity.retirement());
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
}

/// #641 (signed captures at 113108004: `owner_verdict ... first=Adopted
/// observed=(2,5,43) expected=(2,4233,43)`): a host-born member adopted on
/// the quantum whose execution generation equals the birth identity's
/// process generation is later rehomed with its next execution generation.
/// The host retires it with its exact birth identity, so Closing must
/// expect that identity, never the rehomed execution binding.
#[test]
fn arm_rehomed_adopted_member_settles_on_its_birth_identity() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    let birth_identity = control.host_birth_identity().unwrap();
    let sibling_task = Box::leak(Box::new(CurrentTask::new()));
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture.zone.publish_slot(slot, 1, Some(1), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, 1).unwrap();
    let mm = fixture.task.mm.key.load(Ordering::Acquire);
    let bind = |generation: u64| {
        sibling_task.set(
            El1TaskId::from_linux_tid(42),
            carrick_el1_abi::SnapshotGeneration::from_raw(generation),
            5,
        );
        sibling_task.mm.key.store(mm, Ordering::Release);
        sibling_task
            .mm
            .thread_generation
            .store(102, Ordering::Release);
        sibling_task.publish_visible_pid(41);
        sibling_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
        sibling_task.publish_root_generation(fixture.address.generation);
        let record = fixture
            .zone
            .current_or_new(
                slot,
                ThreadIdentity {
                    tid: 42,
                    serial: 102,
                    mm,
                    file_table: 5,
                    generation,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: control as *const _ as u64,
                },
            )
            .unwrap();
        control.bind_zone_record(fixture.zone.record_ref(record));
        record
    };
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot,
    };
    // Adoption must succeed even when the first EL1 entry quantum carries a
    // renewed execution generation (777) distinct from the birth identity's
    // durable process generation (12 for this fixture).
    let first = bind(777);
    registry()
        .register_thread(source, sibling_task, fixture.address, fixture.page, control)
        .expect("adopt host-born sibling");
    // Its next quantum carries a later execution generation.
    fixture.zone.discard_unpublished(slot, first);
    let _ = bind(4_233);
    registry()
        .rehome_entry(source, sibling_task, fixture.address, fixture.page, control)
        .expect("rehome adopted sibling")
        .expect("registered member rehomes");
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    // The host retires the member exactly as production does.
    fixture
        .page
        .reserve_cancelled_member_exit()
        .unwrap()
        .publish();
    fixture
        .page
        .publish_exact_host_retirement(control, birth_identity.retirement());
    assert_eq!(fixture.page.live(), 0);
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        1,
        "closing owner re-parked: {}",
        fixture.page.closing_verdict()
    );
}

/// An adopted member settles only on its exact birth identity. A published
/// retirement receipt naming a different execution must not be accepted by
/// re-reading the control slot it was just written to.
#[test]
fn arm_adopted_member_rejects_a_foreign_retirement_receipt() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let control = host_born_sibling(fixture, 42);
    let birth_identity = control.host_birth_identity().unwrap();
    let sibling_task = Box::leak(Box::new(CurrentTask::new()));
    sibling_task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        5,
    );
    let mm = fixture.task.mm.key.load(Ordering::Acquire);
    sibling_task.mm.key.store(mm, Ordering::Release);
    sibling_task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    sibling_task.publish_visible_pid(41);
    sibling_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    sibling_task.publish_root_generation(fixture.address.generation);
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture.zone.publish_slot(slot, 1, Some(1), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, 1).unwrap();
    let record = fixture
        .zone
        .current_or_new(
            slot,
            ThreadIdentity {
                tid: 42,
                serial: 102,
                mm,
                file_table: 5,
                generation: 12,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
    control.bind_zone_record(fixture.zone.record_ref(record));
    registry()
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            sibling_task,
            fixture.address,
            fixture.page,
            control,
        )
        .expect("adopt host-born sibling");
    // A retirement receipt for a different incarnation of the same tid and
    // thread serial.
    let foreign = carrick_core::terminal::ThreadBirthIdentity::from_parts(
        birth_identity.task(),
        carrick_core_abi::entry::BirthSerial::of_task(
            carrick_sched_core::process::TaskSerial::from_raw_u64(birth_identity.birth().raw() + 1)
                .unwrap(),
        ),
        birth_identity.thread(),
    )
    .unwrap()
    .retirement();
    fixture.page.reserve_nonfinal_exit().unwrap().publish();
    fixture.page.publish_exact_host_retirement(control, foreign);
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(fixture.page.live(), 0);
    assert_eq!(
        service.crossing.root_exits.load(Ordering::Acquire),
        0,
        "a foreign receipt settled the adopted member"
    );
    assert_eq!(control.host_birth_identity(), Some(birth_identity));
}

#[test]
fn arm_host_exit_reserved_live_count_does_not_settle_group_before_receipt() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let sibling = host_born_sibling(fixture, 42);
    let retirement = fixture.page.reserve_nonfinal_exit().unwrap();
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(fixture.page.live(), 0);
    let identity = sibling.host_birth_identity().unwrap();
    assert!(fixture.page.host_birth_requested(identity));
    // #641 census: the parked owner recorded why it is not ready.
    let verdict = fixture.page.closing_verdict().to_string();
    assert!(
        verdict.starts_with("owner_verdict live=0 claimed=0 first=HostBorn"),
        "{verdict}"
    );
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    retirement.publish();
    fixture
        .page
        .publish_exact_host_retirement(sibling, identity.retirement());
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
#[allow(clippy::disallowed_methods)]
fn arm_host_retirement_release_racing_settle_reparks_without_quarantine() {
    use carrick_el1_abi::Lifecycle;
    use std::sync::mpsc;
    use std::time::Duration;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let sibling = host_born_sibling(fixture, 42);
    let retirement = fixture.page.reserve_nonfinal_exit().unwrap();
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    retirement.publish();
    let identity = sibling.host_birth_identity().unwrap();
    let (published_tx, published_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (claimed_tx, claimed_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let page = fixture.page;
    let worker = std::thread::spawn(move || {
        page.publish_exact_host_retirement_with_hooks(
            sibling,
            identity.retirement(),
            || {
                published_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            },
            || {
                claimed_tx.send(()).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            },
        );
    });
    published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    runtime.install_settle_race_hook(Box::new(move || {
        release_tx.send(()).unwrap();
        claimed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }));
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    finish_tx.send(()).unwrap();
    worker.join().unwrap();
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_closing_member_set_capacity_uses_static_registry_bound() {
    use carrick_el1_abi::Lifecycle;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let first = host_born_sibling(fixture, 42);
    let second = host_born_sibling(fixture, 43);
    let first_retirement = fixture.page.reserve_nonfinal_exit().unwrap();
    let second_retirement = fixture.page.reserve_nonfinal_exit().unwrap();
    assert_eq!(fixture.page.live(), 1);
    run_as_leader(fixture);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert!(
        fixture
            .page
            .host_birth_requested(first.host_birth_identity().unwrap())
    );
    assert!(
        fixture
            .page
            .host_birth_requested(second.host_birth_identity().unwrap())
    );
    first_retirement.publish();
    second_retirement.publish();
    for control in [first, second] {
        let identity = control.host_birth_identity().unwrap();
        fixture
            .page
            .publish_exact_host_retirement(control, identity.retirement());
    }
    assert!(matches!(
        wake_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
}

#[cfg(test)]
fn wake_closing_root(
    fixture: &'static Fixture,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
) -> crate::sched::ResumeAction {
    let (mm, address) = fixture.page.exit_wait().unwrap();
    let guard = fixture
        .zone
        .lock(
            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(mm.raw(), address),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    let mut transfers = Vec::new();
    let count = fixture.zone.wake_host(
        &guard,
        mm.raw(),
        address,
        u32::MAX,
        u32::MAX,
        true,
        &mut |transfer| transfers.push(transfer),
        &mut |_| {},
    );
    drop(guard);
    assert_eq!(count, 1);
    assert!(transfers.is_empty());
    resume_closing_root(fixture, service)
}

#[cfg(test)]
fn resume_closing_root(
    fixture: &'static Fixture,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
) -> crate::sched::ResumeAction {
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    // The production scheduler installs the selected MM before resume_selected.
    // A sibling's terminal receipt now vacates this slot's old installation.
    if fixture.zone.installed_space(fixture.slot) != fixture.address.mm.raw().get() {
        fixture
            .zone
            .install_space(fixture.slot, fixture.address.mm.raw().get())
            .unwrap();
    }
    run_as_leader(fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let resumed = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        selected.record,
        service,
    );
    super::aarch64_process::map_resume(resumed, service, &fixture.task, fixture.slot)
}

#[test]
fn arm_unadmitted_thread_runs_ordinary_calls_and_refuses_owner_calls() {
    use super::dispatch::{arm_owner_must_serve, arm_thread_group_owner};
    use super::native_process_runtime::NativeThreadGroupOwner;
    // A non-last thread's raw exit is the host's; the last thread's and the
    // process-family calls stay with a retained owner.
    assert!(!arm_owner_must_serve(
        62,
        3,
        || panic!("not a process call"),
        1
    ));
    assert!(!arm_owner_must_serve(
        93,
        0,
        || NativeThreadGroupOwner::Root,
        2
    ));
    assert!(arm_owner_must_serve(
        93,
        0,
        || NativeThreadGroupOwner::Root,
        1
    ));
    assert!(arm_owner_must_serve(
        94,
        0,
        || NativeThreadGroupOwner::Root,
        2
    ));
    assert!(arm_owner_must_serve(
        260,
        0,
        || NativeThreadGroupOwner::Root,
        2
    ));
    assert!(!arm_owner_must_serve(
        260,
        0,
        || NativeThreadGroupOwner::Unowned,
        2
    ));
    assert!(!arm_owner_must_serve(
        94,
        0,
        || NativeThreadGroupOwner::Unowned,
        2
    ));
    assert!(
        arm_owner_must_serve(220, 17, || NativeThreadGroupOwner::Unowned, 1),
        "fork"
    );
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let foreign_page = Box::leak(Box::new(ThreadLifecyclePage::new()));
    assert_eq!(
        arm_thread_group_owner(fixture.zone, &fixture.task, fixture.page),
        NativeThreadGroupOwner::Unowned
    );
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    assert_eq!(
        arm_thread_group_owner(fixture.zone, &fixture.task, fixture.page),
        NativeThreadGroupOwner::Root
    );
    for ordinal in [221, 281] {
        assert!(
            !arm_owner_must_serve(
                ordinal,
                0,
                || arm_thread_group_owner(fixture.zone, &fixture.task, fixture.page),
                1,
            ),
            "the admitted root execs through the host with its live authority ({ordinal})"
        );
    }
    assert!(
        !arm_owner_must_serve(221, 0, || NativeThreadGroupOwner::Unowned, 1),
        "an unowned task's execve keeps the host route"
    );
    let mut exec_frame = carrick_el1_abi::TrapFrame::default();
    exec_frame.x[0] = 0x1234;
    exec_frame.x[8] = 221;
    let exec_route = arm_call(fixture, fixture.control, &mut service, &mut exec_frame).unwrap();
    assert_eq!(
        exec_route,
        carrick_personality_linux::dispatch::CompletionRoute::NativeService,
        "the production ARM adapter must hand execve to native service capture"
    );
    assert_eq!(
        super::dispatch::resolve_arm_process_route(
            exec_route,
            &mut exec_frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(&fixture.task),
            || panic!("a native-service handoff is not an owner refusal"),
        ),
        carrick_el1_abi::Action::Forward,
    );
    assert_eq!(
        exec_frame.x[0], 0x1234,
        "ring-first dispatch must not install ENOSYS before native exec capture"
    );
    assert_eq!(
        arm_thread_group_owner(fixture.zone, &fixture.task, foreign_page),
        NativeThreadGroupOwner::Unowned
    );
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
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
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

#[test]
fn arm_raw_exit_control_reallocation_none_before_closing() {
    arm_pool_raw_exit_closing_at_commit_boundary(true, Some(false));
}
#[test]
fn arm_raw_exit_control_reallocation_rebound_before_closing() {
    arm_pool_raw_exit_closing_at_commit_boundary(true, Some(true));
}

#[cfg(test)]
fn arm_exit_group_under_gate(state: carrick_el1_abi::GateState) {
    use carrick_el1_abi::Lifecycle;
    {
        let arena = Box::leak(Box::new(
            carrick_kernel::kernel::objects::TestThreadControlArena::try_new().unwrap(),
        ));
        let fixture = Box::leak(Box::new(Fixture::with_page(
            0x10000,
            asid(1),
            5,
            arena.lifecycle(),
        )));
        let (sibling, sibling_record) = imported_thread(fixture);
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |_| (),
            )
            .unwrap();
        if state == carrick_el1_abi::GateState::HostOnly {
            fixture.page.decline_to_host();
        }
        let mut admission = arena.birth_admission().unwrap();
        if state == carrick_el1_abi::GateState::AwaitingExecBinding {
            admission.keep_closed();
        }
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[0] = 7;
        frame.x[8] = 94;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            arm_call(fixture, fixture.control, &mut service, &mut frame)
        }));
        assert!(
            outcome.is_ok(),
            "exit_group must not quarantine under {state:?}: {:?}",
            outcome
                .as_ref()
                .err()
                .and_then(|failure| failure
                    .downcast_ref::<super::native_run_failure::NativeRunFailurePanic>())
        );
        assert_eq!(
            outcome.unwrap().unwrap(),
            carrick_personality_linux::dispatch::CompletionRoute::Suspended,
            "{state:?}"
        );
        assert_eq!(
            service.crossing.root_exits.load(Ordering::Acquire),
            0,
            "live sibling must delay status publication"
        );
        let entry = sibling.entry().unwrap();
        fixture.page.publish(entry).unwrap();
        let membership = fixture.page.reserve_cancelled_member_exit().unwrap();
        fixture
            .page
            .retire_published_host_member(
                entry,
                sibling,
                membership,
                &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
            )
            .unwrap();
        let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
            ),
            carrick_core_abi::EntryThreadGeneration::from_raw(102),
        )
        .unwrap();
        fixture
            .page
            .publish_exact_host_retirement(sibling, receipt.retirement());
        let _ = fixture.zone.claim_for_host(
            sibling_record,
            None,
            carrick_el1_abi::Handback::Cancelled,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        );
        assert!(fixture.zone.record(sibling_record.id).is_cancelled());
        drop(admission);
        assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
        assert!(matches!(
            wake_closing_root(fixture, &mut service),
            crate::sched::ResumeAction::Left
        ));
        assert_eq!(
            service.crossing.root_exits.load(Ordering::Acquire),
            1,
            "{state:?}"
        );
        assert_eq!(
            service.crossing.root_exit_status.load(Ordering::Acquire),
            7,
            "{state:?}"
        );
    }
}

#[test]
fn arm_exit_group_under_fork_closing() {
    arm_exit_group_under_gate(carrick_el1_abi::GateState::ForkClosing);
}
#[test]
fn arm_exit_group_under_awaiting_exec_binding() {
    arm_exit_group_under_gate(carrick_el1_abi::GateState::AwaitingExecBinding);
}
#[test]
fn arm_exit_group_under_host_only_closed() {
    arm_exit_group_under_gate(carrick_el1_abi::GateState::HostOnly);
}

/// Actual host reservations share the exact parent's page and control with
/// ARM dispatch; the peer is another live process in the same host registry.
#[cfg(test)]
fn arm_exit_group_host_fork_race(stage: u8) {
    use carrick_el1_abi::Lifecycle;
    use carrick_kernel::kernel::clone_plan::ClonePlan;
    use carrick_kernel::kernel::{Kernel, KernelOperationError, RootBootstrap};
    let input = RootBootstrap::for_reference_model(
        41,
        carrick_hal::ThreadId::synthetic_for_tests(41),
        "fork-exit-root".into(),
    )
    .unwrap();
    let (kernel, root) = Kernel::bootstrap_root(input).unwrap();
    let root = Box::leak(Box::new(root));
    let plan = ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
    let peer = kernel
        .reserve_fork(root, plan, "live-peer".into(), None)
        .unwrap()
        .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(42))
        .unwrap()
        .commit()
        .unwrap()
        .start_child()
        .unwrap()
        .into_parts()
        .0;
    assert!(root.exact_thread_is_live() && peer.exact_thread_is_live());
    let page_lease = Box::leak(Box::new(root.lifecycle_page()));
    let page = &**page_lease;
    let control = root.thread().control_slot();
    let fixture = Box::leak(Box::new(Fixture::with_identity(
        0x10000,
        asid(1),
        page,
        control,
        ThreadIdentity {
            tid: root.thread().key().tid.raw() as u64,
            serial: root.thread().key().serial.raw(),
            generation: root.task().key().serial.raw(),
            mm: root.shared().mm().id().raw(),
            file_table: root.resources().files().id().raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: page as *const _ as u64,
            control_slot: control as *const _ as u64,
        },
    )));
    let mut service = fixture.process_service();
    fixture
        .enter(control, fixture_ttbr0(fixture), &mut service, |_| ())
        .unwrap();
    let baseline_claimed = page.claimed_count();
    let reserved = kernel
        .reserve_fork(root, plan, "racing-child".into(), None)
        .unwrap();
    let child_id = reserved.child_id();
    let mut exit = || {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[0] = 7;
        frame.x[8] = 94;
        arm_call(fixture, control, &mut service, &mut frame).unwrap()
    };
    if stage == 0 {
        let _ = exit();
    }
    let prepared = reserved
        .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(43))
        .unwrap();
    let retained = prepared.resource_retention_probe();
    if stage == 1 {
        let _ = exit();
    }
    let result = carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        if stage == 2 {
            prepared.commit_with_publication_boundary(
                || {
                    assert_eq!(page.claimed_count(), baseline_claimed + 1);
                    assert_eq!(
                        exit(),
                        carrick_personality_linux::dispatch::CompletionRoute::Suspended
                    );
                },
                || panic!("terminal close must defeat publication"),
            )
        } else if stage == 3 {
            let mut publication = prepared.publication();
            let admitted = publication.admit().unwrap();
            assert_eq!(
                exit(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            let result = admitted.commit();
            // Kernel publication alone cannot release Closing: the backend
            // still owns its publication scope until its transaction finishes.
            assert_eq!(page.claimed_count(), baseline_claimed + 1);
            drop(publication);
            result
        } else if stage == 4 {
            let mut publication = prepared.publication();
            assert_eq!(
                exit(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            let error = match publication.admit() {
                Ok(_) => panic!("terminal close must defeat backend admission"),
                Err(error) => error,
            };
            assert!(!retained(), "kernel rollback precedes backend rollback");
            assert_eq!(page.claimed_count(), baseline_claimed + 1);
            drop(publication);
            Err(error)
        } else {
            prepared.commit()
        }
    });
    let child = if stage == 3 {
        Some(result.unwrap().start_child().unwrap().into_parts().0)
    } else {
        assert!(
            matches!(result, Err(KernelOperationError::LifecycleAdmissionBusy(_))),
            "exit_group must defeat host fork at stage {stage}"
        );
        assert!(
            !retained(),
            "prepared record, MM and file table must be dropped"
        );
        assert!(
            kernel
                .context(
                    child_id,
                    carrick_kernel::kernel::LinuxTid::for_task_leader(child_id)
                )
                .is_err()
        );
        None
    };
    assert_eq!(page.claimed_count(), baseline_claimed);
    assert_eq!(page.live(), 0);
    if stage >= 2 {
        assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
        assert!(matches!(
            resume_closing_root(fixture, &mut service),
            crate::sched::ResumeAction::Left
        ));
    }
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
    // The fork's reservation was released: host topology exit can now commit.
    let status = carrick_kernel::kernel::objects::LinuxWaitStatus::exited(7);
    assert_eq!(
        kernel
            .exit_task(root.task().key().id, status, None)
            .unwrap()
            .status,
        status
    );
    assert!(peer.exact_thread_is_live());
    if let Some(child) = child {
        assert!(child.exact_thread_is_live());
        assert_ne!(
            kernel.task_parent_key(child.task().key()).unwrap(),
            Some(root.task().key())
        );
    }
}

#[test]
fn arm_exit_group_defeats_admitted_host_fork() {
    arm_exit_group_host_fork_race(0);
}
#[test]
fn arm_exit_group_defeats_prepared_host_fork() {
    arm_exit_group_host_fork_race(1);
}
#[test]
fn arm_exit_group_defeats_committing_host_fork() {
    arm_exit_group_host_fork_race(2);
}

#[test]
fn arm_exit_group_waits_for_winning_host_fork_publication() {
    arm_exit_group_host_fork_race(3);
}

#[test]
fn arm_exit_group_waits_for_losing_host_fork_backend_rollback() {
    arm_exit_group_host_fork_race(4);
}

#[test]
fn arm_concurrent_exit_group_loser_retires_and_wakes_owner() {
    use carrick_el1_abi::Lifecycle;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let slot2 = SlotId::new(1);
    fixture.zone.drive(slot2, 2);
    fixture.zone.publish_slot(slot2, 1, Some(1), 1);
    fixture.zone.enter_guest(slot2);
    fixture.zone.install_space(slot2, 1).unwrap();
    let (control2, record2) = imported_thread_on_slot(fixture, slot2, |id| id.affinity = u64::MAX);
    let control3: &'static ThreadControlSlot = Box::leak(Box::new(ThreadControlSlot::new()));
    let entry3 = fixture
        .page
        .stock(
            1,
            carrick_el1_abi::EntryIdentity {
                tid: 43,
                visible_tid: 43,
                thread_serial: 103,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(13).unwrap(),
                ),
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(entry3, control3 as *const _ as u64)
        .unwrap();
    let record3 = fixture
        .zone
        .alloc_record(carrick_sched_core::ThreadIdentity {
            tid: 43,
            serial: 103,
            mm: 1,
            file_table: 5,
            generation: 0,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: fixture.page as *const _ as u64,
            control_slot: control3 as *const _ as u64,
        })
        .unwrap();
    let reference3 = fixture.zone.record_ref(record3);
    unsafe {
        *fixture.zone.record(record3).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    control3
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry3)
        .unwrap();
    assert!(control3.publish_visible_tid(43));
    control3.bind_zone_record(reference3);
    let claim3 = fixture.page.claim_any().unwrap();
    fixture.page.thread_born().unwrap();
    fixture
        .page
        .record_born(
            claim3,
            carrick_el1_abi::BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x0001_0000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record3)
            .is_queued()
    );

    let service: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(fixture.process_service()));
    let service2: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            slot2,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        )));
    crate::native_process_runtime::seed_fixture_namespace(
        fixture.zone,
        &fixture.task,
        fixture.page,
    );
    run_as_leader(fixture);
    fixture
        .enter(fixture.control, fixture_ttbr0(fixture), service, |_| ())
        .unwrap();

    // Admit and register sibling 2 (tid 42) on slot2, keeping it OnCpu on slot2
    // while leader initiates group exit on slot 0.
    assert_eq!(
        fixture.zone.switch_in_full(slot2).unwrap().record,
        record2.id
    );
    run_as(fixture, 42, 12, 102, control2);
    fixture
        .enter(control2, fixture_ttbr0(fixture), service2, |_| ())
        .unwrap();

    // Switch in unadopted sibling 3 (tid 43) on slot 0 to begin raw SYS_exit(0)
    // while the admission gate is open; pause it after begin_exit and before commit.
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record3
    );
    run_as(fixture, 43, 0, 103, control3);
    let service_address = service as *mut _ as usize;
    let service2_address = service2 as *mut _ as usize;
    let fixture_address = fixture as *const Fixture as usize;
    super::lifecycle::install_raw_exit_before_commit_hook(
        fixture.page,
        Box::new(move || {
            // SAFETY: all allocations are leaked for this test and accessed
            // sequentially while the outer raw-exit call runs this hook.
            let fixture = unsafe { &*(fixture_address as *const Fixture) };
            let service = unsafe {
                &mut *(service_address
                    as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
            };
            fixture.zone.clear_current(fixture.slot);

            let source = BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            };
            run_as_leader(fixture);
            let runtime = registry()
                .for_entry(source, &fixture.task, fixture.address)
                .unwrap();
            let runtime_for_hook = runtime.clone();
            runtime.install_pool_control_hook(Box::new(move || {
                runtime_for_hook.install_closing_race_hook(Box::new(move || {
                    // 2. Sibling 2 (tid 42), still OnCpu on slot2, concurrently
                    //    calls exit_group(9) right after pending_exit is published
                    //    and registry_state dropped, before leader's cancel_members
                    //    and park_pending_exit. Its committed member custody
                    //    releases its record without joining the owner's wait.
                    let fixture = unsafe { &*(fixture_address as *const Fixture) };
                    let service2 = unsafe {
                        &mut *(service2_address
                            as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
                    };
                    assert_eq!(
                        super::dispatch::arm_signal_return_admission(
                            fixture.zone,
                            fixture.page,
                            control2,
                            false,
                        ),
                        Some(true),
                        "a closed gate still owes the sibling its group-exit checkpoint"
                    );
                    run_as(fixture, 42, 12, 102, control2);
                    let mut sibling2_exit_frame = carrick_el1_abi::TrapFrame::default();
                    sibling2_exit_frame.x[0] = 9;
                    sibling2_exit_frame.x[8] = 94;
                    assert_eq!(
                        arm_call_with_cpu(
                            fixture,
                            control2,
                            service2,
                            &mut sibling2_exit_frame,
                            &mut crate::sched::FakeCpu {
                                ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
                                ..Default::default()
                            }
                        )
                        .unwrap(),
                        carrick_personality_linux::dispatch::CompletionRoute::Suspended
                    );
                    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 0);
                    assert!(fixture.zone.live(record2).is_none());
                    assert_eq!(
                        fixture.zone.installed_space(slot2),
                        0,
                        "losing exit_group caller must release its physical slot"
                    );
                    assert_eq!(service2.crossing.root_exits.load(Ordering::Acquire), 0);
                    run_as_leader(fixture);
                }));
            }));

            // 1. Leader (tid 41) calls exit_group(7) on slot 0, becomes the closing
            //    owner, and parks on the exit-wait channel while sibling 3's
            //    admitted raw exit is still uncommitted.
            let mut leader_exit_frame = carrick_el1_abi::TrapFrame::default();
            leader_exit_frame.x[0] = 7;
            leader_exit_frame.x[8] = 94;
            assert_eq!(
                arm_call_with_cpu(
                    fixture,
                    fixture.control,
                    service,
                    &mut leader_exit_frame,
                    &mut crate::sched::FakeCpu {
                        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
                        ..Default::default()
                    }
                )
                .unwrap(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);

            run_as(fixture, 43, 0, 103, control3);
        }),
    );

    // 3. Sibling 3 (tid 43) commits raw SYS_exit(0). Its terminal notification
    //    must wake the retained process owner. The losing caller has already
    //    retired and cannot absorb the terminal notification.
    let mut raw_exit_frame = carrick_el1_abi::TrapFrame::default();
    raw_exit_frame.x[8] = 93;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut raw_exit_frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        None::<
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<'_, Aarch64ParkedContext>,
        >,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
            | carrick_personality_linux::dispatch::CompletionRoute::Served
    ));
    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 1);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    run_as_leader(fixture);
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();

    // Raw exit switched in the owner that it woke. The losing caller's
    // retired continuation must never be scheduled or reserve membership again.
    let owner_record = fixture
        .zone
        .slot(fixture.slot)
        .current()
        .expect("terminal notification must select the process owner");
    assert_ne!(owner_record, record2.id);
    assert!(fixture.zone.live(record2).is_none());
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    assert_eq!(service2.crossing.root_exits.load(Ordering::Acquire), 0);
    run_as_leader(fixture);
    let resumed_leader = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        owner_record,
        service,
    );
    assert!(matches!(
        super::aarch64_process::map_resume(resumed_leader, service, &fixture.task, fixture.slot,),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
    assert_eq!(fixture.page.live(), 0);
}

/// The unadopted sibling's terminal notification wakes a closing owner no
/// guest slot may run now: in the ring, never refused (#1941). The owner is
/// queued on the waker's slot, misplaced, and the waker's host boundary
/// relocates it (the host crossing this used to take is gone).
#[test]
fn arm_unadopted_exit_wakes_unplaceable_closing_owner_without_process_venue() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) =
        imported_thread_with_identity(fixture, |identity| identity.generation = 0);
    let mut worker_service = fixture.process_service();
    run_as_leader(fixture);
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut worker_service,
            |_| (),
        )
        .unwrap();
    let leader_record = fixture.control.zone_record().unwrap().id;
    run_as(fixture, 42, 0, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let root_service: &'static mut Aarch64NativeProcessService<'static, TestStockCrossing> =
        Box::leak(Box::new(fixture.process_service()));
    let root_service_address = root_service as *mut _ as usize;
    let fixture_address = fixture as *const Fixture as usize;
    super::lifecycle::install_raw_exit_before_commit_hook(
        fixture.page,
        Box::new(move || {
            let fixture = unsafe { &*(fixture_address as *const Fixture) };
            let service = unsafe {
                &mut *(root_service_address
                    as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
            };
            fixture.zone.clear_current(fixture.slot);
            run_as_leader(fixture);
            let mut frame = carrick_el1_abi::TrapFrame::default();
            frame.x[0] = 7;
            frame.x[8] = 94;
            assert_eq!(
                arm_call(fixture, fixture.control, service, &mut frame).unwrap(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
            // Make the parked closing owner unplaceable in the zone: no
            // guest slot may run it when the unadopted sibling's
            // venue-absent terminal notification wakes it.
            fixture.zone.unhome(fixture.slot, leader_record, 1);
            fixture.zone.publish_slot(fixture.slot, 0, Some(0), 1);
            fixture.zone.release_space(fixture.slot);
            run_as(fixture, 42, 0, 102, control);
        }),
    );
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
    let route = super::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        None::<
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<'_, Aarch64ParkedContext>,
        >,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
            | carrick_personality_linux::dispatch::CompletionRoute::Served
    ));
    assert!(
        matches!(
            fixture.zone.record(leader_record).claim(),
            carrick_el1_abi::Claim::Queued { slot, .. } if slot == fixture.slot
        ),
        "venue-absent unplaceable wake queues the closing owner on the waker: {:?}",
        fixture.zone.record(leader_record).claim()
    );
    assert_eq!(
        fixture.zone.counters.el1_misplaced.load(Ordering::Acquire),
        1,
        "misplaced, for the waker's host boundary to relocate"
    );
}

#[cfg(test)]
struct ArmWaitSignalMachine {
    user_sp: UserVa,
    backend: ArmWaitSignalBackend,
}

#[cfg(test)]
impl crate::signal_delivery::SignalMachine<Aarch64ParkedContext> for ArmWaitSignalMachine {
    type Backend = ArmWaitSignalBackend;

    fn backend(&mut self) -> &mut Self::Backend {
        &mut self.backend
    }

    fn user_sp(&self, _frame: &carrick_el1_abi::TrapFrame) -> UserVa {
        self.user_sp
    }

    fn restart(
        &self,
        frame: &mut carrick_el1_abi::TrapFrame,
        original: &Aarch64ParkedContext,
    ) -> bool {
        frame.x[0] = original.syscall_return();
        if let Some(pc) = frame.elr.checked_sub(4) {
            frame.elr = pc;
            true
        } else {
            false
        }
    }

    fn restart_forwarded(&self, frame: &mut carrick_el1_abi::TrapFrame) -> Option<bool> {
        crate::arm_signal::restart_forwarded_frame(frame)
    }

    fn sync_parked_context(
        &self,
        frame: &carrick_el1_abi::TrapFrame,
        ctx: &mut Aarch64ParkedContext,
    ) {
        ctx.native.x = frame.x;
        ctx.native.pc = frame.elr;
        ctx.native.pstate = frame.spsr;
        ctx.native.sp_el0 = self.user_sp.raw();
    }

    fn group_exit_custody(
        &self,
        _task: &CurrentTask,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    }
}

#[cfg(test)]
struct ArmWaitSignalBackend;

#[cfg(test)]
impl carrick_guest_arch::ArchTypes for ArmWaitSignalBackend {
    type Error = carrick_el1::isa::ArchError;
    type NativeFrame = carrick_el1_abi::TrapFrame;
    type SavedContext = carrick_el1_abi::ThreadCtx;
    type Context = carrick_el1_abi::ThreadCtx;
    type Root = RootGpa;
    type MmOwner = CurrentTask;
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type HardwareInterrupt = ();
    type InterruptMask = ();
}

#[cfg(test)]
impl carrick_personality_linux::signal::SignalBackend for ArmWaitSignalBackend {
    fn setup_signal_frame(
        &mut self,
        frame: &mut carrick_el1_abi::TrapFrame,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&[u8]>,
        fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> carrick_core::user_copy::CopyOutcome,
    ) -> Result<carrick_personality_linux::signal::SignalFrameSetup, Self::Error> {
        crate::arm_signal::setup_arm_signal_frame(frame, params, siginfo, fpstate, copy_out)
    }

    fn restore_signal_frame(
        &mut self,
        _frame: &mut carrick_el1_abi::TrapFrame,
        _fpstate: &mut [u8],
        _copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, Self::Error> {
        Err(carrick_el1::isa::ArchError::Unbound)
    }
}

// #1846 slice C: a caught signal must borrow a parked anonymous syscall only
// until its handler returns. The syscall then re-enters its saved SVC, never
// reports EINTR, and owns no stale wait token after its real completion.
#[test]
fn arm_caught_signal_returns_then_reexecutes_parked_anonymous_edit() {
    use carrick_el1::memory::{DelegatedAnonymous, serve_delegated_anonymous};
    use carrick_el1::substrate::sched::{Sched, Served};
    use carrick_mmu_core::aarch64::descriptor_txn::TableWindow;
    use carrick_personality_linux::signal::ProcessSignals;
    use carrick_sched_core::spaces::notification::SpaceWaitCause;
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use zerocopy::{FromBytes, IntoBytes};

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    fixture.tables.words[1536].store(0, Ordering::Relaxed);
    fixture.tables.words[1537].store(0, Ordering::Relaxed);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let user_sp = stack.va_at(stack.len());
    let mut native = ThreadCtx::ZERO;
    native.x[0] = VA;
    native.x[1] = 4096;
    native.x[8] = 215;
    native.pc = 0x500004;
    native.sp_el0 = user_sp.raw();
    let initial = Aarch64ParkedContext::from_parts(native, fixture.address);
    let runtime = std::sync::Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            initial,
        )
        .unwrap(),
    );
    let owner_registry = Box::leak(Box::new(NativeProcessRegistry::new()));
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    )
    .with_words(words);
    let signal = Signal::from_number(10).unwrap();
    {
        let mut entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut service,
            )
            .unwrap();
        entry
            .rt_sigaction(
                signal,
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x700000)),
                    ..Default::default()
                }),
            )
            .unwrap();
    }
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let binding = runtime.task_binding(parent).unwrap();
    fixture
        .zone
        .discard_unpublished(fixture.slot, binding.record.id);
    let record = fixture
        .zone
        .current_or_new(
            fixture.slot,
            crate::sched::identity_of(&fixture.task, fixture.zone.slot(fixture.slot).affinity()),
        )
        .unwrap();
    // SAFETY: the fixture owns this unpublished AArch64 home exclusively.
    unsafe {
        *fixture.zone.record(record).ctx_mut() = initial;
    }
    fixture
        .control
        .bind_zone_record(fixture.zone.record_ref(record));
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record
    );
    assert!(fixture.zone.mark_native_owned(record));
    assert_ne!(fixture.zone.record_ref(record), binding.record);
    owner_registry
        .rehome_entry(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    let binding = runtime.task_binding(parent).unwrap();
    assert_eq!(binding.record.id, record);
    let index = fixture
        .zone
        .spaces
        .find(fixture.address.mm.raw().get())
        .unwrap();
    let held = fixture
        .region
        .table()
        .lock_in(
            crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
            index.index(),
            ReservationMm::new(fixture.address.mm.raw().get()).unwrap(),
            91,
        )
        .unwrap();
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: native.pc,
        ..Default::default()
    };
    frame.x = native.x;
    let counters = carrick_el1_abi::Counters::new();
    let mut cpu = crate::sched::FakeCpu::default();
    fixture.task.linux.mark_pending_host_work();
    assert_eq!(
        fixture.zone.slot(fixture.slot).current(),
        Some(binding.record.id),
        "the production park must save the registered native record"
    );
    assert_eq!(
        crate::mm_portal::park_anonymous_edit(
            &mut Sched {
                handoff: None,
                zone: fixture.zone,
                slot: fixture.slot,
                task: &fixture.task,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
                counters: &counters,
            },
            &mut frame,
            fixture.region.table(),
            SpaceWaitCause::Reservations,
            carrick_core_abi::service::ServiceOrigin::Initial,
        ),
        Some(Served::Idle)
    );
    fixture
        .task
        .linux
        .take_host_work_doorbell()
        .unwrap()
        .settled();
    let parked_record = binding.record.id;
    assert!(fixture.zone.record(parked_record).has_object_operation());

    let event_binding = crate::common_entry::execution_binding(&fixture.task);
    assert!(
        owner_registry
            .admit_external_event(
                fixture.zone,
                carrick_el1_abi::ExternalSignalRecord::new(
                    carrick_core_abi::EntryEventIdentity::from_binding(event_binding),
                    event_binding,
                    binding.record,
                    carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::MIN),
                    signal,
                    carrick_el1_abi::ExternalSignalSource::InZoneIpc,
                ),
                fixture.slot,
                &mut service,
            )
            .unwrap()
    );
    assert_eq!(
        fixture.zone.record(binding.record.id).handback(),
        Some(carrick_sched_core::Handback::Signal)
    );
    drop(held);

    let mut cpu = ResumeCpu {
        inner: crate::sched::FakeCpu::default(),
        runtime: &runtime,
        registry: owner_registry,
        source,
        task: &fixture.task,
        service: &mut service,
    };
    assert_eq!(
        (Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .run_next(&mut frame, 0),
        Served::Returned { switched: true }
    );

    let mut resumed = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    crate::sched::ThreadCpu::save(
        &mut cpu.inner,
        &frame,
        &mut resumed,
        crate::sched::CpuExitCause::Svc,
    );
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    {
        let mut entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &resumed,
                &mut service,
            )
            .unwrap();
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                fixture.control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut ArmWaitSignalMachine {
                    user_sp,
                    backend: ArmWaitSignalBackend,
                },
            ),
            None
        );
    }
    assert_eq!(frame.elr, 0x700000, "the real handler must run");

    let signal_sp = UserVa::new(frame.x[1]);
    let offset = usize::try_from(signal_sp.raw() - stack.va().raw()).unwrap();
    let signal_frame = carrick_personality_linux::signal::arm::RtSigframe::ref_from_bytes(
        &stack.as_bytes()
            [offset..offset + carrick_personality_linux::signal::arm::PUBLIC_FRAME_LEN],
    )
    .unwrap();
    let mut restored_fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let (mask, restored_sp, altstack) = crate::arm_signal::restore(
        &mut frame,
        signal_frame,
        restored_fp.as_mut_bytes(),
        signal_sp,
    )
    .unwrap();
    fixture
        .control
        .init_blocked(carrick_el1_abi::BlockedMask(mask));
    fixture.control.write_altstack(altstack);
    assert_eq!(restored_sp, user_sp.raw());
    assert_eq!(frame.elr, 0x500000, "sigreturn must resume the saved SVC");

    let arenas = [&fixture.tables];
    let mut editor = crate::mm_portal::tests::anonymous_editor::ForkAnonymousEditor {
        arenas: &arenas,
        pool: TableWindow {
            words: fixture.tables.words.as_ptr().cast_mut(),
            physical_base: fixture.tables.base,
            byte_len: fixture.tables.words.len() * 8,
        },
    };
    assert_eq!(
        serve_delegated_anonymous(
            &mut frame,
            &counters,
            &fixture.task,
            crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
            fixture.region.table(),
            &mut editor,
            None,
        ),
        DelegatedAnonymous::Served,
        "nr={}, arg0={:#x}, arg1={}, leaves={:?}",
        frame.x[8],
        frame.x[0],
        frame.x[1],
        counters
            .anonymous_leaves
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed)),
    );
    assert_eq!(frame.x[0] as i64, 0, "the replayed munmap must complete");
    assert_ne!(
        frame.x[0] as i64,
        carrick_syscall_abi::LINUX_EINTR.guest_retval(),
        "anonymous edit interruption never returns EINTR"
    );
    assert!(
        carrick_core::wait::complete_anonymous_edit_replay(
            fixture.zone,
            fixture.slot,
            fixture.task.mm.key.load(Ordering::Acquire),
        )
        .unwrap(),
        "successful replay must consume its anonymous operation"
    );
    assert!(
        !fixture
            .zone
            .record(binding.record.id)
            .has_object_operation(),
        "completed replay must release the anonymous operation token"
    );
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum ArmAnonymousTerminalEntry {
    Exit,
    Exec,
}

// #1846 slice C: the real terminal entries own cancellation.  An anonymous
// edit has no adapter pin, so both paths must unlink it, consume its typed
// replay token, retire its record, and publish no reservation effect.
#[test]
fn arm_terminal_entries_release_parked_anonymous_edit() {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceCell,
    };
    use carrick_el1::substrate::sched::{Sched, Served};
    use carrick_el1_abi::Lifecycle as _;
    use carrick_sched_core::WakeEffects;
    use carrick_sched_core::spaces::notification::SpaceWaitCause;

    for terminal in [
        ArmAnonymousTerminalEntry::Exit,
        ArmAnonymousTerminalEntry::Exec,
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        fixture.zone.spaces.set_idle_ttbr(0x30000);
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        let runtime = std::sync::Arc::new(
            NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
                source,
                &fixture.task,
                fixture.page,
                fixture.control,
                fixture.address,
                fixture.address,
                initial,
            )
            .unwrap(),
        );
        runtime.give_fixture_root_a_cwd();
        let owner_registry = Box::leak(Box::new(NativeProcessRegistry::new()));
        owner_registry
            .register_root(runtime.clone(), source, &fixture.task, fixture.address)
            .unwrap();
        // This low-level fixture publishes an already-issued sibling directly.
        // Reserve its tid before native registration claims that exact birth.
        fixture
            .zone
            .namespace()
            .with_view(&carrick_sched_core::ShortLockSpin, |namespace| {
                use carrick_sched_core::process::identity_allocator::ClaimKind;
                namespace.reserve_exact(42, ClaimKind::Thread).unwrap();
            });
        let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
        let mut service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[
                0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
            ]),
        )
        .with_words(words);
        let sibling_control = Box::leak(Box::new(ThreadControlSlot::new()));
        let sibling_entry = fixture
            .page
            .stock(
                0,
                carrick_el1_abi::EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 102,
                    birth: carrick_core_abi::BirthSerial::of_task(
                        TaskSerial::from_raw_u64(12).unwrap(),
                    ),
                    uid_credit: 0,
                },
            )
            .unwrap();
        fixture
            .page
            .bind_control_address(sibling_entry, sibling_control as *const _ as u64)
            .unwrap();
        sibling_control
            .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, sibling_entry)
            .unwrap();
        assert!(sibling_control.publish_visible_tid(42));
        let sibling_claim = fixture.page.claim(sibling_entry).unwrap();
        fixture
            .page
            .record_born(
                sibling_claim,
                carrick_el1_abi::BornRecord {
                    caller_task: 41,
                    caller_serial: 101,
                    clone_flags: 0x0001_0000,
                    clear_child_tid: 0,
                    blocked: carrick_el1_abi::BlockedMask(0),
                },
            )
            .unwrap();
        carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
        fixture.page.publish(sibling_entry).unwrap();

        let sibling_task = Box::leak(Box::new(CurrentTask::new()));
        sibling_task.set(
            El1TaskId::from_linux_tid(42),
            carrick_el1_abi::SnapshotGeneration::from_raw(12),
            5,
        );
        sibling_task
            .mm
            .key
            .store(fixture.address.mm.raw().get(), Ordering::Release);
        sibling_task
            .mm
            .thread_generation
            .store(102, Ordering::Release);
        sibling_task.publish_visible_pid(41);
        sibling_task.publish_root_generation(fixture.address.generation);
        sibling_task.publish_lifecycle(
            fixture.page as *const _ as u64,
            sibling_control as *const _ as u64,
        );
        let sibling_slot = SlotId::new(1);
        let sibling_source = BornInZoneSource {
            zone: fixture.zone,
            slot: sibling_slot,
        };
        fixture.zone.drive(sibling_slot, 2);
        fixture
            .zone
            .publish_slot(sibling_slot, fixture.address.mm.raw().get(), Some(1), 1);
        fixture.zone.enter_guest(sibling_slot);
        fixture
            .zone
            .install_space(sibling_slot, fixture.address.mm.raw().get())
            .unwrap();
        let sibling_record = fixture
            .zone
            .current_or_new(
                sibling_slot,
                ThreadIdentity {
                    tid: 42,
                    serial: 102,
                    mm: fixture.address.mm.raw().get(),
                    file_table: 5,
                    generation: 12,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: sibling_control as *const _ as u64,
                },
            )
            .unwrap();
        let sibling_record = fixture.zone.record_ref(sibling_record);
        sibling_control.bind_zone_record(sibling_record);
        // SAFETY: this fixture exclusively owns the live sibling before it parks.
        *unsafe { fixture.zone.record(sibling_record.id).ctx_mut() } = initial;
        assert!(
            fixture
                .zone
                .requeue_preempted(sibling_slot, sibling_record.id)
                .is_queued()
        );
        let idle_record = fixture
            .zone
            .current_or_new(
                sibling_slot,
                ThreadIdentity {
                    tid: 99,
                    serial: 199,
                    mm: fixture.address.mm.raw().get(),
                    file_table: 5,
                    generation: 19,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: sibling_control as *const _ as u64,
                },
            )
            .unwrap();
        // SAFETY: the fixture owns this scheduler-only successor record.
        *unsafe { fixture.zone.record(idle_record).ctx_mut() } = initial;
        assert!(
            fixture
                .zone
                .requeue_preempted(sibling_slot, idle_record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(sibling_slot).unwrap().record,
            sibling_record.id
        );
        assert!(fixture.zone.mark_native_owned(sibling_record.id));
        owner_registry
            .register_thread(
                sibling_source,
                sibling_task,
                fixture.address,
                fixture.page,
                sibling_control,
            )
            .unwrap();

        let index = fixture
            .zone
            .spaces
            .find(fixture.address.mm.raw().get())
            .unwrap();
        let held = fixture
            .region
            .table()
            .lock_in(
                crate::sched::object_wait::space_access(fixture.zone, sibling_slot),
                index.index(),
                ReservationMm::new(fixture.address.mm.raw().get()).unwrap(),
                92,
            )
            .unwrap();
        let notifications = fixture
            .zone
            .space_entry(NonZeroU64::new(fixture.address.mm.raw().get()).unwrap())
            .unwrap()
            .live_notifications()
            .unwrap();
        let revision = notifications.observe(SpaceWaitCause::Reservations);
        let key = notifications.key(SpaceWaitCause::Reservations);
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x600004,
            ..Default::default()
        };
        frame.x[0] = VA;
        frame.x[1] = 4096;
        frame.x[8] = 215;
        let counters = carrick_el1_abi::Counters::new();
        let mut cpu = crate::sched::FakeCpu::default();
        assert_eq!(
            crate::mm_portal::park_anonymous_edit(
                &mut Sched {
                    handoff: None,
                    zone: fixture.zone,
                    slot: sibling_slot,
                    task: sibling_task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters: &counters,
                },
                &mut frame,
                fixture.region.table(),
                SpaceWaitCause::Reservations,
                carrick_core_abi::service::ServiceOrigin::Initial,
            ),
            Some(Served::Idle),
            "terminal={terminal:?}"
        );
        let parked_record = sibling_record;
        assert!(
            fixture.zone.record(parked_record.id).has_object_operation(),
            "claim={:?}, handback={:?}, current={:?}, host={:?}, queue={:?}, census={:?}",
            fixture.zone.record(parked_record.id).claim(),
            fixture.zone.record(parked_record.id).handback(),
            fixture.zone.slot(sibling_slot).current(),
            fixture.zone.slot(sibling_slot).host_record(),
            fixture.zone.object_queue_census(key.index()),
            fixture.zone.record(parked_record.id).object_wait_census(),
        );
        match terminal {
            ArmAnonymousTerminalEntry::Exit => {
                let mut entry = runtime
                    .enter_registered(
                        owner_registry,
                        source,
                        &fixture.task,
                        fixture.address,
                        &initial,
                        &mut service,
                    )
                    .unwrap();
                assert!(matches!(
                    entry.exit_group(23),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(entry.take_run_failure().is_none());
            }
            ArmAnonymousTerminalEntry::Exec => {
                let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
                payload.extend_from_slice(b"/bin/static\0");
                carrick_core_abi::service::encode_exec_payload_header(
                    &mut payload,
                    carrick_core_abi::service::ExecCall::Execve,
                    b"/bin/static\0".len(),
                    0,
                    0,
                )
                .unwrap();
                {
                    let mut entry = runtime
                        .enter_registered(
                            owner_registry,
                            source,
                            &fixture.task,
                            fixture.address,
                            &initial,
                            &mut service,
                        )
                        .unwrap();
                    let begin = entry.begin_exec_service(
                        payload.into_boxed_slice(),
                        None,
                        crate::native_process_runtime::NativeServiceCall::new(
                            carrick_guest_arch::NativeOrdinal::new(221),
                            &counters,
                        ),
                    );
                    assert!(matches!(
                        begin,
                        Ok(crate::native_process_runtime::NativeResume::Left(None))
                    ));
                    assert!(entry.take_handoff_receipt().is_some());
                }
                let selector = fixture.task.service_notice.take().unwrap().unwrap();
                let member = fixture.zone.record(selector.record.id).identity();
                // SAFETY: the selected live root retains this exact control.
                let control = unsafe { &*(member.control_slot as *const ThreadControlSlot) };
                // SAFETY: this fixture consumes the exact published ticket once.
                let ticket = unsafe {
                    ServiceCell::claim_notice(&control.service, selector, NonZeroU64::MIN, member)
                }
                .unwrap();
                let identity = ticket.request().identity;
                // SAFETY: service custody retains the manifest through publish.
                let manifest = unsafe {
                    &mut *(ticket.reply_address().unwrap().raw() as *mut ExecSuccessorManifest)
                };
                let receipt =
                    ExecAdoptionReceipt::checked(NonZeroU64::new(0x1846).unwrap()).unwrap();
                *manifest = manifest
                    .seal(
                        identity,
                        receipt,
                        ExecSuccessorBacking {
                            root: RootGpa::page_aligned(FrameGpa::new(0xa0_0000)).unwrap(),
                            asid: asid(111),
                            asid_generation: NonZeroU64::new(113).unwrap(),
                        },
                        ExecSuccessorEntry {
                            entry: UserVa::new(0x400000),
                            stack_pointer: UserVa::new(0x7fff_f000),
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
                        carrick_sched_core::object_wait::ObjectWaitKey::native_service(
                            selector.record,
                        )
                        .unwrap(),
                        &carrick_sched_core::ShortLockSpin,
                        &|owned| {
                            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                        },
                    )
                    .unwrap();
                let mut effects = WakeEffects::default();
                queue.notify_object(fixture.slot, &mut effects).unwrap();
                drop(queue);
                NativeProcessService::wake_effects(&mut service, effects);
                let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
                // SAFETY: service completion selected this exact root record.
                let saved =
                    unsafe { runtime.record_binding(fixture.zone.record_ref(selected.record)) }
                        .unwrap()
                        .words;
                let mut entry = runtime
                    .enter(source, &fixture.task, saved, &mut service)
                    .unwrap();
                assert!(entry.resume_checkpoint(|_| Ok(None)).is_ok());
                assert!(entry.take_run_failure().is_none());
            }
        }
        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0,
            "terminal={terminal:?}"
        );
        assert!(
            !fixture.zone.record(parked_record.id).has_object_operation(),
            "terminal={terminal:?}, claim={:?}, handback={:?}, cancelled={}, census={:?}",
            fixture.zone.record(parked_record.id).claim(),
            fixture.zone.record(parked_record.id).handback(),
            fixture.zone.record(parked_record.id).is_cancelled(),
            fixture.zone.record(parked_record.id).object_wait_census(),
        );
        assert!(
            fixture.zone.live(parked_record).is_none(),
            "terminal={terminal:?}"
        );
        assert_eq!(
            notifications.observe(SpaceWaitCause::Reservations),
            revision,
            "terminal cancellation cannot publish the anonymous edit: {terminal:?}"
        );
        drop(held);
    }
}

// VM-free binding for kernel.el1.signal-delivery-owner: the scheduler must
// preserve the original wait4 context across a fresh signal-delivery entry.
// No guest instructions or hardware user-memory translation execute here;
// the signal frame lands on a guest user stack.
#[test]
fn arm_parked_wait4_signal_wake_sa_restart_saves_original_context_across_fresh_checkpoint() {
    arm_parked_wait4_signal_wake_case(true, false, true);
}

#[test]
fn arm_parked_wait4_signal_wake_without_sa_restart_retains_eintr() {
    arm_parked_wait4_signal_wake_case(false, false, false);
}

#[test]
fn arm_parked_wait4_signal_wake_replaced_record_discards_restart_context() {
    arm_parked_wait4_signal_wake_case(true, true, false);
}

#[cfg(test)]
fn arm_parked_wait4_signal_wake_case(restart: bool, replace: bool, check_member: bool) {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };
    use carrick_signal_core::policy::{Action, ActionFlags, Disposition, HandlerAddress, Signal};
    use zerocopy::IntoBytes;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let words = fixture.tables.live(&fixture.maintenance);
    let child_task = CurrentTask::new();
    let sibling_task = CurrentTask::new();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let stack_base = stack.va().raw();
    let user_sp = stack.va_at(stack.len());
    assert_eq!(user_sp.raw() & 15, 0);
    let initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    // Match arm_child_wait_wake's supported ownership setup. Fixture::enter
    // scopes an unpublished admission home to its callback; a fork alone
    // does not publish that home, so its Drop retires the parent's record.
    let runtime = std::sync::Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            initial,
        )
        .unwrap(),
    );
    let owner_registry = Box::leak(Box::new(NativeProcessRegistry::new()));
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
    )
    .with_words(&words);
    let usr1 = Signal::from_number(10).unwrap();
    let action = Action {
        disposition: Disposition::Handler(HandlerAddress(0x700000)),
        flags: ActionFlags {
            restart,
            ..Default::default()
        },
        ..Default::default()
    };
    let child_pid = {
        let mut process = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut service,
            )
            .unwrap();
        process.rt_sigaction(usr1, Some(action)).unwrap();
        let LifecycleOutcome::Returned { result, .. } = process.fork(ProcessForkChildTid::NONE)
        else {
            panic!("expected fork return");
        };
        result.raw() as u32
    };
    assert_eq!(child_pid, 42);
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    assert_eq!(
        fixture.zone.record_ref(parent_binding.record.id),
        parent_binding.record,
        "fork must retain the exact admitted parent record",
    );
    let child_key = runtime.namespace_child_key(parent_key, child_pid).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();

    let mut wait_native = ThreadCtx::ZERO;
    wait_native.x[0] = u64::from(child_pid);
    wait_native.x[8] = 260;
    wait_native.pc = 0x500004;
    wait_native.sp_el0 = user_sp.raw();
    let wait_context = Aarch64ParkedContext::from_parts(wait_native, fixture.address);
    {
        let mut parent_entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &wait_context,
                &mut service,
            )
            .unwrap();
        assert_eq!(parent_entry.rt_sigaction(usr1, None).unwrap(), action);
        assert!(matches!(
            parent_entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::from(child_pid)),
                UserVa::new(0),
                LinuxWaitOptions::empty(),
                UserVa::new(0),
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(parent_entry.take_handoff_receipt().is_some());
    }

    activate(source, &child_task, &child_binding);
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        &child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[0x28000, 0x29000]),
    )
    .with_words(&words);
    {
        let mut child_entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &child_task,
                child_binding.address,
                &child_binding.words,
                &mut child_service,
            )
            .unwrap();
        child_entry
            .kill(
                SignalProcessSelector::from_abi(41),
                SignalRequest::from_abi(10).unwrap(),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_binding.record.id)
            .is_queued()
    );

    // Production scheduler -> resume_selected -> NativeProcessEntry::resume_checkpoint.
    // resume_selected drops its temporary entry before returning -EINTR.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = ResumeCpu {
        inner: crate::sched::FakeCpu::default(),
        runtime: &runtime,
        registry: owner_registry,
        source,
        task: &fixture.task,
        service: &mut service,
    };
    let counters = carrick_el1_abi::Counters::new();
    assert_eq!(
        (crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .run_next(&mut frame, 0),
        crate::sched::Served::Returned { switched: true }
    );
    assert_eq!(
        frame.x[0],
        carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
    );
    assert_eq!(frame.elr, 0x500004);
    assert_eq!(frame.esr, 0);
    assert_eq!(fixture.task.visible_pid(), Some(41));
    assert_eq!(
        fixture.zone.record_ref(parent_binding.record.id),
        parent_binding.record
    );

    // Fresh registered entry, as at the ARM user-return checkpoint, using the
    // same exact owner throughout; no fabricated sibling or signal consumption.
    // FakeCpu::save saves registers only. Preserve the admitted address just
    // as with_process_entry reconstructs it around the saved native words.
    let mut saved = Box::new(Aarch64ParkedContext::from_parts(
        ThreadCtx::ZERO,
        fixture.address,
    ));
    crate::sched::ThreadCpu::save(
        &mut cpu.inner,
        &frame,
        &mut saved,
        crate::sched::CpuExitCause::Svc,
    );
    assert_eq!(saved.native.sp_el0, user_sp.raw());
    if check_member {
        // A real host-born member of this same process cannot take the
        // leader's interrupted wait. No fabricated RecordRef selects custody.
        let control = host_born_sibling(fixture, 43);
        run_as_leader(fixture);
        sibling_task.set(
            El1TaskId::from_linux_tid(43),
            carrick_el1_abi::SnapshotGeneration::from_raw(13),
            5,
        );
        sibling_task.mm.key.store(1, Ordering::Release);
        sibling_task
            .mm
            .thread_generation
            .store(103, Ordering::Release);
        sibling_task.publish_visible_pid(41);
        sibling_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
        sibling_task.publish_root_generation(fixture.address.generation);
        let sibling_slot = SlotId::new(1);
        fixture.zone.drive(sibling_slot, 1);
        fixture.zone.publish_slot(sibling_slot, 1, Some(1), 1);
        fixture.zone.enter_guest(sibling_slot);
        fixture.zone.install_space(sibling_slot, 1).unwrap();
        let record = fixture
            .zone
            .current_or_new(
                sibling_slot,
                ThreadIdentity {
                    tid: 43,
                    serial: 103,
                    mm: 1,
                    file_table: 5,
                    generation: 13,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: control as *const _ as u64,
                },
            )
            .unwrap();
        let sibling_words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
        // SAFETY: this fixture exclusively owns the new unpublished home.
        unsafe {
            *fixture.zone.record(record).ctx_mut() = sibling_words;
        }
        control.bind_zone_record(fixture.zone.record_ref(record));
        let sibling_source = BornInZoneSource {
            zone: fixture.zone,
            slot: sibling_slot,
        };
        let registered = owner_registry
            .register_thread(
                sibling_source,
                &sibling_task,
                fixture.address,
                fixture.page,
                control,
            )
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&registered, &runtime));
        let mut sibling_service = Aarch64NativeProcessService::with_crossing(
            &sibling_task,
            sibling_slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        )
        .with_words(&words);
        let mut sibling = runtime
            .enter_registered(
                owner_registry,
                sibling_source,
                &sibling_task,
                fixture.address,
                &sibling_words,
                &mut sibling_service,
            )
            .unwrap();
        assert!(
            sibling.take_interrupted_child_wait().is_none(),
            "same-process sibling must not consume the leader's wait context"
        );
    }
    if replace {
        // Retire the actual OnCpu record through the scheduler, then rehome
        // the live member through the production registry onto a fresh record.
        assert_eq!(
            fixture.zone.release_current(
                fixture.slot,
                parent_binding.record.id,
                &carrick_sched_core::ShortLockSpin,
            ),
            carrick_sched_core::CurrentRelease::Released
        );
        let record = process_record_for_call(
            source,
            &fixture.task,
            &saved.native,
            fixture_ttbr0(fixture),
            fixture.control,
        )
        .unwrap();
        assert_ne!(fixture.zone.record_ref(record), parent_binding.record);
        owner_registry
            .rehome_entry(
                source,
                &fixture.task,
                fixture.address,
                fixture.page,
                fixture.control,
            )
            .unwrap()
            .unwrap();
        let mut entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(
            entry.take_interrupted_child_wait().is_none(),
            "a replacement record cannot inherit the retired record's restart"
        );
    }
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let delivered = {
        let mut process = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(
            process.signal_checkpoint_needed(),
            "SIGUSR1 must remain deliverable after scheduler resume"
        );
        assert_eq!(process.rt_sigaction(usr1, None).unwrap(), action);
        // Host allocations are outside lifecycle_refs' fixed EL1 metadata
        // window. Use the same explicit-control production entry point as
        // native_process_runtime::host_test_support, with this exact member.
        assert_eq!(
            fixture.task.metadata.control_slot.load(Ordering::Acquire),
            fixture.control as *const _ as u64,
        );
        super::signal_delivery::deliver_signal_on_syscall_return(
            &fixture.task,
            fixture.control,
            &mut process,
            &mut frame,
            fp.as_bytes(),
            &mut ArmWaitSignalMachine {
                user_sp: UserVa::new(saved.native.sp_el0),
                backend: ArmWaitSignalBackend,
            },
        )
    };
    assert_eq!(delivered, None);
    assert_eq!(
        frame.elr, 0x700000,
        "must reach real handler delivery before judging restart semantics"
    );
    assert_eq!(frame.x[0], 10);
    assert_eq!(
        frame.x[2],
        frame.x[1] + carrick_personality_linux::signal::arm::UCONTEXT_OFFSET as u64
    );
    let offset = usize::try_from(frame.x[1].checked_sub(stack_base).unwrap()).unwrap();
    let decoded = carrick_personality_linux::signal::arm::decode(
        &stack.as_bytes()[offset..],
        UserVa::new(frame.x[1]),
        true,
    )
    .unwrap();
    assert_eq!(decoded.sp, user_sp);
    let expected = if restart && !replace {
        (0x500000, u64::from(child_pid))
    } else {
        (
            0x500004,
            carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
        )
    };
    assert_eq!(
        (decoded.pc.raw(), decoded.regs[0]),
        expected,
        "handler restart must use only this exact member's unconsumed wait context"
    );

    // A subsequent fresh checkpoint on an unrelated syscall neither finds
    // retained custody nor rewinds the frame, even after a non-restart handler.
    let mut later = carrick_el1_abi::TrapFrame {
        elr: 0x600004,
        ..Default::default()
    };
    later.x[0] = 99;
    later.x[8] = 172;
    let mut later_words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    crate::sched::ThreadCpu::save(
        &mut crate::sched::FakeCpu::default(),
        &later,
        &mut later_words,
        crate::sched::CpuExitCause::Svc,
    );
    let mut later_entry = runtime
        .enter_registered(
            owner_registry,
            source,
            &fixture.task,
            fixture.address,
            &later_words,
            &mut service,
        )
        .unwrap();
    assert!(
        later_entry.take_interrupted_child_wait().is_none(),
        "handler delivery must consume restart custody exactly once, with or without SA_RESTART"
    );
    assert_eq!(
        super::signal_delivery::deliver_signal_on_syscall_return(
            &fixture.task,
            fixture.control,
            &mut later_entry,
            &mut later,
            fp.as_bytes(),
            &mut ArmWaitSignalMachine {
                user_sp,
                backend: ArmWaitSignalBackend
            },
        ),
        None
    );
    assert_eq!((later.elr, later.x[0]), (0x600004, 99));
}

#[test]
fn serial_host_native_fork_two_children_inherit_the_complete_ipc_namespace() {
    native_child_resources(None);
}

#[test]
fn serial_host_native_child_exit_never_spins_on_a_host_owned_pipe() {
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable};
    use carrick_kernel::el1_zone::HostLockWait;
    use std::sync::Arc;
    use std::time::Duration;

    let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
    let parent = HostTable::create(Arc::clone(&owner), 64, 64).unwrap();
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
    reader.install(parent.id(), fd::Fd(3), false).unwrap();
    writer.install(parent.id(), fd::Fd(4), false).unwrap();
    drop(reader);
    drop(writer);

    let child = parent.fork().unwrap();
    let child_table = child.id();
    parent.close(fd::Fd(3)).unwrap();
    child.close(fd::Fd(4)).unwrap();
    // `retire_namespace` consumes this table's lifecycle custody. Do not let
    // the host wrapper independently destroy it at scope exit.
    core::mem::forget(child);

    let region = owner.region();
    let host_guard = region.lock(object, &HostLockWait).unwrap();
    let task = CurrentTask::new();
    let (sent, received) = std::sync::mpsc::channel();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            started_tx.send(()).unwrap();
            let result = super::ipc::retire_namespace(&region, child_table, &task);
            sent.send(result).unwrap();
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("native child exit witness did not start");
        let completed = received.recv_timeout(Duration::from_secs(1));
        drop(host_guard);
        let result = match completed {
            Ok(result) => result,
            Err(_) => received
                .recv_timeout(Duration::from_secs(5))
                .expect("native child exit did not finish after the host released the pipe"),
        };
        result.unwrap();
        assert!(
            completed.is_ok(),
            "native child exit spun on a host-owned pipe instead of deferring physical release"
        );
    });

    assert_eq!(owner.drain_retired_tables().unwrap(), 1);
    let mut guard = region.lock(object, &HostLockWait).unwrap();
    let pipe = guard.pipe().unwrap();
    assert_eq!(pipe.references(End::Reader), 0);
    assert_eq!(pipe.references(End::Writer), 1);
    drop(guard);
    parent.close(fd::Fd(4)).unwrap();
}

#[test]
fn serial_host_native_fork_restored_view_mapping_outlives_children() {
    native_child_resources(Some(true));
}

#[test]
fn serial_host_native_fork_children_outlive_restored_view_mapping() {
    native_child_resources(Some(false));
}

#[cfg(test)]
fn native_child_resources(mapping_last: Option<bool>) {
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use carrick_sched_core::ShortLockSpin;
    use std::sync::Arc;

    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
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
    writer.install(table.id(), fd::Fd(4), true).unwrap();
    let mut host_file =
        carrick_kernel::dispatch::NativeFileWitness::new(&table, fd::Fd(5)).unwrap();
    let mut mapping = mapping_last.map(|_| host_file.mapping().unwrap());
    if mapping_last.is_some() {
        host_file.restore_parent_view().unwrap();
    }
    // Aligned, zero-initialized ABI storage; no process-global fixture pointer.
    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
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
        assert!(result.raw() > 0, "fork errno number: {}", -result.raw());
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        let binding = runtime.task_binding(child).unwrap();
        fixture.zone.record(binding.record.id).identity().file_table
    });
    assert_ne!(children[0], children[1]);
    let ipc = owner.region();
    let authority = ipc.fd(ShortLockSpin);
    // Both native children remain live while a new host capsule's OFD
    // admission refuses. Rollback must neither close their file nor leak a
    // resource token. These pressure pins have no physical backing.
    let mut pressure = Vec::new();
    for _ in 0..ipc.ofd_count() {
        match authority.create_pinned(fd::Description::new(
            fd::BackingToken(0),
            fd::AccessMode::ReadWrite,
            fd::StatusFlags::default(),
        )) {
            Ok(pin) => pressure.push(pin),
            Err(fd::Error::NeedsOfds) => break,
            other => panic!("unexpected pressure admission: {other:?}"),
        }
    }
    assert_eq!(
        carrick_kernel::dispatch::NativeFileWitness::new(&table, fd::Fd(6))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(23),
        "shared OFD exhaustion is ENFILE, errno 23"
    );
    assert_eq!(owner.retained_host_resources(), 1);
    for pin in pressure {
        assert!(authority.unpin(pin).unwrap().is_some());
    }
    let child_tables = children.map(|child| {
        fd::TableId::from_raw(
            map.lookup(child)
                .expect("native child has no IPC namespace"),
        )
    });
    authority
        .set_offset(child_tables[0], fd::Fd(3), fd::Offset(73))
        .unwrap();
    authority
        .setfl(
            child_tables[0],
            fd::Fd(4),
            fd::StatusFlags {
                nonblock: true,
                ..fd::StatusFlags::default()
            },
        )
        .unwrap();
    authority.setfd(child_tables[0], fd::Fd(4), false).unwrap();
    assert_eq!(
        authority.get(table.id(), fd::Fd(3)).unwrap().offset,
        fd::Offset(73)
    );
    assert_eq!(
        authority.get(child_tables[1], fd::Fd(3)).unwrap().offset,
        fd::Offset(73)
    );
    assert!(authority.getfl(table.id(), fd::Fd(4)).unwrap().1.nonblock);
    assert!(
        authority
            .getfl(child_tables[1], fd::Fd(4))
            .unwrap()
            .1
            .nonblock
    );
    assert_eq!(authority.getfd(table.id(), fd::Fd(4)), Ok(true));
    assert_eq!(authority.getfd(child_tables[1], fd::Fd(4)), Ok(true));
    authority.setfd(child_tables[0], fd::Fd(4), true).unwrap();
    let (pin, _) = authority.pin(table.id(), fd::Fd(4)).unwrap();
    assert_eq!(authority.holds(&pin), Ok((3, 2)));
    assert!(authority.unpin(pin).unwrap().is_none());
    let mut guard = ipc.lock(object, &ShortLockSpin).unwrap();
    assert_eq!(guard.pipe().unwrap().references(End::Writer), 1);
    drop(guard);
    for child in children {
        let raw = map
            .lookup(child)
            .expect("native child has no IPC namespace");
        let child_table = fd::TableId::from_raw(raw);
        assert_ne!(child_table, table.id());
        assert_eq!(
            authority.get(child_table, fd::Fd(3)).unwrap().backing,
            IpcBacking::Pipe {
                object,
                end: End::Reader
            }
            .encode()
        );
        assert_eq!(authority.getfd(child_table, fd::Fd(4)), Ok(true));
    }
    drop(writer);
    table.close(fd::Fd(4)).unwrap();
    table.close(fd::Fd(5)).unwrap();
    host_file.close_parent();
    assert_eq!(owner.retained_host_resources(), 1);
    assert_eq!(
        host_file.registered_opens(),
        1,
        "native OFD retains inode admission accounting after the wrapper closes"
    );
    let mut bytes = [0; 5];
    assert_eq!(
        host_file.read(&mut bytes).map_err(|e| e.raw_os_error()),
        Ok(5),
        "both native children retain the real host file; EBADF is errno 9"
    );
    assert_eq!(&bytes, b"child");
    if mapping_last == Some(false) {
        drop(mapping.take());
        assert_eq!(host_file.read(&mut bytes).unwrap(), 5);
    }
    service.retire_fd_table(children[0]);
    assert_eq!(owner.drain_retired_tables().unwrap(), 1);
    assert_eq!(host_file.read(&mut bytes).unwrap(), 5);
    assert_eq!(owner.retained_host_resources(), 1);
    assert!(
        map.lookup(children[0]).is_none(),
        "retired native namespace remains published"
    );
    assert_eq!(
        ipc.lock(object, &ShortLockSpin)
            .unwrap()
            .pipe()
            .unwrap()
            .references(End::Writer),
        1
    );
    service.retire_fd_table(children[1]);
    assert!(map.lookup(children[1]).is_none());
    assert_eq!(
        owner.drain_retired_tables().unwrap(),
        1,
        "the exit boundary must settle the revoked namespace before its parent observes EOF"
    );
    assert_eq!(
        ipc.lock(object, &ShortLockSpin)
            .unwrap()
            .pipe()
            .unwrap()
            .references(End::Writer),
        0,
        "EOF is due only after both child writer descriptions close"
    );
    assert_eq!(
        ipc.lock(object, &ShortLockSpin)
            .unwrap()
            .pipe()
            .unwrap()
            .read_with(1, |_| panic!("EOF copies no bytes"))
            .result,
        Ok(0)
    );
    table.close(fd::Fd(3)).unwrap();
    drop(reader);
    assert!(
        ipc.lock(object, &ShortLockSpin).is_err(),
        "final pipe release leaked the object"
    );
    assert_eq!(owner.retained_host_resources(), 0);
    if mapping_last == Some(true) {
        assert_eq!(host_file.registered_opens(), 1);
        assert_eq!(host_file.read(&mut bytes).unwrap(), 5);
        drop(mapping.take());
    }
    assert_eq!(host_file.physical_fd_errno(), Some(9));
    assert_eq!(host_file.registered_opens(), 0);
    assert_eq!(
        host_file.read(&mut bytes).unwrap_err().raw_os_error(),
        Some(9)
    );
    assert_eq!(
        ipc.descriptor_allocations(),
        1,
        "only the live parent retains table backing"
    );
    // Root exit crosses to the host owner. The native hook must not also
    // retire that owner's table; HostTable's eventual Drop closes it once.
    let parent_table = table.id();
    service.retire_fd_table(5);
    if let Err(error) = authority.backing_capacity(parent_table) {
        // Preserve the assertion on the red implementation instead of a
        // second-retirement fatal abort from fixture destruction.
        core::mem::forget(table);
        panic!("native retirement stole the host-owned root table: {error:?}");
    }
    assert_eq!(map.lookup(5), Some(parent_table.to_raw()));
    drop(table);
    assert_eq!(ipc.descriptor_allocations(), 0);
}

#[test]
fn serial_host_native_fork_concurrent_sibling_table_publish_does_not_einval() {
    use carrick_el1_abi::ipc::{IpcBacking, RawTableId, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let fixture = Fixture::new(0x10000, asid(1));
    let words = fixture.tables.live(&fixture.maintenance);
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
    reader.install(table.id(), fd::Fd(3), false).unwrap();

    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    let home_of = |key: u64| {
        (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize
            % carrick_el1_abi::ipc_tables::IPC_TABLE_MAP_ENTRIES
    };
    let mut colliding = (6..u64::MAX).filter(|&k| home_of(k) == home_of(5));
    let sibling_keys: Vec<u64> = (0..8).map(|_| colliding.next().unwrap()).collect();
    // Place 8 sibling entries ahead of parent_table (5) on their shared probe chain.
    for (idx, &k) in sibling_keys.iter().enumerate() {
        map.publish(
            k,
            RawTableId {
                authority: 99,
                index: idx as u64 + 1,
                generation: 1,
            },
        )
        .unwrap();
    }
    map.publish(5, table.id().to_raw()).unwrap();

    let pages: Vec<_> = (0..64).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.ipc = Some((Arc::clone(&owner), map));

    let stop = AtomicBool::new(false);
    let ready = AtomicBool::new(false);
    std::thread::scope(|s| {
        let churn = s.spawn(|| {
            ready.store(true, Ordering::Release);
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for &k in &sibling_keys {
                    n = n.wrapping_add(1);
                    map.publish(
                        k,
                        RawTableId {
                            authority: 99,
                            index: n,
                            generation: n + 1,
                        },
                    )
                    .unwrap();
                }
            }
        });
        while !ready.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let mut service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        for i in 0..512u64 {
            let child_ft = 100_000 + i;
            let res = service.fork_fd_table(5, child_ft);
            if let Err(e) = res {
                stop.store(true, Ordering::Release);
                panic!("concurrent sibling table publish caused fork_fd_table failure: {e:?}");
            }
            service.retire_fd_table(child_ft);
            assert_eq!(
                owner.drain_retired_tables().unwrap(),
                1,
                "child IPC table must be published"
            );
        }
        stop.store(true, Ordering::Release);
        churn.join().unwrap();
    });
}

#[test]
fn serial_host_native_fork_unpublished_parent_ipc_table_succeeds_without_einval() {
    use carrick_kernel::el1_ipc::{HostIpc, IpcLimits};
    use std::sync::Arc;

    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
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
    let owner = Arc::new(HostIpc::with_limits(1 << 20, IpcLimits::ZONE).unwrap());
    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    // Carrier has IPC bound, but parent_table (5) is unpublished (e.g. after
    // host IPC publication withdrew on shared-OFD exhaustion).
    assert!(map.lookup(5).is_none());
    let pages: Vec<_> = (0..16).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
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
    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE) else {
        panic!("native fork must return");
    };
    assert!(
        result.raw() > 0,
        "fork after host IPC withdrawal must not fail with EINVAL (22); got errno {}",
        -result.raw()
    );
}

#[cfg(test)]
fn activate_target(
    source: BornInZoneSource<'_, Aarch64ParkedContext>,
    task: &CurrentTask,
    binding: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
) -> carrick_sched_core::SwitchedIn {
    let zone = source.zone;
    for _ in 0..8 {
        let switched = zone.switch_in_full(source.slot).unwrap();
        if switched.record == binding.record.id {
            zone.install_space(source.slot, binding.address.mm.raw().get())
                .unwrap();
            let identity = zone.record(binding.record.id).identity();
            task.set(
                El1TaskId::from_linux_tid(binding.key.id.raw()),
                carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
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
            return switched;
        }
        assert!(
            zone.requeue_preempted(source.slot, switched.record)
                .is_queued()
        );
    }
    panic!("target record {:?} not runnable in slot", binding.record.id);
}

/// The ARM EL1 vector's close(57)/fstat(80) fast return, as emitted by
/// `carrick-mem`'s `write_fstat_ceiling_handler`: with the carrier gate
/// enabled, `-EBADF` before any EL1 dispatch for a nonnegative fd strictly
/// above the carrier ceiling word. A live descriptor it would answer is a
/// descriptor the guest can never close (#1398).
// Test-only: this module also builds under `host-test`, without dev-deps.
#[cfg(all(test, not(target_os = "macos")))]
fn vector_fast_path_answers_ebadf(ceiling: &CarrierCeilingWord, fd: i64) -> bool {
    fd >= 0 && fd > i64::from(ceiling.0.load(Ordering::Acquire))
}

/// The carrier's ceiling word, as the HVF publisher owns it: raised only
/// through the kernel's `FdCeilingAuthority`, which every host install and
/// (through the venue's sink) every ring install of this fixture reaches.
#[cfg(all(test, not(target_os = "macos")))]
#[derive(Debug, Default)]
struct CarrierCeilingWord(core::sync::atomic::AtomicU32);
#[cfg(all(test, not(target_os = "macos")))]
impl carrick_hal::FdCeilingPublisher for CarrierCeilingWord {
    fn raise(&self, maximum: u32) {
        self.0.fetch_max(maximum, Ordering::AcqRel);
    }
    fn disable(&self) {}
}

// #1398. Production state this fixture models: the carrier-wide descriptor
// ceiling word the EL1 vector reads before EL1 dispatch, which host
// FileTable installs raised only to the root's highest descriptor. Two live
// native children each dup a descriptor past the capacity they inherited
// (in-ring table growth, no host FileTable), then close every new fd. Each
// live fd must be at or below the ceiling the vector compares against, and
// each close must complete in ring with 0. On main the ring never raised the
// ceiling, so the vector answered EBADF for every fd above the root's.
// Same Linux-only placement as the fixture below.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_children_close_descriptors_above_inherited_capacity() {
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    // The carrier word starts at the authority's maximum 2 and is raised only
    // through the authority this IPC owner's views are bound to.
    let ceiling = Arc::new(CarrierCeilingWord::default());
    let authority = Arc::new(carrick_kernel::kernel::FdCeilingAuthority::new());
    authority.register(Arc::clone(&ceiling) as Arc<dyn carrick_hal::FdCeilingPublisher>);

    let fixture = Fixture::new(0x10000, asid(1));
    let metadata_scope = MetadataScope::new(&fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let task = CurrentTask::new();
    let owner = Arc::new(
        HostIpc::with_ceiling(
            1 << 20,
            IpcLimits {
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
                ..IpcLimits::ZONE
            },
            Arc::clone(&authority),
        )
        .unwrap(),
    );
    // Capacity 2: every child dup lands above the inherited capacity and
    // grows the child's ring-owned table in ring.
    let table = HostTable::create(Arc::clone(&owner), 64, 2).unwrap();
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
    reader.install(table.id(), fd::Fd(0), false).unwrap();
    writer.install(table.id(), fd::Fd(1), false).unwrap();

    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
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
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((Arc::clone(&owner), map));
    let tables = crate::ipc::MapTables(map);
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
    for child in children {
        assert!(
            map.lookup_owned(child).is_some(),
            "each child owns its table"
        );
    }
    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );

    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let run_in_child = |idx: usize, nr: u64, fd: u64| -> (CompletionRoute, i64) {
        activate_target(source, &task, &child_bindings[idx]);
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
        let child_ctx =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[idx].address);
        let mut entry = runtime.enter(source, &task, child_ctx, &mut svc).unwrap();
        let mut frame = carrick_el1_abi::TrapFrame {
            slot: fixture.slot.index() as u64,
            elr: 0x4004,
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[0] = fd;
        carrick_test_support::assert_guest_args(&[fd, 0, 0]);
        let route = super::dispatch::dispatch_syscall_with_native(
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
        let ret = frame.x[0] as i64;
        drop(entry);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, child_bindings[idx].record.id)
                .is_queued()
        );
        (route, ret)
    };

    let sys_dup = carrick_personality_linux::crossing::nr::DUP.raw();
    let sys_close = carrick_personality_linux::crossing::nr::CLOSE.raw();
    // Interleave the two live children so each grows and closes while its
    // sibling holds descriptors above the inherited capacity too.
    let mut opened = [Vec::new(), Vec::new()];
    for _ in 0..4 {
        for (idx, fds) in opened.iter_mut().enumerate() {
            let (route, fd) = run_in_child(idx, sys_dup, 0);
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "child {idx} dup must complete in ring, got {route:?}"
            );
            assert!(fd >= 2, "child {idx} dup(0) errno {}", -fd);
            fds.push(fd);
        }
    }
    assert_eq!(opened, [vec![2, 3, 4, 5], vec![2, 3, 4, 5]]);
    for (idx, fds) in opened.iter().enumerate() {
        for &fd in fds.iter().rev() {
            assert!(
                !vector_fast_path_answers_ebadf(&ceiling, fd),
                "child {idx} fd {fd} is live above the vector's ceiling {}",
                ceiling.0.load(Ordering::Acquire)
            );
            let (route, ret) = run_in_child(idx, sys_close, fd as u64);
            assert_eq!(ret, 0, "child {idx} close({fd}) errno {}", -ret);
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "child {idx} close({fd}) must complete in ring, got {route:?}"
            );
            let (_, again) = run_in_child(idx, sys_close, fd as u64);
            assert_eq!(again, -9, "child {idx} fd {fd} must be gone after close");
        }
    }
    assert!(
        vector_fast_path_answers_ebadf(&ceiling, 6),
        "the ceiling stays conservative: no descriptor above it was ever live"
    );
}

// Places host memory at the EL1 metadata window (0x2D_0800_0000). macOS 27
// refuses every user allocation below 0x70_0000_0000 (even a fixed
// `vm_allocate` in a fresh process), so this runs on Linux hosts, where
// `just test` and the Linux CI lanes exercise it.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_two_children_descriptor_mutations_and_last_writer_eof() {
    native_fork_descriptor_calls(None);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_children_create_eventfd_in_their_own_tables() {
    native_fork_descriptor_calls(Some(
        carrick_personality_linux::crossing::nr::EVENTFD2.raw(),
    ));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_children_create_epoll_in_their_own_tables() {
    native_fork_descriptor_calls(Some(
        carrick_personality_linux::crossing::nr::EPOLL_CREATE1.raw(),
    ));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_children_create_pipe_in_their_own_tables() {
    native_fork_descriptor_calls(Some(carrick_personality_linux::crossing::nr::PIPE2.raw()));
}

#[cfg(not(target_os = "macos"))]
#[test]
#[ignore = "#1506: timerfd for native children is a later slice"]
fn serial_host_native_fork_children_create_timerfd_in_their_own_tables() {
    native_fork_descriptor_calls(Some(
        carrick_personality_linux::crossing::nr::TIMERFD_CREATE.raw(),
    ));
}

#[cfg(all(test, not(target_os = "macos")))]
fn native_fork_descriptor_calls(constructor: Option<u64>) {
    native_descriptor_calls(constructor, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_root_creates_epoll_with_live_children() {
    native_descriptor_calls(
        Some(carrick_personality_linux::crossing::nr::EPOLL_CREATE1.raw()),
        true,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_root_creates_pipe_with_live_children() {
    native_descriptor_calls(
        Some(carrick_personality_linux::crossing::nr::PIPE2.raw()),
        true,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_root_creates_eventfd_with_live_children() {
    native_descriptor_calls(
        Some(carrick_personality_linux::crossing::nr::EVENTFD2.raw()),
        true,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
#[ignore = "#1506: timerfd for native children is a later slice"]
fn serial_host_native_root_creates_timerfd_with_live_children() {
    native_descriptor_calls(
        Some(carrick_personality_linux::crossing::nr::TIMERFD_CREATE.raw()),
        true,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_epoll_ctl_observes_peer_pipe_write() {
    native_descriptor_witness(None, false, true, false, false, false, false, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_epoll_pwait_sigmask_on_a_ring_epoll_is_never_forwarded() {
    native_descriptor_witness(None, false, false, false, false, false, true, false);
}

/// #2588: a native child's pselect6 with a temporary sigmask parks in ring
/// on an inherited zone pipe under that mask, wakes on a live sibling's write
/// and restores the persistent mask.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_pselect6_sigmask_on_a_zone_pipe_parks_in_ring() {
    native_descriptor_argument_witness(
        None, false, false, false, false, false, false, false, None, None, true,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_netpoll_eventfd_wait() {
    native_descriptor_witness(None, false, false, true, false, false, false, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_poll_observes_child_pipe_write() {
    native_descriptor_witness(None, true, false, false, false, false, false, true);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_zone_poll_output_owner_wait_preserves_ready_answer() {
    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
    // SAFETY: aligned, zero-valid ABI storage owned for the complete test.
    let zone = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<ZoneTables<Aarch64ParkedContext>>()
    };
    zone.spaces.set_idle_ttbr(0x30000);
    let space = zone.spaces.publish_closed(1, 0x10000, 0x10000).unwrap();
    zone.spaces.open(space);
    let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let binding = carrick_el1_abi::ExecutionBinding {
        task: carrick_core_abi::EntryTaskKey::from_raw(41),
        generation: carrick_core_abi::SnapshotGeneration::from_raw(11),
        mm: carrick_core_abi::EntryMmKey::from_raw(1),
        thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(101),
    };
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            binding.task,
            carrick_core_abi::entry::BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap()),
            binding.thread_generation,
        )
        .unwrap(),
    );
    assert!(control.publish_visible_tid(41));
    control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[1]));
    let address = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(0x10000)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::MIN),
        generation: ContextGeneration::new(NonZeroU64::MIN),
    };
    let owner = crate::native_process_runtime::host_test_support::NativeOwnerSignalFixture::new::<
        Aarch64Mmu,
    >(
        zone,
        binding,
        page,
        control,
        5,
        Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, address),
    );
    owner.poll_output_owner_wait();
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_root_pipe_zone_ceiling() {
    native_descriptor_witness(None, true, false, false, true, false, false, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_pipe_zone_ceiling() {
    native_descriptor_witness(None, false, false, false, true, false, false, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_root_pipe_zone_ofd_ceiling() {
    native_descriptor_witness(None, true, false, false, false, true, false, false);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_pipe_zone_ofd_ceiling() {
    native_descriptor_witness(None, false, false, false, false, true, false, false);
}

#[cfg(all(test, not(target_os = "macos")))]
fn native_descriptor_calls(constructor: Option<u64>, root_constructor: bool) {
    native_descriptor_witness(
        constructor,
        root_constructor,
        false,
        false,
        false,
        false,
        false,
        false,
    );
}

#[cfg(all(test, not(target_os = "macos")))]
#[allow(clippy::too_many_arguments)]
fn native_descriptor_witness(
    constructor: Option<u64>,
    root_constructor: bool,
    inherited_epoll: bool,
    netpoll: bool,
    zone_ceiling: bool,
    ofd_ceiling: bool,
    epoll_sigmask: bool,
    poll_inherited_pipe: bool,
) {
    native_descriptor_argument_witness(
        constructor,
        root_constructor,
        inherited_epoll,
        netpoll,
        zone_ceiling,
        ofd_ceiling,
        epoll_sigmask,
        poll_inherited_pipe,
        None,
        None,
        false,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_ppoll_prepared_pollfd() {
    native_descriptor_argument_witness(
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        None,
        Some(PreparedPollArgument::Pollfd),
        false,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_ppoll_prepared_timeout() {
    native_descriptor_argument_witness(
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        None,
        Some(PreparedPollArgument::Timeout),
        false,
    );
}

#[cfg(all(test, not(target_os = "macos")))]
#[derive(Clone, Copy, PartialEq)]
enum PreparedPollArgument {
    Pollfd,
    Timeout,
    Unmapped,
    Forbidden,
    EventfdInput,
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_ppoll_unmapped_argument() {
    native_descriptor_argument_witness(
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        None,
        Some(PreparedPollArgument::Unmapped),
        false,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_ppoll_forbidden_argument() {
    native_descriptor_argument_witness(
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        None,
        Some(PreparedPollArgument::Forbidden),
        false,
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_prepared_fork_parent_ppoll_shared_eventfd_input() {
    native_descriptor_argument_witness(
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        None,
        Some(PreparedPollArgument::EventfdInput),
        false,
    );
}

/// Physical supply for the VM-free argument page. The native service selects
/// the real parent owner before this fixture projects its bytes to host memory.
#[cfg(all(test, not(target_os = "macos")))]
fn prepare_poll_argument(
    fixture: &'static Fixture,
    mm: &Mm,
    len: carrick_guest_arch::GuestLen,
    address: UserVa,
) -> Result<(), NativeProcessError> {
    use carrick_core::mm::transaction::{
        SelectionVenues, UserWriteRequest, UserWriteTarget, UserWriteVenue,
    };
    use carrick_core::mm::transfer::ValidatedChunk;
    use carrick_el1::fault::NoopCowResolver;
    struct Supply {
        prepared: native_fault_supply_tests::SelectionWords<'static>,
        cow: NoopCowResolver,
        residency: Box<carrick_el1_abi::FrameGrantResidencyTable>,
        fixture: &'static Fixture,
        mm: ReservationMm,
        supplied: bool,
    }
    impl UserWriteVenue<Aarch64ParkedContext> for Supply {
        type Prepared = native_fault_supply_tests::SelectionWords<'static>;
        type Cow = NoopCowResolver;
        type Error = ();
        fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow> {
            SelectionVenues {
                prepared: &mut self.prepared,
                cow: &mut self.cow,
                residency: &self.residency,
                slot: 0,
            }
        }
        fn settle_completions(&mut self, _: &UserWriteRequest<'_>) -> Result<(), ()> {
            panic!("read preparation has no output")
        }
        fn supply_cow(&mut self, _: carrick_el1_abi::PortalGrantWindow) -> Result<(), ()> {
            panic!("read preparation cannot request write COW")
        }
        fn supply_backing(
            &mut self,
            window: carrick_el1_abi::PortalGrantWindow,
        ) -> Option<Result<(), ()>> {
            assert_eq!(window.operation.mm, self.mm);
            assert_eq!(window.fault_page, VA);
            assert!(!self.supplied, "one input page, one backing supply");
            self.supplied = true;
            // Model the physical service copying the inherited bytes into a
            // private frame. Host bytes stay unchanged until syscall copyout.
            self.fixture.tables.words[1536].store(
                0x9100_0000 | crate::mm_portal::test_support::RW,
                Ordering::Release,
            );
            Some(Ok(()))
        }
        fn copy(&mut self, _: &ValidatedChunk<'_, Aarch64ParkedContext>, _: &[u8]) -> bool {
            panic!("preparation must not copy user output")
        }
    }
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut supply = Supply {
        prepared: native_fault_supply_tests::SelectionWords(words),
        cow: NoopCowResolver,
        residency: carrick_el1::cow::test_support::residency_table(),
        fixture,
        mm: ReservationMm::new(mm.mm.raw().get()).unwrap(),
        supplied: false,
    };
    let portal = super::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    );
    let result = portal.prepare_user_read(
        UserWriteTarget {
            handle: portal.admitted_handle(supply.mm, 0).unwrap(),
            address,
            len,
            slot: fixture.slot,
        },
        words,
        &mut supply,
    );
    if matches!(
        result,
        Err(carrick_core::mm::transaction::UserWriteError::Fault
            | carrick_core::mm::transaction::UserWriteError::Owner(
                carrick_core::mm::transaction::MmError::Fault
            ))
    ) {
        assert!(!supply.supplied, "forbidden input must not allocate");
        return Err(NativeProcessError::Fault);
    }
    assert_eq!(
        result,
        Ok(()),
        "the real parent owner must select and prepare the input"
    );
    assert!(supply.supplied);
    Ok(())
}

#[cfg(all(test, not(target_os = "macos")))]
#[allow(clippy::too_many_arguments)]
fn native_descriptor_metadata_witness(
    constructor: Option<u64>,
    root_constructor: bool,
    inherited_epoll: bool,
    netpoll: bool,
    zone_ceiling: bool,
    ofd_ceiling: bool,
    epoll_sigmask: bool,
    metadata: Option<pipe_metadata_tests::Case>,
) {
    native_descriptor_argument_witness(
        constructor,
        root_constructor,
        inherited_epoll,
        netpoll,
        zone_ceiling,
        ofd_ceiling,
        epoll_sigmask,
        false,
        metadata,
        None,
        false,
    );
}

#[cfg(all(test, not(target_os = "macos")))]
#[allow(clippy::too_many_arguments)]
fn native_descriptor_argument_witness(
    constructor: Option<u64>,
    root_constructor: bool,
    inherited_epoll: bool,
    netpoll: bool,
    zone_ceiling: bool,
    ofd_ceiling: bool,
    epoll_sigmask: bool,
    poll_inherited_pipe: bool,
    metadata: Option<pipe_metadata_tests::Case>,
    prepared_timeout: Option<PreparedPollArgument>,
    select_sigmask: bool,
) {
    use crate::ipc::IpcTables;
    use carrick_abi::{
        LINUX_F_DUPFD, LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_GETFL, LINUX_F_SETFD,
        LINUX_F_SETFL, LINUX_O_NONBLOCK, LINUX_O_WRONLY,
    };
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let metadata_scope = MetadataScope::new(fixture);
    if prepared_timeout.is_some() {
        let descriptor = fixture.tables.words[1536].load(Ordering::Relaxed);
        fixture.tables.words[1536]
            .store((descriptor & !1) | (1 << 56) | (1 << 57), Ordering::Relaxed);
    }
    if prepared_timeout == Some(PreparedPollArgument::Forbidden) {
        crate::mm_portal::test_support::change_policy(
            fixture.region,
            crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
            ReservationMm::new(1).unwrap(),
            &fixture.tables,
            Some(carrick_el1_abi::ReservationProtection::NONE),
        );
    }
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let task = CurrentTask::new();
    let owner = Arc::new(
        HostIpc::with_limits(
            1 << 20,
            IpcLimits {
                objects: if zone_ceiling {
                    carrick_el1_abi::ipc::IPC_OBJECT_SEGMENT
                } else {
                    IpcLimits::ZONE.objects
                },
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
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
    let mut host_file =
        carrick_kernel::dispatch::NativeFileWitness::new(&table, fd::Fd(5)).unwrap();
    host_file.require_close_effects(carrick_el1_abi::ipc::fd::CloseEffects::POSIX_RECORD_LOCKS);
    assert_eq!(
        owner
            .region()
            .fd(carrick_kernel::el1_zone::HostLockWait)
            .close_effects(table.id(), fd::Fd(5))
            .unwrap(),
        carrick_el1_abi::ipc::fd::CloseEffects::POSIX_RECORD_LOCKS,
    );

    // Supply an inherited, fully admitted epoll only in the control witness.
    // Constructor witnesses still have to create their object through dispatch.
    let epoll = (inherited_epoll || epoll_sigmask).then(|| {
        let object = owner.create_epoll().unwrap();
        let description = owner
            .admit_description(fd::Description::new(
                IpcBacking::Epoll { object }.encode(),
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        description.install(table.id(), fd::Fd(6), true).unwrap();
        description
    });

    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
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
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((Arc::clone(&owner), map));
    let tables = crate::ipc::MapTables(map);
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

    // Close parent's writer (fd 4), fd 1, and host file (fd 5); only the two live
    // native children hold them now.
    drop(writer);
    table.close(fd::Fd(1)).unwrap();
    table.close(fd::Fd(4)).unwrap();
    table.close(fd::Fd(5)).unwrap();
    host_file.close_parent();
    assert_eq!(owner.retained_host_resources(), 1);

    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );

    if let Some(epoll) = epoll {
        table.close(fd::Fd(6)).unwrap();
        drop(epoll);
    }

    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());

    let run_binding6 = |binding: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
                        nr: u64,
                        args: [u64; 6]|
     -> (CompletionRoute, i64) {
        let mut cpu = crate::sched::FakeCpu {
            // Keep the timerfd past-deadline witness independent of defaults.
            now: 1_000_000,
            freq: 24_000_000,
            ..Default::default()
        };
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
        frame.x[3] = args[3];
        frame.x[4] = args[4];
        frame.x[5] = args[5];
        carrick_test_support::assert_guest_args(&args);
        let mut attempts = 0;
        let route = loop {
            attempts += 1;
            assert!(attempts <= 3, "argument preparation must make progress");
            let route = super::dispatch::dispatch_syscall_with_native(
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
                Some(fixture),
                Some(&mut entry),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            if frame.elr != 0x4000 {
                break route;
            }
            assert_eq!(frame.x[8], nr);
            assert_eq!(
                &frame.x[..6],
                &args,
                "preparation preserves original arguments"
            );
            frame.elr = 0x4004;
        };
        (route, frame.x[0] as i64)
    };
    let run_binding = |binding: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
                       nr: u64,
                       args: [u64; 4]|
     -> (CompletionRoute, i64) {
        run_binding6(binding, nr, [args[0], args[1], args[2], args[3], 0, 0])
    };

    let run_in_child_full = |idx: usize, nr: u64, args: [u64; 4]| {
        run_binding(
            if root_constructor {
                &parent_binding
            } else {
                &child_bindings[idx]
            },
            nr,
            args,
        )
    };

    let run_in_child = |idx: usize, nr: u64, args: [u64; 3]| {
        run_in_child_full(idx, nr, [args[0], args[1], args[2], 0])
    };

    let sys_dup = carrick_personality_linux::crossing::nr::DUP.raw();
    let sys_dup3 = carrick_personality_linux::crossing::nr::DUP3.raw();
    let sys_fcntl = carrick_personality_linux::crossing::nr::FCNTL.raw();
    let sys_close = carrick_personality_linux::crossing::nr::CLOSE.raw();
    let sys_read = carrick_personality_linux::crossing::nr::READ.raw();
    let sys_write = carrick_personality_linux::crossing::nr::WRITE.raw();
    activate_target(
        source,
        &task,
        if root_constructor {
            &parent_binding
        } else {
            &child_bindings[0]
        },
    );
    for binding in &child_bindings {
        assert!(runtime.task_binding(binding.key).is_some());
    }

    if matches!(metadata, Some(pipe_metadata_tests::Case::Contended)) {
        let start = crate::dispatch::NATIVE_FD_CONTENTIONS.load(Ordering::Acquire);
        std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::channel();
            let owner = &owner;
            let holder = scope.spawn(move || {
                let guard = owner
                    .region()
                    .lock(object, &carrick_kernel::el1_zone::HostLockWait)
                    .unwrap();
                send.send(()).unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while crate::dispatch::NATIVE_FD_CONTENTIONS.load(Ordering::Acquire) == start {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "metadata never encountered Busy"
                    );
                    core::hint::spin_loop();
                }
                drop(guard);
            });
            receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            let (route, result) =
                run_in_child_full(0, sys_fcntl, [3, carrick_abi::LINUX_F_GETPIPE_SZ, 0, 0]);
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(result, 65536);
            holder.join().unwrap();
        });
        assert!(crate::dispatch::NATIVE_FD_CONTENTIONS.load(Ordering::Acquire) > start);
        return;
    }
    if let Some(case) = metadata {
        pipe_metadata_tests::exercise(case, |nr, args| {
            let served = counters.served[nr as usize].load(Ordering::Relaxed);
            let (route, result) = run_in_child_full(0, nr, args);
            assert_eq!(
                counters.served[nr as usize].load(Ordering::Relaxed),
                served + 1,
                "metadata syscall {nr} must record a completed ring call, route {route:?}"
            );
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "pipe metadata syscall {nr} must complete in ring: {route:?}, result {result}"
            );
            result
        });
        return;
    }

    if zone_ceiling {
        // Fill the configured object population through the host authority.
        // Retain every token so the production child's pipe must grow stock.
        let mut retained = Vec::new();
        while let Ok(object) = owner.create_pipe(65536) {
            retained.push(object);
        }
        assert_eq!(retained.len() + 1, carrick_el1_abi::ipc::IPC_OBJECT_SEGMENT);
        assert!(
            owner.create_pipe(65536).is_err(),
            "root observes zone ceiling"
        );
        let output = carrick_test_support::GuestUserBuffer::from_bytes(&[0; 8]);
        let (route, result) = run_in_child_full(
            0,
            carrick_personality_linux::crossing::nr::PIPE2.raw(),
            [output.arg(), 0, 0, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, -23, "constructor must observe zone ENFILE (23)");
        return;
    }

    if ofd_ceiling {
        // Keep objects plentiful and fill the description segment with real
        // reader/writer pairs, each backed by its own pipe object.
        let mut retained = Vec::new();
        loop {
            let object = owner
                .create_pipe(65536)
                .expect("object ceiling is not full");
            let reader = owner.admit_description(fd::Description::new(
                IpcBacking::Pipe {
                    object,
                    end: End::Reader,
                }
                .encode(),
                fd::AccessMode::ReadOnly,
                fd::StatusFlags::default(),
            ));
            let Ok(reader) = reader else {
                break;
            };
            let writer = owner.admit_description(fd::Description::new(
                IpcBacking::Pipe {
                    object,
                    end: End::Writer,
                }
                .encode(),
                fd::AccessMode::WriteOnly,
                fd::StatusFlags::default(),
            ));
            let Ok(writer) = writer else {
                drop(reader);
                break;
            };
            retained.push((object, reader, writer));
        }
        assert_eq!(
            owner.region().ofd_count(),
            carrick_el1_abi::ipc::IPC_OFD_SEGMENT
        );
        let extra_object = owner.create_pipe(65536).expect("objects remain available");
        let _ = extra_object;

        let before_objects = owner.region().object_count();
        let before_ofds = owner.region().ofd_count();
        let output = carrick_test_support::GuestUserBuffer::from_bytes(&[0; 8]);
        let (route, result) = run_in_child_full(
            0,
            carrick_personality_linux::crossing::nr::PIPE2.raw(),
            [output.arg(), 0, 0, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, -23, "pipe2 must observe OFD ceiling ENFILE (23)");
        assert_eq!(
            owner.region().object_count(),
            before_objects,
            "failed pipe2 leaked an object"
        );
        assert_eq!(
            owner.region().ofd_count(),
            before_ofds,
            "failed pipe2 leaked a description"
        );

        let (object, reader, writer) = retained.pop().expect("at least one pipe pair");
        drop(reader);
        drop(writer);
        let _ = object;
        let (route, result) = run_in_child_full(
            0,
            carrick_personality_linux::crossing::nr::PIPE2.raw(),
            [output.arg(), 0, 0, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert!(result >= 0, "pipe2 after freeing an OFD pair: {result}");
        drop(retained);
        return;
    }

    if poll_inherited_pipe {
        use crate::file_table::{LINUX_POLLIN, PollFd};
        use carrick_personality_linux::crossing::nr as sys;

        let activate = |binding: &super::native_process_runtime::NativeRecordBinding<
            AddressContext<RootGpa>,
            Aarch64ParkedContext,
        >| {
            if fixture.zone.slot(fixture.slot).current() == Some(binding.record.id) {
                return;
            }
            if let Some(current) = fixture.zone.slot(fixture.slot).current() {
                assert!(
                    fixture
                        .zone
                        .requeue_preempted(fixture.slot, current)
                        .is_queued()
                );
            }
            activate_target(source, &task, binding);
        };
        let output = carrick_test_support::GuestUserBuffer::zeroed(8);
        let (route, result) = run_binding(
            &parent_binding,
            sys::PIPE2.raw(),
            [output.arg(), carrick_syscall_abi::LINUX_O_CLOEXEC, 0, 0],
        );
        assert!(
            matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork | CompletionRoute::Suspended
            ),
            "parent pipe2 must complete in ring: route={route:?} result={result}"
        );
        assert_eq!(result, 0, "parent pipe2 errno {}", -result);
        let reader = u64::from(u32::from_ne_bytes(
            output.as_bytes()[..4].try_into().unwrap(),
        ));
        let writer_fd = u64::from(u32::from_ne_bytes(
            output.as_bytes()[4..].try_into().unwrap(),
        ));

        let ack_output = carrick_test_support::GuestUserBuffer::zeroed(8);
        let (route, result) = run_binding(
            &parent_binding,
            sys::PIPE2.raw(),
            [ack_output.arg(), carrick_syscall_abi::LINUX_O_CLOEXEC, 0, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, 0);
        let ack_reader = u32::from_ne_bytes(ack_output.as_bytes()[..4].try_into().unwrap()) as u64;
        let ack_writer = u32::from_ne_bytes(ack_output.as_bytes()[4..].try_into().unwrap()) as u64;

        let pollfds = carrick_test_support::GuestUserBuffer::from_values(&[PollFd {
            fd: reader as i32,
            events: LINUX_POLLIN,
            revents: 0x7777,
        }]);
        let timeout = carrick_test_support::GuestUserBuffer::from_values(&[5i64, 0]);
        let writer = {
            let mut writer_service = Aarch64NativeProcessService::with_crossing(
                &task,
                fixture.slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                &crossing,
            )
            .with_words(&words);
            let mut entry = runtime
                .enter(source, &task, parent_binding.words, &mut writer_service)
                .unwrap();
            let before = crate::common_entry::execution_binding(&task);
            assert_eq!(entry.binding(), before);
            let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
            else {
                panic!("prepared-pipe writer fork must return");
            };
            assert_eq!(
                crate::common_entry::execution_binding(&task),
                before,
                "prepared fork must preserve the parent's presented MM and generations"
            );
            assert_eq!(
                entry.binding(),
                before,
                "prepared fork must preserve the parent's expected owner binding"
            );
            assert!(result.raw() > 0, "writer fork errno {}", -result.raw());
            let key = runtime
                .namespace_child_key(parent_binding.key, result.raw() as u32)
                .unwrap();
            runtime.task_binding(key).unwrap()
        };

        for fd in [writer_fd, ack_reader] {
            let (route, result) = run_binding(&parent_binding, sys::CLOSE.raw(), [fd, 0, 0, 0]);
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(result, 0);
        }
        if prepared_timeout.is_none() {
            let (route, result) = run_binding(
                &parent_binding,
                sys::PPOLL.raw(),
                [pollfds.arg(), 1, timeout.arg(), 0],
            );
            assert!(
                matches!(
                    route,
                    CompletionRoute::Served
                        | CompletionRoute::WithWork
                        | CompletionRoute::Suspended
                ),
                "parent ppoll must park and switch in ring: route={route:?} result={result}",
            );
            assert!(
                fixture
                    .zone
                    .record(parent_binding.record.id)
                    .has_object_operation(),
                "the parent must retain its poll readiness operation"
            );
            assert_eq!(
                pollfds.get::<PollFd>(0).revents,
                0x7777,
                "a parked poll must not publish output"
            );
        }
        activate(&writer);
        for fd in [reader, ack_writer] {
            let (route, result) = run_binding(&writer, sys::CLOSE.raw(), [fd, 0, 0, 0]);
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(result, 0);
        }
        let payload = carrick_test_support::GuestUserBuffer::from_value(1u64);
        let (route, result) =
            run_binding(&writer, sys::WRITE.raw(), [writer_fd, payload.arg(), 8, 0]);
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, 8, "child pipe write errno {}", -result);

        activate(&parent_binding);
        let eventfd = if prepared_timeout == Some(PreparedPollArgument::EventfdInput) {
            let (route, result) = run_binding(&parent_binding, sys::EVENTFD2.raw(), [0, 0, 0, 0]);
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert!(result >= 0);
            Some(result as u64)
        } else {
            None
        };
        struct ResetAccess;
        impl Drop for ResetAccess {
            fn drop(&mut self) {
                super::aarch64_process::TEST_OWNER_ACCESS.with(|hook| *hook.borrow_mut() = None);
                carrick_el1::substrate::file::TEST_USER_ACCESS
                    .with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _reset = ResetAccess;
        if let Some(timeout_page) = prepared_timeout {
            let descriptor = fixture.tables.words[1536].load(Ordering::Acquire);
            assert!(carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private(descriptor));
            assert_ne!(
                descriptor & (1 << 59),
                0,
                "real fork must share prepared backing as COW"
            );
            let target = if matches!(
                timeout_page,
                PreparedPollArgument::Timeout | PreparedPollArgument::EventfdInput
            ) {
                timeout.arg()
            } else {
                pollfds.arg()
            };
            super::aarch64_process::TEST_OWNER_ACCESS.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |mm, address, len, bytes, access| {
                    if address.raw() != target || bytes.is_some() {
                        return None;
                    }
                    assert_eq!(
                        mm.mm, fixture.address.mm,
                        "preparation must select the parent MM"
                    );
                    assert_eq!(
                        access,
                        carrick_guest_arch::Access::Read,
                        "private supply makes later output writable"
                    );
                    assert!(
                        bytes.is_none(),
                        "argument preparation has no output effects"
                    );
                    Some(prepare_poll_argument(
                        fixture,
                        mm,
                        len,
                        UserVa::new(if timeout_page == PreparedPollArgument::Unmapped {
                            VA + 8192
                        } else {
                            VA
                        }),
                    ))
                }));
            });
            carrick_el1::substrate::file::TEST_USER_ACCESS.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |address, _, access| {
                    if address.raw() != target {
                        return true;
                    }
                    if matches!(
                        timeout_page,
                        PreparedPollArgument::Unmapped | PreparedPollArgument::Forbidden
                    ) {
                        return false;
                    }
                    let descriptor = fixture.tables.words[1536].load(Ordering::Acquire);
                    descriptor & 1 != 0
                        && (access != carrick_guest_arch::Access::Write
                            || descriptor & (1 << 7) == 0)
                }));
            });
        }
        activate(&parent_binding);
        if let Some(eventfd) = eventfd {
            let (route, result) = run_binding(
                &parent_binding,
                sys::WRITE.raw(),
                [eventfd, timeout.arg(), 8, 0],
            );
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(result, 8, "eventfd input uses the same owner preparation");
            let (route, result) = run_binding(
                &parent_binding,
                sys::WRITE.raw(),
                [eventfd, carrick_guest_arch::USER_CEILING, 8, 0],
            );
            assert_eq!(
                result, -14,
                "bad eventfd input must complete with EFAULT: {route:?}"
            );
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            let value = carrick_test_support::GuestUserBuffer::zeroed(8);
            let (_, result) = run_binding(
                &parent_binding,
                sys::READ.raw(),
                [eventfd, value.arg(), 8, 0],
            );
            assert_eq!(result, 8);
            assert_eq!(
                value.get::<u64>(0),
                5,
                "admission must not replay a successful effect"
            );
            return;
        }
        let (route, result) = run_binding(
            &parent_binding,
            sys::PPOLL.raw(),
            [pollfds.arg(), 1, timeout.arg(), 0],
        );
        if prepared_timeout.is_some() {
            let argument = if prepared_timeout == Some(PreparedPollArgument::Timeout) {
                2
            } else {
                0
            };
            let row = counters.copy_refusals.iter().find(|row| {
                row[0].load(Ordering::Acquire) == 1
                    && row[1].load(Ordering::Relaxed) == sys::PPOLL.raw()
                    && row[4].load(Ordering::Relaxed) == argument
                    && row[6].load(Ordering::Relaxed)
                        == carrick_el1_abi::CopyRefusalReason::GuardedFault.code()
            });
            assert!(
                row.is_some(),
                "ring ppoll must retain the original guarded-copy refusal before owner preparation"
            );
            let row = row.unwrap();
            let arguments = [pollfds.arg(), 1, timeout.arg(), 0, 0, 0];
            for (i, expected) in arguments.iter().enumerate() {
                assert_eq!(
                    row[17 + i].load(Ordering::Relaxed),
                    *expected,
                    "copy refusal must retain raw decoded argument {i}"
                );
            }
            let mut frames = String::new();
            counters.write_syscall_frames(&mut frames).unwrap();
            assert!(frames.contains("source=decoded-dispatch nr=73"), "{frames}");
            assert_eq!(row[7].load(Ordering::Relaxed), 1, "owner present");
            for i in 0..4 {
                assert_eq!(
                    row[8 + i].load(Ordering::Relaxed),
                    row[12 + i].load(Ordering::Relaxed),
                    "post-fork presented/expected binding word {i} differs"
                );
            }
            assert_eq!(
                row[8].load(Ordering::Relaxed),
                fixture.address.mm.raw().get()
            );
            let mut rows = String::new();
            counters.write_copy_refusals(&mut rows).unwrap();
            println!("{rows}");
        }
        let revents = pollfds.get::<PollFd>(0).revents;
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        if matches!(
            prepared_timeout,
            Some(PreparedPollArgument::Unmapped | PreparedPollArgument::Forbidden)
        ) {
            assert_eq!(result, -14, "genuinely forbidden argument remains EFAULT");
            assert_eq!(revents, 0x7777, "failed input must not publish readiness");
            assert!(
                !fixture
                    .zone
                    .record(parent_binding.record.id)
                    .has_object_operation()
            );
            return;
        }
        assert_eq!(result, 1, "ready=true parent ppoll result");
        assert_ne!(
            revents & LINUX_POLLIN,
            0,
            "parent ppoll revents={revents:#x}"
        );
        assert!(runtime.task_binding(parent).is_some(), "parent stays live");
        assert!(
            runtime.task_binding(writer.key).is_some(),
            "child stays live"
        );
        let received = carrick_test_support::GuestUserBuffer::zeroed(8);
        let (route, result) = run_binding(
            &parent_binding,
            sys::READ.raw(),
            [reader, received.arg(), 8, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, 8);
        assert_eq!(
            received.get::<u64>(0),
            1,
            "ready includes the 8-byte read, not just ppoll"
        );

        activate(&writer);
        let ack = carrick_test_support::GuestUserBuffer::from_value(0xa5a5_a5a5_a5a5_a5a5u64);
        let (route, _) = run_binding(&writer, sys::READ.raw(), [ack_reader, ack.arg(), 8, 0]);
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork | CompletionRoute::Suspended
        ));
        assert!(
            fixture.zone.record(writer.record.id).has_object_operation(),
            "child blocks until parent acknowledgement"
        );
        activate(&parent_binding);
        let (route, result) = run_binding(
            &parent_binding,
            sys::WRITE.raw(),
            [ack_writer, payload.arg(), 8, 0],
        );
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, 8);
        activate(&writer);
        let (route, result) = run_binding(&writer, sys::READ.raw(), [ack_reader, ack.arg(), 8, 0]);
        assert!(matches!(
            route,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(result, 8);
        assert_eq!(ack.get::<u64>(0), 1);
        // Fork and lifecycle completion use the same production native owner
        // as the existing birth above. Physical retirement is modeled by the
        // fixture crossing; a WithWork SVC route is not an observed exit.
        *crossing.zone.lock().unwrap() = Some(fixture.zone);
        *crossing.child.lock().unwrap() = Some((
            super::common_entry::execution_binding(&task),
            writer.address,
        ));
        let exit = |binding: &super::native_process_runtime::NativeRecordBinding<
            AddressContext<RootGpa>,
            Aarch64ParkedContext,
        >| {
            let mut service = Aarch64NativeProcessService::with_crossing(
                &task,
                fixture.slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                &crossing,
            )
            .with_words(&words);
            let mut entry = runtime
                .enter(source, &task, binding.words, &mut service)
                .unwrap();
            assert!(matches!(
                entry.exit_group(0),
                LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
            entry.take_root_exit()
        };
        assert_eq!(exit(&writer), None);
        assert_eq!(crossing.retirements.load(Ordering::Acquire), 1);
        activate(&parent_binding);
        let status = carrick_test_support::GuestUserBuffer::from_value(-1i32);
        {
            let mut service = Aarch64NativeProcessService::with_crossing(
                &task,
                fixture.slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                &crossing,
            )
            .with_words(&words);
            let mut entry = runtime
                .enter(source, &task, parent_binding.words, &mut service)
                .unwrap();
            let LifecycleOutcome::Returned { result, .. } = entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::from(writer.visible_pid)),
                status.va(),
                LinuxWaitOptions::empty(),
                UserVa::new(0),
            ) else {
                panic!("exited child must be reaped without another wait");
            };
            assert_eq!(result.raw(), i64::from(writer.visible_pid));
        }
        assert_eq!(status.get::<i32>(0), 0, "waitpid must observe child exit 0");
        // This is an IPC schedule. Memory-fault and signed execution evidence
        // belongs to its own fixtures; no memory/isolation tuple is invented.
        assert_eq!(exit(&parent_binding), Some(LinuxWaitStatus::exited(0)));
        println!(
            "prepared-fork-ipc owner=zone ready=true notified=true child_ack=1 child_exit=0 parent_exit=0"
        );
        return;
    }

    if netpoll {
        use carrick_personality_linux::crossing::nr as sys;
        let child = &child_bindings[0];
        let completed = |nr, args| {
            let (route, result) = run_binding(child, nr, args);
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "native child netpoll call {nr}: {route:?} ({result})"
            );
            result
        };
        let epoll = completed(
            sys::EPOLL_CREATE1.raw(),
            [carrick_syscall_abi::LINUX_O_CLOEXEC, 0, 0, 0],
        );
        assert!(epoll >= 0);
        let event = completed(
            sys::EVENTFD2.raw(),
            [
                0,
                carrick_syscall_abi::LINUX_O_CLOEXEC | LINUX_O_NONBLOCK,
                0,
                0,
            ],
        );
        assert!(event >= 0);
        let epoll = epoll as u64;
        let event = event as u64;
        assert_eq!(completed(sys::FCNTL.raw(), [epoll, LINUX_F_GETFD, 0, 0]), 1);
        assert_eq!(completed(sys::FCNTL.raw(), [event, LINUX_F_GETFD, 0, 0]), 1);
        assert_ne!(
            completed(sys::FCNTL.raw(), [event, LINUX_F_GETFL, 0, 0]) & LINUX_O_NONBLOCK as i64,
            0
        );
        let cookie = 0x1506_1740_0000_0001u64;
        let mut member = [0; 16];
        member[..4].copy_from_slice(
            &(carrick_el1_abi::ipc::epoll::events::IN | carrick_el1_abi::ipc::epoll::events::ET)
                .to_ne_bytes(),
        );
        member[8..].copy_from_slice(&cookie.to_ne_bytes());
        let mut member = carrick_test_support::GuestUserBuffer::from_bytes(&member);
        let events = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 16]);
        assert_eq!(
            completed(
                sys::EPOLL_CTL.raw(),
                [epoll, carrick_abi::LINUX_EPOLL_CTL_ADD, event, member.arg()]
            ),
            0
        );
        assert_eq!(
            completed(sys::EPOLL_PWAIT.raw(), [epoll, events.arg(), 1, 0]),
            0
        );
        assert_eq!(events.as_bytes(), &[0xa5; 16]);
        // epoll_pwait2 shares this ring-created object and must not cross.
        let zero_timeout = carrick_test_support::GuestUserBuffer::zeroed(16);
        assert_eq!(
            completed(
                sys::EPOLL_PWAIT2.raw(),
                [epoll, events.arg(), 1, zero_timeout.arg()]
            ),
            0
        );
        let invalid_timeout =
            carrick_test_support::GuestUserBuffer::from_value([0i64, 1_000_000_000]);
        assert_eq!(
            completed(
                sys::EPOLL_PWAIT2.raw(),
                [epoll, events.arg(), 1, invalid_timeout.arg()]
            ),
            -22
        );
        let value = carrick_test_support::GuestUserBuffer::from_value(1u64);
        let counter = carrick_test_support::GuestUserBuffer::zeroed(8);
        assert_eq!(completed(sys::WRITE.raw(), [event, value.arg(), 8, 0]), 8);
        assert_eq!(
            completed(sys::EPOLL_PWAIT.raw(), [epoll, events.arg(), 1, 0]),
            1
        );
        assert_eq!(
            u64::from_ne_bytes(events.as_bytes()[8..].try_into().unwrap()),
            cookie
        );
        assert_eq!(
            u32::from_ne_bytes(events.as_bytes()[..4].try_into().unwrap()),
            carrick_el1_abi::ipc::epoll::events::IN
        );
        assert_eq!(completed(sys::READ.raw(), [event, counter.arg(), 8, 0]), 8);
        assert_eq!(
            completed(sys::EPOLL_PWAIT.raw(), [epoll, events.arg(), 1, 0]),
            0
        );
        let writer = {
            let mut writer_service = Aarch64NativeProcessService::with_crossing(
                &task,
                fixture.slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                &crossing,
            )
            .with_words(&words);
            let mut entry = runtime
                .enter(source, &task, child.words, &mut writer_service)
                .unwrap();
            let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
            else {
                panic!("netpoll writer fork must return");
            };
            assert!(
                result.raw() > 0,
                "netpoll writer fork errno {}",
                -result.raw()
            );
            let key = runtime
                .namespace_child_key(child.key, result.raw() as u32)
                .unwrap();
            runtime.task_binding(key).unwrap()
        };
        for wait_call in [sys::EPOLL_PWAIT, sys::EPOLL_PWAIT2] {
            // MOD rearms the same edge with a new data cookie. Fork the writer
            // after construction so only real descriptor inheritance connects it
            // to the child's private eventfd; the original parent stays live.
            let cookie = cookie + wait_call.raw();
            member.as_mut_bytes()[8..].copy_from_slice(&cookie.to_ne_bytes());
            assert_eq!(
                completed(
                    sys::EPOLL_CTL.raw(),
                    [epoll, carrick_abi::LINUX_EPOLL_CTL_MOD, event, member.arg()]
                ),
                0
            );
            // End this VM-free entry at its real park boundary instead of loading
            // a peer's guest instructions on the fake CPU.
            task.linux.mark_pending_host_work();
            let mut timeout =
                carrick_test_support::GuestUserBuffer::from_value([0i64, 500_000_000]);
            let timeout_arg = if wait_call == sys::EPOLL_PWAIT2 {
                timeout.arg()
            } else {
                500
            };
            let (route, _) = run_binding(
                child,
                wait_call.raw(),
                [epoll, events.arg(), 1, timeout_arg],
            );
            assert_eq!(
                route,
                CompletionRoute::Suspended,
                "empty finite wait must really park in ring"
            );
            assert!(fixture.zone.slot(fixture.slot).current().is_none());
            assert_eq!(
                fixture.zone.record(child.record.id).deadline(),
                Some(13_000_001)
            );
            let parked_operation = fixture
                .zone
                .record(child.record.id)
                .object_wait_census()
                .unwrap();
            assert_ne!(parked_operation.operation, 0);
            assert_ne!(parked_operation.queue, 0);
            assert!(matches!(
                fixture.zone.record(child.record.id).claim(),
                carrick_sched_core::Claim::Parked { .. }
                    | carrick_sched_core::Claim::Transferring { .. }
            ));
            activate_target(source, &task, &writer);
            let (route, result) =
                run_binding(&writer, sys::WRITE.raw(), [event, value.arg(), 8, 0]);
            assert!(matches!(
                route,
                CompletionRoute::Served | CompletionRoute::WithWork
            ));
            assert_eq!(result, 8);
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, writer.record.id)
                    .is_queued()
            );
            activate_target(source, &task, child);
            assert!(fixture.zone.record(child.record.id).has_object_operation());
            // SAFETY: activate_target holds this record OnCpu, and no guest CPU
            // runs concurrently. Verify the arguments retained by the actual park
            // before reconstructing its SVC entry through the helper.
            let saved = unsafe { &*fixture.zone.record(child.record.id).ctx_mut() };
            assert_eq!(&saved.native.x[..4], &[epoll, events.arg(), 1, timeout_arg]);
            assert_eq!(saved.native.x[8], wait_call.raw());
            // A resumed wait uses the retained deadline, even if the caller's
            // timespec has since become invalid.
            timeout.as_mut_bytes().fill(0xff);
            assert_eq!(
                completed(wait_call.raw(), [epoll, events.arg(), 1, timeout_arg]),
                1
            );
            assert_eq!(fixture.zone.timer_deadline(fixture.slot), None);
            assert!(!fixture.zone.record(child.record.id).has_object_operation());
            assert_eq!(
                u64::from_ne_bytes(events.as_bytes()[8..].try_into().unwrap()),
                cookie
            );
            assert_eq!(completed(sys::READ.raw(), [event, counter.arg(), 8, 0]), 8);
            assert_eq!(
                u64::from_ne_bytes(counter.as_bytes().try_into().unwrap()),
                1
            );
        }
        assert_eq!(
            completed(
                sys::EPOLL_CTL.raw(),
                [epoll, carrick_abi::LINUX_EPOLL_CTL_DEL, event, 0]
            ),
            0
        );
        assert_eq!(completed(sys::WRITE.raw(), [event, value.arg(), 8, 0]), 8);
        assert_eq!(
            completed(sys::EPOLL_PWAIT.raw(), [epoll, events.arg(), 1, 0]),
            0
        );
        assert!(runtime.task_binding(parent).is_some());
        assert!(runtime.task_binding(child.key).is_some());
        assert!(
            counters
                .forwarded
                .iter()
                .all(|count| count.load(Ordering::Relaxed) == 0)
        );
        return;
    }

    if select_sigmask {
        // #2588: pselect(3) callers pass a temporary sigmask. Two live tasks
        // share the inherited pipe (fd 3 reads, fd 4 writes): child 0 waits
        // with the mask while child 1 makes the pipe readable. The call is
        // served in ring under the shared readiness owner, never forwarded.
        use carrick_personality_linux::crossing::nr as sys;
        use carrick_test_support::GuestUserBuffer;
        let pselect = sys::PSELECT6.raw();
        let forwarded = || counters.forwarded[pselect as usize].load(Ordering::Relaxed);
        let sigusr1 = 1u64 << (10 - 1);
        let mask = GuestUserBuffer::from_bytes(&sigusr1.to_ne_bytes());
        let pair = |len: u64| GuestUserBuffer::from_value([mask.arg(), len]);
        let (sized, short) = (pair(8), pair(4));
        let empty = GuestUserBuffer::from_value([0u64, 8]);
        let zero = GuestUserBuffer::from_value([0u64, 0]);
        let read_bit = (1u64 << 3).to_ne_bytes();
        let mut read_set = GuestUserBuffer::from_bytes(&read_bit);
        let control = |binding: &super::native_process_runtime::NativeRecordBinding<
            AddressContext<RootGpa>,
            Aarch64ParkedContext,
        >| {
            let address = fixture
                .zone
                .record(binding.record.id)
                .identity()
                .control_slot;
            assert_ne!(address, 0);
            // SAFETY: the live zone record retains its published control slot.
            unsafe {
                &*(address as *const carrick_personality_linux::abi::thread::ThreadControlSlot)
            }
        };
        let (waiter, writer) = (&child_bindings[0], &child_bindings[1]);
        let waiter_control = control(waiter);
        let original = waiter_control.blocked();
        let in_ring = |(route, result): (CompletionRoute, i64)| {
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "pselect6 with a sigmask must be served in ring, got {route:?} ({result}); \
                 forwarded pselect6 {}",
                forwarded()
            );
            result
        };
        // A set size other than sizeof(sigset_t) is EINVAL, in ring.
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pselect,
                [4, read_set.arg(), 0, 0, zero.arg(), short.arg()]
            )),
            -22
        );
        // A NULL set leaves the mask alone, whatever its size.
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pselect,
                [4, read_set.arg(), 0, 0, zero.arg(), empty.arg()]
            )),
            0
        );
        // Nothing ready, zero timeout: the set is cleared and the mask is
        // never changed by a call that does not park.
        read_set.as_mut_bytes().copy_from_slice(&read_bit);
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pselect,
                [4, read_set.arg(), 0, 0, zero.arg(), sized.arg()]
            )),
            0
        );
        assert_eq!(read_set.as_bytes(), &[0; 8]);
        assert_eq!(waiter_control.blocked(), original);
        assert!(!waiter_control.forwarded_wait_mask_armed());

        // Nothing ready, no timeout: the wait parks in ring under the mask.
        read_set.as_mut_bytes().copy_from_slice(&read_bit);
        let wait = [4, read_set.arg(), 0, 0, 0, sized.arg()];
        task.linux.mark_pending_host_work();
        let (route, _) = run_binding6(waiter, pselect, wait);
        assert_eq!(
            route,
            CompletionRoute::Suspended,
            "a zone pipe select with a sigmask must park in ring (forwarded {})",
            forwarded()
        );
        assert!(fixture.zone.record(waiter.record.id).has_object_operation());
        assert!(waiter_control.forwarded_wait_mask_armed());
        assert_eq!(waiter_control.blocked().0, sigusr1);

        // The peer task makes the pipe readable; the waiter re-enters the
        // same call, reports the descriptor and has its persistent mask back.
        activate_target(source, &task, writer);
        let payload = GuestUserBuffer::from_bytes(b"peer");
        assert_eq!(
            in_ring(run_binding(
                writer,
                sys::WRITE.raw(),
                [4, payload.arg(), 4, 0]
            )),
            4
        );
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, writer.record.id)
                .is_queued()
        );
        activate_target(source, &task, waiter);
        read_set.as_mut_bytes().fill(0);
        assert_eq!(in_ring(run_binding6(waiter, pselect, wait)), 1);
        assert_eq!(read_set.as_bytes(), &read_bit);
        assert!(!fixture.zone.record(waiter.record.id).has_object_operation());
        assert!(!waiter_control.forwarded_wait_mask_armed());
        assert_eq!(waiter_control.blocked(), original);
        assert_eq!(forwarded(), 0);
        return;
    }

    if epoll_sigmask {
        // #1671: libuv's `uv__io_poll` calls `epoll_pwait` with a SIGPROF
        // mask. Two live tasks share one ring epoll (inherited across fork):
        // child 0 waits with the mask while child 1 makes the pipe readable.
        // The call must never be forwarded: the host has no such descriptor.
        use carrick_el1_abi::IpcLeave;
        use carrick_personality_linux::crossing::nr as sys;
        let pwait = sys::EPOLL_PWAIT.raw();
        let forwarded = || counters.forwarded[pwait as usize].load(Ordering::Relaxed);
        let sigmask_leaves =
            || counters.ipc_leaves[IpcLeave::EpollSigmask as usize].load(Ordering::Relaxed);
        let sigprof = 1u64 << (27 - 1);
        let mut mask = carrick_test_support::GuestUserBuffer::from_bytes(&sigprof.to_le_bytes());
        let mask_arg = mask.arg();
        let cookie = 0x1671_0000_0000_0001u64;
        let mut interest = [0u8; 16];
        interest[..4].copy_from_slice(&carrick_abi::LINUX_EPOLLIN.to_ne_bytes());
        interest[8..].copy_from_slice(&cookie.to_ne_bytes());
        let interest = carrick_test_support::GuestUserBuffer::from_bytes(&interest);
        let events = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 16]);
        let forever = u64::from(u32::MAX); // timeout -1
        let control = |binding: &super::native_process_runtime::NativeRecordBinding<
            AddressContext<RootGpa>,
            Aarch64ParkedContext,
        >| {
            let address = fixture
                .zone
                .record(binding.record.id)
                .identity()
                .control_slot;
            assert_ne!(address, 0);
            // SAFETY: the live zone record retains its published control slot.
            unsafe {
                &*(address as *const carrick_personality_linux::abi::thread::ThreadControlSlot)
            }
        };
        let (waiter, writer) = (&child_bindings[0], &child_bindings[1]);
        let waiter_control = control(waiter);
        let original = waiter_control.blocked();
        let in_ring = |(route, result): (CompletionRoute, i64)| {
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "epoll_pwait with a sigmask must be served in ring, got {route:?} ({result}); \
                 forwarded epoll_pwait {}, IpcLeave::EpollSigmask {}",
                forwarded(),
                sigmask_leaves()
            );
            result
        };
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                sys::EPOLL_CTL.raw(),
                [6, carrick_abi::LINUX_EPOLL_CTL_ADD, 3, interest.arg(), 0, 0]
            )),
            0
        );
        // A size other than 8 is EINVAL, in ring, before any wait.
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pwait,
                [6, events.arg(), 1, forever, mask_arg, 4]
            )),
            -22
        );
        // Nothing ready, zero timeout: served with the mask untouched.
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pwait,
                [6, events.arg(), 1, 0, mask_arg, 8]
            )),
            0
        );
        assert_eq!(waiter_control.blocked(), original);
        assert!(!waiter_control.forwarded_wait_mask_armed());

        // Nothing ready, no timeout: the wait parks in ring under the mask.
        task.linux.mark_pending_host_work();
        let (route, _) = run_binding6(waiter, pwait, [6, events.arg(), 1, forever, mask_arg, 8]);
        assert_eq!(
            route,
            CompletionRoute::Suspended,
            "a ring epoll with a sigmask must park in ring (forwarded {}, sigmask leaves {})",
            forwarded(),
            sigmask_leaves()
        );
        assert_eq!(forwarded(), 0);
        assert_eq!(sigmask_leaves(), 0);
        assert!(waiter_control.forwarded_wait_mask_armed());
        assert_eq!(waiter_control.blocked().0, sigprof);

        // Wake then drain before re-entry: first preserve the user buffer as
        // a control, then overwrite it while the original call is parked.
        for overwrite in [false, true] {
            if overwrite {
                mask.as_mut_bytes().fill(0);
            }
            activate_target(source, &task, writer);
            let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"peer");
            let drained = carrick_test_support::GuestUserBuffer::zeroed(4);
            assert_eq!(
                in_ring(run_binding(
                    writer,
                    sys::WRITE.raw(),
                    [4, payload.arg(), 4, 0]
                )),
                4
            );
            assert_eq!(
                in_ring(run_binding(
                    writer,
                    sys::READ.raw(),
                    [3, drained.arg(), 4, 0]
                )),
                4
            );
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, writer.record.id)
                    .is_queued()
            );
            activate_target(source, &task, waiter);
            task.linux.mark_pending_host_work();
            let (route, _) =
                run_binding6(waiter, pwait, [6, events.arg(), 1, forever, mask_arg, 8]);
            assert_eq!(route, CompletionRoute::Suspended);
            assert_eq!(waiter_control.blocked().0, sigprof);
            assert!(waiter_control.forwarded_wait_mask_armed());
        }
        // The accepted snapshot also survives an unreadable original buffer.
        drop(mask);

        // The peer task makes the member readable; the waiter re-enters the
        // same call, harvests the event and has its own mask back.
        activate_target(source, &task, writer);
        let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"peer");
        assert_eq!(
            in_ring(run_binding(
                writer,
                sys::WRITE.raw(),
                [4, payload.arg(), 4, 0]
            )),
            4
        );
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, writer.record.id)
                .is_queued()
        );
        activate_target(source, &task, waiter);
        assert_eq!(
            in_ring(run_binding6(
                waiter,
                pwait,
                [6, events.arg(), 1, forever, mask_arg, 8]
            )),
            1
        );
        assert_eq!(
            u64::from_ne_bytes(events.as_bytes()[8..16].try_into().unwrap()),
            cookie
        );
        assert!(!waiter_control.forwarded_wait_mask_armed());
        assert_eq!(waiter_control.blocked(), original);
        assert_eq!(forwarded(), 0);
        assert_eq!(sigmask_leaves(), 0);

        // #2160: a descriptor that is not a zone epoll (fd 3 is the pipe's
        // read end) is the host's EINVAL to give. That forward names itself.
        let not_zone =
            || counters.ipc_leaves[IpcLeave::EpollNotZone as usize].load(Ordering::Relaxed);
        assert_eq!(not_zone(), 0);
        let (route, _) = run_binding6(waiter, pwait, [3, events.arg(), 1, 0, 0, 0]);
        assert!(
            matches!(route, CompletionRoute::Forward | CompletionRoute::WithWork),
            "{route:?}"
        );
        assert_eq!(forwarded(), 1);
        assert_eq!(not_zone(), 1, "the forward must name its arm");
        return;
    }

    if inherited_epoll {
        use carrick_personality_linux::crossing::nr as sys;
        let cookie = 0x1506_1234_5678_9abcu64;
        let mut interest = [0u8; 16];
        interest[..4].copy_from_slice(&carrick_abi::LINUX_EPOLLIN.to_ne_bytes());
        interest[8..].copy_from_slice(&cookie.to_ne_bytes());
        let interest = carrick_test_support::GuestUserBuffer::from_bytes(&interest);
        let events = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 16]);
        let completed = |idx, ordinal, arguments| {
            let (route, result) = run_in_child_full(idx, ordinal, arguments);
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "child {idx} epoll member call {ordinal} must be served in ring, got {route:?} ({result})"
            );
            result
        };
        assert_eq!(
            completed(
                0,
                sys::EPOLL_CTL.raw(),
                [6, carrick_abi::LINUX_EPOLL_CTL_ADD, 3, interest.arg()]
            ),
            0
        );
        assert_eq!(
            completed(0, sys::EPOLL_PWAIT.raw(), [6, events.arg(), 1, 0]),
            0
        );
        assert_eq!(events.as_bytes(), &[0xa5; 16]);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, child_bindings[0].record.id)
                .is_queued()
        );
        activate_target(source, &task, &child_bindings[1]);
        let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"peer");
        assert_eq!(completed(1, sys::WRITE.raw(), [4, payload.arg(), 4, 0]), 4);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, child_bindings[1].record.id)
                .is_queued()
        );
        activate_target(source, &task, &child_bindings[0]);
        assert_eq!(
            completed(0, sys::EPOLL_PWAIT.raw(), [6, events.arg(), 1, 0]),
            1
        );
        assert_eq!(
            u32::from_ne_bytes(events.as_bytes()[..4].try_into().unwrap())
                & carrick_abi::LINUX_EPOLLIN,
            carrick_abi::LINUX_EPOLLIN
        );
        assert_eq!(
            u64::from_ne_bytes(events.as_bytes()[8..16].try_into().unwrap()),
            cookie
        );
        let received = carrick_test_support::GuestUserBuffer::zeroed(4);
        assert_eq!(completed(0, sys::READ.raw(), [3, received.arg(), 4, 0]), 4);
        assert_eq!(received.as_bytes(), b"peer");
        assert_eq!(
            completed(0, sys::EPOLL_PWAIT.raw(), [6, events.arg(), 1, 0]),
            0
        );
        return;
    }

    if let Some(nr) = constructor {
        use carrick_personality_linux::crossing::nr as sys;
        let output = carrick_test_support::GuestUserBuffer::zeroed(8);
        // Every follow-up read is nonblocking: an empty or miswired object
        // must fail an assertion instead of parking this fixture indefinitely.
        let flags = carrick_syscall_abi::LINUX_O_CLOEXEC
            | if nr == sys::EPOLL_CREATE1.raw() {
                0
            } else {
                LINUX_O_NONBLOCK
            };
        let args = if nr == sys::PIPE2.raw() {
            [output.arg(), flags, 0]
        } else if nr == sys::EVENTFD2.raw() {
            [7, flags, 0]
        } else if nr == sys::TIMERFD_CREATE.raw() {
            [1, flags, 0] // CLOCK_MONOTONIC
        } else {
            [flags, 0, 0]
        };
        if root_constructor {
            assert_eq!(tables.table_of(&task), Some(table.id().to_raw()));
            assert!(tables.owned_table_of(&task).is_none());
            let (route, result) = run_in_child(0, nr, args);
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "root constructor {nr} must share the children's ring path, got {route:?} ({result})"
            );
            assert!(result >= 0, "root constructor {nr} errno {}", -result);
            let created = if nr == sys::PIPE2.raw() {
                assert_eq!(result, 0);
                output
                    .as_bytes()
                    .chunks_exact(4)
                    .map(|bytes| u64::from(u32::from_ne_bytes(bytes.try_into().unwrap())))
                    .collect::<Vec<_>>()
            } else {
                vec![result as u64]
            };
            for fd in created.iter().copied() {
                let (route, result) = run_in_child(0, sys::FCNTL.raw(), [fd, LINUX_F_GETFD, 0]);
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(result, 1, "root descriptor must expose FD_CLOEXEC in ring");
                let (route, result) = run_in_child(0, sys::CLOSE.raw(), [fd, 0, 0]);
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(
                    result, 0,
                    "root descriptor must close through its ring owner"
                );
            }
            if nr == sys::EVENTFD2.raw() {
                let invalid = run_in_child(0, nr, [7, 2, 0]);
                assert!(matches!(
                    invalid.0,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(invalid.1, -22, "unknown eventfd flag");
                let (_, semaphore) = run_in_child(0, nr, [2, flags | 1, 0]);
                assert_eq!(
                    semaphore, created[0] as i64,
                    "invalid flags cannot consume an fd"
                );
                let value = carrick_test_support::GuestUserBuffer::zeroed(8);
                for _ in 0..2 {
                    assert_eq!(
                        run_in_child(0, sys::READ.raw(), [semaphore as u64, value.arg(), 8]).1,
                        8
                    );
                    assert_eq!(u64::from_ne_bytes(value.as_bytes().try_into().unwrap()), 1);
                }
                assert_eq!(
                    run_in_child(0, sys::READ.raw(), [semaphore as u64, value.arg(), 8]).1,
                    -11
                );
                assert_eq!(
                    run_in_child(0, sys::CLOSE.raw(), [semaphore as u64, 0, 0]).1,
                    0
                );
            }
            if nr == sys::PIPE2.raw() {
                // A failed exact-MM output must cancel both numeric claims.
                let (route, result) =
                    run_in_child(0, nr, [carrick_guest_arch::USER_CEILING, flags, 0]);
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(result, -14);
                let (route, result) = run_in_child(0, nr, args);
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(result, 0);
                let retried: Vec<_> = output
                    .as_bytes()
                    .chunks_exact(4)
                    .map(|bytes| u64::from(u32::from_ne_bytes(bytes.try_into().unwrap())))
                    .collect();
                assert_eq!(
                    retried, created,
                    "copy fault leaves no descriptors or reserved holes"
                );
                for fd in retried {
                    assert_eq!(run_in_child(0, sys::CLOSE.raw(), [fd, 0, 0]).1, 0);
                }
            }
            return;
        }
        let mut results = Vec::new();
        for idx in 0..2 {
            if idx != 0 {
                assert!(
                    fixture
                        .zone
                        .requeue_preempted(fixture.slot, child_bindings[idx - 1].record.id)
                        .is_queued()
                );
                activate_target(source, &task, &child_bindings[idx]);
            }
            let (route, result) = run_in_child(idx, nr, args);
            // Test the production family entry. Forward here is the missing
            // ring implementation: native_unstaged_exit subsequently lowers
            // this exact child call to counted ENOSYS (-38).
            let pair = output.as_bytes().to_vec();
            // Check completion before using the return as a descriptor. Each
            // functional check runs while this child is still the active task.
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "child {idx} constructor {nr} must be served in ring, got {route:?} ({result})"
            );
            assert!(
                result >= 0,
                "child {idx} constructor {nr} errno {}",
                -result
            );
            let completed = |ordinal, arguments| {
                let (route, result) = run_in_child(idx, ordinal, arguments);
                assert!(
                    matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                    "child {idx} follow-up {ordinal} must be served in ring, got {route:?} ({result})"
                );
                result
            };
            if nr == sys::PIPE2.raw() {
                assert_eq!(result, 0);
                let read = u64::from(u32::from_ne_bytes(pair[..4].try_into().unwrap()));
                let write = u64::from(u32::from_ne_bytes(pair[4..].try_into().unwrap()));
                let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"new pipe");
                let received = carrick_test_support::GuestUserBuffer::zeroed(8);
                assert_eq!(completed(sys::READ.raw(), [read, received.arg(), 8]), -11);
                assert_eq!(completed(sys::WRITE.raw(), [write, payload.arg(), 8]), 8);
                assert_eq!(completed(sys::READ.raw(), [read, received.arg(), 8]), 8);
                assert_eq!(received.as_bytes(), payload.as_bytes());
                assert_eq!(completed(sys::READ.raw(), [read, received.arg(), 8]), -11);
                assert_ne!(
                    completed(sys::FCNTL.raw(), [read, LINUX_F_GETFL, 0]) & LINUX_O_NONBLOCK as i64,
                    0
                );
                assert_ne!(
                    completed(sys::FCNTL.raw(), [write, LINUX_F_GETFL, 0])
                        & LINUX_O_NONBLOCK as i64,
                    0
                );
            } else if nr == sys::EVENTFD2.raw() {
                let fd = result as u64;
                let received = carrick_test_support::GuestUserBuffer::zeroed(8);
                assert_eq!(completed(sys::READ.raw(), [fd, received.arg(), 8]), 8);
                assert_eq!(
                    u64::from_ne_bytes(received.as_bytes().try_into().unwrap()),
                    7
                );
                assert_eq!(completed(sys::READ.raw(), [fd, received.arg(), 8]), -11);
                let value = carrick_test_support::GuestUserBuffer::from_value(23u64);
                assert_eq!(completed(sys::WRITE.raw(), [fd, value.arg(), 8]), 8);
                assert_eq!(completed(sys::READ.raw(), [fd, received.arg(), 8]), 8);
                assert_eq!(
                    u64::from_ne_bytes(received.as_bytes().try_into().unwrap()),
                    23
                );
                assert_ne!(
                    completed(sys::FCNTL.raw(), [fd, LINUX_F_GETFL, 0]) & LINUX_O_NONBLOCK as i64,
                    0
                );
            } else if nr == sys::EPOLL_CREATE1.raw() {
                // The unused argument registers are zero, including timeout
                // and signal mask. An empty instance must return immediately.
                let events = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 16]);
                assert_eq!(
                    completed(sys::EPOLL_PWAIT.raw(), [result as u64, events.arg(), 1]),
                    0
                );
                assert_eq!(events.as_bytes(), &[0xa5; 16]);
                // A newly constructed epoll uses the same member owner as
                // an inherited one; register a newly constructed eventfd.
                let eventfd = completed(sys::EVENTFD2.raw(), [1, LINUX_O_NONBLOCK, 0]);
                assert!(eventfd >= 0);
                let mut member_bytes = [0; 16];
                member_bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
                member_bytes[8..].copy_from_slice(&0x1506u64.to_ne_bytes());
                let member = carrick_test_support::GuestUserBuffer::from_bytes(&member_bytes);
                let (route, added) = run_in_child_full(
                    idx,
                    sys::EPOLL_CTL.raw(),
                    [result as u64, 1, eventfd as u64, member.arg()],
                );
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(added, 0);
                assert_eq!(
                    completed(sys::EPOLL_PWAIT.raw(), [result as u64, events.arg(), 1]),
                    1
                );
                assert_eq!(
                    u64::from_ne_bytes(events.as_bytes()[8..16].try_into().unwrap()),
                    0x1506
                );
                let counter = carrick_test_support::GuestUserBuffer::zeroed(8);
                assert_eq!(
                    completed(sys::READ.raw(), [eventfd as u64, counter.arg(), 8]),
                    8
                );
                assert_eq!(
                    completed(sys::EPOLL_PWAIT.raw(), [result as u64, events.arg(), 1]),
                    0
                );
                assert_eq!(completed(sys::CLOSE.raw(), [eventfd as u64, 0, 0]), 0);
            } else {
                // A timer constructor must publish a usable timer, not just
                // an fd. All calls go through this child's production entry.
                let spec = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 32]);
                assert_eq!(
                    completed(sys::TIMERFD_GETTIME.raw(), [result as u64, spec.arg(), 0]),
                    0
                );
                assert_eq!(spec.as_bytes(), &[0; 32]);
                let received = carrick_test_support::GuestUserBuffer::zeroed(8);
                assert_eq!(
                    completed(sys::READ.raw(), [result as u64, received.arg(), 8]),
                    -11
                );
                // Absolute monotonic 1ns is already in the past in this
                // default-clock fixture. A one-shot must fire exactly once;
                // no sleep, polling loop or host timer supplies the answer.
                let mut armed = [0u8; 32];
                armed[24..32].copy_from_slice(&1i64.to_ne_bytes());
                let armed = carrick_test_support::GuestUserBuffer::from_bytes(&armed);
                let previous = carrick_test_support::GuestUserBuffer::from_bytes(&[0xa5; 32]);
                let (route, set) = run_in_child_full(
                    idx,
                    sys::TIMERFD_SETTIME.raw(),
                    [
                        result as u64,
                        carrick_abi::LINUX_TIMER_ABSTIME,
                        armed.arg(),
                        previous.arg(),
                    ],
                );
                assert!(matches!(
                    route,
                    CompletionRoute::Served | CompletionRoute::WithWork
                ));
                assert_eq!(set, 0, "child {idx} arms its own timerfd");
                assert_eq!(previous.as_bytes(), &[0; 32]);
                assert_eq!(
                    completed(sys::READ.raw(), [result as u64, received.arg(), 8]),
                    8
                );
                assert_eq!(
                    u64::from_ne_bytes(received.as_bytes().try_into().unwrap()),
                    1
                );
                assert_eq!(
                    completed(sys::READ.raw(), [result as u64, received.arg(), 8]),
                    -11,
                    "a consumed one-shot cannot fire twice"
                );
                assert_eq!(
                    completed(sys::TIMERFD_GETTIME.raw(), [result as u64, spec.arg(), 0]),
                    0
                );
                assert_eq!(spec.as_bytes(), &[0; 32], "expired one-shot is disarmed");
            }
            results.push((route, result, pair));
        }
        let mut backings = Vec::new();
        for (idx, (route, result, pair)) in results.into_iter().enumerate() {
            assert!(
                matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
                "child {idx} constructor {nr} must be served in ring, got {route:?} ({result})"
            );
            assert!(
                result >= 0,
                "child {idx} constructor {nr} errno {}",
                -result
            );
            let child_table = fd::TableId::from_raw(map.lookup_owned(children[idx]).unwrap());
            let fds = if nr == sys::PIPE2.raw() {
                assert_eq!(result, 0);
                pair.chunks_exact(4)
                    .map(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>()
            } else {
                vec![i32::try_from(result).unwrap()]
            };
            for created in fds {
                assert!(
                    owner
                        .region()
                        .fd(carrick_kernel::el1_zone::HostLockWait)
                        .getfd(child_table, fd::Fd(created))
                        .unwrap()
                );
                backings.push(
                    owner
                        .region()
                        .fd(carrick_kernel::el1_zone::HostLockWait)
                        .get(child_table, fd::Fd(created))
                        .unwrap()
                        .backing,
                );
                assert!(
                    owner
                        .region()
                        .fd(carrick_kernel::el1_zone::HostLockWait)
                        .get(table.id(), fd::Fd(created))
                        .is_err(),
                    "child creation must not publish in the parent table"
                );
            }
        }
        let per_child = if nr == sys::PIPE2.raw() { 2 } else { 1 };
        for endpoint in 0..per_child {
            assert_ne!(
                backings[endpoint],
                backings[per_child + endpoint],
                "new constructors must allocate independent objects in the two live children"
            );
        }
        return;
    }

    // 1. dup(4) allocates lowest free slot 0 and clears FD_CLOEXEC.
    let (route, ret) = run_in_child(0, sys_dup, [4, 0, 0]);
    assert!(
        matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
        "native dup must complete in ring, got {route:?}"
    );
    assert_eq!(ret, 0, "dup(4) must pick fd 0; errno {}", -ret);
    assert_eq!(run_in_child(0, sys_fcntl, [0, LINUX_F_GETFD, 0]).1, 0);
    assert_eq!(run_in_child(0, sys_fcntl, [4, LINUX_F_GETFD, 0]).1, 1);

    // 2. dup2(4, 1) replaces open fd 1 and clears FD_CLOEXEC.
    assert_eq!(
        run_in_child(0, carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2, [4, 1, 0]).1,
        1
    );
    assert_eq!(run_in_child(0, sys_fcntl, [1, LINUX_F_GETFD, 0]).1, 0);

    // 3. dup3 validation (EINVAL = -22) and growth past initial capacity 8 -> fd 20.
    assert_eq!(
        run_in_child(0, sys_dup3, [4, 4, carrick_syscall_abi::LINUX_O_CLOEXEC]).1,
        -22,
        "same-fd dup3 must fail with EINVAL (-22)"
    );
    assert_eq!(
        run_in_child(0, sys_dup3, [4, 2, 0x9999]).1,
        -22,
        "dup3 unknown flags must fail with EINVAL (-22)"
    );
    assert_eq!(
        run_in_child(0, sys_dup3, [4, 20, carrick_syscall_abi::LINUX_O_CLOEXEC]).1,
        20
    );
    assert_eq!(run_in_child(0, sys_fcntl, [20, LINUX_F_GETFD, 0]).1, 1);

    // 4. fcntl F_DUPFD, F_DUPFD_CLOEXEC, F_SETFD, EBADF (-9) vs EINVAL (-22), EMFILE (-24).
    assert_eq!(run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD, 10]).1, 10);
    assert_eq!(run_in_child(0, sys_fcntl, [10, LINUX_F_GETFD, 0]).1, 0);
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD_CLOEXEC, 10]).1,
        11
    );
    assert_eq!(run_in_child(0, sys_fcntl, [11, LINUX_F_GETFD, 0]).1, 1);
    assert_eq!(run_in_child(0, sys_fcntl, [10, LINUX_F_SETFD, 1]).1, 0);
    assert_eq!(run_in_child(0, sys_fcntl, [10, LINUX_F_GETFD, 0]).1, 1);
    assert_eq!(run_in_child(0, sys_fcntl, [10, LINUX_F_SETFD, 0]).1, 0);
    assert_eq!(run_in_child(0, sys_fcntl, [10, LINUX_F_GETFD, 0]).1, 0);
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD, 64]).1,
        -22,
        "F_DUPFD at RLIMIT_NOFILE (64) must fail with EINVAL (-22)"
    );
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD, (-1i32) as u32 as u64]).1,
        -22,
        "F_DUPFD with negative 32-bit arg must fail with EINVAL (-22)"
    );
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD, 1u64 << 32]).1,
        -22,
        "F_DUPFD must reject a minimum outside i32 instead of truncating it to fd 0"
    );
    assert_eq!(
        run_in_child(0, sys_fcntl, [99, LINUX_F_DUPFD, 64]).1,
        -9,
        "F_DUPFD checks bad oldfd EBADF (-9) before min arg EINVAL (-22)"
    );

    let mut fillers = Vec::new();
    loop {
        let fd_or_err = run_in_child(0, sys_dup, [4, 0, 0]).1;
        if fd_or_err < 0 {
            assert_eq!(
                fd_or_err, -24,
                "table full at RLIMIT_NOFILE must fail with EMFILE (-24)"
            );
            break;
        }
        fillers.push(fd_or_err as u64);
    }
    assert_eq!(run_in_child(0, sys_fcntl, [4, LINUX_F_DUPFD, 0]).1, -24);
    for filler in fillers {
        assert_eq!(run_in_child(0, sys_close, [filler, 0, 0]).1, 0);
    }

    // 5. F_GETFL / F_SETFL mutate the shared open file description visible to child 1.
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_GETFL, 0]).1,
        LINUX_O_WRONLY as i64
    );
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_SETFL, LINUX_O_NONBLOCK]).1,
        0
    );
    assert_eq!(
        run_in_child(0, sys_fcntl, [4, LINUX_F_GETFL, 0]).1,
        (LINUX_O_WRONLY | LINUX_O_NONBLOCK) as i64
    );

    // 6. Duplicate a host-backed description through the same reservation
    // transaction. Child 0's fd 2 keeps the physical object alive after both
    // inherited fd 5 entries close.
    let child0_table = carrick_el1_abi::ipc::fd::TableId::from_raw(
        map.lookup_owned(children[0]).expect("owned child table"),
    );
    assert_eq!(
        owner
            .region()
            .fd(carrick_kernel::el1_zone::HostLockWait)
            .close_effects(child0_table, fd::Fd(5))
            .unwrap(),
        carrick_el1_abi::ipc::fd::CloseEffects::POSIX_RECORD_LOCKS,
    );
    assert_eq!(run_in_child(0, sys_dup, [5, 0, 0]).1, 2);
    let (close_effect_route, close_effect_result) = run_in_child(0, sys_close, [5, 0, 0]);
    assert_eq!(close_effect_result, 0);
    assert_eq!(close_effect_route, CompletionRoute::WithWork);
    assert_eq!(
        task.linux.take_served_boundary(),
        Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0: 5 }),
        "host-owned close effects must replay the already-committed numeric close"
    );
    assert_eq!(
        run_in_child(0, sys_close, [5, 0, 0]).1,
        -9,
        "second close must fail with EBADF (-9)"
    );
    let _ = owner.drain_retired_tables().unwrap();
    assert_eq!(
        owner.retained_host_resources(),
        1,
        "child 1 still holds host-backed fd 5"
    );

    // Close all writer aliases in child 0 EXCEPT fd 1 (created by dup2).
    for writer_fd in [0, 4, 10, 11, 20] {
        assert_eq!(run_in_child(0, sys_close, [writer_fd, 0, 0]).1, 0);
    }

    // Switch to live child 1.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    assert_eq!(
        run_in_child(1, sys_fcntl, [4, LINUX_F_GETFL, 0]).1,
        (LINUX_O_WRONLY | LINUX_O_NONBLOCK) as i64,
        "child 1 shares the writer OFD flags mutated by child 0"
    );
    let (close_effect_route, close_effect_result) = run_in_child(1, sys_close, [5, 0, 0]);
    assert_eq!(close_effect_result, 0);
    assert_eq!(close_effect_route, CompletionRoute::WithWork);
    assert_eq!(
        task.linux.take_served_boundary(),
        Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0: 5 }),
    );
    let _ = owner.drain_retired_tables().unwrap();
    assert_eq!(
        owner.retained_host_resources(),
        1,
        "child 0's duplicate must retain the host resource"
    );

    // Child 1 closes its writer fd 4; child 0's dup2 alias (fd 1) is still open,
    // so nonblocking read on fd 3 MUST return EAGAIN (-11), never premature EOF!
    assert_eq!(run_in_child(1, sys_close, [4, 0, 0]).1, 0);
    let read_buf = carrick_test_support::GuestUserBuffer::zeroed(8);
    assert_eq!(
        run_in_child(1, sys_read, [3, read_buf.arg(), 8]).1,
        -11,
        "reader must see EAGAIN (-11) while child 0 still holds dup2 writer alias fd 1"
    );

    // Switch back to child 0: write 2 bytes via fd 1 and close the final writer description.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[1].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[0]);
    let (route, result) = run_in_child(0, sys_close, [2, 0, 0]);
    assert_eq!(result, 0);
    assert_eq!(route, CompletionRoute::WithWork);
    assert_eq!(
        task.linux.take_served_boundary(),
        Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0: 2 }),
        "close effects and the final host resource must share one carrier crossing"
    );
    assert!(
        task.linux.has_pending_host_work(),
        "final duplicated host close must schedule host drain"
    );
    let _ = owner.drain_retired_tables().unwrap();
    task.linux
        .take_host_work_doorbell()
        .expect("doorbell must be armed")
        .settled();
    assert_eq!(owner.retained_host_resources(), 0);
    assert_eq!(host_file.physical_fd_errno(), Some(9));
    let payload = carrick_test_support::GuestUserBuffer::from_bytes(b"ok");
    assert_eq!(run_in_child(0, sys_write, [1, payload.arg(), 2]).1, 2);
    assert_eq!(run_in_child(0, sys_close, [1, 0, 0]).1, 0);

    // Switch back to child 1: read drains "ok" (2 bytes), then returns EOF (0).
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    assert_eq!(run_in_child(1, sys_read, [3, read_buf.arg(), 8]).1, 2);
    assert_eq!(&read_buf.as_bytes()[..2], b"ok");
    assert_eq!(
        run_in_child(1, sys_read, [3, read_buf.arg(), 8]).1,
        0,
        "reader must observe EOF (0) once last writer across both children closed"
    );

    for binding in &child_bindings {
        assert!(runtime.task_binding(binding.key).is_some());
    }
    service.retire_fd_table(children[0]);
    service.retire_fd_table(children[1]);
    assert_eq!(owner.drain_retired_tables().unwrap(), 2);
    table.close(fd::Fd(3)).unwrap();
    drop(reader);
}

// Places host memory at the EL1 metadata window (0x2D_0800_0000). macOS 27
// refuses every user allocation below 0x70_0000_0000 (even a fixed
// `vm_allocate` in a fresh process), so this runs on Linux hosts, where
// `just test` and the Linux CI lanes exercise it.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_two_children_pipe_buf_partial_write_and_sigpipe_epipe() {
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
    use carrick_personality_linux::{dispatch::CompletionRoute, signal::ProcessSignals};
    use carrick_signal_core::{
        SignalSet,
        policy::{Action as SigAction, Disposition, SigBlockMask, Signal},
    };
    use std::sync::Arc;

    let fixture = Fixture::new(0x10000, asid(1));
    let metadata_scope = MetadataScope::new(&fixture);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let task = CurrentTask::new();
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
    let nonblock_flags = fd::StatusFlags {
        nonblock: true,
        ..fd::StatusFlags::default()
    };
    let reader = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            nonblock_flags,
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
            nonblock_flags,
        ))
        .unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    writer.install(table.id(), fd::Fd(4), false).unwrap();

    let region =
        carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
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
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((Arc::clone(&owner), map));
    let tables = crate::ipc::MapTables(map);
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

    // Drop parent's reader and writer so ONLY the two live native children hold endpoints.
    drop(reader);
    drop(writer);
    table.close(fd::Fd(3)).unwrap();
    table.close(fd::Fd(4)).unwrap();

    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );

    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());

    let run_in_child = |idx: usize, nr: u64, args: [u64; 3]| -> (CompletionRoute, i64) {
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
        let child_ctx =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[idx].address);
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
        let route = super::dispatch::dispatch_syscall_with_native(
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

    let sys_close = carrick_personality_linux::crossing::nr::CLOSE.raw();
    let sys_read = carrick_personality_linux::crossing::nr::READ.raw();
    let sys_write = carrick_personality_linux::crossing::nr::WRITE.raw();
    const PIPE_BUF: usize = 4096;

    // Child 0 is sole writer (closes fd 3); Child 1 is sole reader (closes fd 4).
    activate_target(source, &task, &child_bindings[0]);
    assert!(!task.linux.has_pending_host_work());
    let (route, result) = run_in_child(0, sys_close, [3, 0, 0]);
    assert_eq!(result, 0);
    assert_eq!(
        route,
        CompletionRoute::Served,
        "a completed in-zone close must not bounce through carrier service"
    );
    assert_eq!(task.linux.take_served_boundary(), None);
    assert!(!task.linux.has_pending_host_work());
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    let (route, result) = run_in_child(1, sys_close, [4, 0, 0]);
    assert_eq!(result, 0);
    assert_eq!(route, CompletionRoute::Served);
    assert_eq!(task.linux.take_served_boundary(), None);
    assert!(!task.linux.has_pending_host_work());

    // Switch to writer (child 0): fill 15 full pages + 2096 bytes (leaving 2000 < PIPE_BUF free).
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[1].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[0]);
    let pattern_bytes: Vec<u8> = (0..(15 * PIPE_BUF + 2096))
        .map(|i| (i % 251) as u8)
        .collect();
    let pattern = carrick_test_support::GuestUserBuffer::from_bytes(&pattern_bytes);
    assert_eq!(
        run_in_child(0, sys_write, [4, pattern.arg(), pattern_bytes.len() as u64]).1,
        pattern_bytes.len() as i64
    );

    // 1. PIPE_BUF (4096) write with < PIPE_BUF space refuses atomically with EAGAIN (-11), 0 written.
    let atomic_chunk = carrick_test_support::GuestUserBuffer::from_bytes(&vec![0xA5u8; PIPE_BUF]);
    assert_eq!(
        run_in_child(0, sys_write, [4, atomic_chunk.arg(), PIPE_BUF as u64]).1,
        -11,
        "O_NONBLOCK write <= PIPE_BUF (4096) without room must fail atomically with EAGAIN (-11)"
    );

    // Switch to reader (child 1): drain 1 full page (4096 bytes), freeing 1 page in the 16-page ring.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    let mut drained = Vec::new();
    let page_buf = carrick_test_support::GuestUserBuffer::zeroed(PIPE_BUF);
    assert_eq!(
        run_in_child(1, sys_read, [3, page_buf.arg(), PIPE_BUF as u64]).1,
        PIPE_BUF as i64
    );
    drained.extend_from_slice(page_buf.as_bytes());

    // 2. Write > PIPE_BUF (8192 bytes) with 1 page free performs partial write of 4096 bytes.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[1].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[0]);
    let large_write_bytes: Vec<u8> = (0..(2 * PIPE_BUF)).map(|i| ((i + 7) % 251) as u8).collect();
    let large_write = carrick_test_support::GuestUserBuffer::from_bytes(&large_write_bytes);
    assert_eq!(
        run_in_child(
            0,
            sys_write,
            [4, large_write.arg(), large_write_bytes.len() as u64]
        )
        .1,
        PIPE_BUF as i64,
        "O_NONBLOCK write > PIPE_BUF must transfer available partial bytes (4096)"
    );
    assert_eq!(
        run_in_child(0, sys_write, [4, atomic_chunk.arg(), PIPE_BUF as u64]).1,
        -11
    );

    // Switch to reader (child 1): drain all remaining bytes and verify stream integrity, then close fd 3!
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[0].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[1]);
    let rest = carrick_test_support::GuestUserBuffer::zeroed(65536);
    let n = run_in_child(1, sys_read, [3, rest.arg(), 65536]).1;
    assert_eq!(n, (14 * PIPE_BUF + 2096 + PIPE_BUF) as i64);
    drained.extend_from_slice(&rest.as_bytes()[..n as usize]);
    let mut expected = pattern_bytes;
    expected.extend_from_slice(&large_write_bytes[..PIPE_BUF]);
    assert_eq!(
        drained, expected,
        "partial write must preserve exact stream bytes"
    );

    // Close the LAST reader description across all live processes.
    assert_eq!(run_in_child(1, sys_close, [3, 0, 0]).1, 0);

    // 3. Switch to writer (child 0): write after last reader closed returns EPIPE (-32) IN RING
    // and enqueues SIGPIPE (13, SI_KERNEL) unless SIG_IGN is installed.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_bindings[1].record.id)
            .is_queued()
    );
    activate_target(source, &task, &child_bindings[0]);
    let sigpipe = Signal::from_number(13).unwrap();
    let byte = carrick_test_support::GuestUserBuffer::from_bytes(b"z");
    let (route, ret) = run_in_child(0, sys_write, [4, byte.arg(), 1]);
    assert!(
        matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
        "native child write on broken pipe must complete in ring, got {route:?}"
    );
    assert_eq!(
        ret, -32,
        "write after last reader closed must return EPIPE (-32)"
    );
    {
        let mut svc = Aarch64NativeProcessService::with_crossing(
            &task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        let child_ctx =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[0].address);
        let mut entry = runtime.enter(source, &task, child_ctx, &mut svc).unwrap();
        let pipe_mask = SigBlockMask::blocking_all_of(SignalSet::from_bits(sigpipe.bit()));
        assert_eq!(
            entry.rt_sigpending(pipe_mask),
            sigpipe.bit(),
            "broken pipe write must enqueue SIGPIPE (13) on the calling native thread"
        );
        let (sig, info, _) = entry
            .take_deliverable(SigBlockMask::NONE)
            .expect("SIGPIPE must be deliverable");
        assert_eq!(sig, sigpipe);
        let info = info.expect("SIGPIPE must carry kernel siginfo");
        let si_signo = info.si_signo;
        let si_code = info.si_code;
        assert_eq!(si_signo, 13);
        assert_eq!(si_code, carrick_syscall_abi::LINUX_SI_KERNEL);

        // Install SIG_IGN for SIGPIPE; subsequent broken-pipe write returns EPIPE (-32) without SIGPIPE.
        entry
            .rt_sigaction(
                sigpipe,
                Some(SigAction {
                    disposition: Disposition::Ignore,
                    ..SigAction::default()
                }),
            )
            .unwrap();
    }
    let (route2, ret2) = run_in_child(0, sys_write, [4, byte.arg(), 1]);
    assert!(matches!(
        route2,
        CompletionRoute::Served | CompletionRoute::WithWork
    ));
    assert_eq!(ret2, -32);
    {
        let mut svc = Aarch64NativeProcessService::with_crossing(
            &task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        let child_ctx =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[0].address);
        let entry = runtime.enter(source, &task, child_ctx, &mut svc).unwrap();
        let pipe_mask = SigBlockMask::blocking_all_of(SignalSet::from_bits(sigpipe.bit()));
        assert_eq!(
            entry.rt_sigpending(pipe_mask),
            0,
            "SIG_IGN must suppress SIGPIPE while still returning EPIPE (-32)"
        );
    }

    service.retire_fd_table(children[0]);
    service.retire_fd_table(children[1]);
    assert_eq!(owner.drain_retired_tables().unwrap(), 2);
}

#[cfg(test)]
std::thread_local! {
    static FUTEX_ENROLLED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[test]
fn arm_kill_nonleader_prefers_named_member_and_keeps_blocked_fallback() {
    for blocked in [false, true] {
        arm_kill_nonleader_recipient(blocked);
    }
}

#[cfg(test)]
fn arm_kill_nonleader_recipient(blocked: bool) {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let runtime = std::sync::Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            initial,
        )
        .unwrap(),
    );
    let owner_registry = registry();
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let waiter = fixture
        .zone
        .record_ref(fixture.zone.slot(fixture.slot).host_record().unwrap());
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, waiter.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        waiter.id
    );
    let mut service = fixture.process_service();
    {
        let mut entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut service,
            )
            .unwrap();
        entry
            .rt_sigaction(
                Signal::from_number(10).unwrap(),
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x700000)),
                    ..Default::default()
                }),
            )
            .unwrap();
    }
    let control = host_born_sibling(fixture, 42);
    run_as_leader(fixture);
    let sender_task: &'static CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    sender_task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        5,
    );
    sender_task.mm.key.store(1, Ordering::Release);
    sender_task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    sender_task.publish_visible_pid(41);
    sender_task.publish_root_generation(fixture.address.generation);
    sender_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    let sender_slot = SlotId::new(1);
    fixture.zone.drive(sender_slot, 2);
    fixture.zone.publish_slot(sender_slot, 1, Some(0), 1);
    fixture.zone.enter_guest(sender_slot);
    fixture.zone.install_space(sender_slot, 1).unwrap();
    let sender_record = fixture
        .zone
        .current_or_new(
            sender_slot,
            ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: 1,
                file_table: 5,
                generation: 12,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
    control.bind_zone_record(fixture.zone.record_ref(sender_record));
    let sender_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sender_slot,
    };
    owner_registry
        .register_thread(
            sender_source,
            sender_task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(sender_slot, sender_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(sender_slot).unwrap().record,
        sender_record
    );
    let live_members = carrick_el1_abi::Lifecycle::live(fixture.page);
    assert_eq!(live_members, 2);

    let signal = Signal::from_number(10).unwrap();
    if blocked {
        control.init_blocked(carrick_el1_abi::BlockedMask(signal.bit()));
    }
    fixture.zone.slot(fixture.slot).set_sgi_target(0x1000);
    fixture.zone.slot(sender_slot).set_sgi_target(0x2000);
    crate::sched::object_wait::clear_test_wake_trace();
    let mut entry = runtime
        .enter_registered(
            owner_registry,
            source,
            &fixture.task,
            fixture.address,
            &initial,
            &mut service,
        )
        .unwrap();
    entry
        .kill(
            SignalProcessSelector::from_abi(42),
            SignalRequest::Deliver(signal),
            SignalInfo::Generated(None),
        )
        .unwrap();
    let mut trace = crate::sched::object_wait::test_wake_trace();
    trace.sort_by_key(|(_, target)| *target);
    let mut expected = if blocked {
        vec![(fixture.slot, 0x1000)]
    } else {
        vec![(fixture.slot, 0x1000), (sender_slot, 0x2000)]
    };
    expected.sort_by_key(|(_, target)| *target);
    assert_eq!(
        trace, expected,
        "every eligible member is kicked: the named member and its unblocked siblings"
    );
    if !blocked {
        // The named member stops being eligible before its checkpoint. The
        // sibling that was kicked must still own the process-directed signal.
        control.init_blocked(carrick_el1_abi::BlockedMask(signal.bit()));
        let (got, _, _) = entry
            .take_deliverable(carrick_signal_core::policy::SigBlockMask::NONE)
            .expect("the kicked sibling must receive the signal");
        assert_eq!(got, signal);
        assert!(
            entry
                .take_deliverable(carrick_signal_core::policy::SigBlockMask::NONE)
                .is_none(),
            "the signal is delivered exactly once"
        );
        return;
    }
    // A tkill substitution would leave this pending signal private to the
    // named sibling. Blocking the caller now must expose shared custody.
    fixture
        .control
        .init_blocked(carrick_el1_abi::BlockedMask(signal.bit()));
    assert_eq!(
        entry.rt_sigpending(carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::EMPTY.with(signal),
        )),
        signal.bit(),
        "kill retains process-pending custody visible to another member"
    );
}

#[cfg(test)]
#[test]
fn tgkill_during_futex_enrollment_returns_eintr() {
    use crate::sched::LinuxSchedEntry;
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
    };
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use std::sync::mpsc;
    use std::time::Duration;

    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let initial = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let runtime = std::sync::Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            initial,
        )
        .unwrap(),
    );
    let owner_registry = registry();
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let waiter = fixture
        .zone
        .record_ref(fixture.zone.slot(fixture.slot).host_record().unwrap());
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, waiter.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        waiter.id
    );
    let mut service = fixture.process_service();
    {
        let mut entry = runtime
            .enter_registered(
                owner_registry,
                source,
                &fixture.task,
                fixture.address,
                &initial,
                &mut service,
            )
            .unwrap();
        entry
            .rt_sigaction(
                Signal::from_number(10).unwrap(),
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x700000)),
                    ..Default::default()
                }),
            )
            .unwrap();
    }
    let control = host_born_sibling(fixture, 42);
    run_as_leader(fixture);
    let sender_task: &'static CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    sender_task.set(
        El1TaskId::from_linux_tid(42),
        carrick_el1_abi::SnapshotGeneration::from_raw(12),
        5,
    );
    sender_task.mm.key.store(1, Ordering::Release);
    sender_task
        .mm
        .thread_generation
        .store(102, Ordering::Release);
    sender_task.publish_visible_pid(41);
    sender_task.publish_root_generation(fixture.address.generation);
    sender_task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    let sender_slot = SlotId::new(1);
    fixture.zone.drive(sender_slot, 2);
    fixture.zone.publish_slot(sender_slot, 1, Some(0), 1);
    fixture.zone.enter_guest(sender_slot);
    fixture.zone.install_space(sender_slot, 1).unwrap();
    let sender_record = fixture
        .zone
        .current_or_new(
            sender_slot,
            ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: 1,
                file_table: 5,
                generation: 12,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
    control.bind_zone_record(fixture.zone.record_ref(sender_record));
    let sender_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sender_slot,
    };
    owner_registry
        .register_thread(
            sender_source,
            sender_task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(sender_slot, sender_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(sender_slot).unwrap().record,
        sender_record
    );
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    let (go_tx, go_rx) = mpsc::sync_channel(1);
    let (sent_tx, sent_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let sender_runtime = runtime.clone();
    let sender_address = fixture.address;
    let sender_zone = fixture.zone;
    let sender_table = fixture.region.table();
    // Test-only bounded actor; production thread creation remains catalogued.
    #[allow(clippy::disallowed_methods)]
    let sender = std::thread::spawn(move || {
        go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let words = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, sender_address);
        let mut service = Aarch64NativeProcessService::with_crossing(
            sender_task,
            sender_slot,
            sender_zone,
            sender_table,
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        let mut entry = sender_runtime
            .enter_registered(
                owner_registry,
                sender_source,
                sender_task,
                sender_address,
                &words,
                &mut service,
            )
            .unwrap();
        // Once the signal is queued, the fixed sender waits for the waiter's bucket.
        // The old sender instead returns immediately while the target is OnCpu.
        let notified = core::sync::atomic::AtomicBool::new(false);
        let probe = |_: u32| {
            if !notified.swap(true, Ordering::AcqRel) {
                sent_tx.send(()).unwrap();
            }
        };
        entry.publication_wait_probe = Some(&probe);
        entry
            .tgkill(
                SignalThreadSelector::from_abi(41),
                SignalThreadSelector::from_abi(41),
                SignalRequest::Deliver(Signal::from_number(10).unwrap()),
                SignalInfo::Generated(None),
            )
            .unwrap();
        entry.publication_wait_probe = None;
        if !notified.swap(true, Ordering::AcqRel) {
            sent_tx.send(()).unwrap();
        }
        assert!(entry.take_run_failure().is_none());
        done_tx.send(()).unwrap();
    });
    FUTEX_ENROLLED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            assert_eq!(fixture.zone.record(waiter.id).entry_count(), 1);
            assert!(matches!(
                fixture.zone.record(waiter.id).claim(),
                carrick_sched_core::Claim::OnCpu { .. }
            ));
            go_tx.send(()).unwrap();
            sent_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // Bound the bad implementation's observation: its idle boundary exits
            // with the waiter still parked, rather than executing an endless WFI.
            fixture.task.linux.mark_pending_host_work();
        }))
    });
    let mut cpu = crate::sched::FakeCpu {
        after_wait_enqueue: Some(|| {
            FUTEX_ENROLLED.with(|hook| hook.borrow_mut().take().unwrap()())
        }),
        ..Default::default()
    };
    let word = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = crate::sched::SYS_FUTEX as u64;
    frame.x[0] = word.arg();
    frame.x[1] = crate::sched::FUTEX_WAIT_PRIVATE;
    let counters = carrick_el1_abi::Counters::new();
    let result = (crate::sched::Sched {
        handoff: None,
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
        counters: &counters,
    })
    .serve_futex(&mut frame);
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    sender.join().unwrap();
    assert_eq!(
        result,
        Some(crate::sched::Served::Returned { switched: false }),
        "a deliverable signal after enrollment must prevent futex park"
    );
    assert_eq!(
        frame.x[0] as i64, -4,
        "futex enrollment signal returns EINTR"
    );
    assert_eq!(fixture.zone.record(waiter.id).entry_count(), 0);
    assert_eq!(fixture.zone.record(waiter.id).deadline(), None);
    assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 0);
    owner_registry.unregister_root_for_test(&runtime);
}

#[test]
fn native_process_venue_survives_host_only_and_closed_admission() {
    use carrick_el1::substrate::sched::NativeEntryVenue;
    use carrick_el1_abi::Lifecycle;
    for closed in [false, true] {
        let fixture = Fixture::new(0x10000, asid(1));
        let record = fixture.zone.slot(fixture.slot).host_record().unwrap();
        assert!(fixture.zone.mark_native_owned(record));
        if closed {
            fixture.page.close();
        } else {
            fixture.page.decline_to_host();
        }
        // A retained host home is a service-exit concern, not a running
        // native thread for IRQ or fault supply.
        assert_eq!(
            NativeEntryVenue::select(fixture.zone, fixture.slot, &fixture.task),
            NativeEntryVenue::Host
        );
        assert_eq!(
            NativeEntryVenue::select_service_with_lifecycle(
                fixture.zone,
                fixture.slot,
                &fixture.task,
                fixture.page,
                fixture.control,
            ),
            NativeEntryVenue::NativeProcess(record)
        );
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            record
        );
        assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(record));
        assert_eq!(
            NativeEntryVenue::select_with_lifecycle(
                fixture.zone,
                fixture.slot,
                &fixture.task,
                fixture.page,
                fixture.control,
            ),
            NativeEntryVenue::NativeProcess(record)
        );
        assert_eq!(
            NativeEntryVenue::select(fixture.zone, fixture.slot, &fixture.task),
            NativeEntryVenue::NativeProcess(record)
        );
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        for entry in [
            carrick_sched_core::object_wait::OwnerEntry::Syscall,
            carrick_sched_core::object_wait::OwnerEntry::Exception,
        ] {
            assert!(super::native_process_runtime::native_entry_owned(
                source,
                &fixture.task,
                fixture.page,
                fixture.control,
                entry,
            ));
        }
        fixture.task.linux.mark_pending_host_work();
        let counters = carrick_el1_abi::Counters::new();
        let mut cpu = crate::sched::FakeCpu {
            host_work_once: Some(carrick_el1_abi::Action::Idle),
            ..Default::default()
        };
        let action = crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        }
        .finish_interrupt_for_test(
            &mut carrick_el1_abi::TrapFrame::default(),
            carrick_el1_abi::Action::Served,
        );
        assert_eq!(action, carrick_el1_abi::Action::Idle);
        assert_eq!(cpu.host_work_boundaries, [record]);
    }
}

#[test]
fn arm_classified_maperr_and_bus_use_signal_owner() {
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use zerocopy::{FromBytes, IntoBytes};
    for (signal, code) in [(Signal::SEGV, 1), (Signal::BUS, 2)] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |process| {
                    process
                        .signal_venue()
                        .unwrap()
                        .rt_sigaction(
                            signal,
                            Some(Action {
                                disposition: Disposition::Handler(HandlerAddress(0x40_0100)),
                                ..Default::default()
                            }),
                        )
                        .unwrap();
                },
            )
            .unwrap();
        let address = 0x1234_5000;
        fixture
            .control
            .publish_synchronous_fault(signal, code, address);
        let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
        let mut machine = ArmWaitSignalMachine {
            user_sp: stack.va_at(stack.len()),
            backend: ArmWaitSignalBackend,
        };
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let mut frame = carrick_el1_abi::TrapFrame {
            slot: u64::from(fixture.slot.raw()),
            esr: 0xfffc,
            elr: 0x40_0200,
            spsr: 0x3c0,
            ..Default::default()
        };
        assert_eq!(
            super::dispatch::arm_deliver_declined_fault_signal_with(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot
                },
                &fixture.task,
                &ThreadCtx::ZERO,
                fixture_ttbr0(fixture),
                fixture.page,
                fixture.control,
                &mut service,
                &mut frame,
                &mut None,
                |process, frame| super::arm_signal::deliver_on_user_return_with(
                    &fixture.task,
                    fixture.control,
                    process,
                    frame,
                    fp.as_bytes(),
                    &mut machine,
                ),
            )
            .unwrap(),
            carrick_el1_abi::Action::Served
        );
        assert_eq!(frame.elr, 0x40_0100);
        assert!(fixture.control.synchronous_fault().is_none());
        let offset = (frame.x[1] - stack.va().raw()) as usize;
        let built = carrick_personality_linux::signal::arm::SignalFrame::ref_from_bytes(
            &stack.as_bytes()[offset
                ..offset
                    + core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()],
        )
        .unwrap();
        let info = built.rt.siginfo;
        let actual = (info.si_signo, info.si_code, info.si_addr);
        assert_eq!(actual, (signal.number(), code, address));
        let pc = built.rt.ucontext.uc_mcontext.pc;
        assert_eq!(pc, 0x40_0200);
    }
}

#[test]
fn arm_classified_fault_default_ignored_and_blocked_return_to_host_core_path() {
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    for (signal, disposition, blocked) in [
        (Signal::SEGV, Disposition::Default, false),
        (Signal::BUS, Disposition::Default, false),
        (Signal::SEGV, Disposition::Ignore, false),
        (
            Signal::SEGV,
            Disposition::Handler(HandlerAddress(0x40_0100)),
            true,
        ),
        (
            Signal::SEGV,
            Disposition::Handler(HandlerAddress(0x40_0100)),
            false,
        ),
    ] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |process| {
                    process
                        .signal_venue()
                        .unwrap()
                        .rt_sigaction(
                            signal,
                            Some(Action {
                                disposition,
                                ..Default::default()
                            }),
                        )
                        .unwrap();
                },
            )
            .unwrap();
        if blocked {
            fixture.control.init_blocked(carrick_el1_abi::BlockedMask(
                carrick_signal_core::SignalSet::EMPTY.with(signal).bits(),
            ));
        }
        fixture
            .control
            .publish_synchronous_fault(signal, 1, 0x1234_5000);
        let mut frame = carrick_el1_abi::TrapFrame {
            slot: u64::from(fixture.slot.raw()),
            esr: 0xfffc,
            elr: 0x40_0200,
            spsr: 0x3c0,
            ..Default::default()
        };
        assert_eq!(
            super::dispatch::arm_deliver_declined_fault_signal_with(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot
                },
                &fixture.task,
                &ThreadCtx::ZERO,
                fixture_ttbr0(fixture),
                fixture.page,
                fixture.control,
                &mut service,
                &mut frame,
                &mut None,
                |process, frame| {
                    // A sibling changes disposition after fault publication, before
                    // the shared delivery operation selects it.
                    if matches!(disposition, Disposition::Handler(_)) && !blocked {
                        process
                            .signal_venue()
                            .unwrap()
                            .rt_sigaction(signal, Some(Action::default()))
                            .unwrap();
                    }
                    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
                    use zerocopy::IntoBytes;
                    super::arm_signal::deliver_on_user_return_with(
                        &fixture.task,
                        fixture.control,
                        process,
                        frame,
                        fp.as_bytes(),
                        &mut ArmWaitSignalMachine {
                            user_sp: UserVa::new(0x7000),
                            backend: ArmWaitSignalBackend,
                        },
                    )
                },
            )
            .unwrap(),
            carrick_el1_abi::Action::Forward
        );
        assert_eq!(
            fixture.control.synchronous_fault(),
            Some((signal, 1, 0x1234_5000, true))
        );
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |process| {
                    assert_eq!(
                        process
                            .signal_venue()
                            .unwrap()
                            .rt_sigaction(signal, None)
                            .unwrap()
                            .disposition,
                        Disposition::Default
                    );
                },
            )
            .unwrap();
        assert_eq!(frame.elr, 0x40_0200);
    }
}

#[test]
fn arm_classified_bus_bad_signal_stack_returns_sigsegv_to_host_core_path() {
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use zerocopy::IntoBytes;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(
                        Signal::BUS,
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x40_0100)),
                            ..Default::default()
                        }),
                    )
                    .unwrap();
            },
        )
        .unwrap();
    fixture
        .control
        .publish_synchronous_fault(Signal::BUS, 2, 0x1234_5000);
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0xfffc,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    super::native_diagnostic::capture();
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    assert_eq!(
        super::dispatch::arm_deliver_declined_fault_signal_with(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot
            },
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut None,
            |process, frame| super::arm_signal::deliver_on_user_return_with(
                &fixture.task,
                fixture.control,
                process,
                frame,
                fp.as_bytes(),
                &mut ArmWaitSignalMachine {
                    user_sp: UserVa::new(0),
                    backend: ArmWaitSignalBackend
                },
            ),
        )
        .unwrap(),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(
        fixture.control.synchronous_fault(),
        Some((Signal::SEGV, 2, 0x1234_5000, true))
    );
    let diagnostics = super::native_diagnostic::take();
    assert!(
        diagnostics
            .iter()
            .any(|line| line.contains("signal-frame-build")
                && line.contains("pc=0x400200")
                && line.contains("far=0x12345000")
                && line.contains("sp=0x0")
                && line.contains("error=InvalidFrame")),
        "missing the production signal-frame refusal: {diagnostics:?}"
    );
    assert!(
        diagnostics
            .iter()
            .any(|line| line.contains("signal-terminal entry-esr=0xfffc")
                && line.contains("pc=0x400200")
                && line.contains("far=0x12345000")
                && line.contains("signal=11 code=2")),
        "{diagnostics:?}"
    );
}

#[test]
fn arm_classified_fault_racing_live_sibling_exit_group_settles() {
    use carrick_signal_core::policy::Signal;
    for published_before_close in [true, false] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |_| (),
            )
            .unwrap();
        let control = host_born_sibling(fixture, 42);
        let mut gettid = carrick_el1_abi::TrapFrame::default();
        gettid.x[8] = 178;
        arm_call(fixture, control, &mut service, &mut gettid).unwrap();
        assert_eq!(gettid.x[0], 42);
        assert!(leader_sees_thread(fixture, &mut service, 42));
        assert!(control.native_signal_owner());
        assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
        // Thread 42 has faulted while thread 41 wins exit_group admission.
        if published_before_close {
            control.publish_synchronous_fault(Signal::SEGV, 1, 0x1234_5000);
        }
        let mut exit = carrick_el1_abi::TrapFrame::default();
        exit.x[0] = 7;
        exit.x[8] = 94;
        assert_eq!(
            arm_call(fixture, fixture.control, &mut service, &mut exit).unwrap(),
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
        assert_eq!(
            carrick_el1_abi::Lifecycle::gate(fixture.page),
            carrick_el1_abi::GateState::Closed
        );
        assert!(control.host_exit_requested());
        run_as(fixture, 42, 12, 102, control);
        if !published_before_close {
            control.publish_synchronous_fault(Signal::SEGV, 1, 0x1234_5000);
        }
        assert!(fixture.task.owns_lifecycle_page(fixture.page));
        assert!(fixture.task.owns_control_slot(control));
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0xfffc,
            elr: 0x40_0200,
            ..Default::default()
        };
        assert_eq!(
            super::dispatch::arm_deliver_declined_fault_signal(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot
                },
                &fixture.task,
                &ThreadCtx::ZERO,
                fixture_ttbr0(fixture),
                fixture.page,
                control,
                &mut service,
                &mut frame,
                &mut None,
                |_, _| panic!("closed owner must not select a signal action")
            )
            .unwrap(),
            carrick_el1_abi::Action::Forward
        );
        assert_eq!(
            control.synchronous_fault(),
            Some((Signal::SEGV, 1, 0x1234_5000, true)),
            "closed gate must return a terminal verdict, not re-enter forever"
        );
        assert_eq!(frame.esr, 0xfffc);
        assert_eq!(frame.elr, 0x40_0200);
    }
}

#[test]
fn arm_classified_fault_rejects_non_fault_returns_without_clobbering_syndrome() {
    use carrick_signal_core::policy::Signal;
    for esr in [0, 0x5600_0000, 0xfffd, 0xfffe] {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        let mut service = fixture.process_service();
        fixture
            .enter(
                fixture.control,
                fixture_ttbr0(fixture),
                &mut service,
                |_| (),
            )
            .unwrap();
        fixture
            .control
            .publish_synchronous_fault(Signal::SEGV, 1, 0x1234_5000);
        let mut frame = carrick_el1_abi::TrapFrame {
            esr,
            far: 0xabc,
            ..Default::default()
        };
        let result = super::dispatch::arm_deliver_declined_fault_signal_with(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut None,
            |_, _| panic!("non-fault entry must fail before delivery"),
        );
        assert_eq!(result, Err(NativeProcessError::Invalid));
        assert_eq!((frame.esr, frame.far), (esr, 0xabc));
    }
}

/// #1575 (ported from #1386): a sibling that enters a native service after its process's
/// terminal close has closed the lifecycle gate is not contended. The close is
/// a terminal state: two live threads of one native process, the leader in
/// `exit_group(7)` and the sibling (tid 42) entering a host crossing through
/// the production `with_process_entry` -> `begin_service` ->
/// `settle_service_exit` sequence that `arm_native_service_exit` drives.
/// Red before the fix: `begin_service` refused `Busy`, which dispatch turns
/// into the carrier fatal `NativeServiceBusy` (signed `cleartid_tid_reuse`
/// and `fork_cow`). Green: the sibling retires with the close status in the
/// same entry (no host work published, no EL0 return), and the group ends 7.
#[test]
#[cfg(test)]
fn arm_closed_gate_service_entry_retires_the_sibling_instead_of_busy() {
    closed_gate_service_entry(false);
}

#[test]
#[cfg(test)]
fn arm_closed_gate_service_entry_cancels_retained_ipc_before_retirement() {
    closed_gate_service_entry(true);
}

#[cfg(test)]
fn closed_gate_service_entry(retained_ipc: bool) {
    use crate::native_process_runtime::{NativeResume, NativeServiceExit};
    use carrick_core_abi::service::ServiceOperation;
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let (control, record) = imported_thread_with_identity(fixture, |_| {});
    let mut service = fixture.process_service();
    let ipc = retained_ipc.then(|| {
        use carrick_el1_abi::ipc::{IpcBacking, fd};
        let owner = std::sync::Arc::new(
            carrick_kernel::el1_ipc::HostIpc::with_limits(
                1 << 20,
                carrick_kernel::el1_ipc::IpcLimits::ZONE,
            )
            .unwrap(),
        );
        let object = owner
            .create_eventfd(7, carrick_el1_abi::ipc::EventMode::Counter)
            .unwrap();
        let table = owner.create_table(64, 64).unwrap();
        let description = owner
            .admit_description(fd::Description::new(
                IpcBacking::EventFd { object }.encode(),
                fd::AccessMode::ReadOnly,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        description.install(table, fd::Fd(0), false).unwrap();
        drop(description);
        let storage =
            carrick_test_support::ZeroedBox::leak(carrick_test_support::TestEl1Region::zeroed());
        // SAFETY: this typed fixture owns the aligned, zero-valid map storage.
        let map = unsafe {
            &*storage
                .as_ptr()
                .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
                .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
        };
        service.crossing.ipc = Some((std::sync::Arc::clone(&owner), map));
        (owner, table, object)
    });
    let ttbr0 = fixture_ttbr0(fixture);
    fixture
        .enter(fixture.control, ttbr0, &mut service, |_| ())
        .unwrap();
    // The sibling runs and registers its member before the close.
    run_as(fixture, 42, 12, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    fixture
        .enter(control, ttbr0, &mut service, |process| {
            assert!(process.has_thread(41) && process.has_thread(42));
            if let Some((owner, table, object)) = &ipc {
                use carrick_el1_abi::ipc::{
                    IpcMmKey, IpcOpKind, IpcOperation, IpcTaskKey, IpcUserVa, WriteProgress, fd::Fd,
                };
                let region = owner.region();
                let (pin, _) = region
                    .fd(carrick_sched_core::ShortLockSpin)
                    .pin(*table, Fd(0))
                    .unwrap();
                let binding = process.binding();
                let operation = region
                    .begin_operation(IpcOperation {
                        kind: IpcOpKind::EventFdRead,
                        pin: pin.into_raw(),
                        object: object.to_raw(),
                        task: IpcTaskKey(binding.task.raw()),
                        mm: IpcMmKey(binding.mm.raw()),
                        buf: IpcUserVa(0x10000),
                        progress: WriteProgress::new(8),
                        ..IpcOperation::EMPTY
                    })
                    .unwrap();
                let token = carrick_el1::substrate::ipc::to_sched_token(operation).unwrap();
                assert!(matches!(
                    process.yield_owned_operation(token),
                    carrick_core::mm::transaction::OwnedOperationYield::Suspended
                ));
                // Only the operation's pin now retains the endpoint.
                assert!(
                    region
                        .fd(carrick_sched_core::ShortLockSpin)
                        .close(*table, Fd(0))
                        .unwrap()
                        .is_none()
                );
                assert!(region.observe(*object).is_ok());
            }
        })
        .unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, record.id)
            .is_queued()
    );
    fixture.zone.clear_current(fixture.slot);
    assert!(leader_sees_thread(fixture, &mut service, 42));
    // The leader's exit_group closes the gate and waits for the sibling.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[0] = 7;
    frame.x[8] = 94;
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 1);
    // The sibling, still running, enters a host crossing.
    run_as(fixture, 42, 12, 102, control);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record.id
    );
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let entered = with_process_entry(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        ttbr0,
        fixture.page,
        control,
        &mut service,
        |entry| {
            let operation = if retained_ipc {
                assert!(fixture.zone.record(record.id).has_adapter_operation());
                ServiceOperation::CarrierWork {
                    entry: carrick_sched_core::object_wait::OwnerEntry::Syscall,
                    demand: carrick_core_abi::service::CarrierDemand::Work,
                }
            } else {
                ServiceOperation::Crossing {
                    ordinal: carrick_guest_arch::NativeOrdinal::new(115),
                }
            };
            let result = entry.begin_service(operation, None);
            let result = entry.settle_service_exit(
                result,
                if retained_ipc {
                    NativeServiceExit::CarrierWork
                } else {
                    NativeServiceExit::Bridge
                },
            );
            crate::dispatch::native_service_completion(result, entry.native_service_phase())
                .unwrap_or_else(|reason| panic!("service-exit fatal: {:?}", reason.fatal_reason()))
        },
    )
    .expect("the sibling's admission precedes its service");
    assert!(
        matches!(entered, NativeResume::Left(None)),
        "the sibling leaves its lane for the terminal checkpoint"
    );
    assert!(
        fixture.task.service_notice.take().unwrap().is_none(),
        "no host work is published into a closed process"
    );
    assert_eq!(
        carrick_el1_abi::Lifecycle::claimed_count(fixture.page),
        0,
        "the service claim is released"
    );
    assert!(
        fixture.zone.slot(fixture.slot).current().is_none(),
        "the sibling's lane is released, not resumed at EL0"
    );
    assert!(
        fixture.zone.live(record).is_none(),
        "the sibling's record retired"
    );
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 0);
    if let Some((owner, _, object)) = &ipc {
        assert!(!fixture.zone.record(record.id).has_adapter_operation());
        assert!(
            owner.region().observe(*object).is_err(),
            "terminal cancellation releases the last endpoint pin"
        );
    }
    // The sibling's retirement woke the closing owner; it completes the close.
    assert!(matches!(
        resume_closing_root(fixture, &mut service),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
    assert_eq!(service.crossing.root_exit_status.load(Ordering::Acquire), 7);
}

#[test]
fn arm_sigaction_nonresident_input_redispatches() {
    signal_setup_nonresident_input(134);
}

#[test]
fn arm_sigaltstack_nonresident_input_redispatches() {
    signal_setup_nonresident_input(132);
}

#[test]
fn arm_sigsuspend_nonresident_input_redispatches_before_installing_mask() {
    signal_setup_nonresident_input(133);
}

#[cfg(test)]
fn signal_setup_nonresident_input(nr: u64) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let mut input = [0_u64; 4];
    match nr {
        134 => input[0] = 1, // SIG_IGN
        132 => input[1] = 2, // SS_DISABLE
        _ => {}
    }
    let input = carrick_test_support::GuestUserBuffer::from_value(input);
    let old = carrick_test_support::GuestUserBuffer::from_value([0x55_u8; 32]);
    let args = match nr {
        134 => [10, input.arg(), old.arg(), 8, 0, 0],
        132 => [input.arg(), old.arg(), 0, 0, 0, 0],
        _ => [input.arg(), 8, 0, 0, 0, 0],
    };
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = nr;
    frame.x[..6].copy_from_slice(&args);
    let pc = frame.elr;
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let first = arm_call(fixture, fixture.control, &mut service, &mut frame);
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    assert_eq!(
        first.unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Served
    );
    assert_eq!(frame.elr, pc.wrapping_sub(4));
    assert_eq!(&frame.x[..6], &args);
    assert_eq!(fixture.control.blocked().0, 0);
    assert_eq!(old.get::<[u8; 32]>(0), [0x55; 32]);
    frame.x[..6].copy_from_slice(&args);
    let second = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    if nr == 133 {
        assert_eq!(
            second,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
    } else {
        assert_eq!(
            second,
            carrick_personality_linux::dispatch::CompletionRoute::WithWork
        );
        assert_eq!(frame.x[0], 0);
        if nr == 134 {
            assert_eq!(old.get::<[u8; 32]>(0), [0; 32]);
        } else {
            assert_eq!(old.get::<[u64; 3]>(0), [0, 2, 0]);
        }
    }
}

#[test]
fn futex_unbacked_word_waits_for_owner_with_two_live_threads() {
    futex_owner_wait_episode(
        false,
        false,
        false,
        None,
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_relative_deadline_survives_owner_wait_with_two_live_threads() {
    futex_owner_wait_episode(
        true,
        false,
        false,
        None,
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_relative_deadline_survives_synchronous_owner_redispatch_with_two_live_threads() {
    futex_owner_wait_episode(
        true,
        true,
        false,
        None,
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_cancelled_owner_wait_releases_deadline_before_next_wait() {
    futex_owner_wait_episode(
        true,
        false,
        true,
        None,
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_owner_deadline_is_discarded_before_an_unrelated_syscall() {
    futex_owner_wait_episode(
        true,
        false,
        false,
        Some(172),
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_owner_deadline_is_discarded_before_an_unserved_futex() {
    futex_owner_wait_episode(
        true,
        false,
        false,
        Some(98),
        false,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_caught_signal_releases_owner_deadline_before_handler_wait() {
    futex_owner_wait_episode(
        true,
        false,
        false,
        None,
        true,
        false,
        FutexOwnerRefusal::Copy,
    );
}

#[test]
fn futex_signal_during_owner_park_interrupts_then_starts_fresh_handler_wait() {
    futex_owner_wait_episode(
        true,
        false,
        false,
        None,
        true,
        true,
        FutexOwnerRefusal::Copy,
    );
}

#[cfg(test)]
#[test]
fn futex_copy_not_yet_owner_fault_publishes_efault() {
    futex_owner_wait_episode(
        false,
        false,
        false,
        None,
        false,
        false,
        FutexOwnerRefusal::CopyFault,
    );
}

#[test]
fn futex_mapping_synchronous_redispatch_rewinds_syscall() {
    futex_owner_wait_episode(
        false,
        true,
        false,
        None,
        false,
        false,
        FutexOwnerRefusal::Mapping,
    );
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum FutexOwnerRefusal {
    Copy,
    CopyFault,
    Mapping,
}

#[cfg(test)]
fn futex_owner_wait_episode(
    timed: bool,
    synchronous: bool,
    cancelled: bool,
    intervening: Option<u64>,
    caught_signal: bool,
    signal_during_owner: bool,
    refusal: FutexOwnerRefusal,
) {
    use crate::native_process_runtime::host_test_support::Physical;
    use crate::sched::{LinuxSchedEntry, UserWord};
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::dispatch::CompletionRoute;
    struct Word {
        missing: core::cell::Cell<bool>,
        value: core::cell::Cell<u32>,
        reads: core::cell::Cell<u32>,
    }
    impl UserWord for Word {
        fn read_u32(&self, _: &CurrentTask, address: u64) -> Option<u32> {
            assert_eq!(address, VA);
            self.reads.set(self.reads.get() + 1);
            (!self.missing.get()).then_some(self.value.get())
        }
        fn read_u64(&self, _: &CurrentTask, address: u64) -> Option<u64> {
            match address {
                value if value == VA + 8 => Some(5),
                value if value == VA + 16 => Some(0),
                _ => None,
            }
        }
    }
    let fault = matches!(refusal, FutexOwnerRefusal::CopyFault);
    let mapping = matches!(refusal, FutexOwnerRefusal::Mapping);
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut native_service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut native_service,
            |_| (),
        )
        .unwrap();
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let sibling = host_born_sibling(fixture, 42);
    if !signal_during_owner {
        let mut gettid = carrick_el1_abi::TrapFrame::default();
        gettid.x[8] = 178;
        arm_call(fixture, sibling, &mut native_service, &mut gettid).unwrap();
        assert_eq!(gettid.x[0], 42);
        assert!(leader_sees_thread(fixture, &mut native_service, 42));
    }
    run_as_leader(fixture);
    assert_eq!(fixture.page.live(), 2);
    let record = process_record_for_call(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        fixture.control,
    )
    .unwrap();
    registry()
        .rehome_entry(
            source,
            &fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    assert!(fixture.zone.mark_native_owned(record));
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let mut service = Physical {
        zone: fixture.zone,
        page: fixture.page,
        controls: core::slice::from_ref(fixture.control),
        copies: Vec::new(),
        tid_words: Default::default(),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: None,
        refuse_copy: false,
        waker_slot: carrick_sched_core::SlotId::new(0),
        on_signal_clock: None,
    };
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(1).unwrap())
        .unwrap();
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    if signal_during_owner {
        let sender_slot = SlotId::new(1);
        fixture.zone.drive(sender_slot, 2);
        fixture.zone.publish_slot(sender_slot, 1, Some(0), 1);
        fixture.zone.enter_guest(sender_slot);
        fixture.zone.install_space(sender_slot, 1).unwrap();
    }
    access.raise(space.index());
    // SAFETY: the fixture retains this exact owner and its observed closed gate.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.prepare_copy_error = if fault {
        Some(NativeProcessError::Fault)
    } else {
        (!synchronous).then_some(NativeProcessError::OwnerWait(wait))
    };
    if mapping {
        access.lower(space.index());
        crate::native_process_runtime::host_test_support::FUTEX_MAPPING
            .with(|slot| slot.set(Some(Err(NativeProcessError::OwnerWait(wait)))));
    }
    let word = Word {
        missing: core::cell::Cell::new(true),
        value: core::cell::Cell::new(0x12345678),
        reads: core::cell::Cell::new(0),
    };
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        now: 100,
        freq: 1,
        ..Default::default()
    };
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: 0x4004,
        ..Default::default()
    };
    frame.x[8] = crate::sched::SYS_FUTEX as u64;
    frame.x[0] = VA;
    frame.x[1] = if mapping {
        0
    } else {
        crate::sched::FUTEX_WAIT_PRIVATE
    };
    frame.x[2] = 0x12345678;
    frame.x[3] = if timed { VA + 8 } else { 0 };
    let mut parked = parked;
    crate::sched::ThreadCpu::save(
        &mut cpu,
        &frame,
        &mut parked,
        crate::sched::CpuExitCause::Svc,
    );
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &parked,
                &mut service,
            )
            .unwrap();
        if signal_during_owner {
            use carrick_personality_linux::signal::ProcessSignals;
            use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
            entry
                .rt_sigaction(
                    Signal::from_number(10).unwrap(),
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x700000)),
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &word,
            }),
            None,
            Some(fixture),
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        if mapping {
            crate::native_process_runtime::host_test_support::FUTEX_MAPPING
                .with(|slot| slot.set(None));
            assert_eq!(route, CompletionRoute::Served);
            assert_eq!(frame.elr, 0x4000, "redispatch must re-execute SVC");
            assert_eq!(&frame.x[..6], &[VA, 0, 0x12345678, 0, 0, 0]);
            assert_eq!(frame.x[8], crate::sched::SYS_FUTEX as u64);
            assert_eq!(word.reads.get(), 0);
            assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 0);
            return;
        }
        if fault {
            assert_eq!(route, CompletionRoute::Served);
            assert_eq!(
                frame.x[0] as i64, -14,
                "copy refusal must replace uaddr with EFAULT"
            );
            assert_eq!(word.reads.get(), 1);
            assert_eq!(fixture.page.live(), 2);
            assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 0);
            let mut diagnostic = String::new();
            counters.write_futex_errors(&mut diagnostic).unwrap();
            assert!(diagnostic.contains("result=-14 errno=14"), "{diagnostic}");
            assert!(
                diagnostic.contains(&format!("address={VA:#x}")),
                "{diagnostic}"
            );
            return;
        }
        assert_eq!(
            route,
            if synchronous {
                CompletionRoute::Served
            } else {
                CompletionRoute::Suspended
            },
            "missing backing must park on the owner, never forward an unexpected errno"
        );
        if !synchronous {
            assert!(fixture.zone.slot(fixture.slot).current().is_none());
        }
        assert_eq!(
            fixture.zone.counters.el1_parks.load(Ordering::Relaxed),
            u64::from(!synchronous)
        );
    }
    assert!(
        word.missing.get(),
        "a refused load cannot supply its own backing"
    );
    assert_eq!(
        runtime.has_relative_futex_wait_for_test(fixture.control.zone_record().unwrap()),
        timed
    );
    if cancelled {
        runtime.cancel_futex_owner_wait_for_test(fixture.control.zone_record().unwrap());
    }
    if signal_during_owner {
        use carrick_personality_linux::signal::{
            ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
        };
        use carrick_signal_core::policy::Signal;
        // A second live guest thread sends through the production signal entry.
        let sender_task = Box::leak(Box::new(CurrentTask::new()));
        sender_task.set(
            El1TaskId::from_linux_tid(42),
            carrick_el1_abi::SnapshotGeneration::from_raw(12),
            5,
        );
        sender_task.mm.key.store(1, Ordering::Release);
        sender_task
            .mm
            .thread_generation
            .store(102, Ordering::Release);
        sender_task.publish_visible_pid(41);
        sender_task.publish_root_generation(fixture.address.generation);
        sender_task.publish_lifecycle(fixture.page as *const _ as u64, sibling as *const _ as u64);
        let sender_slot = SlotId::new(1);

        let sender_record = fixture
            .zone
            .current_or_new(
                sender_slot,
                ThreadIdentity {
                    tid: 42,
                    serial: 102,
                    mm: 1,
                    file_table: 5,
                    generation: 12,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: fixture.page as *const _ as u64,
                    control_slot: sibling as *const _ as u64,
                },
            )
            .unwrap();
        sibling.bind_zone_record(fixture.zone.record_ref(sender_record));
        let sender_source = BornInZoneSource {
            zone: fixture.zone,
            slot: sender_slot,
        };
        registry()
            .register_thread(
                sender_source,
                sender_task,
                fixture.address,
                fixture.page,
                sibling,
            )
            .unwrap();
        assert!(
            fixture
                .zone
                .requeue_preempted(sender_slot, sender_record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(sender_slot).unwrap().record,
            sender_record
        );
        let mut sender = runtime
            .enter_registered(
                registry(),
                sender_source,
                sender_task,
                fixture.address,
                &parked,
                &mut service,
            )
            .unwrap();
        sender
            .tgkill(
                SignalThreadSelector::from_abi(41),
                SignalThreadSelector::from_abi(41),
                SignalRequest::Deliver(Signal::from_number(10).unwrap()),
                SignalInfo::Generated(None),
            )
            .unwrap();
    }
    word.missing.set(false);
    service.prepare_copy_error = None;
    access.lower(space.index());
    if !synchronous {
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
        assert_eq!(selected.record, fixture.control.zone_record().unwrap().id);
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &parked,
                &mut service,
            )
            .unwrap();
        let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        if cancelled {
            assert!(
                matches!(resumed, crate::native_process_runtime::NativeResume::Returned(result) if result.raw() == -14)
            );
            assert!(
                !runtime.has_relative_futex_wait_for_test(fixture.control.zone_record().unwrap())
            );
        } else {
            assert!(matches!(
                resumed,
                crate::native_process_runtime::NativeResume::RetrySyscall
            ));
        }
        drop(entry);
    } else {
        crate::sched::ThreadCpu::save(
            &mut cpu,
            &frame,
            &mut parked,
            crate::sched::CpuExitCause::Svc,
        );
    }
    // A fresh comparison uses the original syscall arguments retained by
    // the owner continuation, even if a sibling changed the word meanwhile.
    let retained = if synchronous {
        parked
    } else {
        unsafe { *fixture.zone.record(record).ctx_mut() }
    };
    if !cancelled {
        assert_eq!(retained.native.x[0], VA);
    }
    assert_eq!(retained.native.x[2], 0x12345678);
    crate::sched::ThreadCpu::load(&mut cpu, &mut frame, &retained);
    if caught_signal {
        use zerocopy::IntoBytes;

        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &retained,
                &mut service,
            )
            .unwrap();
        if signal_during_owner {
            cpu.now = 101;
            crate::dispatch::dispatch_syscall_with_native(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                &[],
                &[],
                &[],
                &[],
                &cache,
                Some(crate::dispatch::Zone {
                    tables: fixture.zone,
                    cpu: &mut cpu,
                    user: &word,
                }),
                None,
                Some(fixture),
                Some(&mut *entry),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            assert_eq!(
                frame.x[0] as i64, -4,
                "signal during owner service interrupts the retained wait"
            );
            assert_eq!(
                cpu.now, 101,
                "interruption must not spend the retained deadline"
            );
            assert!(entry.signal_checkpoint_needed());
        } else {
            use carrick_personality_linux::signal::ProcessSignals;
            use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
            let signal = Signal::from_number(10).unwrap();
            entry
                .rt_sigaction(
                    signal,
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x700000)),
                        ..Default::default()
                    }),
                )
                .unwrap();
            fixture
                .control
                .post_in_zone_standard_signal(signal)
                .unwrap();
            entry.import_in_zone_standard_signals().unwrap();
            assert!(entry.signal_checkpoint_needed());
        }
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        assert_eq!(
            super::signal_delivery::deliver_signal_on_syscall_return(
                &fixture.task,
                fixture.control,
                &mut entry,
                &mut frame,
                fp.as_bytes(),
                &mut ArmWaitSignalMachine {
                    user_sp: UserVa::new(0x900000),
                    backend: ArmWaitSignalBackend,
                },
            ),
            None
        );
        assert_eq!(
            frame.elr, 0x700000,
            "caught signal must actually reach its handler"
        );
        drop(entry);
        assert!(!runtime.has_relative_futex_wait_for_test(fixture.control.zone_record().unwrap()));
        // The handler makes the same timed WAIT immediately: no intervening
        // unrelated syscall can incidentally clear the previous operation.
        frame.x[8] = crate::sched::SYS_FUTEX as u64;
        frame.x[0] = VA;
        frame.x[1] = crate::sched::FUTEX_WAIT_PRIVATE;
        frame.x[2] = 0x12345678;
        frame.x[3] = VA + 8;
    }
    if let Some(ordinal) = intervening {
        frame.x[8] = ordinal;
        if ordinal == 98 {
            frame.x[1] = 512;
        }
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &retained,
                &mut service,
            )
            .unwrap();
        crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &word,
            }),
            None,
            Some(fixture),
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        drop(entry);
        assert!(!runtime.has_relative_futex_wait_for_test(fixture.control.zone_record().unwrap()));
        crate::sched::ThreadCpu::load(&mut cpu, &mut frame, &retained);
    }
    if timed {
        frame.x[0] = VA;
        frame.far = 0xdead_beef; // The next SVC may overwrite FAR freely.
        cpu.now = 101;
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                fixture.address,
                &retained,
                &mut service,
            )
            .unwrap();
        crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &word,
            }),
            None,
            Some(fixture),
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        drop(entry);
        assert_eq!(
            cpu.now,
            if cancelled || intervening.is_some() || caught_signal {
                106
            } else {
                105
            },
            "owner redispatch must retain the original relative deadline"
        );
        assert_eq!(frame.x[0] as i64, -110);
        assert!(!runtime.has_relative_futex_wait_for_test(fixture.control.zone_record().unwrap()));
        registry().unregister_root_for_test(&runtime);
        return;
    }
    word.value.set(0);
    let served = crate::sched::Sched {
        handoff: None,
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut cpu,
        user: &word,
        counters: &counters,
    }
    .serve_futex(&mut frame);
    assert_eq!(
        served,
        Some(crate::sched::Served::Returned { switched: false })
    );
    assert_eq!(frame.x[0] as i64, -11);
    crate::sched::ThreadCpu::load(&mut cpu, &mut frame, &retained);
    word.value.set(0x12345678);
    // Bound the matching untimed park at the existing host-kick boundary.
    cpu.pending.push_back(carrick_el1_abi::GIC_KICK_INTID);
    assert_eq!(
        crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &word,
            counters: &counters,
        }
        .serve_futex(&mut frame),
        Some(crate::sched::Served::Idle)
    );
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = fixture.task.linux.take_served_boundary();
    // The adopted sibling executes the production futex dispatcher. WAKE must
    // be address-only: HardwareUserWord cannot dereference this synthetic VA.
    run_as(fixture, 42, 12, 102, sibling);
    let mut wake = carrick_el1_abi::TrapFrame::default();
    wake.x[8] = crate::sched::SYS_FUTEX as u64;
    wake.x[0] = VA;
    wake.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
    wake.x[2] = 1;
    wake.x[5] = 0xffff_ffff;
    let waker_slot = SlotId::new(1);
    fixture.zone.drive(waker_slot, 2);
    fixture.zone.publish_slot(waker_slot, 1, Some(0), 1);
    fixture.zone.enter_guest(waker_slot);
    fixture.zone.install_space(waker_slot, 1).unwrap();
    let mut wake_cpu = crate::sched::FakeCpu::default();
    word.missing.set(true);
    let reads_before_wake = word.reads.get();
    for expected in [1, 0] {
        wake.x[0] = VA;
        assert_eq!(
            crate::sched::Sched {
                handoff: None,
                zone: fixture.zone,
                slot: waker_slot,
                task: &fixture.task,
                cpu: &mut wake_cpu,
                user: &word,
                counters: &counters,
            }
            .serve_futex(&mut wake),
            Some(crate::sched::Served::Returned { switched: false })
        );
        assert_eq!(wake.x[0], expected);
    }
    assert!(word.missing.get(), "WAKE must not prepare or read the word");
    assert_eq!(word.reads.get(), reads_before_wake);
    run_as_leader(fixture);
    assert_eq!(
        wake.x[0], 0,
        "one futex waiter requires exactly one counted wake"
    );
    let completed = crate::sched::Sched {
        handoff: None,
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut cpu,
        user: &word,
        counters: &counters,
    }
    .run_ready(&mut frame);
    assert_eq!(
        completed,
        Some(crate::sched::Served::Returned { switched: true })
    );
    assert_eq!(frame.x[0], 0, "successful FUTEX_WAIT must return zero");
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(
        word.reads.get(),
        3,
        "one refusal, one mismatch, one enrollment compare"
    );
    registry().unregister_root_for_test(&runtime);
}

// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_pid_excludes_live_host_thread_tids() {
    native_fork_with_live_host_threads([42, 43], NamespaceScenario::Collision);
}

// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_fork_live_threads_identity_and_wait_control() {
    // Qualify the child identity and reap assertions independently of the
    // known allocator collision, without changing production allocation.
    native_fork_with_live_host_threads([52, 53], NamespaceScenario::Control);
}

#[cfg(all(test, not(target_os = "macos")))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum NamespaceScenario {
    Collision,
    Control,
    Reverse,
    Reap,
    Contention,
    Exhaustion,
}

// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_namespace_ring_pid_excludes_host_reservation() {
    native_fork_with_live_host_threads([42, 43], NamespaceScenario::Reverse);
}
// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_namespace_reap_releases_number_to_host() {
    native_fork_with_live_host_threads([42, 43], NamespaceScenario::Reap);
}
// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_namespace_fork_waits_for_host_leaf_lock() {
    native_fork_with_live_host_threads([42, 43], NamespaceScenario::Contention);
}
// Maps host memory at the EL1 metadata window; macOS 27's VM_MEMORY_GUARD covers it (#1910).
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_namespace_exhaustion_is_eagain_and_recovers_after_reap() {
    native_fork_with_live_host_threads([42, 43], NamespaceScenario::Exhaustion);
}

#[cfg(all(test, not(target_os = "macos")))]
fn native_fork_with_live_host_threads(sibling_tids: [u32; 2], scenario: NamespaceScenario) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let metadata_scope = MetadataScope::new(fixture);
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
    let mut live_tids = vec![41];
    for tid in sibling_tids {
        let control = host_born_sibling(fixture, tid);
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 178;
        arm_call(fixture, control, &mut service, &mut frame).unwrap();
        assert_eq!(frame.x[0], u64::from(tid));
        live_tids.push(tid);
    }
    run_as_leader(fixture);
    let live_threads = carrick_el1_abi::Lifecycle::live(fixture.page);
    assert_eq!(live_threads, 3);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    let crossing = &crossing;
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let (outcome, runtime) = with_process_entry(
        source,
        &fixture.task,
        &ThreadCtx::ZERO,
        fixture_ttbr0(fixture),
        fixture.page,
        fixture.control,
        &mut service,
        |process| {
            for &tid in &live_tids {
                assert!(process.has_thread(tid));
            }
            let runtime = registry()
                .for_entry(source, &fixture.task, fixture.address)
                .unwrap();
            let outcome = if scenario == NamespaceScenario::Contention {
                let table = fixture.zone.namespace();
                let probe = table.contention_probe().unwrap();
                std::thread::scope(|scope| {
                    let (held, acquired) = std::sync::mpsc::sync_channel(1);
                    let probe = &probe;
                    scope.spawn(move || {
                        table.with_view(&carrick_sched_core::ShortLockSpin, |_| {
                            held.send(()).unwrap();
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(5);
                            while !probe.observed() {
                                assert!(
                                    std::time::Instant::now() < deadline,
                                    "ring fork never contended on the host-held table"
                                );
                                core::hint::spin_loop();
                            }
                        })
                    });
                    acquired
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    process.fork(ProcessForkChildTid::NONE)
                })
            } else {
                process.fork(ProcessForkChildTid::NONE)
            };
            let parent_record = fixture
                .zone
                .slot(fixture.slot)
                .current()
                .or_else(|| fixture.zone.slot(fixture.slot).host_record())
                .unwrap();
            assert!(
                fixture
                    .zone
                    .requeue_preempted(fixture.slot, parent_record)
                    .is_queued()
            );
            (outcome, runtime)
        },
    )
    .unwrap();
    let LifecycleOutcome::Returned { result, .. } = outcome else {
        panic!("fork must return");
    };
    assert!(result.raw() > 0, "fork failed: {}", result.raw());
    let child_pid = u32::try_from(result.raw()).unwrap();
    assert!(
        !live_tids.contains(&child_pid),
        "child pid {child_pid} collides with live parent tid"
    );

    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child = runtime.namespace_child_key(parent, child_pid).unwrap();
    assert!(runtime.identity_number_reserved(child.id));
    if scenario == NamespaceScenario::Reverse {
        runtime.set_next_identity_for_test(child.id);
        let (host_tid, reservation) = fixture.host_ids.reserve_thread().unwrap();
        assert_ne!(
            host_tid.raw(),
            child.id.raw(),
            "host reused a live ring pid"
        );
        drop(reservation);
    }
    let mut capacity_claims = Vec::new();
    let child_binding = runtime.task_binding(child).unwrap();
    let child_task = &*Box::leak(Box::new(CurrentTask::new()));
    activate(source, child_task, &child_binding);
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.child.lock().unwrap() = Some((
        super::common_entry::execution_binding(child_task),
        child_binding.address,
    ));
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    struct ChildLifecycle;
    impl super::thread_setup::LifecycleVenue for ChildLifecycle {
        fn thread<'a>(
            &'a self,
            task: &'a CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            let (page, slot) = task.lifecycle_refs()?;
            Some(carrick_personality_linux::thread::LifecycleThread { page, slot })
        }
        fn born_slot(
            &self,
            _: &ThreadLifecyclePage,
            _: carrick_el1_abi::EntryRef,
        ) -> Option<&ThreadControlSlot> {
            None
        }
    }
    let (_, child_control) = child_task.lifecycle_refs().unwrap();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    for nr in [172, 178] {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = nr;
        super::dispatch::dispatch_arm_syscall_with_native_process(
            &mut frame, &counters, core::slice::from_ref(child_task), &[], &[], &[], &[],
            &cache, None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None, Some(&ChildLifecycle), child_task.lifecycle_refs().unwrap().0, child_control,
            &ThreadCtx::ZERO, fixture.zone.spaces.grant(fixture.zone.spaces.find(child_binding.address.mm.raw().get()).unwrap(), child_binding.address.mm.raw().get()).unwrap().ttbr0,
            &mut child_service, |_| core::ptr::null_mut(),
        ).unwrap();
        assert_eq!(frame.x[0], u64::from(child_pid), "child syscall {nr}");
    }
    let mut entry = runtime
        .enter(source, child_task, child_binding.words, &mut child_service)
        .unwrap();
    assert!(matches!(
        entry.exit_group(23),
        LifecycleOutcome::Transferred { .. }
    ));
    drop(entry);
    assert!(
        runtime.identity_number_reserved(child.id),
        "an unreaped zombie must retain its internal number"
    );
    let parent_binding = runtime.task_binding(parent).unwrap();
    activate(source, &fixture.task, &parent_binding);
    let status = carrick_test_support::GuestUserBuffer::from_value(0i32);
    let mut entry = runtime
        .enter(source, &fixture.task, parent_binding.words, &mut service)
        .unwrap();
    if scenario == NamespaceScenario::Exhaustion {
        let mut exhausted = false;
        for _ in 0..carrick_sched_core::process::identity_allocator::NAMESPACE_TABLE_NODES {
            match fixture.host_ids.reserve_thread() {
                Ok((_, reservation)) => capacity_claims.push(reservation.commit()),
                Err(
                    carrick_kernel::kernel::IdError::StorageRequired
                    | carrick_kernel::kernel::IdError::Exhausted,
                ) => {
                    exhausted = true;
                    break;
                }
                Err(error) => panic!("unexpected reservation failure: {error}"),
            }
        }
        assert!(exhausted, "bounded table did not exhaust");
        let refused = entry.fork(ProcessForkChildTid::NONE);
        assert!(
            matches!(refused, LifecycleOutcome::Returned { result, .. } if result.raw() == -11),
            "capacity must return errno 11"
        );
    }
    let waited = entry.wait4(
        ProcessWaitPid::from_syscall_argument(u64::from(child_pid)),
        status.va(),
        LinuxWaitOptions::WNOHANG,
        UserVa::new(0),
    );
    assert!(
        matches!(waited, LifecycleOutcome::Returned { result, .. } if result.raw() == i64::from(child_pid))
    );
    assert_eq!(status.get::<i32>(0), 23 << 8, "real child exit status");
    drop(entry);
    assert!(runtime.namespace_child_key(parent, child_pid).is_none());
    assert!(
        !runtime.identity_number_reserved(child.id),
        "wait4 must release the reaped child's internal number"
    );
    runtime.set_next_identity_for_test(child.id);
    if scenario == NamespaceScenario::Reap {
        let (host_tid, reservation) = fixture.host_ids.reserve_thread().unwrap();
        assert_eq!(
            host_tid.raw(),
            child.id.raw(),
            "ring reap did not free the shared number for host reservation"
        );
        drop(reservation);
        runtime.set_next_identity_for_test(child.id);
    }
    let mut entry = runtime
        .enter(source, &fixture.task, parent_binding.words, &mut service)
        .unwrap();
    let reused = entry.fork(ProcessForkChildTid::NONE);
    let LifecycleOutcome::Returned { result, .. } = reused else {
        panic!("fork after reap must return");
    };
    assert!(result.raw() > 0, "fork after reap failed: {}", result.raw());
    let next_pid = u32::try_from(result.raw()).unwrap();
    assert!(!live_tids.contains(&next_pid));
    let next_child = runtime.namespace_child_key(parent, next_pid).unwrap();
    assert_eq!(next_child.id, child.id, "fully released number is reusable");
    assert_ne!(next_child.serial, child.serial, "reuse starts a new task");
}

/// A native child's forwarded call as the carrier serves it: the ring's
/// host-file stage for the child's own table, served by the run's host
/// dispatcher, its output copied back. `None`: the venue stages nothing.
/// A carrier refusal is the ring's ENOSYS.
#[cfg(test)]
fn serve_child_host_file(
    frame: &carrick_el1_abi::TrapFrame,
    task: &CurrentTask,
    venue: &crate::ipc::IpcVenue<'_>,
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    credentials: &carrick_personality_linux::identity::TaskCredentials,
    network_caller: Option<(TaskKey, u32)>,
) -> Option<i64> {
    use carrick_core_abi::service::ServiceOrigin;
    use carrick_personality_linux::native_host_file::HostFileStage;
    let table = crate::ipc::native_table(venue, task)
        .expect("a fork child owns a published ring descriptor table");
    let stage = crate::dispatch::native_host_file_stage(
        frame,
        task,
        &crate::file::HardwareValidator,
        table,
        ServiceOrigin::Descendant,
        |fd| crate::ipc::native_descriptor(venue, table, fd),
        &mut |_| 0,
    )?;
    Some(match stage {
        HostFileStage::Request {
            record,
            output,
            resolves_path,
            ..
        } => {
            // The production service stamps a path call's access context
            // from the caller's task row (`service.rs`): here the child's
            // `credentials`, with its cwd at `/`.
            let record = if resolves_path {
                use carrick_personality_linux::task_fs::{TaskFs, TaskPath};
                let fs = TaskFs {
                    cwd: TaskPath::root_directory(),
                    root: None,
                };
                let mut access = Vec::new();
                fs.encode_access(credentials, 0o022, &mut access).unwrap();
                carrick_personality_linux::native_host_file::stamp_access_context(&record, &access)
                    .expect("a child context and test path fit one record")
            } else {
                record
            };
            // The production carrier stamps the writer's RLIMIT_FSIZE
            // (`service.rs`); an unstamped write reads as a finite 0.
            let is_network = carrick_core_abi::host_file::request_parts(&record).is_some_and(
                |(header, _, _)| header.op == carrick_core_abi::host_file::HostFileOp::NetSyscall,
            );
            let record = if is_network {
                use carrick_personality_linux::native_host_file::{net_caller, stamp_net_caller};
                let (key, pid) = network_caller.expect("network test supplies the child identity");
                let caller = net_caller(key, pid, credentials).expect("live child network caller");
                stamp_net_caller(&record, &caller).expect("stamp child network identity")
            } else {
                record
            };
            let mut record = record.into_vec();
            carrick_personality_linux::native_host_file::stamp_write_file_size_limit::<()>(
                &mut record,
                || Ok(u64::MAX),
            )
            .unwrap();
            match dispatcher.serve_native_host_file(&mut record, None) {
                Ok(_) => {
                    let mut copy = crate::file::ValidatedCopy {
                        task,
                        validator: &crate::file::HardwareValidator,
                    };
                    carrick_personality_linux::native_host_file::complete(
                        &record,
                        output,
                        &mut |address, bytes| {
                            crate::file::UserCopy::copy_out(&mut copy, address, bytes)
                        },
                    )
                    .raw()
                }
                Err(_) => carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
            }
        }
        HostFileStage::Returned(result) => result.raw(),
        other => panic!("unexpected child stage: {other:?}"),
    })
}

/// The run root on the production ARM dispatch, with a real host
/// dispatcher behind every call the ring forwards. `body` gets the root's
/// syscall entry; the run's stdout comes back beside its result.
#[cfg(test)]
fn with_arm_root_host_dispatch<R>(
    body: impl FnOnce(
        &mut dyn FnMut(u64, [u64; 6]) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
    ) -> R,
) -> (R, Vec<u8>) {
    with_arm_process_host_dispatch(|call| body(&mut |nr, args| call(ArmCaller::Root, nr, args)))
}

/// [`with_arm_process_host_dispatch`]'s pseudo call: switch to the caller
/// and return the result its wake left for its parked call (`i64::MIN` for
/// a caller that resumes with its registers as they were).
#[cfg(test)]
const ARM_RESUME: u64 = u64::MAX;

/// [`with_arm_process_host_dispatch`]'s pseudo call: a child's
/// `setresgid(a1, a1, a1)` then `setresuid(a0, a0, a0)`, applied to its task
/// row directly. The harness's children share the root's thread slot, so a
/// child's own identity call would name the root's tid.
#[cfg(test)]
const ARM_CHILD_SETRESIDS: u64 = u64::MAX - 1;

/// [`with_arm_process_host_dispatch`]'s pseudo call: the caller's next
/// call that parks finds host work pending, so its park leaves for the
/// carrier boundary at once rather than selecting another record (the
/// harness has no other runnable record to switch to).
#[cfg(test)]
const ARM_LEAVE_ON_PARK: u64 = u64::MAX - 2;

/// [`with_arm_process_host_dispatch`]'s pseudo call: a thread sharing the
/// child's descriptor table runs `dup2(a0, a1)` while the child itself may
/// be parked. The harness runs one thread per process, so the sibling's
/// dup2 is played on the child's ring table at the fd authority, with the
/// release a replaced descriptor owes (its description's last reference,
/// its file's record locks). Returns 0 or the negated errno.
#[cfg(test)]
const ARM_SIBLING_DUP2: u64 = u64::MAX - 3;

/// [`with_arm_process_host_dispatch`]'s answer for a forwarded call the
/// host would block in (`DispatchOutcome::WaitOnFds`): the harness has no
/// carrier waiter to run it.
#[cfg(test)]
const ARM_HOST_WAITS: i64 = i64::MIN + 1;

/// Which task of [`with_arm_process_host_dispatch`]'s run makes a call.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArmCaller {
    Root,
    /// A ring child the root's `clone` returned this pid for.
    Child(u32),
}

/// [`with_arm_root_host_dispatch`] with the root's ring children: a root
/// `clone` admits the root through production fork, and a child's call runs
/// the production child entry, its host-backed descriptors staged to the
/// same host dispatcher the carrier serves them through.
#[cfg(test)]
fn with_arm_process_host_dispatch<R>(
    body: impl FnOnce(
        &mut dyn FnMut(
            ArmCaller,
            u64,
            [u64; 6],
        ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
    ) -> R,
) -> (R, Vec<u8>) {
    with_arm_process_host_files(|call, _| body(call))
}

/// [`with_arm_process_host_dispatch`] that also hands `body` the root's
/// host file table, for a witness that plays a concurrent host operation
/// (a sibling's exact slot claim) between the root's calls.
#[cfg(test)]
fn with_arm_process_host_files<R>(
    body: impl FnOnce(
        &mut dyn FnMut(
            ArmCaller,
            u64,
            [u64; 6],
        ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
        &std::sync::Arc<carrick_kernel::kernel::FileTable>,
    ) -> R,
) -> (R, Vec<u8>) {
    with_arm_process_host_files_on(carrick_kernel::dispatch::SyscallDispatcher::new(), body)
}

#[cfg(test)]
fn with_arm_process_host_files_on<R>(
    mut dispatcher: carrick_kernel::dispatch::SyscallDispatcher,
    body: impl FnOnce(
        &mut dyn FnMut(
            ArmCaller,
            u64,
            [u64; 6],
        ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
        &std::sync::Arc<carrick_kernel::kernel::FileTable>,
    ) -> R,
) -> (R, Vec<u8>) {
    use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    struct HostPointerMemory;
    impl GuestMemory for HostPointerMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            if address == 0 {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            // SAFETY: test passes live GuestUserBuffer host addresses.
            let slice = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
            Ok(slice.to_vec())
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            if address == 0 {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
            // SAFETY: test passes live GuestUserBuffer host addresses.
            let slice = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, bytes.len()) };
            slice.copy_from_slice(bytes);
            Ok(())
        }
    }
    impl CurrentMmMemory for HostPointerMemory {}

    let context = dispatcher.capture_one_task_context().unwrap();
    let wait_service = carrick_kernel::kernel::continuation::CarrierWaitService::new(Arc::new(
        carrick_kernel::kernel::Scheduler::new(Arc::clone(context.kernel())),
    ));
    wait_service.serve_host_readiness();
    let owner: &'static _ = Box::leak(Box::new(context.kernel().ipc().unwrap()));
    let files = context.resources().files();

    let root_table_key = files.id().raw();
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::with_file_table(
        0x10000,
        asid(1),
        root_table_key,
    )));

    let map = unsafe {
        &*fixture
            .region
            .ptr
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    files.publish_ipc(Arc::clone(owner), map).unwrap();

    let pages: Vec<_> = (0..16).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = Box::new(TestStockCrossing::new(&pages));
    crossing.ipc = Some((Arc::clone(owner), map));
    // A ring child's lifecycle page and control slot live in the EL1
    // metadata window, as production places them: the identity a child's
    // entry publishes then matches its record's (#2361: its IPC transfers
    // take their owned operations by that identity). macOS refuses user
    // memory at the window, so there a child's IPC transfer is not run.
    #[cfg(not(target_os = "macos"))]
    let metadata_scope = {
        let scope = MetadataScope::new(fixture);
        crossing.metadata_in_el1_window = true;
        crossing.metadata_allocations = Arc::clone(&scope.allocations);
        scope
    };
    let crossing: &'static TestStockCrossing = Box::leak(crossing);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let tables: &'static _ = Box::leak(Box::new(crate::ipc::MapTables(map)));
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables,
    };
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut host_mem = HostPointerMemory;
    let reporter = carrick_kernel::compat::CompatReporter::default();

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let root_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    // The root's first `clone` admits it into the production registry.
    let mut runtime = None;
    // `None`: the slot's running record is not yet a registered binding.
    let mut active = Some(ArmCaller::Root);
    let mut cpu = crate::sched::FakeCpu::default();
    // Children resolved so far: a later pid may be one's own fork child.
    let mut known_children: Vec<TaskKey> = Vec::new();
    let mut resolve_child =
        |runtime: &std::sync::Arc<NativeProcessRuntime<'_, _, _>>, pid: u32| -> TaskKey {
            let key = core::iter::once(root_key)
                .chain(known_children.iter().copied())
                .find_map(|parent| runtime.namespace_child_key(parent, pid))
                .unwrap_or_else(|| panic!("no live child {pid}"));
            if !known_children.contains(&key) {
                known_children.push(key);
            }
            key
        };

    let mut leave_on_park = false;
    let mut call = |caller: ArmCaller, nr: u64, args: [u64; 6]| -> (CompletionRoute, i64) {
        if nr == ARM_RESUME && active == Some(caller) {
            return (CompletionRoute::Served, i64::MIN);
        }
        if nr == ARM_CHILD_SETRESIDS {
            let ArmCaller::Child(pid) = caller else {
                panic!("ARM_CHILD_SETRESIDS names a child");
            };
            let (uid, gid) = (Some(args[0] as u32), Some(args[1] as u32));
            let runtime: &std::sync::Arc<NativeProcessRuntime<'_, _, _>> = runtime
                .as_ref()
                .expect("a child exists only after the root's clone");
            let set = runtime.update_task_identity_for_test(pid, |creds| {
                creds.set_resgid(gid, gid, gid)?;
                creds.set_resuid(uid, uid, uid)
            });
            return (CompletionRoute::Served, set.err().unwrap_or(0));
        }
        if nr == ARM_LEAVE_ON_PARK {
            leave_on_park = true;
            return (CompletionRoute::Served, 0);
        }
        if nr == ARM_SIBLING_DUP2 {
            let ArmCaller::Child(pid) = caller else {
                panic!("ARM_SIBLING_DUP2 names a ring child");
            };
            let runtime: &std::sync::Arc<NativeProcessRuntime<'_, _, _>> = runtime
                .as_ref()
                .expect("a child exists only after the root's clone");
            let binding = runtime.task_binding(resolve_child(runtime, pid)).unwrap();
            let file_table = fixture.zone.record(binding.record.id).identity().file_table;
            let table = carrick_el1_abi::ipc::fd::TableId::from_raw(
                map.lookup_owned(file_table)
                    .expect("a ring child owns its table"),
            );
            let region = owner.region();
            let retired = match region.fd(carrick_sched_core::ShortLockSpin).dup2_filtered(
                table,
                carrick_el1_abi::ipc::fd::Fd(args[0] as i32),
                carrick_el1_abi::ipc::fd::Fd(args[1] as i32),
                crate::ipc::is_zone_releasable_backing,
            ) {
                Ok(retired) => retired,
                Err(carrick_el1_abi::ipc::fd::Error::BadFd) => {
                    return (
                        CompletionRoute::Served,
                        carrick_syscall_abi::LINUX_EBADF.guest_retval(),
                    );
                }
                Err(error) => panic!("sibling dup2: {error:?}"),
            };
            let zone = Some((fixture.zone, fixture.slot));
            crate::ipc::settle_native_release(&region, retired.release, zone, &fixture.task)
                .unwrap();
            if let Some(file) = retired.file {
                crate::ipc::release_record_locks(&region, zone, &fixture.task, table, file)
                    .unwrap();
            }
            return (CompletionRoute::Served, 0);
        }
        if active != Some(caller) {
            let runtime: &std::sync::Arc<NativeProcessRuntime<'_, _, _>> = runtime
                .as_ref()
                .expect("a child exists only after the root's clone");
            let key = match caller {
                ArmCaller::Root => root_key,
                ArmCaller::Child(pid) => resolve_child(runtime, pid),
            };
            let binding = runtime.task_binding(key).unwrap();
            // Only the selected caller is queued: a parked caller left on the
            // run queue would be the next dispatch's switch target.
            let _ = fixture
                .zone
                .requeue_preempted(source.slot, binding.record.id);
            let claim = fixture.zone.record(binding.record.id).claim();
            if nr == ARM_RESUME && !matches!(claim, carrick_sched_core::Claim::Queued { .. }) {
                // Still parked: nothing woke it.
                return (CompletionRoute::Suspended, 0);
            }
            let selected = activate_target(source, &fixture.task, &binding);
            assert_eq!(selected.record, binding.record.id, "{caller:?} selected");
            active = Some(caller);
            if nr == ARM_RESUME {
                let result = selected.result.map_or(i64::MIN, |result| result as i64);
                return (CompletionRoute::Served, result);
            }
        }
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            elr: 0x4000,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let ArmCaller::Child(pid) = caller else {
            let route = super::dispatch::dispatch_arm_syscall_with_native_process(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                crossing.fd_map(),
                &[],
                crossing.open_table(),
                &[],
                &cache,
                Some(crate::dispatch::Zone {
                    tables: fixture.zone,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                }),
                Some(&venue),
                Some(fixture),
                fixture.page,
                fixture.control,
                &ThreadCtx::ZERO,
                ttbr0,
                &mut service,
                |_| core::ptr::null_mut(),
            )
            .unwrap();
            if route == CompletionRoute::Suspended {
                // Parked: no record runs until a switch selects one.
                active = None;
                return (route, frame.x[0] as i64);
            }
            // The carrier's boundary: it settles the host work the call
            // announced, and forwards a call served-with-forward-work.
            let mut forward = route == CompletionRoute::Forward;
            if route == CompletionRoute::WithWork {
                if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
                    work.settled();
                }
                if let Some(
                    carrick_personality_linux::abi::entry::ServedBoundary::ForwardOriginal {
                        ..
                    },
                ) = fixture.task.linux.take_served_boundary()
                {
                    forward = true;
                }
                if nr == 220 {
                    active = None;
                    runtime.get_or_insert_with(|| {
                        registry()
                            .for_entry(source, &fixture.task, fixture.address)
                            .expect("clone admitted the root into the production registry")
                    });
                }
            }
            let ret = if forward {
                match dispatcher
                    .dispatch(
                        &context,
                        carrick_kernel::dispatch::SyscallRequest::new(
                            nr,
                            carrick_kernel::compat::SyscallArgs(args),
                        ),
                        &mut host_mem,
                        &reporter,
                    )
                    .unwrap()
                {
                    carrick_kernel::dispatch::DispatchOutcome::Returned { value } => value,
                    carrick_kernel::dispatch::DispatchOutcome::Errno { errno } => {
                        errno.guest_retval()
                    }
                    carrick_kernel::dispatch::DispatchOutcome::WaitOnFds { .. } => ARM_HOST_WAITS,
                    other => panic!("unexpected host dispatch outcome for nr={nr}: {other:?}"),
                }
            } else {
                frame.x[0] as i64
            };
            // A call the host answered reports Forward, whatever boundary
            // (served-with-forward-work) sent it there.
            let route = if forward {
                CompletionRoute::Forward
            } else {
                route
            };
            return (route, ret);
        };
        let runtime = runtime.as_ref().unwrap();
        let binding = runtime.task_binding(resolve_child(runtime, pid)).unwrap();
        let saved = unsafe { runtime.record_binding(binding.record) }
            .unwrap()
            .words;
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                binding.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let boundary = core::mem::take(&mut leave_on_park);
        if boundary {
            fixture.task.linux.mark_pending_host_work();
        }
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            crossing.fd_map(),
            &[],
            crossing.open_table(),
            &[],
            &cache,
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
        drop(entry);
        if boundary && let Some(work) = fixture.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        if route == CompletionRoute::Suspended {
            active = None;
            if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
                work.settled();
            }
        }
        // The carrier's boundary settles the work a child's call (its own
        // clone) announced, as it does for the root's, and replays a call
        // declined for that work.
        let mut forward = route == CompletionRoute::Forward;
        if route == CompletionRoute::WithWork {
            if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
                work.settled();
            }
            if let Some(carrick_personality_linux::abi::entry::ServedBoundary::ForwardOriginal {
                ..
            }) = fixture.task.linux.take_served_boundary()
            {
                forward = true;
            }
        }
        if !forward && route != CompletionRoute::NativeService {
            return (route, frame.x[0] as i64);
        }
        // A child has no host fallback: a forward is the native host-file
        // venue's request, or nothing (a counted ENOSYS).
        let key = binding.key;
        let credentials = runtime
            .task_identity_of_for_test(key)
            .expect("a live child's task row")
            .0;
        let ret = serve_child_host_file(
            &frame,
            &fixture.task,
            &venue,
            &dispatcher,
            &credentials,
            Some((key, pid)),
        )
        .unwrap_or(carrick_syscall_abi::LINUX_ENOSYS.guest_retval());
        (route, ret)
    };

    let result = body(&mut call, &files);
    if let Some(runtime) = &runtime {
        registry().unregister_root_for_test(runtime);
    }
    #[cfg(not(target_os = "macos"))]
    drop(metadata_scope);
    (result, dispatcher.stdout())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_child_epoll_ctl_adds_an_inet_socket() {
    use carrick_abi::{
        LINUX_AF_INET, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD,
        LINUX_EPOLLET, LINUX_EPOLLEXCLUSIVE, LINUX_EPOLLONESHOT, LINUX_EPOLLOUT, LINUX_SOCK_DGRAM,
    };
    use carrick_personality_linux::{crossing::nr as sys, dispatch::CompletionRoute};
    use carrick_test_support::GuestUserBuffer;

    with_arm_process_host_dispatch(|call| {
        let (route, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        let (_, socket) = call(
            child,
            sys::SOCKET.raw(),
            [LINUX_AF_INET as u64, LINUX_SOCK_DGRAM as u64, 0, 0, 0, 0],
        );
        assert!(socket >= 0, "child socket: {socket}");
        let (route, epoll) = call(child, sys::EPOLL_CREATE1.raw(), [0; 6]);
        assert_eq!(route, CompletionRoute::Served);
        assert!(epoll >= 0, "child epoll_create1: {epoll}");
        let (socket, epoll) = (socket as u64, epoll as u64);
        let edge = epoll_event_buffer(LINUX_EPOLLOUT | LINUX_EPOLLET, 0x2418);
        let level = epoll_event_buffer(LINUX_EPOLLOUT, 0x2419);
        let ctl = |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64),
                   op,
                   event| {
            let (route, result) = call(
                child,
                sys::EPOLL_CTL.raw(),
                [epoll, op, socket, event, 0, 0],
            );
            assert_eq!(result, 0, "child epoll_ctl({op}): {route:?}");
            assert_ne!(route, CompletionRoute::Forward, "child epoll_ctl({op})");
        };
        let output = GuestUserBuffer::zeroed(16);
        let wait = |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64),
                    count,
                    cookie: u64| {
            let (route, result) = call(
                child,
                sys::EPOLL_PWAIT.raw(),
                [epoll, output.arg(), 1, 0, 0, 0],
            );
            assert_eq!(result, count, "child epoll_pwait: {route:?}");
            assert_ne!(route, CompletionRoute::Forward, "child epoll_pwait");
            if count != 0 {
                assert_eq!(&output.as_bytes()[..4], &LINUX_EPOLLOUT.to_ne_bytes());
                assert_eq!(&output.as_bytes()[8..16], &cookie.to_ne_bytes());
            }
        };
        let exclusive = epoll_event_buffer(LINUX_EPOLLOUT | LINUX_EPOLLEXCLUSIVE, 0x2420);
        let invalid = epoll_event_buffer(
            LINUX_EPOLLOUT | LINUX_EPOLLEXCLUSIVE | LINUX_EPOLLONESHOT,
            0,
        );
        ctl(call, LINUX_EPOLL_CTL_ADD, exclusive.arg());
        let (route, result) = call(
            child,
            sys::EPOLL_CTL.raw(),
            [epoll, LINUX_EPOLL_CTL_MOD, socket, exclusive.arg(), 0, 0],
        );
        assert_ne!(route, CompletionRoute::Forward);
        assert_eq!(result, carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        let (route, result) = call(
            child,
            sys::EPOLL_CTL.raw(),
            [epoll, LINUX_EPOLL_CTL_MOD, socket, level.arg(), 0, 0],
        );
        assert_ne!(route, CompletionRoute::Forward);
        assert_eq!(result, carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        wait(call, 1, 0x2420);
        ctl(call, LINUX_EPOLL_CTL_DEL, 0);
        let (route, result) = call(
            child,
            sys::EPOLL_CTL.raw(),
            [epoll, LINUX_EPOLL_CTL_ADD, socket, invalid.arg(), 0, 0],
        );
        assert_ne!(route, CompletionRoute::Forward);
        assert_eq!(result, carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        let (_, nested) = call(child, sys::EPOLL_CREATE1.raw(), [0; 6]);
        assert!(nested >= 0);
        let (route, result) = call(
            child,
            sys::EPOLL_CTL.raw(),
            [
                epoll,
                LINUX_EPOLL_CTL_ADD,
                nested as u64,
                exclusive.arg(),
                0,
                0,
            ],
        );
        assert_ne!(route, CompletionRoute::Forward);
        assert_eq!(result, carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        ctl(call, LINUX_EPOLL_CTL_ADD, edge.arg());
        wait(call, 1, 0x2418);
        wait(call, 0, 0);
        ctl(call, LINUX_EPOLL_CTL_MOD, level.arg());
        wait(call, 1, 0x2419);
        wait(call, 1, 0x2419);
        ctl(call, LINUX_EPOLL_CTL_DEL, 0);
        wait(call, 0, 0);
    });
}

/// A native child's select waits on the inherited pipe while its sibling
/// retains a live writer. The harness switches to that sibling only after
/// the child parks, so the wake cannot be an immediate readiness sample.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_child_pselect6_wakes_on_sibling_pipe_write() {
    use ArmCaller::Root;
    use carrick_personality_linux::{crossing::nr as sys, dispatch::CompletionRoute};
    use carrick_test_support::GuestUserBuffer;

    with_arm_process_host_dispatch(|call| {
        let pipe = GuestUserBuffer::zeroed(8);
        assert_eq!(
            call(Root, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]).1,
            0
        );
        let read = u32::from_ne_bytes(pipe.as_bytes()[..4].try_into().unwrap());
        let write = u32::from_ne_bytes(pipe.as_bytes()[4..].try_into().unwrap());
        let (_, parent) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(parent > 0);
        let parent = ArmCaller::Child(parent as u32);
        let (_, reader) = call(parent, 220, [17, 0, 0, 0, 0, 0]);
        assert!(reader > 0);
        let reader = ArmCaller::Child(reader as u32);
        call(reader, ARM_RESUME, [0; 6]);
        let (_, writer) = call(parent, 220, [17, 0, 0, 0, 0, 0]);
        assert!(writer > 0);
        let writer = ArmCaller::Child(writer as u32);
        call(writer, ARM_RESUME, [0; 6]);
        let byte = GuestUserBuffer::from_bytes(b"x");
        let buffer = GuestUserBuffer::zeroed(1);
        let mask = (1u64 << read).to_ne_bytes();
        let mut read_set = GuestUserBuffer::from_bytes(&mask);
        let args = [u64::from(read) + 1, read_set.arg(), 0, 0, 0, 0];
        assert_eq!(
            call(
                writer,
                sys::WRITE.raw(),
                [write.into(), byte.arg(), 1, 0, 0, 0]
            )
            .1,
            1
        );
        let ready = call(reader, sys::PSELECT6.raw(), args);
        assert_eq!(ready.1, 1, "ready pipe: {ready:?}");
        assert!(matches!(
            ready.0,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(read_set.as_bytes(), &mask);
        assert_eq!(
            call(
                reader,
                sys::READ.raw(),
                [read.into(), buffer.arg(), 1, 0, 0, 0]
            )
            .1,
            1,
        );
        call(reader, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(reader, sys::PSELECT6.raw(), args);
        assert_eq!(
            parked.0,
            CompletionRoute::Suspended,
            "empty pipe: {parked:?}"
        );
        assert_eq!(
            call(reader, ARM_RESUME, [0; 6]).0,
            CompletionRoute::Suspended
        );
        // Another thread could change this memory while the reader is parked.
        // Resume uses the retained interest and replaces the output once.
        read_set.as_mut_bytes().fill(0);
        assert_eq!(
            call(
                writer,
                sys::WRITE.raw(),
                [write.into(), byte.arg(), 1, 0, 0, 0]
            )
            .1,
            1
        );
        let mut result = call(reader, ARM_RESUME, [0; 6]);
        if result.1 == i64::MIN {
            result = call(reader, sys::PSELECT6.raw(), args);
        }
        assert_eq!(result.1, 1, "sibling wake: {result:?}");
        assert!(matches!(
            result.0,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(read_set.as_bytes(), &mask);
    });
}

/// #2588: a fork child calls `pselect6` on a zone pipe its direct parent
/// holds: first a zero timeout on the empty pipe returns `0` with cleared
/// sets, then a blocking `pselect6` parks in ring (releasing the single slot)
/// until its live parent writes, wakes with `1`, reads the byte, and exits 0.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_child_pselect6_wakes_on_parent_pipe_write_and_times_out() {
    use ArmCaller::Root;
    use carrick_personality_linux::{crossing::nr as sys, dispatch::CompletionRoute};
    use carrick_test_support::GuestUserBuffer;

    with_arm_process_host_dispatch(|call| {
        let (_, parent_pid) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(parent_pid > 0);
        let parent = ArmCaller::Child(parent_pid as u32);
        call(parent, ARM_RESUME, [0; 6]);
        let pipe = GuestUserBuffer::zeroed(8);
        assert_eq!(
            call(parent, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]).1,
            0
        );
        let read = u32::from_ne_bytes(pipe.as_bytes()[..4].try_into().unwrap());
        let write = u32::from_ne_bytes(pipe.as_bytes()[4..].try_into().unwrap());
        let (_, child_pid) = call(parent, 220, [17, 0, 0, 0, 0, 0]);
        assert!(child_pid > 0);
        let child = ArmCaller::Child(child_pid as u32);
        call(child, ARM_RESUME, [0; 6]);

        let mask = (1u64 << read).to_ne_bytes();
        let mut read_set = GuestUserBuffer::from_bytes(&mask);
        let zero_ts = GuestUserBuffer::from_value([0u64, 0]);

        // Zero timeout on an empty pipe returns 0 in ring and clears read_set.
        let timed = call(
            child,
            sys::PSELECT6.raw(),
            [u64::from(read) + 1, read_set.arg(), 0, 0, zero_ts.arg(), 0],
        );
        assert_eq!(timed.1, 0, "zero-timeout pselect6: {timed:?}");
        assert!(matches!(
            timed.0,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(read_set.as_bytes(), &[0; 8]);

        // Blocking pselect6 under a temporary SIGUSR1 mask parks in ring,
        // releasing execution capacity so the parent can run on the same slot,
        // signal SIGUSR1 (held by the temporary mask, never EINTR), and write.
        let sigusr1 = 1u64 << (10 - 1);
        let sig_buf = GuestUserBuffer::from_bytes(&sigusr1.to_ne_bytes());
        let sig_pair = GuestUserBuffer::from_value([sig_buf.arg(), 8]);
        read_set.as_mut_bytes().copy_from_slice(&mask);
        let args = [u64::from(read) + 1, read_set.arg(), 0, 0, 0, sig_pair.arg()];
        call(child, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(child, sys::PSELECT6.raw(), args);
        assert_eq!(
            parked.0,
            CompletionRoute::Suspended,
            "blocking child pselect6 must park: {parked:?}"
        );

        // Parent sends SIGUSR1 while child is parked under the temporary mask:
        // child stays Suspended rather than waking with EINTR.
        assert_eq!(
            call(parent, 129, [child_pid as u64, 10, 0, 0, 0, 0]).1,
            0,
            "parent kill(child, SIGUSR1)"
        );
        assert_eq!(
            call(child, ARM_RESUME, [0; 6]).0,
            CompletionRoute::Suspended,
            "masked SIGUSR1 must not wake parked pselect6"
        );

        let byte = GuestUserBuffer::from_bytes(b"p");
        assert_eq!(
            call(
                parent,
                sys::WRITE.raw(),
                [write.into(), byte.arg(), 1, 0, 0, 0]
            )
            .1,
            1
        );

        let mut result = call(child, ARM_RESUME, [0; 6]);
        if result.1 == i64::MIN {
            result = call(child, sys::PSELECT6.raw(), args);
        }
        assert_eq!(
            result.1, 1,
            "parent pipe write wakes child pselect6: {result:?}"
        );
        assert!(matches!(
            result.0,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(read_set.as_bytes(), &mask);

        let buffer = GuestUserBuffer::zeroed(1);
        assert_eq!(
            call(
                child,
                sys::READ.raw(),
                [read.into(), buffer.arg(), 1, 0, 0, 0]
            )
            .1,
            1
        );
        assert_eq!(buffer.as_bytes(), b"p");

        // Close all write ends (parent and child's inherited copy):
        // pselect6 on the drained pipe reports readable EOF (1).
        for holder in [parent, child] {
            assert_eq!(
                call(holder, sys::CLOSE.raw(), [write.into(), 0, 0, 0, 0, 0]).1,
                0
            );
        }
        read_set.as_mut_bytes().copy_from_slice(&mask);
        let eof = call(child, sys::PSELECT6.raw(), args);
        assert_eq!(eof.1, 1, "EOF pipe must be readable in select: {eof:?}");
        assert!(matches!(
            eof.0,
            CompletionRoute::Served | CompletionRoute::WithWork
        ));
        assert_eq!(read_set.as_bytes(), &mask);
    });
}

/// #2621: apt's refused shape. A fork child's `pselect6(9, read, write,
/// NULL, timeout, NULL)` over three zone pipes (two in the read set, one in
/// the write set) is served in ring as a client of the epoll owner: an
/// immediate answer reports only the writable pipe, a full write pipe and
/// empty read pipes time out at once, and a blocking wait parks until the
/// live parent writes ONE read pipe (exactly that bit, the write set clear)
/// or drains the write pipe (only the write bit). A temporary mask holds a
/// signal across a multi-descriptor wait.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_native_child_pselect6_multi_fd_wakes_on_one_parent_pipe() {
    use ArmCaller::Root;
    use carrick_personality_linux::{crossing::nr as sys, dispatch::CompletionRoute};
    use carrick_test_support::GuestUserBuffer;

    const EAGAIN: i64 = -11;
    let served = |route: CompletionRoute| {
        matches!(route, CompletionRoute::Served | CompletionRoute::WithWork)
    };
    with_arm_process_host_dispatch(|call| {
        let (_, parent_pid) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(parent_pid > 0);
        let parent = ArmCaller::Child(parent_pid as u32);
        call(parent, ARM_RESUME, [0; 6]);
        let mut pipe = |flags: u64| {
            let fds = GuestUserBuffer::zeroed(8);
            assert_eq!(
                call(parent, sys::PIPE2.raw(), [fds.arg(), flags, 0, 0, 0, 0]).1,
                0
            );
            let bytes = fds.as_bytes();
            (
                u64::from(u32::from_ne_bytes(bytes[..4].try_into().unwrap())),
                u64::from(u32::from_ne_bytes(bytes[4..].try_into().unwrap())),
            )
        };
        let a = pipe(0);
        let b = pipe(0);
        let w = pipe(carrick_abi::LINUX_O_NONBLOCK);
        let nfds = a.0.max(a.1).max(b.0).max(b.1).max(w.0).max(w.1) + 1;
        assert_eq!(nfds, 9, "apt's shape: pipes at fds 3..=8");
        let (_, child_pid) = call(parent, 220, [17, 0, 0, 0, 0, 0]);
        assert!(child_pid > 0);
        let child = ArmCaller::Child(child_pid as u32);
        call(child, ARM_RESUME, [0; 6]);

        let bits = |fds: &[u64]| fds.iter().fold(0u64, |set, fd| set | 1 << fd).to_ne_bytes();
        let read_interest = bits(&[a.0, b.0]);
        let write_interest = bits(&[w.1]);
        let mut read_set = GuestUserBuffer::from_bytes(&read_interest);
        let mut write_set = GuestUserBuffer::from_bytes(&write_interest);
        let mut timeout = GuestUserBuffer::from_value([5u64, 0]);
        let args = |read: &GuestUserBuffer, write: &GuestUserBuffer, timeout: u64, mask: u64| {
            [nfds, read.arg(), write.arg(), 0, timeout, mask]
        };

        // The write pipe has room: an immediate answer, the write bit alone.
        let ready = call(
            child,
            sys::PSELECT6.raw(),
            args(&read_set, &write_set, timeout.arg(), 0),
        );
        assert_eq!(ready.1, 1, "immediate multi-fd pselect6: {ready:?}");
        assert!(served(ready.0));
        assert_eq!(read_set.as_bytes(), &[0; 8]);
        assert_eq!(write_set.as_bytes(), &write_interest);

        // Fill the write pipe: nothing is ready, a zero timeout answers 0.
        let chunk = GuestUserBuffer::zeroed(4096);
        let mut filled = 0;
        loop {
            let (_, wrote) = call(child, sys::WRITE.raw(), [w.1, chunk.arg(), 4096, 0, 0, 0]);
            if wrote == EAGAIN {
                break;
            }
            assert!(wrote > 0, "filling the write pipe: {wrote}");
            filled += wrote;
            assert!(filled <= 1 << 20, "a pipe without capacity");
        }
        read_set.as_mut_bytes().copy_from_slice(&read_interest);
        write_set.as_mut_bytes().copy_from_slice(&write_interest);
        timeout.as_mut_bytes().fill(0);
        let none = call(
            child,
            sys::PSELECT6.raw(),
            args(&read_set, &write_set, timeout.arg(), 0),
        );
        assert_eq!(none.1, 0, "zero-timeout multi-fd pselect6: {none:?}");
        assert!(served(none.0));
        assert_eq!(read_set.as_bytes(), &[0; 8]);
        assert_eq!(write_set.as_bytes(), &[0; 8]);

        // Blocking: parks in ring on every member, the parent runs on the
        // released slot and writes the second read pipe only.
        read_set.as_mut_bytes().copy_from_slice(&read_interest);
        write_set.as_mut_bytes().copy_from_slice(&write_interest);
        let blocking = args(&read_set, &write_set, 0, 0);
        call(child, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(child, sys::PSELECT6.raw(), blocking);
        assert_eq!(
            parked.0,
            CompletionRoute::Suspended,
            "blocking multi-fd pselect6 must park: {parked:?}"
        );
        assert_eq!(
            call(child, ARM_RESUME, [0; 6]).0,
            CompletionRoute::Suspended
        );
        let byte = GuestUserBuffer::from_bytes(b"b");
        assert_eq!(
            call(parent, sys::WRITE.raw(), [b.1, byte.arg(), 1, 0, 0, 0]).1,
            1
        );
        let mut result = call(child, ARM_RESUME, [0; 6]);
        if result.1 == i64::MIN {
            result = call(child, sys::PSELECT6.raw(), blocking);
        }
        assert_eq!(result.1, 1, "parent write wakes the set: {result:?}");
        assert!(served(result.0));
        assert_eq!(read_set.as_bytes(), &bits(&[b.0]));
        assert_eq!(write_set.as_bytes(), &[0; 8]);
        let received = GuestUserBuffer::zeroed(1);
        assert_eq!(
            call(child, sys::READ.raw(), [b.0, received.arg(), 1, 0, 0, 0]).1,
            1
        );
        assert_eq!(received.as_bytes(), b"b");

        // Blocking again: the parent drains the write pipe, which wakes the
        // write member alone.
        read_set.as_mut_bytes().copy_from_slice(&read_interest);
        write_set.as_mut_bytes().copy_from_slice(&write_interest);
        call(child, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(child, sys::PSELECT6.raw(), blocking);
        assert_eq!(parked.0, CompletionRoute::Suspended, "{parked:?}");
        let drain = GuestUserBuffer::zeroed(4096);
        let mut drained = 0;
        loop {
            let (_, got) = call(parent, sys::READ.raw(), [w.0, drain.arg(), 4096, 0, 0, 0]);
            if got == EAGAIN {
                break;
            }
            assert!(got > 0, "draining the write pipe: {got}");
            drained += got;
        }
        assert_eq!(drained, filled);
        let mut result = call(child, ARM_RESUME, [0; 6]);
        if result.1 == i64::MIN {
            result = call(child, sys::PSELECT6.raw(), blocking);
        }
        assert_eq!(
            result.1, 1,
            "a drained pipe wakes the write member: {result:?}"
        );
        assert_eq!(read_set.as_bytes(), &[0; 8]);
        assert_eq!(write_set.as_bytes(), &write_interest);

        // Two read pipes under a temporary SIGUSR1 mask: the masked signal
        // never ends the wait, the parent's write to the first pipe does.
        let sigusr1 = 1u64 << (10 - 1);
        let sig_buf = GuestUserBuffer::from_bytes(&sigusr1.to_ne_bytes());
        let sig_pair = GuestUserBuffer::from_value([sig_buf.arg(), 8]);
        read_set.as_mut_bytes().copy_from_slice(&read_interest);
        let masked = [nfds, read_set.arg(), 0, 0, 0, sig_pair.arg()];
        call(child, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(child, sys::PSELECT6.raw(), masked);
        assert_eq!(parked.0, CompletionRoute::Suspended, "{parked:?}");
        assert_eq!(
            call(parent, 129, [child_pid as u64, 10, 0, 0, 0, 0]).1,
            0,
            "parent kill(child, SIGUSR1)"
        );
        assert_eq!(
            call(child, ARM_RESUME, [0; 6]).0,
            CompletionRoute::Suspended,
            "a masked signal must not end the multi-fd wait"
        );
        let byte = GuestUserBuffer::from_bytes(b"a");
        assert_eq!(
            call(parent, sys::WRITE.raw(), [a.1, byte.arg(), 1, 0, 0, 0]).1,
            1
        );
        let mut result = call(child, ARM_RESUME, [0; 6]);
        if result.1 == i64::MIN {
            result = call(child, sys::PSELECT6.raw(), masked);
        }
        assert_eq!(result.1, 1, "masked multi-fd wait: {result:?}");
        assert_eq!(read_set.as_bytes(), &bits(&[a.0]));
    });
}

#[test]
fn arm_root_host_backed_descriptors_keep_one_owner() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_DUPFD, LINUX_F_GETFL, LINUX_F_GETLK, LINUX_F_SETFL, LINUX_F_SETLK,
        LINUX_F_WRLCK, LINUX_O_APPEND, LINUX_O_CREAT, LINUX_O_NONBLOCK, LINUX_O_TRUNC,
        LINUX_O_WRONLY, LinuxFlock64,
    };
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    let ((contents, final_contents, mut mismatches), stdout) =
        with_arm_root_host_dispatch(|call_root| {
            // The run root's host-opened descriptions keep the host FileTable as their
            // one owner (#1410 review P0-1..P0-4): its redirect reaches its own
            // writes, close releases the host fd, and fcntl reports and changes the
            // host description, including record locks the ring does not serve.
            let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
            let (_, made) = call_root(34, [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0]);
            assert!(made == 0 || made == -17, "mkdir /tmp: {made}");
            let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-1410-redirect-target\0");
            // Reads the redirect target back through a fresh root descriptor.
            let read_target =
                |call_root: &mut dyn FnMut(u64, [u64; 6]) -> (CompletionRoute, i64)| {
                    let (_, fd) = call_root(56, [LINUX_AT_FDCWD, path.arg(), 0, 0, 0, 0]);
                    if fd < 0 {
                        return format!("<reopen failed: {fd}>").into_bytes();
                    }
                    let buf = GuestUserBuffer::zeroed(64);
                    let (_, n) = call_root(63, [fd as u64, buf.arg(), 64, 0, 0, 0]);
                    call_root(57, [fd as u64, 0, 0, 0, 0, 0]);
                    if n < 0 {
                        return format!("<read failed: {n}>").into_bytes();
                    }
                    buf.as_bytes()[..n as usize].to_vec()
                };
            let (_, file_fd) = call_root(
                56,
                [
                    LINUX_AT_FDCWD,
                    path.arg(),
                    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_TRUNC,
                    0o600,
                    0,
                    0,
                ],
            );
            assert_eq!(file_fd, 3);

            // Every observation is checked, so a regression reports each broken
            // owner rule at once instead of the first.
            let mut mismatches = Vec::new();
            let mut expect = |what: &str, got: i64, want: i64| {
                if got != want {
                    mismatches.push(format!("{what}: got {got}, want {want}"));
                }
            };

            // P0-4: F_GETFL reports the host description's access mode.
            expect(
                "F_GETFL on an O_WRONLY host file",
                call_root(25, [3, LINUX_F_GETFL, 0, 0, 0, 0]).1,
                LINUX_O_WRONLY as i64,
            );

            // P0-3: record locks on a host file are served, as on main.
            let lock = GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: LINUX_F_WRLCK as i16,
                ..Default::default()
            });
            expect(
                "F_GETLK on a host file",
                call_root(25, [3, LINUX_F_GETLK, lock.arg(), 0, 0, 0]).1,
                0,
            );
            expect(
                "F_SETLK on a host file",
                call_root(25, [3, LINUX_F_SETLK, lock.arg(), 0, 0, 0]).1,
                0,
            );

            // P0-1: the shell's save/redirect/restore reaches the root's own write.
            expect(
                "fcntl(1, F_DUPFD, 10)",
                call_root(25, [1, LINUX_F_DUPFD, 10, 0, 0, 0]).1,
                10,
            );
            expect("dup3(3, 1)", call_root(24, [3, 1, 0, 0, 0, 0]).1, 1);
            let redirected = GuestUserBuffer::from_bytes(b"redirected\n");
            expect(
                "redirected write(1)",
                call_root(64, [1, redirected.arg(), 11, 0, 0, 0]).1,
                11,
            );
            expect("dup3(10, 1)", call_root(24, [10, 1, 0, 0, 0, 0]).1, 1);
            expect("close(10)", call_root(57, [10, 0, 0, 0, 0, 0]).1, 0);
            let restored = GuestUserBuffer::from_bytes(b"restored\n");
            expect(
                "restored write(1)",
                call_root(64, [1, restored.arg(), 9, 0, 0, 0]).1,
                9,
            );
            let contents = read_target(&mut *call_root);

            // P0-4: F_SETFL reaches the host description.
            let append_nonblock = LINUX_O_APPEND | LINUX_O_NONBLOCK;
            expect(
                "F_SETFL O_APPEND|O_NONBLOCK",
                call_root(25, [3, LINUX_F_SETFL, append_nonblock, 0, 0, 0]).1,
                0,
            );
            expect(
                "F_GETFL after F_SETFL",
                call_root(25, [3, LINUX_F_GETFL, 0, 0, 0, 0]).1,
                (LINUX_O_WRONLY | append_nonblock) as i64,
            );

            // P0-2: close releases the host fd; a later write is EBADF.
            expect("close(3)", call_root(57, [3, 0, 0, 0, 0, 0]).1, 0);
            let late = GuestUserBuffer::from_bytes(b"late\n");
            expect(
                "write(3) after close",
                call_root(64, [3, late.arg(), 5, 0, 0, 0]).1,
                carrick_syscall_abi::LINUX_EBADF.guest_retval(),
            );
            let final_contents = read_target(&mut *call_root);
            (contents, final_contents, mismatches)
        });
    for (what, got, want) in [
        ("target after restore", contents, &b"redirected\n"[..]),
        ("target after close", final_contents, &b"redirected\n"[..]),
        ("run stdout", stdout, &b"restored\n"[..]),
    ] {
        if got != want {
            mismatches.push(format!(
                "{what}: got {:?}, want {:?}",
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(want)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "root host-backed descriptors left their one owner:\n{}",
        mismatches.join("\n")
    );
}

/// A fork child resolves each pathname through its ring descriptor table.
#[test]
fn arm_fork_child_resolves_relative_paths_through_dirfds() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_AT_REMOVEDIR, LINUX_O_CREAT, LINUX_O_DIRECTORY, LINUX_O_RDWR,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::new().expect("host-file fixture scratch"),
    ));
    let (mismatches, _) = with_arm_process_host_files_on(dispatcher, |call, _| {
        let root = ArmCaller::Root;
        let dir = GuestUserBuffer::from_bytes(b"/dirfd-witness\0");
        assert_eq!(
            call(
                root,
                sys::MKDIRAT.raw(),
                [LINUX_AT_FDCWD, dir.arg(), 0o755, 0, 0, 0]
            )
            .1,
            0
        );
        let (_, parent_dirfd) = call(
            root,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, dir.arg(), LINUX_O_DIRECTORY, 0, 0, 0],
        );
        assert!(parent_dirfd >= 0, "parent directory open: {parent_dirfd}");
        let parent_sibling = GuestUserBuffer::from_bytes(b"/dirfd-witness/parent-sibling\0");
        let (_, parent_file) = call(
            root,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                parent_sibling.arg(),
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o600,
                0,
                0,
            ],
        );
        assert!(parent_file >= 0, "parent sibling create: {parent_file}");
        let (_, pid) = call(root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid}");
        let child = ArmCaller::Child(pid as u32);
        let mut mismatches = Vec::new();
        let mut expect = |step, got, want| {
            if got != want {
                mismatches.push(format!("{step}: got {got}, want {want}"));
            }
        };
        let (_, dfd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, dir.arg(), LINUX_O_DIRECTORY, 0, 0, 0],
        );
        assert!(dfd >= 0, "child directory open: {dfd}");
        let dfd = dfd as u64;
        let subdir = GuestUserBuffer::from_bytes(b"subdir\0");
        let file = GuestUserBuffer::from_bytes(b"file\0");
        let moved = GuestUserBuffer::from_bytes(b"moved\0");
        let stat = GuestUserBuffer::from_bytes(&[0; 128]);

        expect(
            "mkdirat",
            call(
                child,
                sys::MKDIRAT.raw(),
                [dfd, subdir.arg(), 0o755, 0, 0, 0],
            )
            .1,
            0,
        );
        let (_, fd) = call(
            child,
            sys::OPENAT.raw(),
            [dfd, file.arg(), LINUX_O_CREAT | LINUX_O_RDWR, 0o600, 0, 0],
        );
        expect("openat", fd.min(0), 0);
        expect(
            "newfstatat",
            call(
                child,
                sys::NEWFSTATAT.raw(),
                [dfd, file.arg(), stat.arg(), 0, 0, 0],
            )
            .1,
            0,
        );
        let sibling = GuestUserBuffer::from_bytes(b"parent-sibling\0");
        expect(
            "parent unlinkat sibling",
            call(
                root,
                sys::UNLINKAT.raw(),
                [parent_dirfd as u64, sibling.arg(), 0, 0, 0, 0],
            )
            .1,
            0,
        );
        let (_, destination) = call(
            child,
            sys::OPENAT.raw(),
            [dfd, subdir.arg(), LINUX_O_DIRECTORY, 0, 0, 0],
        );
        expect("openat destination directory", destination.min(0), 0);
        let destination = if destination < 0 {
            dfd
        } else {
            destination as u64
        };
        expect(
            "renameat",
            call(
                child,
                sys::RENAMEAT.raw(),
                [dfd, file.arg(), destination, moved.arg(), 0, 0],
            )
            .1,
            0,
        );
        expect(
            "unlinkat file",
            call(
                child,
                sys::UNLINKAT.raw(),
                [destination, moved.arg(), 0, 0, 0, 0],
            )
            .1,
            0,
        );
        expect(
            "unlinkat directory",
            call(
                child,
                sys::UNLINKAT.raw(),
                [dfd, subdir.arg(), LINUX_AT_REMOVEDIR, 0, 0, 0],
            )
            .1,
            0,
        );
        mismatches
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// An open ring file uses the carrier's regular filesystem operations.
#[test]
fn arm_fork_child_syncs_and_queries_its_host_file() {
    use carrick_abi::{LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_RDWR};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::new().expect("host-file fixture scratch"),
    ));
    let (mismatches, _) = with_arm_process_host_files_on(dispatcher, |call, _| {
        let (_, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid}");
        let child = ArmCaller::Child(pid as u32);
        let path = GuestUserBuffer::from_bytes(b"/host-file-metadata\0");
        let (_, fd) = call(
            child,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o600,
                0,
                0,
            ],
        );
        assert!(fd >= 0, "openat: {fd}");
        let fd = fd as u64;
        let data = GuestUserBuffer::from_bytes(b"child");
        assert_eq!(
            call(child, sys::WRITE.raw(), [fd, data.arg(), 5, 0, 0, 0]).1,
            5
        );
        let statfs =
            GuestUserBuffer::from_bytes(&[0; core::mem::size_of::<carrick_abi::LinuxStatfs>()]);
        let mut mismatches = Vec::new();
        for (step, syscall, args) in [
            ("fsync", sys::FSYNC, [fd, 0, 0, 0, 0, 0]),
            ("fdatasync", sys::FDATASYNC, [fd, 0, 0, 0, 0, 0]),
            ("sync_file_range", sys::SYNC_FILE_RANGE, [fd, 0, 5, 2, 0, 0]),
            ("syncfs", sys::SYNCFS, [fd, 0, 0, 0, 0, 0]),
            (
                "statfs",
                sys::STATFS,
                [path.arg(), statfs.arg(), 0, 0, 0, 0],
            ),
            ("fstatfs", sys::FSTATFS, [fd, statfs.arg(), 0, 0, 0, 0]),
            ("fallocate", sys::FALLOCATE, [fd, 0, 0, 4096, 0, 0]),
        ] {
            let (route, result) = call(child, syscall.raw(), args);
            if result != 0 {
                mismatches.push(format!("{step}: {result} ({route:?})"));
            }
        }
        let (_, size) = call(child, sys::LSEEK.raw(), [fd, 0, 2, 0, 0, 0]);
        if size != 4096 {
            mismatches.push(format!("fallocate file size: {size}, want 4096"));
        }
        mismatches
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Positional I/O keeps the open description's cursor and vectors scatter.
#[test]
fn arm_fork_child_uses_positioned_and_vectored_io() {
    use carrick_abi::{LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_RDWR};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::new().expect("host-file fixture scratch"),
    ));
    let (mismatches, _) = with_arm_process_host_files_on(dispatcher, |call, _| {
        let (_, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid}");
        let child = ArmCaller::Child(pid as u32);
        let path = GuestUserBuffer::from_bytes(b"/host-file-vectors\0");
        let (_, fd) = call(
            child,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o600,
                0,
                0,
            ],
        );
        assert!(fd >= 0, "openat: {fd}");
        let fd = fd as u64;
        let data = GuestUserBuffer::from_bytes(b"abcd");
        let insert = GuestUserBuffer::from_bytes(b"X");
        let left = GuestUserBuffer::zeroed(2);
        let right = GuestUserBuffer::zeroed(2);
        let iov = GuestUserBuffer::from_values(&[left.arg(), 2u64, right.arg(), 2u64]);
        let appended = GuestUserBuffer::from_values(&[insert.arg(), 1u64, data.arg(), 1u64]);
        assert_eq!(
            call(child, sys::WRITE.raw(), [fd, data.arg(), 4, 0, 0, 0]).1,
            4
        );
        assert_eq!(call(child, sys::LSEEK.raw(), [fd, 0, 0, 0, 0, 0]).1, 0);
        let mut mismatches = Vec::new();
        for (step, syscall, args, expected) in [
            ("pwrite64", sys::PWRITE64, [fd, insert.arg(), 1, 1, 0, 0], 1),
            ("pwritev", sys::PWRITEV, [fd, appended.arg(), 2, 2, 0, 0], 2),
            ("preadv", sys::PREADV, [fd, iov.arg(), 2, 0, 0, 0], 4),
            ("position after preadv", sys::LSEEK, [fd, 0, 1, 0, 0, 0], 0),
            ("readv", sys::READV, [fd, iov.arg(), 2, 0, 0, 0], 4),
            ("position after readv", sys::LSEEK, [fd, 0, 1, 0, 0, 0], 4),
        ] {
            let (_, result) = call(child, syscall.raw(), args);
            if result != expected {
                mismatches.push(format!("{step}: got {result}, want {expected}"));
            }
            if matches!(syscall, sys::PREADV | sys::READV)
                && (left.as_bytes() != b"aX" || right.as_bytes() != b"Xa")
            {
                mismatches.push(format!(
                    "{step}: {:?} and {:?}",
                    left.as_bytes(),
                    right.as_bytes()
                ));
            }
        }
        mismatches
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Path and descriptor xattrs use the same carrier filesystem.
#[test]
fn arm_fork_child_uses_host_file_xattrs() {
    use carrick_abi::{LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_RDWR};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::new().expect("host-file fixture scratch"),
    ));
    let (mismatches, _) = with_arm_process_host_files_on(dispatcher, |call, _| {
        let (_, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid}");
        let child = ArmCaller::Child(pid as u32);
        let path = GuestUserBuffer::from_bytes(b"/host-file-xattrs\0");
        let (_, fd) = call(
            child,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_CREAT | LINUX_O_RDWR,
                0o600,
                0,
                0,
            ],
        );
        assert!(fd >= 0, "openat: {fd}");
        let fd = fd as u64;
        let name = GuestUserBuffer::from_bytes(b"user.witness\0");
        let value = GuestUserBuffer::from_bytes(b"owned");
        let list = GuestUserBuffer::zeroed(32);
        let read = GuestUserBuffer::zeroed(5);
        let mut mismatches = Vec::new();
        for (step, syscall, args, expected) in [
            (
                "listxattr empty",
                sys::LISTXATTR,
                [path.arg(), 0, 0, 0, 0, 0],
                0,
            ),
            (
                "fsetxattr",
                sys::FSETXATTR,
                [fd, name.arg(), value.arg(), 5, 0, 0],
                0,
            ),
            (
                "getxattr",
                sys::GETXATTR,
                [path.arg(), name.arg(), read.arg(), 5, 0, 0],
                5,
            ),
            (
                "flistxattr",
                sys::FLISTXATTR,
                [fd, list.arg(), 32, 0, 0, 0],
                13,
            ),
        ] {
            let (_, result) = call(child, syscall.raw(), args);
            if result != expected {
                mismatches.push(format!("{step}: got {result}, want {expected}"));
            }
        }
        if read.as_bytes() != b"owned" || !list.as_bytes().starts_with(b"user.witness\0") {
            mismatches.push("xattr payload differs".into());
        }
        mismatches
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Host-backed implicit stdio accepts only the native file ioctl subset;
/// unlisted requests stay unrouted.
#[test]
fn arm_fork_child_uses_allowlisted_host_ioctls() {
    use carrick_abi::{LINUX_ENOSYS, LINUX_ENOTTY, LINUX_FIONBIO, LINUX_O_NONBLOCK, LINUX_TCGETS};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (mismatches, _) = with_arm_process_host_files_on(
        carrick_kernel::dispatch::SyscallDispatcher::new(),
        |call, _| {
            let (_, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
            assert!(pid > 0, "clone: {pid}");
            let child = ArmCaller::Child(pid as u32);
            let terminal = GuestUserBuffer::zeroed(36);
            let nonblock = GuestUserBuffer::from_values(&[1i32]);
            // SAFETY: isatty only probes the live process descriptor.
            let tcgets = if unsafe { libc::isatty(0) } == 1 {
                0
            } else {
                LINUX_ENOTTY.guest_retval()
            };
            let mut mismatches = Vec::new();
            for (step, fd, request, arg, expected) in [
                ("TCGETS on stdin", 0, LINUX_TCGETS, terminal.arg(), tcgets),
                ("FIONBIO on stdout", 1, LINUX_FIONBIO, nonblock.arg(), 0),
                (
                    "unlisted ioctl on stdout",
                    1,
                    0xdead,
                    0,
                    LINUX_ENOSYS.guest_retval(),
                ),
            ] {
                let (_, result) = call(child, sys::IOCTL.raw(), [fd, request, arg, 0, 0, 0]);
                if result != expected {
                    mismatches.push(format!("{step}: got {result}, want {expected}"));
                }
            }
            let (_, flags) = call(child, sys::FCNTL.raw(), [1, 3, 0, 0, 0, 0]);
            if flags < 0 || flags as u64 & LINUX_O_NONBLOCK == 0 {
                mismatches.push(format!("F_GETFL after FIONBIO: {flags:#x}"));
            }
            mismatches
        },
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// #231 parity (pip): CPython opens a script with `fopen` and then marks it
/// close-on-exec with `ioctl(fd, FIOCLEX)`. A fork child's file is a ring
/// descriptor the carrier opened for its staged `openat`; on main the ioctl
/// fell to the host crossing, whose operand resolver answered the ring
/// descriptor with a counted ENOSYS, and `pip` died with "can't open file
/// '/usr/local/bin/pip': [Errno 38]". Linux sets the flag for any open file
/// and refuses an O_PATH descriptor with EBADF.
#[test]
fn arm_fork_child_ioctl_cloexec_on_a_ring_file() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_GETFD, LINUX_FIOCLEX, LINUX_FIONCLEX, LINUX_O_CREAT, LINUX_O_PATH,
        LINUX_O_WRONLY,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mut mismatches = Vec::new();
        let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
        let (_, made) = call(
            ArmCaller::Root,
            sys::MKDIRAT.raw(),
            [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
        );
        assert!(made == 0 || made == -17, "mkdir /tmp: {made}");
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-231-pip-script\0");
        let (_, created) = call(
            ArmCaller::Root,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_WRONLY | LINUX_O_CREAT,
                0o755,
                0,
                0,
            ],
        );
        assert!(created >= 0, "create the script: {created}");
        call(
            ArmCaller::Root,
            sys::CLOSE.raw(),
            [created as u64, 0, 0, 0, 0, 0],
        );
        let (route, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        let mut expect = |what: &str, got: i64, want: i64| {
            if got != want {
                mismatches.push(format!("{what}: got {got}, want {want}"));
            }
        };
        let (route, fd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), 0, 0, 0, 0],
        );
        assert!(fd >= 0, "child open of the script: {fd} ({route:?})");
        let fd = fd as u64;
        let ioctl = sys::IOCTL.raw();
        let fcntl = sys::FCNTL.raw();
        expect(
            "FIOCLEX",
            call(child, ioctl, [fd, LINUX_FIOCLEX, 0, 0, 0, 0]).1,
            0,
        );
        expect(
            "F_GETFD after FIOCLEX",
            call(child, fcntl, [fd, LINUX_F_GETFD, 0, 0, 0, 0]).1,
            1,
        );
        expect(
            "FIONCLEX",
            call(child, ioctl, [fd, LINUX_FIONCLEX, 0, 0, 0, 0]).1,
            0,
        );
        expect(
            "F_GETFD after FIONCLEX",
            call(child, fcntl, [fd, LINUX_F_GETFD, 0, 0, 0, 0]).1,
            0,
        );
        let (_, path_fd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), LINUX_O_PATH, 0, 0, 0],
        );
        assert!(path_fd >= 0, "child O_PATH open: {path_fd}");
        expect(
            "FIOCLEX on an O_PATH descriptor",
            call(child, ioctl, [path_fd as u64, LINUX_FIOCLEX, 0, 0, 0, 0]).1,
            carrick_abi::LINUX_EBADF.guest_retval(),
        );
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "a ring file's close-on-exec ioctl left Linux's contract:\n{}",
        mismatches.join("\n")
    );
}

/// #231 parity (apt): apt's `chown ... (38: Function not implemented)` and
/// `chmod 0755 ... (38)`. A fork child's `fchmod`/`fchown` name a ring file
/// the carrier opened for its staged `openat`, and its path
/// `fchmodat`/`fchmodat2`/`fchownat` were unclaimed by the ring's host-file
/// venue: on main every one was a counted ENOSYS. Linux (chmod(2),
/// chown(2)): the mode and owner change on the file, `fchmod` of an O_PATH
/// descriptor is EBADF, `AT_SYMLINK_NOFOLLOW` of a non-link changes the
/// file itself, and a missing path is ENOENT. (This harness's backend has
/// no symlinks; the x86 oracle witness covers lchown of a link and
/// `fchmodat2`'s EOPNOTSUPP on one.)
#[test]
fn arm_fork_child_chmod_chown_on_ring_files() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_AT_SYMLINK_NOFOLLOW, LINUX_O_CREAT, LINUX_O_PATH, LINUX_O_RDWR,
        LINUX_O_WRONLY,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let errno = |errno: carrick_abi::LinuxErrno| errno.guest_retval();
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mut mismatches = Vec::new();
        let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
        let (_, made) = call(
            ArmCaller::Root,
            sys::MKDIRAT.raw(),
            [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
        );
        assert!(made == 0 || made == -17, "mkdir /tmp: {made}");
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-231-apt-attr\0");
        let missing = GuestUserBuffer::from_bytes(b"/tmp/carrick-231-apt-attr-missing\0");
        let (_, created) = call(
            ArmCaller::Root,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_WRONLY | LINUX_O_CREAT,
                0o644,
                0,
                0,
            ],
        );
        assert!(created >= 0, "create the file: {created}");
        call(
            ArmCaller::Root,
            sys::CLOSE.raw(),
            [created as u64, 0, 0, 0, 0, 0],
        );
        let (route, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        let mut expect = |what: &str, got: i64, want: i64| {
            if got != want {
                mismatches.push(format!("{what}: got {got}, want {want}"));
            }
        };
        let (route, fd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), LINUX_O_RDWR, 0, 0, 0],
        );
        assert!(fd >= 0, "child open of the file: {fd} ({route:?})");
        let fd = fd as u64;
        // aarch64 `struct stat`: st_mode is the u32 at byte 16.
        let stat = GuestUserBuffer::zeroed(128);
        let group_other = |stat: &GuestUserBuffer| {
            i64::from(u32::from_le_bytes(stat.as_bytes()[16..20].try_into().unwrap()) & 0o77)
        };
        expect(
            "fchmod(fd, 0640)",
            call(child, sys::FCHMOD.raw(), [fd, 0o640, 0, 0, 0, 0]).1,
            0,
        );
        let (_, statted) = call(child, sys::FSTAT.raw(), [fd, stat.arg(), 0, 0, 0, 0]);
        expect("fstat after fchmod", statted, 0);
        expect("fstat mode & 077 after fchmod", group_other(&stat), 0o40);
        expect(
            "fchown(fd, -1, -1)",
            call(
                child,
                sys::FCHOWN.raw(),
                [fd, u32::MAX as u64, u32::MAX as u64, 0, 0, 0],
            )
            .1,
            0,
        );
        expect(
            "fchmodat(path, 0600)",
            call(
                child,
                sys::FCHMODAT.raw(),
                [LINUX_AT_FDCWD, path.arg(), 0o600, 0, 0, 0],
            )
            .1,
            0,
        );
        let (_, statted) = call(
            child,
            sys::NEWFSTATAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), stat.arg(), 0, 0, 0],
        );
        expect("newfstatat after fchmodat", statted, 0);
        expect("stat mode & 077 after fchmodat", group_other(&stat), 0);
        expect(
            "fchownat(path, -1, -1, AT_SYMLINK_NOFOLLOW)",
            call(
                child,
                sys::FCHOWNAT.raw(),
                [
                    LINUX_AT_FDCWD,
                    path.arg(),
                    u32::MAX as u64,
                    u32::MAX as u64,
                    LINUX_AT_SYMLINK_NOFOLLOW,
                    0,
                ],
            )
            .1,
            0,
        );
        expect(
            "fchmodat2(path, 0604, AT_SYMLINK_NOFOLLOW)",
            call(
                child,
                sys::FCHMODAT2.raw(),
                [
                    LINUX_AT_FDCWD,
                    path.arg(),
                    0o604,
                    LINUX_AT_SYMLINK_NOFOLLOW,
                    0,
                    0,
                ],
            )
            .1,
            0,
        );
        let (_, statted) = call(
            child,
            sys::NEWFSTATAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), stat.arg(), 0, 0, 0],
        );
        expect("newfstatat after fchmodat2", statted, 0);
        expect("stat mode & 077 after fchmodat2", group_other(&stat), 0o04);
        expect(
            "fchmodat2(path, 0600, unknown flag)",
            call(
                child,
                sys::FCHMODAT2.raw(),
                [LINUX_AT_FDCWD, path.arg(), 0o600, 0x200, 0, 0],
            )
            .1,
            errno(carrick_abi::LINUX_EINVAL),
        );
        expect(
            "fchmodat(missing)",
            call(
                child,
                sys::FCHMODAT.raw(),
                [LINUX_AT_FDCWD, missing.arg(), 0o600, 0, 0, 0],
            )
            .1,
            errno(carrick_abi::LINUX_ENOENT),
        );
        expect(
            "fchownat(missing)",
            call(
                child,
                sys::FCHOWNAT.raw(),
                [
                    LINUX_AT_FDCWD,
                    missing.arg(),
                    u32::MAX as u64,
                    u32::MAX as u64,
                    0,
                    0,
                ],
            )
            .1,
            errno(carrick_abi::LINUX_ENOENT),
        );
        expect(
            "fchmod(999)",
            call(child, sys::FCHMOD.raw(), [999, 0o600, 0, 0, 0, 0]).1,
            errno(carrick_abi::LINUX_EBADF),
        );
        expect(
            "fchown(999)",
            call(
                child,
                sys::FCHOWN.raw(),
                [999, u32::MAX as u64, u32::MAX as u64, 0, 0, 0],
            )
            .1,
            errno(carrick_abi::LINUX_EBADF),
        );
        let (_, path_fd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), LINUX_O_PATH, 0, 0, 0],
        );
        assert!(path_fd >= 0, "child O_PATH open: {path_fd}");
        expect(
            "fchmod of an O_PATH descriptor",
            call(
                child,
                sys::FCHMOD.raw(),
                [path_fd as u64, 0o600, 0, 0, 0, 0],
            )
            .1,
            errno(carrick_abi::LINUX_EBADF),
        );
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "a fork child's chmod/chown left Linux's contract:\n{}",
        mismatches.join("\n")
    );
}

/// #2406 review P0-1: chown(2) lets an unprivileged owner "change" the uid
/// to its own and the group to one it is in; -1 leaves either alone, and a
/// foreign uid or group is EPERM. A root fork child gives a file to
/// 65534:65534 and drops to those ids, so it still owns the file. On the PR's first head every explicit
/// uid was EPERM for a non-root caller, its own included.
#[test]
fn arm_fork_child_owner_chown_keeps_its_own_ids() {
    use carrick_abi::{LINUX_AT_FDCWD, LINUX_AT_SYMLINK_NOFOLLOW, LINUX_O_CREAT, LINUX_O_RDWR};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let unchanged = u64::from(u32::MAX);
    let eperm = carrick_abi::LINUX_EPERM.guest_retval();
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mut mismatches = Vec::new();
        let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
        let (_, made) = call(
            ArmCaller::Root,
            sys::MKDIRAT.raw(),
            [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
        );
        assert!(made == 0 || made == -17, "mkdir /tmp: {made}");
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-2406-owner-chown\0");
        let (_, created) = call(
            ArmCaller::Root,
            sys::OPENAT.raw(),
            [
                LINUX_AT_FDCWD,
                path.arg(),
                LINUX_O_RDWR | LINUX_O_CREAT,
                0o644,
                0,
                0,
            ],
        );
        assert!(created >= 0, "create the file: {created}");
        let (route, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        let (route, fd) = call(
            child,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), LINUX_O_RDWR, 0, 0, 0],
        );
        assert!(fd >= 0, "child open of the file: {fd} ({route:?})");
        let fd = fd as u64;
        let (_, given) = call(child, sys::FCHOWN.raw(), [fd, 65534, 65534, 0, 0, 0]);
        assert_eq!(given, 0, "the root child gives the file to 65534:65534");
        let (_, dropped) = call(child, ARM_CHILD_SETRESIDS, [65534, 65534, 0, 0, 0, 0]);
        assert_eq!(dropped, 0, "the child drops to 65534:65534");
        let mut expect = |what: &str, got: i64, want: i64| {
            if got != want {
                mismatches.push(format!("{what}: got {got}, want {want}"));
            }
        };
        let fchown = |uid, gid| [fd, uid, gid, 0, 0, 0];
        let fchownat = |uid, gid, flags| [LINUX_AT_FDCWD, path.arg(), uid, gid, flags, 0];
        for (what, nr, args, want) in [
            (
                "fchown(fd, own uid, -1)",
                sys::FCHOWN,
                fchown(65534, unchanged),
                0,
            ),
            (
                "fchownat(path, own uid, -1, 0)",
                sys::FCHOWNAT,
                fchownat(65534, unchanged, 0),
                0,
            ),
            (
                "fchownat(path, own uid, -1, AT_SYMLINK_NOFOLLOW)",
                sys::FCHOWNAT,
                fchownat(65534, unchanged, LINUX_AT_SYMLINK_NOFOLLOW),
                0,
            ),
            (
                "fchown(fd, -1, own gid)",
                sys::FCHOWN,
                fchown(unchanged, 65534),
                0,
            ),
            (
                "fchownat(path, own uid, own gid, 0)",
                sys::FCHOWNAT,
                fchownat(65534, 65534, 0),
                0,
            ),
            (
                "fchown(fd, -1, -1)",
                sys::FCHOWN,
                fchown(unchanged, unchanged),
                0,
            ),
            (
                "fchown(fd, 0, -1)",
                sys::FCHOWN,
                fchown(0, unchanged),
                eperm,
            ),
            (
                "fchown(fd, -1, 0)",
                sys::FCHOWN,
                fchown(unchanged, 0),
                eperm,
            ),
            (
                "fchownat(path, own uid, 0, 0)",
                sys::FCHOWNAT,
                fchownat(65534, 0, 0),
                eperm,
            ),
            (
                "fchownat(path, 0, own gid, 0)",
                sys::FCHOWNAT,
                fchownat(0, 65534, 0),
                eperm,
            ),
        ] {
            expect(what, call(child, nr.raw(), args).1, want);
        }
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "an unprivileged owner's chown left chown(2):\n{}",
        mismatches.join("\n")
    );
}

/// #231 parity (apt and dpkg): two fork children contend for one file's
/// POSIX record lock and flock(2) lock in the ring's one lock table. apt
/// opens `/var/lib/apt/lists/lock` with `O_CREAT|O_RDWR|O_NOFOLLOW` and
/// takes a whole-file write lock with `fcntl(F_SETLK)`; dpkg takes flock.
/// On main every fcntl lock command and flock on a ring descriptor was a
/// counted ENOSYS. Linux (fcntl(2), flock(2)): another process's lock
/// refuses F_SETLK with EAGAIN and F_GETLK reports it with its holder's
/// PID; a close of ANY descriptor naming the file releases the closer's
/// record locks; F_SETLKW and a blocking flock wait, releasing the CPU,
/// until the holder lets go; a flock belongs to its open file description
/// and ends with its last close.
/// #231: two F_SETLKW waiters on one lock. A's unlock wakes both; the one
/// that reruns first takes the lock, the other finds it held again and
/// parks once more on its retained operation; B's unlock wakes it and its
/// rerun takes the lock. No waiter is lost, none spins.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_two_lock_waiters_rerun_and_park_again() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_F_UNLCK, LINUX_F_WRLCK, LINUX_O_CREAT,
        LINUX_O_RDWR, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute::{self, Suspended};
    use carrick_test_support::GuestUserBuffer;

    let (steps, _) = with_arm_process_host_dispatch(|call| {
        let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
        call(
            ArmCaller::Root,
            sys::MKDIRAT.raw(),
            [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
        );
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-231-two-waiters-lock\0");
        // The root's child A forks B and C (the harness admits one root fork).
        let (_, a) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        let a = ArmCaller::Child(a as u32);
        let (_, b) = call(a, 220, [17, 0, 0, 0, 0, 0]);
        let b = ArmCaller::Child(b as u32);
        call(b, ARM_RESUME, [0; 6]);
        let (_, c) = call(a, 220, [17, 0, 0, 0, 0, 0]);
        let c = ArmCaller::Child(c as u32);
        call(c, ARM_RESUME, [0; 6]);
        let mut open = |who| {
            let (_, fd) = call(
                who,
                sys::OPENAT.raw(),
                [
                    LINUX_AT_FDCWD,
                    path.arg(),
                    LINUX_O_RDWR | LINUX_O_CREAT,
                    0o640,
                    0,
                    0,
                ],
            );
            assert!(fd >= 0, "{who:?} open: {fd}");
            fd as u64
        };
        let (fa, fb, fc) = (open(a), open(b), open(c));
        let lock = |l_type: i32| {
            GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: l_type as i16,
                ..Default::default()
            })
        };
        let (write, unlock) = (lock(LINUX_F_WRLCK), lock(LINUX_F_UNLCK));
        let fcntl = sys::FCNTL.raw();
        let set = |fd, cmd, arg: &GuestUserBuffer| [fd, cmd, arg.arg(), 0, 0, 0];
        let mut steps = Vec::new();
        let mut step = |what: &'static str, got: (CompletionRoute, i64)| {
            steps.push((what, got.0, if got.0 == Suspended { 0 } else { got.1 }));
        };
        step("A F_SETLK", call(a, fcntl, set(fa, LINUX_F_SETLK, &write)));
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "B F_SETLKW parks",
            call(b, fcntl, set(fb, LINUX_F_SETLKW, &write)),
        );
        call(c, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "C F_SETLKW parks",
            call(c, fcntl, set(fc, LINUX_F_SETLKW, &write)),
        );
        step("A unlock", call(a, fcntl, set(fa, LINUX_F_SETLK, &unlock)));
        let woken = call(b, ARM_RESUME, [0; 6]);
        step("B woken", (woken.0, 0));
        step(
            "B rerun takes it",
            call(b, fcntl, set(fb, LINUX_F_SETLKW, &write)),
        );
        let woken = call(c, ARM_RESUME, [0; 6]);
        step("C woken", (woken.0, 0));
        call(c, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "C rerun parks again",
            call(c, fcntl, set(fc, LINUX_F_SETLKW, &write)),
        );
        step("C still parked", call(c, ARM_RESUME, [0; 6]));
        step("B unlock", call(b, fcntl, set(fb, LINUX_F_SETLK, &unlock)));
        let woken = call(c, ARM_RESUME, [0; 6]);
        step("C woken again", (woken.0, 0));
        step(
            "C rerun takes it",
            call(c, fcntl, set(fc, LINUX_F_SETLKW, &write)),
        );
        steps
    });
    let routes: Vec<_> = steps
        .iter()
        .map(|&(what, route, ret)| {
            (
                what,
                route == Suspended,
                if route == Suspended { 0 } else { ret },
            )
        })
        .collect();
    assert_eq!(
        routes,
        [
            ("A F_SETLK", false, 0),
            ("B F_SETLKW parks", true, 0),
            ("C F_SETLKW parks", true, 0),
            ("A unlock", false, 0),
            ("B woken", false, 0),
            ("B rerun takes it", false, 0),
            ("C woken", false, 0),
            ("C rerun parks again", true, 0),
            ("C still parked", true, 0),
            ("B unlock", false, 0),
            ("C woken again", false, 0),
            ("C rerun takes it", false, 0),
        ],
        "{steps:?}"
    );
}

/// The run root's child A and A's children B and C (the harness admits one
/// root fork), each switched in once, for the lock witnesses below.
#[cfg(all(test, not(target_os = "macos")))]
fn arm_three_lock_processes(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
) -> [ArmCaller; 3] {
    use carrick_abi::LINUX_AT_FDCWD;
    use carrick_personality_linux::crossing::nr as sys;
    let tmp = carrick_test_support::GuestUserBuffer::from_bytes(b"/tmp\0");
    call(
        ArmCaller::Root,
        sys::MKDIRAT.raw(),
        [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
    );
    let (_, a) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
    assert!(a > 0, "root fork: {a}");
    let a = ArmCaller::Child(a as u32);
    let mut child = || {
        let (_, pid) = call(a, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "A's fork: {pid}");
        let pid = ArmCaller::Child(pid as u32);
        call(pid, ARM_RESUME, [0; 6]);
        pid
    };
    let (b, c) = (child(), child());
    [a, b, c]
}

/// `openat(path, O_RDWR|O_CREAT, 0640)` as `who`.
#[cfg(all(test, not(target_os = "macos")))]
fn arm_open_lock_file(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
    who: ArmCaller,
    path: &carrick_test_support::GuestUserBuffer,
) -> u64 {
    use carrick_abi::{LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_RDWR};
    let (_, fd) = call(
        who,
        carrick_personality_linux::crossing::nr::OPENAT.raw(),
        [
            LINUX_AT_FDCWD,
            path.arg(),
            LINUX_O_RDWR | LINUX_O_CREAT,
            0o640,
            0,
            0,
        ],
    );
    assert!(fd >= 0, "{who:?} open: {fd}");
    fd as u64
}

/// #2452 re-review P0: a served SEEK_SET range past the largest file
/// offset is fcntl(2)'s EOVERFLOW, not EINVAL. Native Linux 6.12.115
/// (x86_64 oracle, this struct layout): `l_start = i64::MAX, l_len = 2`
/// returns -1/errno 75; the controls `(i64::MAX, 1)` succeed and
/// `(-1, 1)` is errno 22. Red on 820b8bb11: the neutral decoder folded the
/// overflow into its EINVAL.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_review_record_lock_overflow_matches_linux() {
    use carrick_abi::{LINUX_F_SETLK, LINUX_F_WRLCK, LinuxFlock64};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;
    let (results, _) = with_arm_process_host_dispatch(|call| {
        let [a, _, _] = arm_three_lock_processes(call);
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-review2452-overflow\0");
        let fd = arm_open_lock_file(call, a, &path);
        [(i64::MAX, 2), (i64::MAX, 1), (-1, 1)].map(|(l_start, l_len)| {
            let lock = GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: LINUX_F_WRLCK as i16,
                l_start,
                l_len,
                ..Default::default()
            });
            call(
                a,
                sys::FCNTL.raw(),
                [fd, LINUX_F_SETLK, lock.arg(), 0, 0, 0],
            )
            .1
        })
    });
    assert_eq!(
        results,
        [
            carrick_abi::LINUX_EOVERFLOW.guest_retval(),
            0,
            carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
        ],
        "Linux: EOVERFLOW for l_start + l_len - 1 past the largest offset; \
         (i64::MAX, 1) succeeds; (-1, 1) is EINVAL"
    );
}

/// #2452: the ring lock owner answers every served `struct flock` range
/// and the order of fcntl(2)'s and flock(2)'s refusals as native Linux
/// 6.12.115 does (x86_64 oracle, one O_RDWR and one O_RDONLY description
/// of a regular file, `SEEK_SET`): the range is checked before an
/// `F_SETLK`'s lock type and a description's access mode, and an OFD
/// lock's `l_pid` after both; `F_GETLK` refuses a type other than
/// `F_RDLCK`/`F_WRLCK` first; flock(2) refuses an unknown operation
/// before it looks at the descriptor. Red on 820b8bb11 in the overflow
/// rows, the type-before-range and pid-before-access rows, and flock's
/// EBADF-before-EINVAL.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_record_lock_range_and_refusal_order_match_linux() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_GETLK, LINUX_F_OFD_GETLK, LINUX_F_OFD_SETLK, LINUX_F_RDLCK,
        LINUX_F_SETLK, LINUX_F_UNLCK, LINUX_F_WRLCK, LINUX_O_RDONLY, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;
    const MAX: i64 = i64::MAX;
    const MIN: i64 = i64::MIN;
    let (eoverflow, einval, ebadf) = (
        carrick_abi::LINUX_EOVERFLOW.guest_retval(),
        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
        carrick_syscall_abi::LINUX_EBADF.guest_retval(),
    );
    let (wr, rd, un) = (LINUX_F_WRLCK, LINUX_F_RDLCK, LINUX_F_UNLCK);
    // (what, read-only descriptor, command, l_type, l_start, l_len, l_pid,
    // Linux's answer)
    type Row = (&'static str, bool, u64, i32, i64, i64, i32, i64);
    let rows: &[Row] = &[
        (
            "SETLK max,2",
            false,
            LINUX_F_SETLK,
            wr,
            MAX,
            2,
            0,
            eoverflow,
        ),
        (
            "SETLK max,max",
            false,
            LINUX_F_SETLK,
            wr,
            MAX,
            MAX,
            0,
            eoverflow,
        ),
        (
            "SETLK 2,max",
            false,
            LINUX_F_SETLK,
            wr,
            2,
            MAX,
            0,
            eoverflow,
        ),
        ("SETLK 1,max", false, LINUX_F_SETLK, wr, 1, MAX, 0, 0),
        ("SETLK max,0", false, LINUX_F_SETLK, wr, MAX, 0, 0, 0),
        ("SETLK 5,-5", false, LINUX_F_SETLK, wr, 5, -5, 0, 0),
        ("SETLK 5,-6", false, LINUX_F_SETLK, wr, 5, -6, 0, einval),
        ("SETLK 0,-1", false, LINUX_F_SETLK, wr, 0, -1, 0, einval),
        (
            "SETLK max,min",
            false,
            LINUX_F_SETLK,
            wr,
            MAX,
            MIN,
            0,
            einval,
        ),
        ("SETLK max,-max", false, LINUX_F_SETLK, wr, MAX, -MAX, 0, 0),
        ("SETLK min,1", false, LINUX_F_SETLK, wr, MIN, 1, 0, einval),
        ("SETLK -1,0", false, LINUX_F_SETLK, wr, -1, 0, 0, einval),
        (
            "GETLK max,2",
            false,
            LINUX_F_GETLK,
            wr,
            MAX,
            2,
            0,
            eoverflow,
        ),
        ("GETLK max,1", false, LINUX_F_GETLK, wr, MAX, 1, 0, 0),
        (
            "OFD_SETLK max,2",
            false,
            LINUX_F_OFD_SETLK,
            wr,
            MAX,
            2,
            0,
            eoverflow,
        ),
        (
            "OFD_GETLK max,2",
            false,
            LINUX_F_OFD_GETLK,
            wr,
            MAX,
            2,
            0,
            eoverflow,
        ),
        (
            "SETLK F_UNLCK max,2",
            false,
            LINUX_F_SETLK,
            un,
            MAX,
            2,
            0,
            eoverflow,
        ),
        (
            "SETLK type 7 max,2: range first",
            false,
            LINUX_F_SETLK,
            7,
            MAX,
            2,
            0,
            eoverflow,
        ),
        ("SETLK type 7 0,1", false, LINUX_F_SETLK, 7, 0, 1, 0, einval),
        (
            "GETLK F_UNLCK max,2: type first",
            false,
            LINUX_F_GETLK,
            un,
            MAX,
            2,
            0,
            einval,
        ),
        (
            "GETLK type 7 max,2: type first",
            false,
            LINUX_F_GETLK,
            7,
            MAX,
            2,
            0,
            einval,
        ),
        (
            "OFD_SETLK pid 5 max,2: range first",
            false,
            LINUX_F_OFD_SETLK,
            wr,
            MAX,
            2,
            5,
            eoverflow,
        ),
        (
            "OFD_GETLK pid 5 max,2: range first",
            false,
            LINUX_F_OFD_GETLK,
            wr,
            MAX,
            2,
            5,
            eoverflow,
        ),
        (
            "OFD_GETLK pid 5 0,1",
            false,
            LINUX_F_OFD_GETLK,
            wr,
            0,
            1,
            5,
            einval,
        ),
        (
            "SETLK write on O_RDONLY max,2: range first",
            true,
            LINUX_F_SETLK,
            wr,
            MAX,
            2,
            0,
            eoverflow,
        ),
        (
            "SETLK write on O_RDONLY -1,1: range first",
            true,
            LINUX_F_SETLK,
            wr,
            -1,
            1,
            0,
            einval,
        ),
        (
            "OFD_SETLK write on O_RDONLY pid 5: access first",
            true,
            LINUX_F_OFD_SETLK,
            wr,
            0,
            1,
            5,
            ebadf,
        ),
        (
            "GETLK write on O_RDONLY",
            true,
            LINUX_F_GETLK,
            wr,
            0,
            1,
            0,
            0,
        ),
        (
            "SETLK read on O_RDONLY max,1",
            true,
            LINUX_F_SETLK,
            rd,
            MAX,
            1,
            0,
            0,
        ),
    ];
    let (got, _) = with_arm_process_host_dispatch(|call| {
        let [a, _, _] = arm_three_lock_processes(call);
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-range-order\0");
        let rw = arm_open_lock_file(call, a, &path);
        let (_, ro) = call(
            a,
            sys::OPENAT.raw(),
            [LINUX_AT_FDCWD, path.arg(), LINUX_O_RDONLY, 0, 0, 0],
        );
        assert!(ro >= 0, "O_RDONLY open: {ro}");
        let mut got: Vec<(&str, i64)> = rows
            .iter()
            .map(
                |&(what, read_only, cmd, l_type, l_start, l_len, l_pid, _)| {
                    let lock = GuestUserBuffer::from_value(LinuxFlock64 {
                        l_type: l_type as i16,
                        l_start,
                        l_len,
                        l_pid,
                        ..Default::default()
                    });
                    let fd = if read_only { ro as u64 } else { rw };
                    (
                        what,
                        call(a, sys::FCNTL.raw(), [fd, cmd, lock.arg(), 0, 0, 0]).1,
                    )
                },
            )
            .collect();
        got.push((
            "flock(-1, 77): operation first",
            call(a, sys::FLOCK.raw(), [u64::MAX, 77, 0, 0, 0, 0]).1,
        ));
        got
    });
    let mut want: Vec<(&str, i64)> = rows
        .iter()
        .map(|&(what, .., linux)| (what, linux))
        .collect();
    want.push(("flock(-1, 77): operation first", einval));
    assert_eq!(got, want);
}

/// #2452 review P0-1: a woken F_SETLKW takes the lock its call asked for
/// when it parked. fcntl(2) copies `struct flock` in once; B's and C's
/// requests sit in one shared structure that is rewritten to F_UNLCK while
/// both wait (another thread could do that). Red on a0bd7837d: each rerun
/// re-read the structure, so B's "rerun" unlocked nothing and returned 0
/// holding no lock, and C returned at once instead of parking behind B.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_woken_lock_waiters_take_the_request_they_parked_with() {
    use carrick_abi::{
        LINUX_F_GETLK, LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_F_UNLCK, LINUX_F_WRLCK, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute::{self, Suspended};
    use carrick_test_support::GuestUserBuffer;

    let (steps, _) = with_arm_process_host_dispatch(|call| {
        let [a, b, c] = arm_three_lock_processes(call);
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-parked-request-lock\0");
        let (fa, fb, fc) = (
            arm_open_lock_file(call, a, &path),
            arm_open_lock_file(call, b, &path),
            arm_open_lock_file(call, c, &path),
        );
        let lock = |l_type: i32| {
            GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: l_type as i16,
                ..Default::default()
            })
        };
        let (write, unlock) = (lock(LINUX_F_WRLCK), lock(LINUX_F_UNLCK));
        let mut shared = lock(LINUX_F_WRLCK);
        let shared_arg = shared.arg();
        let fcntl = sys::FCNTL.raw();
        let mut steps: Vec<(&'static str, bool, i64)> = Vec::new();
        let mut step = |what, got: (CompletionRoute, i64)| {
            let parked = got.0 == Suspended;
            steps.push((what, parked, if parked { 0 } else { got.1 }));
        };
        // A's F_GETLK: the holder's type and whether its l_pid is `pid`.
        let holder = |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64),
                      pid: ArmCaller| {
            let query = lock(LINUX_F_WRLCK);
            call(a, fcntl, [fa, LINUX_F_GETLK, query.arg(), 0, 0, 0]);
            let got = query.values::<LinuxFlock64>()[0];
            let ArmCaller::Child(pid) = pid else {
                unreachable!()
            };
            i64::from(got.l_type) * 10 + i64::from(got.l_pid == pid as i32)
        };
        step(
            "A F_SETLK",
            call(a, fcntl, [fa, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
        );
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "B F_SETLKW parks",
            call(b, fcntl, [fb, LINUX_F_SETLKW, shared_arg, 0, 0, 0]),
        );
        call(c, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "C F_SETLKW parks",
            call(c, fcntl, [fc, LINUX_F_SETLKW, shared_arg, 0, 0, 0]),
        );
        // Another thread rewrites the waiters' structure.
        shared.as_mut_bytes()[..2].copy_from_slice(&(LINUX_F_UNLCK as i16).to_ne_bytes());
        step(
            "A unlock",
            call(a, fcntl, [fa, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
        );
        let woken = call(b, ARM_RESUME, [0; 6]);
        step("B woken", (woken.0, 0));
        step(
            "B rerun takes the write lock",
            call(b, fcntl, [fb, LINUX_F_SETLKW, shared_arg, 0, 0, 0]),
        );
        let held = holder(call, b);
        step(
            "B holds a write lock (type*10 + pid is B)",
            (CompletionRoute::Served, held),
        );
        let woken = call(c, ARM_RESUME, [0; 6]);
        step("C woken", (woken.0, 0));
        call(c, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "C rerun parks behind B",
            call(c, fcntl, [fc, LINUX_F_SETLKW, shared_arg, 0, 0, 0]),
        );
        step(
            "B unlock",
            call(b, fcntl, [fb, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
        );
        let woken = call(c, ARM_RESUME, [0; 6]);
        step("C woken again", (woken.0, 0));
        step(
            "C rerun takes the write lock",
            call(c, fcntl, [fc, LINUX_F_SETLKW, shared_arg, 0, 0, 0]),
        );
        let held = holder(call, c);
        step(
            "C holds a write lock (type*10 + pid is C)",
            (CompletionRoute::Served, held),
        );
        steps
    });
    let wrlck = i64::from(carrick_abi::LINUX_F_WRLCK as i16) * 10 + 1;
    assert_eq!(
        steps,
        [
            ("A F_SETLK", false, 0),
            ("B F_SETLKW parks", true, 0),
            ("C F_SETLKW parks", true, 0),
            ("A unlock", false, 0),
            ("B woken", false, 0),
            ("B rerun takes the write lock", false, 0),
            ("B holds a write lock (type*10 + pid is B)", false, wrlck),
            ("C woken", false, 0),
            ("C rerun parks behind B", true, 0),
            ("B unlock", false, 0),
            ("C woken again", false, 0),
            ("C rerun takes the write lock", false, 0),
            ("C holds a write lock (type*10 + pid is C)", false, wrlck),
        ],
    );
}

/// #2452 review P0-2: a lock waiter is routed by the operation it
/// retained, before any look at its descriptor. While B waits, a thread
/// sharing B's table dup2s a pipe over the waited-on descriptor. Linux
/// (native oracle, Linux 6.12): the blocked call goes on with its open file
/// description; once the lock is free a POSIX F_SETLKW returns EBADF and
/// holds nothing (the number no longer names the file), while a blocking
/// flock returns 0 and its lock ends with the description's last
/// reference, the call's own. Red on a0bd7837d: the rerun was routed by
/// the pipe now at the number, away from the lock owner, stranding the
/// retained operation and the description it pinned.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_lock_waiter_goes_on_with_its_description_after_a_sibling_replaces_its_fd() {
    use carrick_abi::{
        LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_F_UNLCK, LINUX_F_WRLCK, LINUX_LOCK_EX, LINUX_LOCK_NB,
        LINUX_LOCK_UN, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute::{self, Suspended};
    use carrick_test_support::GuestUserBuffer;

    let (steps, _) = with_arm_process_host_dispatch(|call| {
        let [a, b, c] = arm_three_lock_processes(call);
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-replaced-waiter-lock\0");
        let (fa, fb, fc) = (
            arm_open_lock_file(call, a, &path),
            arm_open_lock_file(call, b, &path),
            arm_open_lock_file(call, c, &path),
        );
        let pipe = GuestUserBuffer::zeroed(8);
        let (_, made) = call(b, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]);
        assert_eq!(made, 0, "B pipe2");
        let reader = u64::from(pipe.values::<u32>()[0]);
        let lock = |l_type: i32| {
            GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: l_type as i16,
                ..Default::default()
            })
        };
        let (write, unlock) = (lock(LINUX_F_WRLCK), lock(LINUX_F_UNLCK));
        let (fcntl, flock) = (sys::FCNTL.raw(), sys::FLOCK.raw());
        let mut steps: Vec<(&'static str, bool, i64)> = Vec::new();
        let mut step = |what, got: (CompletionRoute, i64)| {
            let parked = got.0 == Suspended;
            steps.push((what, parked, if parked { 0 } else { got.1 }));
        };
        step(
            "A F_SETLK",
            call(a, fcntl, [fa, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
        );
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "B F_SETLKW parks",
            call(b, fcntl, [fb, LINUX_F_SETLKW, write.arg(), 0, 0, 0]),
        );
        step(
            "B's sibling dup2s a pipe over the fd",
            call(b, ARM_SIBLING_DUP2, [reader, fb, 0, 0, 0, 0]),
        );
        step(
            "A unlock",
            call(a, fcntl, [fa, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
        );
        let woken = call(b, ARM_RESUME, [0; 6]);
        step("B woken", (woken.0, 0));
        step(
            "B rerun: EBADF",
            call(b, fcntl, [fb, LINUX_F_SETLKW, write.arg(), 0, 0, 0]),
        );
        step(
            "C F_SETLK: B holds nothing",
            call(c, fcntl, [fc, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
        );
        step(
            "C unlock",
            call(c, fcntl, [fc, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
        );

        // flock(2): the lock belongs to the description, which the call
        // still holds.
        let fb2 = arm_open_lock_file(call, b, &path);
        step(
            "A flock LOCK_EX",
            call(a, flock, [fa, LINUX_LOCK_EX, 0, 0, 0, 0]),
        );
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "B flock LOCK_EX parks",
            call(b, flock, [fb2, LINUX_LOCK_EX, 0, 0, 0, 0]),
        );
        step(
            "B's sibling dup2s a pipe over the flock fd",
            call(b, ARM_SIBLING_DUP2, [reader, fb2, 0, 0, 0, 0]),
        );
        step(
            "A flock LOCK_UN",
            call(a, flock, [fa, LINUX_LOCK_UN, 0, 0, 0, 0]),
        );
        let woken = call(b, ARM_RESUME, [0; 6]);
        step("B woken by LOCK_UN", (woken.0, 0));
        step(
            "B flock rerun takes it",
            call(b, flock, [fb2, LINUX_LOCK_EX, 0, 0, 0, 0]),
        );
        step(
            "C flock LOCK_EX|LOCK_NB: B's ended with its description",
            call(c, flock, [fc, LINUX_LOCK_EX | LINUX_LOCK_NB, 0, 0, 0, 0]),
        );
        steps
    });
    let ebadf = carrick_syscall_abi::LINUX_EBADF.guest_retval();
    assert_eq!(
        steps,
        [
            ("A F_SETLK", false, 0),
            ("B F_SETLKW parks", true, 0),
            ("B's sibling dup2s a pipe over the fd", false, 0),
            ("A unlock", false, 0),
            ("B woken", false, 0),
            ("B rerun: EBADF", false, ebadf),
            ("C F_SETLK: B holds nothing", false, 0),
            ("C unlock", false, 0),
            ("A flock LOCK_EX", false, 0),
            ("B flock LOCK_EX parks", true, 0),
            ("B's sibling dup2s a pipe over the flock fd", false, 0),
            ("A flock LOCK_UN", false, 0),
            ("B woken by LOCK_UN", false, 0),
            ("B flock rerun takes it", false, 0),
            (
                "C flock LOCK_EX|LOCK_NB: B's ended with its description",
                false,
                0
            ),
        ],
    );
}

/// #2452 director ruling, item 2: a record lock asked through a
/// descriptor a sibling replaced is never taken, so nothing is ever given
/// back, even when the lock table is full. B parks in F_SETLKW on [0, 1);
/// a thread sharing B's table dup2s a pipe over B's descriptor; C fills
/// the table until F_SETLK is ENOLCK (its capacity); A's unlock frees one
/// record, which C takes again. B's rerun, with nothing blocking it,
/// answers EBADF and holds nothing, as Linux's (native oracle for #2452
/// review P0-2: EBADF once the lock is free; Linux has no fixed table).
/// Red on 3f83746a7: the rerun took the lock first and the full table
/// refused it, ENOLCK.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_replaced_lock_waiter_with_a_full_lock_table_answers_ebadf() {
    use carrick_abi::{
        LINUX_F_GETLK, LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_F_UNLCK, LINUX_F_WRLCK, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute::{self, Suspended};
    use carrick_test_support::GuestUserBuffer;

    let enolck = carrick_abi::LINUX_ENOLCK.guest_retval();
    let (steps, _) = with_arm_process_host_dispatch(|call| {
        let [a, b, c] = arm_three_lock_processes(call);
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-full-table-lock\0");
        let (fa, fb, fc) = (
            arm_open_lock_file(call, a, &path),
            arm_open_lock_file(call, b, &path),
            arm_open_lock_file(call, c, &path),
        );
        let pipe = GuestUserBuffer::zeroed(8);
        let (_, made) = call(b, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]);
        assert_eq!(made, 0, "B pipe2");
        let reader = u64::from(pipe.values::<u32>()[0]);
        let byte = |l_type: i32, l_start: i64| {
            GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: l_type as i16,
                l_start,
                l_len: 1,
                ..Default::default()
            })
        };
        let (write, unlock) = (byte(LINUX_F_WRLCK, 0), byte(LINUX_F_UNLCK, 0));
        let fcntl = sys::FCNTL.raw();
        let mut steps: Vec<(&'static str, bool, i64)> = Vec::new();
        let mut step = |what, got: (CompletionRoute, i64)| {
            let parked = got.0 == Suspended;
            steps.push((what, parked, if parked { 0 } else { got.1 }));
        };
        step(
            "A F_SETLK [0, 1)",
            call(a, fcntl, [fa, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
        );
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        step(
            "B F_SETLKW [0, 1) parks",
            call(b, fcntl, [fb, LINUX_F_SETLKW, write.arg(), 0, 0, 0]),
        );
        step(
            "B's sibling dup2s a pipe over the fd",
            call(b, ARM_SIBLING_DUP2, [reader, fb, 0, 0, 0, 0]),
        );
        // C's locks on separate bytes [2i, 2i + 1) never merge: one record
        // each, until the table refuses one.
        let mut next = 1;
        let filled = loop {
            assert!(
                next <= carrick_el1_abi::ipc::IPC_FILE_LOCKS as i64,
                "the lock table never filled"
            );
            let lock = byte(LINUX_F_WRLCK, 2 * next);
            let (_, got) = call(c, fcntl, [fc, LINUX_F_SETLK, lock.arg(), 0, 0, 0]);
            next += 1;
            if got != 0 {
                break got;
            }
        };
        step(
            "C fills the table: F_SETLK",
            (CompletionRoute::Served, filled),
        );
        step(
            "A unlock frees one record",
            call(a, fcntl, [fa, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
        );
        let last = byte(LINUX_F_WRLCK, 2 * next);
        step(
            "C takes it: the table is full again",
            call(c, fcntl, [fc, LINUX_F_SETLK, last.arg(), 0, 0, 0]),
        );
        let woken = call(b, ARM_RESUME, [0; 6]);
        step("B woken", (woken.0, 0));
        step(
            "B rerun: EBADF",
            call(b, fcntl, [fb, LINUX_F_SETLKW, write.arg(), 0, 0, 0]),
        );
        let query = byte(LINUX_F_WRLCK, 0);
        call(c, fcntl, [fc, LINUX_F_GETLK, query.arg(), 0, 0, 0]);
        step(
            "C F_GETLK [0, 1): l_type, B holds nothing",
            (
                CompletionRoute::Served,
                i64::from(query.values::<LinuxFlock64>()[0].l_type),
            ),
        );
        steps
    });
    let ebadf = carrick_syscall_abi::LINUX_EBADF.guest_retval();
    assert_eq!(
        steps,
        [
            ("A F_SETLK [0, 1)", false, 0),
            ("B F_SETLKW [0, 1) parks", true, 0),
            ("B's sibling dup2s a pipe over the fd", false, 0),
            ("C fills the table: F_SETLK", false, enolck),
            ("A unlock frees one record", false, 0),
            ("C takes it: the table is full again", false, 0),
            ("B woken", false, 0),
            ("B rerun: EBADF", false, ebadf),
            (
                "C F_GETLK [0, 1): l_type, B holds nothing",
                false,
                i64::from(LINUX_F_UNLCK as i16)
            ),
        ],
    );
}

/// #2452 review P0-3: close(2) releases the table's record locks of the
/// file it actually retired. B holds a write lock on Y (through `m`) and
/// closes `n`, a descriptor of X; between B's entry and the retirement a
/// thread sharing B's table dup2s `m` over `n` (the test hold). The close
/// then retires a descriptor of Y, so Y's lock ends (fcntl(2)) while Y
/// stays open at `m`. Red on a0bd7837d: the close sampled `n` as X in a
/// separate table acquisition and released X's locks; Y's lock survived.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_close_releases_record_locks_of_the_file_it_retired() {
    use carrick_abi::{LINUX_F_SETLK, LINUX_F_WRLCK, LinuxFlock64};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (results, _) = with_arm_process_host_dispatch(|call| {
        let [_, b, c] = arm_three_lock_processes(call);
        let x = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-close-race-x\0");
        let y = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-close-race-y\0");
        // `n` duplicates `x_kept`: the replaced descriptor is not the last
        // of its description.
        let x_kept = arm_open_lock_file(call, b, &x);
        let n = call(b, sys::DUP.raw(), [x_kept, 0, 0, 0, 0, 0]).1;
        assert!(n >= 0, "B dup: {n}");
        let n = n as u64;
        let m = arm_open_lock_file(call, b, &y);
        let y_c = arm_open_lock_file(call, c, &y);
        let write = GuestUserBuffer::from_value(LinuxFlock64 {
            l_type: LINUX_F_WRLCK as i16,
            ..Default::default()
        });
        let fcntl = sys::FCNTL.raw();
        let mut results = Vec::new();
        results.push((
            "B F_SETLK on Y",
            call(b, fcntl, [m, LINUX_F_SETLK, write.arg(), 0, 0, 0]).1,
        ));
        crate::dispatch::close_retire_hold::set(move |region, table, fd| {
            assert_eq!(fd.0 as u64, n, "the hold runs in B's close of n");
            // The sibling's dup2(m, n): X's description keeps `x_kept`,
            // and B's table holds no lock on X, so it owes nothing.
            let retired = region
                .fd(carrick_sched_core::ShortLockSpin)
                .dup2_filtered(
                    table,
                    carrick_el1_abi::ipc::fd::Fd(m as i32),
                    fd,
                    crate::ipc::is_zone_releasable_backing,
                )
                .unwrap();
            assert_eq!(
                retired.release,
                carrick_el1_abi::ipc::fd::DeferredRelease::None
            );
            assert!(retired.file.is_some(), "n named X");
        });
        results.push((
            "B close(n)",
            call(b, sys::CLOSE.raw(), [n, 0, 0, 0, 0, 0]).1,
        ));
        results.push((
            "C F_SETLK on Y after B closed a Y descriptor",
            call(c, fcntl, [y_c, LINUX_F_SETLK, write.arg(), 0, 0, 0]).1,
        ));
        results
    });
    assert_eq!(
        results,
        [
            ("B F_SETLK on Y", 0),
            ("B close(n)", 0),
            ("C F_SETLK on Y after B closed a Y descriptor", 0),
        ]
    );
}

/// #2452 review P0-3, dup2(2): only a descriptor the commit actually
/// displaced ends its file's record locks. B dup3s `m` (Y) over `n` (X);
/// after B's numeric claim on `n`, a thread sharing B's table closes `n`
/// and then takes a write lock on X through `k` (the test hold). The claim
/// lets that close through, so B's commit displaces nothing and the
/// sibling's lock, taken after its own close, stands. Red on a0bd7837d:
/// the dup sampled `n` as X before the commit and released X's locks.
#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_dup_releases_record_locks_only_of_a_displaced_file() {
    use carrick_abi::{LINUX_F_SETLK, LINUX_F_WRLCK, LinuxFlock64};
    use carrick_el1_abi::ipc::fd::record_lock::{
        Lock, LockClass, LockKind, LockOwner, LockPid, LockRange,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (results, _) = with_arm_process_host_dispatch(|call| {
        let [_, b, c] = arm_three_lock_processes(call);
        let ArmCaller::Child(b_pid) = b else {
            unreachable!()
        };
        let x = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-dup-race-x\0");
        let y = GuestUserBuffer::from_bytes(b"/tmp/carrick-2452-dup-race-y\0");
        let k = arm_open_lock_file(call, b, &x);
        // `n` duplicates `k`: the sibling's close of `n` is not the last of
        // its description.
        let n = call(b, sys::DUP.raw(), [k, 0, 0, 0, 0, 0]).1;
        assert!(n >= 0, "B dup: {n}");
        let n = n as u64;
        let m = arm_open_lock_file(call, b, &y);
        let x_c = arm_open_lock_file(call, c, &x);
        crate::dispatch::close_retire_hold::set(move |region, table, fd| {
            assert_eq!(fd.0 as u64, n, "the hold runs in B's dup3 onto n");
            let authority = region.fd(carrick_sched_core::ShortLockSpin);
            // The sibling's close(n): X stays open at `k`, and B's table
            // holds no lock on X yet, so the close owes nothing.
            let retired = authority
                .close_filtered(table, fd, crate::ipc::is_zone_releasable_backing)
                .unwrap();
            assert_eq!(
                retired.release,
                carrick_el1_abi::ipc::fd::DeferredRelease::None
            );
            // Then its F_SETLK F_WRLCK on X through `k`.
            let file = authority
                .file_identity(table, carrick_el1_abi::ipc::fd::Fd(k as i32))
                .unwrap()
                .expect("X is a stamped file");
            let locks = region
                .file_locks(&carrick_sched_core::ShortLockSpin)
                .unwrap();
            let taken = locks.table().set(
                Lock {
                    file,
                    owner: LockOwner::table(table),
                    class: LockClass::Record,
                    kind: LockKind::Write,
                    range: LockRange::WHOLE_FILE,
                    pid: LockPid::new(b_pid),
                },
                &authority,
            );
            assert_eq!(taken.taken, Ok(()));
        });
        let mut results = Vec::new();
        results.push((
            "B dup3(m, n)",
            call(b, sys::DUP3.raw(), [m, n, 0, 0, 0, 0]).1 - n as i64,
        ));
        let write = GuestUserBuffer::from_value(LinuxFlock64 {
            l_type: LINUX_F_WRLCK as i16,
            ..Default::default()
        });
        results.push((
            "C F_SETLK on X against the sibling's lock",
            call(
                c,
                sys::FCNTL.raw(),
                [x_c, LINUX_F_SETLK, write.arg(), 0, 0, 0],
            )
            .1,
        ));
        results
    });
    assert_eq!(
        results,
        [
            ("B dup3(m, n)", 0),
            (
                "C F_SETLK on X against the sibling's lock",
                carrick_syscall_abi::LINUX_EAGAIN.guest_retval()
            ),
        ]
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn serial_host_arm_fork_children_contend_record_locks_and_flock_in_the_ring() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_GETLK, LINUX_F_RDLCK, LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_F_UNLCK,
        LINUX_F_WRLCK, LINUX_LOCK_EX, LINUX_LOCK_NB, LINUX_LOCK_SH, LINUX_LOCK_UN, LINUX_O_CREAT,
        LINUX_O_NOFOLLOW, LINUX_O_RDWR, LinuxFlock64,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    let eagain = carrick_syscall_abi::LINUX_EAGAIN.guest_retval();
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mismatches = core::cell::RefCell::new(Vec::new());
        let tmp = GuestUserBuffer::from_bytes(b"/tmp\0");
        let (_, made) = call(
            ArmCaller::Root,
            sys::MKDIRAT.raw(),
            [LINUX_AT_FDCWD, tmp.arg(), 0o777, 0, 0, 0],
        );
        assert!(made == 0 || made == -17, "mkdir /tmp: {made}");
        let path = GuestUserBuffer::from_bytes(b"/tmp/carrick-231-apt-lists-lock\0");
        let (route, pid_a) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid_a > 0, "first clone: {pid_a} ({route:?})");
        let a = ArmCaller::Child(pid_a as u32);
        // The harness admits one root fork; the second process is A's child.
        let (route, pid_b) = call(a, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid_b > 0, "A's clone: {pid_b} ({route:?})");
        let b = ArmCaller::Child(pid_b as u32);
        // B's first switch-in returns its clone.
        call(b, ARM_RESUME, [0; 6]);
        let expect = |what: &str, got: (CompletionRoute, i64), want: i64| {
            if got.1 != want {
                mismatches
                    .borrow_mut()
                    .push(format!("{what}: got {} ({:?}), want {want}", got.1, got.0));
            }
        };
        let open = |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64),
                    who: ArmCaller| {
            let (route, fd) = call(
                who,
                sys::OPENAT.raw(),
                [
                    LINUX_AT_FDCWD,
                    path.arg(),
                    LINUX_O_RDWR | LINUX_O_CREAT | LINUX_O_NOFOLLOW,
                    0o640,
                    0,
                    0,
                ],
            );
            assert!(fd >= 0, "{who:?} open of the lock file: {fd} ({route:?})");
            fd as u64
        };
        let flock = |l_type: i32| {
            GuestUserBuffer::from_value(LinuxFlock64 {
                l_type: l_type as i16,
                ..Default::default()
            })
        };
        let fcntl = sys::FCNTL.raw();
        let fd_a = open(call, a);
        let fd_b = open(call, b);
        let write = flock(LINUX_F_WRLCK);
        expect(
            "A F_SETLK write lock",
            call(a, fcntl, [fd_a, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
            0,
        );
        expect(
            "B F_SETLK against A",
            call(b, fcntl, [fd_b, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
            eagain,
        );
        let query = flock(LINUX_F_WRLCK);
        expect(
            "B F_GETLK",
            call(b, fcntl, [fd_b, LINUX_F_GETLK, query.arg(), 0, 0, 0]),
            0,
        );
        let reported = query.values::<LinuxFlock64>()[0];
        let (l_type, l_pid, l_len) = (reported.l_type, reported.l_pid, reported.l_len);
        if (i32::from(l_type), i64::from(l_pid), l_len) != (LINUX_F_WRLCK, pid_a, 0) {
            mismatches.borrow_mut().push(format!(
                "B F_GETLK reported type {l_type} pid {l_pid} len {l_len}, want A's whole-file write lock ({pid_a})"
            ));
        }
        // A close of another descriptor of the file releases A's lock.
        let other_a = open(call, a);
        expect(
            "A close of another fd of the file",
            call(a, sys::CLOSE.raw(), [other_a, 0, 0, 0, 0, 0]),
            0,
        );
        let query = flock(LINUX_F_WRLCK);
        call(b, fcntl, [fd_b, LINUX_F_GETLK, query.arg(), 0, 0, 0]);
        let after_close = query.values::<LinuxFlock64>()[0].l_type;
        if i32::from(after_close) != LINUX_F_UNLCK {
            mismatches.borrow_mut().push(format!(
                "F_GETLK after A's close reported type {after_close}, want F_UNLCK"
            ));
        }
        expect(
            "B F_SETLK after A's close",
            call(b, fcntl, [fd_b, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
            0,
        );
        // F_SETLKW parks A until B unlocks, then the rerun takes the lock.
        call(a, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(a, fcntl, [fd_a, LINUX_F_SETLKW, write.arg(), 0, 0, 0]);
        if parked.0 != CompletionRoute::Suspended {
            mismatches
                .borrow_mut()
                .push(format!("A F_SETLKW against B did not park: {parked:?}"));
        } else {
            let still = call(a, ARM_RESUME, [0; 6]);
            if still != (CompletionRoute::Suspended, 0) {
                mismatches
                    .borrow_mut()
                    .push(format!("A F_SETLKW woke with B's lock held: {still:?}"));
            }
            let unlock = flock(LINUX_F_UNLCK);
            expect(
                "B F_SETLK unlock",
                call(b, fcntl, [fd_b, LINUX_F_SETLK, unlock.arg(), 0, 0, 0]),
                0,
            );
            let woken = call(a, ARM_RESUME, [0; 6]);
            if woken.0 != CompletionRoute::Served {
                mismatches
                    .borrow_mut()
                    .push(format!("B's unlock did not wake A: {woken:?}"));
            }
            expect(
                "A F_SETLKW rerun",
                call(a, fcntl, [fd_a, LINUX_F_SETLKW, write.arg(), 0, 0, 0]),
                0,
            );
        }
        let read = flock(LINUX_F_RDLCK);
        expect(
            "B F_SETLK read lock against A's write lock",
            call(b, fcntl, [fd_b, LINUX_F_SETLK, read.arg(), 0, 0, 0]),
            eagain,
        );
        // flock(2) belongs to the open file description, apart from fcntl.
        let flock_nr = sys::FLOCK.raw();
        expect(
            "A flock LOCK_EX|LOCK_NB",
            call(
                a,
                flock_nr,
                [fd_a, LINUX_LOCK_EX | LINUX_LOCK_NB, 0, 0, 0, 0],
            ),
            0,
        );
        expect(
            "B flock LOCK_SH|LOCK_NB against A",
            call(
                b,
                flock_nr,
                [fd_b, LINUX_LOCK_SH | LINUX_LOCK_NB, 0, 0, 0, 0],
            ),
            eagain,
        );
        call(b, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(b, flock_nr, [fd_b, LINUX_LOCK_SH, 0, 0, 0, 0]);
        if parked.0 != CompletionRoute::Suspended {
            mismatches
                .borrow_mut()
                .push(format!("B blocking flock did not park: {parked:?}"));
        } else {
            expect(
                "A flock LOCK_UN",
                call(a, flock_nr, [fd_a, LINUX_LOCK_UN, 0, 0, 0, 0]),
                0,
            );
            let woken = call(b, ARM_RESUME, [0; 6]);
            if woken.0 != CompletionRoute::Served {
                mismatches
                    .borrow_mut()
                    .push(format!("A's LOCK_UN did not wake B: {woken:?}"));
            }
            expect(
                "B blocking flock rerun",
                call(b, flock_nr, [fd_b, LINUX_LOCK_SH, 0, 0, 0, 0]),
                0,
            );
        }
        // A's close of its only descriptor of the file releases its record
        // lock, and its description's last close its flock (the harness
        // runs no child exit: x86 witnesses the exit release).
        expect(
            "A flock LOCK_SH|LOCK_NB beside B's shared flock",
            call(
                a,
                flock_nr,
                [fd_a, LINUX_LOCK_SH | LINUX_LOCK_NB, 0, 0, 0, 0],
            ),
            0,
        );
        expect(
            "B flock LOCK_EX|LOCK_NB against A's shared flock",
            call(
                b,
                flock_nr,
                [fd_b, LINUX_LOCK_EX | LINUX_LOCK_NB, 0, 0, 0, 0],
            ),
            eagain,
        );
        expect(
            "A close of its lock descriptor",
            call(a, sys::CLOSE.raw(), [fd_a, 0, 0, 0, 0, 0]),
            0,
        );
        expect(
            "B F_SETLK after A's close",
            call(b, fcntl, [fd_b, LINUX_F_SETLK, write.arg(), 0, 0, 0]),
            0,
        );
        expect(
            "B flock LOCK_EX|LOCK_NB after A's last close",
            call(
                b,
                flock_nr,
                [fd_b, LINUX_LOCK_EX | LINUX_LOCK_NB, 0, 0, 0, 0],
            ),
            0,
        );
        mismatches.into_inner()
    });
    assert!(
        mismatches.is_empty(),
        "ring record locks and flock left Linux's contract:\n{}",
        mismatches.join("\n")
    );
}

/// #1671: Node's `child_process.execSync` aborted in libuv's `uv__io_poll`
/// (`assert(errno == EEXIST)`). The run root's `epoll_create1` is a ring
/// constructor, the child's stdio pipes are host `socketpair` ends, and the
/// ring forwards `epoll_ctl` of a host-backed member, to a host that had no
/// description for the ring's epoll: `EPOLL_CTL_ADD` returned -9 (EBADF).
/// The libuv spawn loop's shape: a ring signal pipe and a host socket in one
/// ring epoll, re-added (EEXIST, then MOD), waited on, deleted and closed.
#[test]
fn arm_root_ring_epoll_takes_a_host_socket_member() {
    use carrick_abi::{
        LINUX_AF_UNIX, LINUX_EEXIST, LINUX_ENOENT, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL,
        LINUX_EPOLL_CTL_MOD, LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_O_CLOEXEC, LINUX_O_NONBLOCK,
        LINUX_SOCK_CLOEXEC, LINUX_SOCK_DGRAM,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_syscall_abi::{LINUX_EBADF, LINUX_EINVAL};
    use carrick_test_support::GuestUserBuffer;

    const PIPE_COOKIE: u64 = 0x1671_0000_0000_0001;
    const SOCKET_COOKIE: u64 = 0x1671_0000_0000_0002;
    const WRITER_COOKIE: u64 = 0x1671_0000_0000_0003;
    // The aarch64 `struct epoll_event`: events, padding, data.
    let event = |events: u32, data: u64| {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&events.to_ne_bytes());
        bytes[8..].copy_from_slice(&data.to_ne_bytes());
        GuestUserBuffer::from_bytes(&bytes)
    };
    let pair_of = |buffer: &GuestUserBuffer| {
        let bytes = buffer.as_bytes();
        [
            i32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64,
            i32::from_ne_bytes(bytes[4..8].try_into().unwrap()) as u64,
        ]
    };
    let ((mismatches, reported), _) = with_arm_root_host_dispatch(|call_root| {
        let mut mismatches = Vec::new();
        let mut expect = |what: &str, got: i64, want: i64| {
            if got != want {
                mismatches.push(format!("{what}: got {got}, want {want}"));
            }
        };
        let ctl = sys::EPOLL_CTL.raw();
        let (route, epoll) = call_root(sys::EPOLL_CREATE1.raw(), [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0]);
        assert_eq!(
            route,
            CompletionRoute::Served,
            "the root's epoll_create1 is a ring constructor"
        );
        assert!(epoll >= 0, "epoll_create1: {epoll}");
        let epoll = epoll as u64;
        // A host member: an AF_UNIX datagram socketpair (uv_spawn's stream
        // pair is a ring object since #2361; a datagram pair stays the
        // host's).
        let sockets = GuestUserBuffer::zeroed(8);
        let (route, made) = call_root(
            sys::SOCKETPAIR.raw(),
            [
                LINUX_AF_UNIX as u64,
                (LINUX_SOCK_DGRAM | LINUX_SOCK_CLOEXEC) as u64,
                0,
                sockets.arg(),
                0,
                0,
            ],
        );
        assert_eq!((route, made), (CompletionRoute::Forward, 0), "socketpair");
        let [parent, child] = pair_of(&sockets);
        // The loop's signal pipe: a ring pipe.
        let pipe = GuestUserBuffer::zeroed(8);
        let (route, made) = call_root(
            sys::PIPE2.raw(),
            [pipe.arg(), LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
        assert_eq!((route, made), (CompletionRoute::Served, 0), "pipe2");
        let [reader, writer] = pair_of(&pipe);

        let pipe_in = event(LINUX_EPOLLIN, PIPE_COOKIE);
        let socket_in = event(LINUX_EPOLLIN, SOCKET_COOKIE);
        expect(
            "ADD the ring pipe",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, reader, pipe_in.arg(), 0, 0],
            )
            .1,
            0,
        );
        expect(
            "ADD the host socket",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            )
            .1,
            0,
        );
        // libuv's recovery path: ADD of a watched fd is EEXIST, then MOD.
        expect(
            "ADD the host socket again",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            )
            .1,
            LINUX_EEXIST.guest_retval(),
        );
        expect(
            "MOD the host socket",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_MOD, parent, socket_in.arg(), 0, 0],
            )
            .1,
            0,
        );
        // Zone members after the host half: the same record, the same set.
        expect(
            "ADD the ring pipe again",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, reader, pipe_in.arg(), 0, 0],
            )
            .1,
            LINUX_EEXIST.guest_retval(),
        );
        let writer_out = event(LINUX_EPOLLOUT, WRITER_COOKIE);
        expect(
            "ADD the ring pipe's writer",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, writer, writer_out.arg(), 0, 0],
            )
            .1,
            0,
        );

        let events = GuestUserBuffer::zeroed(16 * 4);
        let pwait = sys::EPOLL_PWAIT.raw();
        let mut reported = Vec::new();
        let mut harvest = |call_root: &mut dyn FnMut(u64, [u64; 6]) -> (CompletionRoute, i64)| {
            let (_, ready) = call_root(pwait, [epoll, events.arg(), 4, 0, 0, 8]);
            let cookies: Vec<u64> = (0..ready.max(0) as usize)
                .map(|n| {
                    u64::from_ne_bytes(
                        events.as_bytes()[n * 16 + 8..n * 16 + 16]
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect();
            reported.push((ready, cookies));
        };
        // The writer is ready from the start; then the child writes.
        harvest(&mut *call_root);
        let output = GuestUserBuffer::from_bytes(b"child-ok\n");
        expect(
            "child write",
            call_root(sys::WRITE.raw(), [child, output.arg(), 9, 0, 0, 0]).1,
            9,
        );
        harvest(&mut *call_root);

        expect(
            "DEL the host socket",
            call_root(ctl, [epoll, LINUX_EPOLL_CTL_DEL, parent, 0, 0, 0]).1,
            0,
        );
        expect(
            "DEL the host socket again",
            call_root(ctl, [epoll, LINUX_EPOLL_CTL_DEL, parent, 0, 0, 0]).1,
            LINUX_ENOENT.guest_retval(),
        );
        // A ring pipe is not an epoll: EINVAL, as Linux, not the host's EBADF.
        expect(
            "ADD to a ring pipe as the epoll",
            call_root(
                ctl,
                [reader, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            )
            .1,
            LINUX_EINVAL.guest_retval(),
        );
        expect(
            "close the epoll",
            call_root(sys::CLOSE.raw(), [epoll, 0, 0, 0, 0, 0]).1,
            0,
        );
        expect(
            "ADD to the closed epoll",
            call_root(
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            )
            .1,
            LINUX_EBADF.guest_retval(),
        );
        (mismatches, reported)
    });
    let mut mismatches = mismatches;
    let want = vec![
        (1, vec![WRITER_COOKIE]),
        (2, vec![SOCKET_COOKIE, WRITER_COOKIE]),
    ];
    let mut sorted = reported.clone();
    for (_, cookies) in &mut sorted {
        cookies.sort_unstable();
    }
    if sorted != want {
        mismatches.push(format!(
            "epoll_pwait reports: got {reported:x?}, want {want:x?}"
        ));
    }
    assert!(
        mismatches.is_empty(),
        "a ring epoll's host member left libuv's contract:\n{}",
        mismatches.join("\n")
    );
}

/// The aarch64 `struct epoll_event` (events, padding, data) and the fd
/// pair a `pipe2` or `socketpair` writes, for the #1671 spawn witnesses.
#[cfg(test)]
fn epoll_event_buffer(events: u32, data: u64) -> carrick_test_support::GuestUserBuffer {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&events.to_ne_bytes());
    bytes[8..].copy_from_slice(&data.to_ne_bytes());
    carrick_test_support::GuestUserBuffer::from_bytes(&bytes)
}

#[cfg(test)]
fn fd_pair_of(buffer: &carrick_test_support::GuestUserBuffer) -> [u64; 2] {
    let bytes = buffer.as_bytes();
    [
        i32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64,
        i32::from_ne_bytes(bytes[4..8].try_into().unwrap()) as u64,
    ]
}

/// The root's half of libuv's `uv_spawn` with a piped stdout: an AF_UNIX
/// stream `socketpair` (the child's end close-on-exec), then `fork`.
#[cfg(test)]
fn arm_root_spawn_socketpair(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
) -> [u64; 2] {
    arm_root_socketpair(call, carrick_abi::LINUX_SOCK_STREAM as u32)
}

/// A host-backed epoll member for the #2338 adoption witnesses: an AF_UNIX
/// datagram `socketpair`, which stays the host's (a stream pair is the
/// ring's since #2361).
#[cfg(test)]
fn arm_root_host_socketpair(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
) -> [u64; 2] {
    arm_root_socketpair(call, carrick_abi::LINUX_SOCK_DGRAM as u32)
}

#[cfg(test)]
fn arm_root_socketpair(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
    kind: u32,
) -> [u64; 2] {
    use carrick_abi::{LINUX_AF_UNIX, LINUX_SOCK_CLOEXEC};
    use carrick_personality_linux::crossing::nr as sys;
    let sockets = carrick_test_support::GuestUserBuffer::zeroed(8);
    let (_, made) = call(
        ArmCaller::Root,
        sys::SOCKETPAIR.raw(),
        [
            LINUX_AF_UNIX as u64,
            u64::from(kind | LINUX_SOCK_CLOEXEC as u32),
            0,
            sockets.arg(),
            0,
            0,
        ],
    );
    assert_eq!(made, 0, "socketpair");
    fd_pair_of(&sockets)
}

/// A zero-timeout `epoll_pwait` through `epfd`: its result and the cookies
/// it reported, for the #1671 alias witnesses.
#[cfg(test)]
fn arm_root_poll_now(
    call: &mut dyn FnMut(
        ArmCaller,
        u64,
        [u64; 6],
    ) -> (carrick_personality_linux::dispatch::CompletionRoute, i64),
    epfd: u64,
) -> (i64, Vec<u64>) {
    use carrick_personality_linux::crossing::nr as sys;
    let events = carrick_test_support::GuestUserBuffer::zeroed(16 * 4);
    let (_, ready) = call(
        ArmCaller::Root,
        sys::EPOLL_PWAIT.raw(),
        [epfd, events.arg(), 4, 0, 0, 8],
    );
    let cookies = (0..ready.clamp(0, 4) as usize)
        .map(|n| {
            u64::from_ne_bytes(
                events.as_bytes()[n * 16 + 8..n * 16 + 16]
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    (ready, cookies)
}

/// #1671 (#2338 review P0-1): an epoll's aliases made before the host took
/// its host half are the same open file description. Linux: a `dup` or
/// `F_DUPFD` copy names the one epoll, so a socket ADDed through the
/// original is MODed, waited for and DELeted through either copy, and the
/// epoll lives on while any copy is open, whichever closes first.
#[test]
fn arm_root_ring_epoll_aliases_share_one_host_half() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_EEXIST, LINUX_ENOENT, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD,
        LINUX_EPOLLIN, LINUX_F_DUPFD, LINUX_O_CLOEXEC,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    const SOCKET_COOKIE: u64 = 0x1671_0000_0000_00a1;
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mismatches = std::cell::RefCell::new(Vec::new());
        let expect = |what: &str, got: (CompletionRoute, i64), want: i64| {
            if got.1 != want {
                mismatches
                    .borrow_mut()
                    .push(format!("{what}: got {got:?}, want {want}"));
            }
        };
        let ctl = sys::EPOLL_CTL.raw();
        let (route, epoll) = call(
            Root,
            sys::EPOLL_CREATE1.raw(),
            [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0],
        );
        assert_eq!(route, CompletionRoute::Served, "a ring epoll");
        assert!(epoll >= 0, "epoll_create1: {epoll}");
        let epoll = epoll as u64;
        // Both copies exist before any host member: the ring's own OFD.
        let (_, alias) = call(Root, sys::DUP.raw(), [epoll, 0, 0, 0, 0, 0]);
        assert!(alias >= 0, "dup: {alias}");
        let alias = alias as u64;
        let (_, high) = call(Root, sys::FCNTL.raw(), [epoll, LINUX_F_DUPFD, 20, 0, 0, 0]);
        assert!(high >= 20, "F_DUPFD: {high}");
        let high = high as u64;
        let [parent, child] = arm_root_host_socketpair(call);
        let socket_in = epoll_event_buffer(LINUX_EPOLLIN, SOCKET_COOKIE);

        expect(
            "ADD the host socket through the original",
            call(
                Root,
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            ),
            0,
        );
        let (ready, _) = arm_root_poll_now(call, alias);
        expect(
            "zero-timeout wait through the dup",
            (CompletionRoute::Forward, ready),
            0,
        );
        expect(
            "MOD the socket through the dup",
            call(
                Root,
                ctl,
                [alias, LINUX_EPOLL_CTL_MOD, parent, socket_in.arg(), 0, 0],
            ),
            0,
        );
        expect(
            "MOD the socket through the F_DUPFD copy",
            call(
                Root,
                ctl,
                [high, LINUX_EPOLL_CTL_MOD, parent, socket_in.arg(), 0, 0],
            ),
            0,
        );
        expect(
            "ADD the socket again through the dup",
            call(
                Root,
                ctl,
                [alias, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            ),
            LINUX_EEXIST.guest_retval(),
        );
        let output = GuestUserBuffer::from_bytes(b"child-ok\n");
        expect(
            "the child's end writes",
            call(Root, sys::WRITE.raw(), [child, output.arg(), 9, 0, 0, 0]),
            9,
        );
        expect(
            "close the original",
            call(Root, sys::CLOSE.raw(), [epoll, 0, 0, 0, 0, 0]),
            0,
        );
        let got = arm_root_poll_now(call, alias);
        if got != (1, vec![SOCKET_COOKIE]) {
            mismatches.borrow_mut().push(format!(
                "wait through the dup after the original closed: got {got:x?}"
            ));
        }
        expect(
            "close the dup",
            call(Root, sys::CLOSE.raw(), [alias, 0, 0, 0, 0, 0]),
            0,
        );
        let got = arm_root_poll_now(call, high);
        if got != (1, vec![SOCKET_COOKIE]) {
            mismatches
                .borrow_mut()
                .push(format!("wait through the last copy: got {got:x?}"));
        }
        expect(
            "DEL the socket through the last copy",
            call(Root, ctl, [high, LINUX_EPOLL_CTL_DEL, parent, 0, 0, 0]),
            0,
        );
        expect(
            "DEL the socket again",
            call(Root, ctl, [high, LINUX_EPOLL_CTL_DEL, parent, 0, 0, 0]),
            LINUX_ENOENT.guest_retval(),
        );
        mismatches.into_inner()
    });
    assert!(
        mismatches.is_empty(),
        "an epoll's copies left Linux's one-description contract:\n{}",
        mismatches.join("\n")
    );
}

/// #1671 (#2338 review P0-2): contention is never an errno. A sibling's
/// exact claim on the epoll's slot (a `dup2` onto it, mid-flight in the
/// host) is held while the root ADDs a socket through that slot. Linux
/// orders the two calls; neither fails because the other is running. The
/// ADD lands on the one host half (the dup sees it), and once the claim is
/// released the slot reaches that same host half.
#[test]
fn arm_root_ring_epoll_adoption_beside_a_sibling_exact_claim() {
    use ArmCaller::Root;
    use carrick_abi::{LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLIN, LINUX_O_CLOEXEC};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    const SOCKET_COOKIE: u64 = 0x1671_0000_0000_00b1;
    let (mismatches, _) = with_arm_process_host_files(|call, files| {
        let mut mismatches = Vec::new();
        let mut expect = |what: &str, got: (CompletionRoute, i64), want: i64| {
            if got.1 != want {
                mismatches.push(format!("{what}: got {got:?}, want {want}"));
            }
        };
        let ctl = sys::EPOLL_CTL.raw();
        let (_, epoll) = call(
            Root,
            sys::EPOLL_CREATE1.raw(),
            [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0],
        );
        assert!(epoll >= 0, "epoll_create1: {epoll}");
        let epoll = epoll as u64;
        let (_, alias) = call(Root, sys::DUP.raw(), [epoll, 0, 0, 0, 0, 0]);
        assert!(alias >= 0, "dup: {alias}");
        let alias = alias as u64;
        let [parent, child] = arm_root_host_socketpair(call);
        let socket_in = epoll_event_buffer(LINUX_EPOLLIN, SOCKET_COOKIE);

        let claim = files
            .reserve_exact_target(epoll as i32, 1024)
            .expect("the sibling's exact claim");
        expect(
            "ADD the host socket while a sibling claims the epoll's slot",
            call(
                Root,
                ctl,
                [epoll, LINUX_EPOLL_CTL_ADD, parent, socket_in.arg(), 0, 0],
            ),
            0,
        );
        expect(
            "MOD the socket through the dup",
            call(
                Root,
                ctl,
                [alias, LINUX_EPOLL_CTL_MOD, parent, socket_in.arg(), 0, 0],
            ),
            0,
        );
        // The sibling's dup2 fails late and releases its claim.
        drop(claim);
        let output = GuestUserBuffer::from_bytes(b"child-ok\n");
        expect(
            "the child's end writes",
            call(Root, sys::WRITE.raw(), [child, output.arg(), 9, 0, 0, 0]),
            9,
        );
        for (what, epfd) in [("the claimed slot", epoll), ("the dup", alias)] {
            let got = arm_root_poll_now(call, epfd);
            if got != (1, vec![SOCKET_COOKIE]) {
                mismatches.push(format!("wait through {what}: got {got:x?}"));
            }
        }
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "a sibling's slot claim surfaced as the guest's errno:\n{}",
        mismatches.join("\n")
    );
}

/// #1671 round 2: after #2338's host half, `execSync('echo child-ok')`
/// exits 1 with empty stdout and stderr. libuv gives the child the far end
/// of a host AF_UNIX `socketpair` as fd 1; `/bin/sh`'s `echo` writes it, and
/// the native host-file venue refuses a write to a socket description
/// (`write_description_from_carrier` serves files only), so the child sees
/// ENOSYS on its stdout and its stderr, and exits 1.
// A ring child's IPC transfer needs its metadata in the EL1 window, which
// macOS refuses (see `serial_host_native_fork_two_children_...`): Linux runs it.
#[cfg(not(target_os = "macos"))]
#[test]
fn arm_root_fork_child_writes_its_socket_stdout() {
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mut mismatches = Vec::new();
        let [parent, child_end] = arm_root_spawn_socketpair(call);
        let (route, pid) = call(ArmCaller::Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        let (_, moved) = call(child, sys::DUP3.raw(), [child_end, 1, 0, 0, 0, 0]);
        assert_eq!(moved, 1, "child dup3(socket, 1)");
        let output = GuestUserBuffer::from_bytes(b"child-ok\n");
        let (route, wrote) = call(child, sys::WRITE.raw(), [1, output.arg(), 9, 0, 0, 0]);
        if wrote != 9 {
            mismatches.push(format!(
                "child write(1) to its socket: got {wrote} ({route:?}), want 9"
            ));
        }
        let got = GuestUserBuffer::zeroed(16);
        let (_, n) = call(
            ArmCaller::Root,
            sys::READ.raw(),
            [parent, got.arg(), 16, 0, 0, 0],
        );
        let read = got.as_bytes()[..n.clamp(0, 16) as usize].to_vec();
        if read != b"child-ok\n" {
            let n = if n == ARM_HOST_WAITS {
                "would wait".into()
            } else {
                n.to_string()
            };
            mismatches.push(format!(
                "parent read of the child's output: got {n} {:?}",
                String::from_utf8_lossy(&read)
            ));
        }
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "the child's stdout socket left Linux's contract:\n{}",
        mismatches.join("\n")
    );
}

/// The calls of the #2361 witnesses, each checked: a mismatch reports
/// every broken rule at once instead of the first.
#[cfg(test)]
struct ArmExpect(std::cell::RefCell<Vec<String>>);

#[cfg(test)]
impl ArmExpect {
    fn new() -> Self {
        Self(std::cell::RefCell::new(Vec::new()))
    }
    fn result(
        &self,
        what: &str,
        got: (carrick_personality_linux::dispatch::CompletionRoute, i64),
        want: i64,
    ) {
        if got.1 != want {
            self.0
                .borrow_mut()
                .push(format!("{what}: got {} ({:?}), want {want}", got.1, got.0));
        }
    }
    /// `got` must be `want`, answered in ring (never a host forward). A
    /// run root's descriptor calls complete with host bookkeeping owed
    /// (`WithWork`), as its ring pipe's do.
    fn served(
        &self,
        what: &str,
        got: (carrick_personality_linux::dispatch::CompletionRoute, i64),
        want: i64,
    ) {
        use carrick_personality_linux::dispatch::CompletionRoute;
        if !matches!(got.0, CompletionRoute::Served | CompletionRoute::WithWork) || got.1 != want {
            self.0.borrow_mut().push(format!(
                "{what}: got {} ({:?}), want {want} served in ring",
                got.1, got.0
            ));
        }
    }
    fn bytes(&self, what: &str, got: &[u8], want: &[u8]) {
        if got != want {
            self.0.borrow_mut().push(format!(
                "{what}: got {:?}, want {:?}",
                String::from_utf8_lossy(got),
                String::from_utf8_lossy(want)
            ));
        }
    }
    fn assert_empty(self, contract: &str) {
        let mismatches = self.0.into_inner();
        assert!(
            mismatches.is_empty(),
            "{contract}:\n{}",
            mismatches.join("\n")
        );
    }
}

/// #2361: `socketpair(AF_UNIX, SOCK_STREAM)` is a ring object. The run
/// root's pair is served in ring: two descriptors, bytes both ways, the
/// socket's metadata (`fstat` S_IFSOCK, `getsockopt` type and domain,
/// unnamed `getsockname`/`getpeername`), and EOF and EPIPE once the peer
/// closes. Nothing reaches the host: a host socket would be unreachable
/// from the root's ring children (#2361).
#[test]
fn arm_root_socketpair_is_a_ring_stream_pair() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_AF_UNIX, LINUX_EPIPE, LINUX_ESPIPE, LINUX_F_GETFD, LINUX_F_GETFL, LINUX_FD_CLOEXEC,
        LINUX_FIONREAD, LINUX_O_RDWR, LINUX_SO_DOMAIN, LINUX_SO_ERROR, LINUX_SO_PROTOCOL,
        LINUX_SO_TYPE, LINUX_SOCK_CLOEXEC, LINUX_SOCK_STREAM, LINUX_SOL_SOCKET,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let sockets = GuestUserBuffer::zeroed(8);
        expect.served(
            "socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC)",
            call(
                Root,
                sys::SOCKETPAIR.raw(),
                [
                    LINUX_AF_UNIX as u64,
                    (LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC) as u64,
                    0,
                    sockets.arg(),
                    0,
                    0,
                ],
            ),
            0,
        );
        let [first, second] = fd_pair_of(&sockets);
        assert_ne!(first, second, "two descriptors");
        for (what, from, to, bytes) in [
            ("first to second", first, second, &b"ping"[..]),
            ("second to first", second, first, &b"pong!"[..]),
        ] {
            let out = GuestUserBuffer::from_bytes(bytes);
            expect.served(
                &format!("write {what}"),
                call(
                    Root,
                    sys::WRITE.raw(),
                    [from, out.arg(), bytes.len() as u64, 0, 0, 0],
                ),
                bytes.len() as i64,
            );
            let count = GuestUserBuffer::zeroed(4);
            expect.served(
                &format!("FIONREAD {what}"),
                call(
                    Root,
                    sys::IOCTL.raw(),
                    [to, LINUX_FIONREAD, count.arg(), 0, 0, 0],
                ),
                0,
            );
            expect.bytes(
                &format!("FIONREAD count {what}"),
                count.as_bytes(),
                &(bytes.len() as i32).to_ne_bytes(),
            );
            let got = GuestUserBuffer::zeroed(16);
            let read = call(Root, sys::READ.raw(), [to, got.arg(), 16, 0, 0, 0]);
            expect.served(&format!("read {what}"), read, bytes.len() as i64);
            expect.bytes(
                &format!("bytes {what}"),
                &got.as_bytes()[..read.1.clamp(0, 16) as usize],
                bytes,
            );
        }
        expect.served(
            "F_GETFL",
            call(Root, sys::FCNTL.raw(), [first, LINUX_F_GETFL, 0, 0, 0, 0]),
            LINUX_O_RDWR as i64,
        );
        expect.served(
            "F_GETFD",
            call(Root, sys::FCNTL.raw(), [first, LINUX_F_GETFD, 0, 0, 0, 0]),
            LINUX_FD_CLOEXEC as i64,
        );
        let stat = GuestUserBuffer::zeroed(128);
        expect.served(
            "fstat",
            call(Root, sys::FSTAT.raw(), [first, stat.arg(), 0, 0, 0, 0]),
            0,
        );
        let mode = u32::from_ne_bytes(stat.as_bytes()[16..20].try_into().unwrap());
        if mode & 0o170000 != carrick_syscall_abi::LINUX_S_IFSOCK {
            expect
                .0
                .borrow_mut()
                .push(format!("fstat st_mode: {mode:o}"));
        }
        expect.served(
            "lseek",
            call(Root, sys::LSEEK.raw(), [first, 0, 0, 0, 0, 0]),
            LINUX_ESPIPE.guest_retval(),
        );
        for (what, option, want) in [
            ("SO_TYPE", LINUX_SO_TYPE, LINUX_SOCK_STREAM),
            ("SO_DOMAIN", LINUX_SO_DOMAIN, LINUX_AF_UNIX),
            ("SO_PROTOCOL", LINUX_SO_PROTOCOL, 0),
            ("SO_ERROR", LINUX_SO_ERROR, 0),
        ] {
            let value = GuestUserBuffer::zeroed(4);
            let len = GuestUserBuffer::from_value(4u32);
            expect.served(
                &format!("getsockopt({what})"),
                call(
                    Root,
                    sys::GETSOCKOPT.raw(),
                    [
                        second,
                        LINUX_SOL_SOCKET as u64,
                        option as u64,
                        value.arg(),
                        len.arg(),
                        0,
                    ],
                ),
                0,
            );
            expect.bytes(
                &format!("getsockopt({what}) value"),
                value.as_bytes(),
                &want.to_ne_bytes(),
            );
        }
        for (what, nr) in [
            ("getsockname", sys::GETSOCKNAME),
            ("getpeername", sys::GETPEERNAME),
        ] {
            let address = GuestUserBuffer::from_bytes(&[0xa5; 16]);
            let len = GuestUserBuffer::from_value(16u32);
            expect.served(
                what,
                call(Root, nr.raw(), [first, address.arg(), len.arg(), 0, 0, 0]),
                0,
            );
            // An unnamed socket: just its family, `sizeof(sa_family_t)`.
            expect.bytes(
                &format!("{what} length"),
                len.as_bytes(),
                &2u32.to_ne_bytes(),
            );
            expect.bytes(
                &format!("{what} family"),
                &address.as_bytes()[..2],
                &(LINUX_AF_UNIX as u16).to_ne_bytes(),
            );
        }
        expect.served(
            "close the second end",
            call(Root, sys::CLOSE.raw(), [second, 0, 0, 0, 0, 0]),
            0,
        );
        let got = GuestUserBuffer::zeroed(4);
        expect.served(
            "read after the peer closed (EOF)",
            call(Root, sys::READ.raw(), [first, got.arg(), 4, 0, 0, 0]),
            0,
        );
        let late = GuestUserBuffer::from_bytes(b"late");
        expect.result(
            "write after the peer closed (EPIPE)",
            call(Root, sys::WRITE.raw(), [first, late.arg(), 4, 0, 0, 0]),
            LINUX_EPIPE.guest_retval(),
        );
        expect.served(
            "close the first end",
            call(Root, sys::CLOSE.raw(), [first, 0, 0, 0, 0, 0]),
            0,
        );
        expect
    });
    expect.assert_empty("a ring AF_UNIX stream pair left Linux's contract");
}

/// #2361: SOCK_NONBLOCK sets the pair's status flag (an empty read is
/// EAGAIN, as libuv's loop expects); FIONBIO changes it, as libuv's
/// `uv__nonblock` does; `shutdown(SHUT_WR)` gives the peer EOF after the
/// bytes already sent and this end EPIPE; FIONREAD counts unread bytes.
#[test]
fn arm_root_socketpair_nonblock_and_shutdown() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_AF_UNIX, LINUX_EAGAIN, LINUX_EINVAL, LINUX_EPIPE, LINUX_F_GETFL, LINUX_FIONBIO,
        LINUX_O_NONBLOCK, LINUX_O_RDWR, LINUX_SHUT_WR, LINUX_SOCK_CLOEXEC, LINUX_SOCK_NONBLOCK,
        LINUX_SOCK_STREAM,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let sockets = GuestUserBuffer::zeroed(8);
        expect.served(
            "socketpair(SOCK_NONBLOCK)",
            call(
                Root,
                sys::SOCKETPAIR.raw(),
                [
                    LINUX_AF_UNIX as u64,
                    (LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC) as u64,
                    0,
                    sockets.arg(),
                    0,
                    0,
                ],
            ),
            0,
        );
        let [first, second] = fd_pair_of(&sockets);
        let got = GuestUserBuffer::zeroed(16);
        expect.served(
            "empty nonblocking read",
            call(Root, sys::READ.raw(), [first, got.arg(), 16, 0, 0, 0]),
            LINUX_EAGAIN.guest_retval(),
        );
        expect.served(
            "F_GETFL",
            call(Root, sys::FCNTL.raw(), [first, LINUX_F_GETFL, 0, 0, 0, 0]),
            (LINUX_O_RDWR | LINUX_O_NONBLOCK) as i64,
        );
        let off = GuestUserBuffer::from_value(0i32);
        expect.served(
            "FIONBIO 0",
            call(
                Root,
                sys::IOCTL.raw(),
                [second, LINUX_FIONBIO, off.arg(), 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "F_GETFL after FIONBIO 0",
            call(Root, sys::FCNTL.raw(), [second, LINUX_F_GETFL, 0, 0, 0, 0]),
            LINUX_O_RDWR as i64,
        );
        let out = GuestUserBuffer::from_bytes(b"tail");
        expect.served(
            "write before shutdown",
            call(Root, sys::WRITE.raw(), [second, out.arg(), 4, 0, 0, 0]),
            4,
        );
        expect.served(
            "shutdown(SHUT_WR)",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [second, LINUX_SHUT_WR as u64, 0, 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "shutdown(how = 3)",
            call(Root, sys::SHUTDOWN.raw(), [second, 3, 0, 0, 0, 0]),
            LINUX_EINVAL.guest_retval(),
        );
        let read = call(Root, sys::READ.raw(), [first, got.arg(), 16, 0, 0, 0]);
        expect.served("read the bytes sent before shutdown", read, 4);
        expect.bytes("bytes", &got.as_bytes()[..4], b"tail");
        expect.served(
            "read after the peer's SHUT_WR (EOF)",
            call(Root, sys::READ.raw(), [first, got.arg(), 16, 0, 0, 0]),
            0,
        );
        expect.result(
            "write after this end's SHUT_WR (EPIPE)",
            call(Root, sys::WRITE.raw(), [second, out.arg(), 4, 0, 0, 0]),
            LINUX_EPIPE.guest_retval(),
        );
        let back = GuestUserBuffer::from_bytes(b"back");
        expect.served(
            "the other direction still flows",
            call(Root, sys::WRITE.raw(), [first, back.arg(), 4, 0, 0, 0]),
            4,
        );
        expect.served(
            "read the other direction",
            call(Root, sys::READ.raw(), [second, got.arg(), 16, 0, 0, 0]),
            4,
        );
        for fd in [first, second] {
            expect.served(
                "close",
                call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }
        expect
    });
    expect.assert_empty("a ring stream pair's flags and shutdown left Linux's contract");
}

/// #2361 on #2401's ring-wide FIOCLEX/FIONCLEX: a ring stream end is a ring
/// description like any other, so `ioctl(FIOCLEX)` and `ioctl(FIONCLEX)` set
/// and clear its descriptor's close-on-exec flag in ring (the one writer,
/// `set_owned_cloexec`), and leave the peer end's flag alone.
#[test]
fn arm_root_socketpair_end_fioclex_sets_and_clears_cloexec() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_AF_UNIX, LINUX_F_GETFD, LINUX_FD_CLOEXEC, LINUX_FIOCLEX, LINUX_FIONCLEX,
        LINUX_SOCK_STREAM,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let sockets = GuestUserBuffer::zeroed(8);
        expect.served(
            "socketpair without SOCK_CLOEXEC",
            call(
                Root,
                sys::SOCKETPAIR.raw(),
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64,
                    0,
                    sockets.arg(),
                    0,
                    0,
                ],
            ),
            0,
        );
        let [first, second] = fd_pair_of(&sockets);
        let (ioctl, fcntl) = (sys::IOCTL.raw(), sys::FCNTL.raw());
        expect.served(
            "F_GETFD before FIOCLEX",
            call(Root, fcntl, [first, LINUX_F_GETFD, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "FIOCLEX",
            call(Root, ioctl, [first, LINUX_FIOCLEX, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "F_GETFD after FIOCLEX",
            call(Root, fcntl, [first, LINUX_F_GETFD, 0, 0, 0, 0]),
            LINUX_FD_CLOEXEC as i64,
        );
        expect.served(
            "the peer end's F_GETFD",
            call(Root, fcntl, [second, LINUX_F_GETFD, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "FIONCLEX",
            call(Root, ioctl, [first, LINUX_FIONCLEX, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "F_GETFD after FIONCLEX",
            call(Root, fcntl, [first, LINUX_F_GETFD, 0, 0, 0, 0]),
            0,
        );
        for fd in [first, second] {
            expect.served(
                "close",
                call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }
        expect
    });
    expect.assert_empty("FIOCLEX/FIONCLEX on a ring stream end left Linux's contract");
}

/// #2361: libuv's spawn loop on a ring stream pair: both ends ADD to the
/// root's ring epoll as pure ring members (no host adoption; a second ADD
/// is EEXIST, libuv's `uv__io_poll` assertion), report
/// EPOLLIN once the peer writes and EPOLLRDHUP once it shuts its writes,
/// and DEL like any member.
#[test]
fn arm_root_socketpair_ends_are_ring_epoll_members() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_EEXIST, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLLIN, LINUX_EPOLLRDHUP,
        LINUX_O_CLOEXEC, LINUX_SHUT_WR,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    const PARENT_COOKIE: u64 = 0x2361_0000_0000_0001;
    const CHILD_COOKIE: u64 = 0x2361_0000_0000_0002;
    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let (_, epoll) = call(
            Root,
            sys::EPOLL_CREATE1.raw(),
            [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0],
        );
        assert!(epoll >= 0, "epoll_create1: {epoll}");
        let epoll = epoll as u64;
        let [parent, child] = arm_root_spawn_socketpair(call);
        let ctl = sys::EPOLL_CTL.raw();
        let watch = LINUX_EPOLLIN | LINUX_EPOLLRDHUP;
        let parent_in = epoll_event_buffer(watch, PARENT_COOKIE);
        let child_in = epoll_event_buffer(watch, CHILD_COOKIE);
        for (what, fd, event) in [("parent", parent, &parent_in), ("child", child, &child_in)] {
            expect.served(
                &format!("ADD the {what} end"),
                call(
                    Root,
                    ctl,
                    [epoll, LINUX_EPOLL_CTL_ADD, fd, event.arg(), 0, 0],
                ),
                0,
            );
        }
        // libuv's `uv__io_poll` asserts `errno == EEXIST` on a re-ADD: a ring
        // member is present to the ring epoll, with no host adoption.
        for (what, fd, event) in [("parent", parent, &parent_in), ("child", child, &child_in)] {
            expect.served(
                &format!("a second ADD of the {what} end"),
                call(
                    Root,
                    ctl,
                    [epoll, LINUX_EPOLL_CTL_ADD, fd, event.arg(), 0, 0],
                ),
                LINUX_EEXIST.guest_retval(),
            );
        }
        let got = arm_root_poll_now(call, epoll);
        if got != (0, vec![]) {
            expect
                .0
                .borrow_mut()
                .push(format!("wait before any write: got {got:x?}"));
        }
        let output = GuestUserBuffer::from_bytes(b"child-ok\n");
        expect.served(
            "the child's end writes",
            call(Root, sys::WRITE.raw(), [child, output.arg(), 9, 0, 0, 0]),
            9,
        );
        let got = arm_root_poll_now(call, epoll);
        if got != (1, vec![PARENT_COOKIE]) {
            expect
                .0
                .borrow_mut()
                .push(format!("wait after the child's write: got {got:x?}"));
        }
        let events = GuestUserBuffer::zeroed(16 * 4);
        expect.served(
            "the wait is the ring's",
            call(
                Root,
                sys::EPOLL_PWAIT.raw(),
                [epoll, events.arg(), 4, 0, 0, 8],
            ),
            1,
        );
        expect.served(
            "the child's end shuts its writes",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [child, LINUX_SHUT_WR as u64, 0, 0, 0, 0],
            ),
            0,
        );
        let got = GuestUserBuffer::zeroed(16);
        expect.served(
            "the parent drains",
            call(Root, sys::READ.raw(), [parent, got.arg(), 16, 0, 0, 0]),
            9,
        );
        expect.served(
            "the wait reports the peer's shutdown",
            call(
                Root,
                sys::EPOLL_PWAIT.raw(),
                [epoll, events.arg(), 4, 0, 0, 8],
            ),
            1,
        );
        let reported = u32::from_ne_bytes(events.as_bytes()[..4].try_into().unwrap());
        let cookie = u64::from_ne_bytes(events.as_bytes()[8..16].try_into().unwrap());
        if (reported, cookie) != (watch, PARENT_COOKIE) {
            expect.0.borrow_mut().push(format!(
                "after the peer's SHUT_WR: got {reported:#x} for {cookie:#x}, want IN|RDHUP for the parent"
            ));
        }
        for (what, fd) in [("parent", parent), ("child", child)] {
            expect.served(
                &format!("DEL the {what} end"),
                call(Root, ctl, [epoll, LINUX_EPOLL_CTL_DEL, fd, 0, 0, 0]),
                0,
            );
        }
        expect
    });
    expect.assert_empty("a ring stream pair left the ring epoll's member contract");
}

/// #2361: `send`/`recv` without addresses are a ring stream end's write
/// and read, with `MSG_DONTWAIT`, `MSG_PEEK` and `MSG_NOSIGNAL`; an
/// unnamed peer's source address has length 0; a destination on a
/// connected stream is EISCONN. A connected pair cannot listen, accept or
/// connect again (EINVAL, EINVAL, EISCONN). What the ring does not carry
/// is refused in ring, never forwarded: ancillary-data calls (`sendmsg`,
/// `recvmsg`) and binding a path are EOPNOTSUPP, socket options
/// ENOPROTOOPT; and a ring pipe is no socket (ENOTSOCK).
#[test]
fn arm_root_socketpair_send_recv_and_refusals() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_EAGAIN, LINUX_EINVAL, LINUX_EISCONN, LINUX_ENOPROTOOPT, LINUX_ENOTSOCK, LINUX_EPIPE,
        LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_MSG_PEEK, LINUX_SO_SNDBUF, LINUX_SOL_SOCKET,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_syscall_abi::LINUX_EOPNOTSUPP;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let [first, second] = arm_root_spawn_socketpair(call);
        let got = GuestUserBuffer::zeroed(16);
        expect.served(
            "recv(MSG_DONTWAIT) of an empty end",
            call(
                Root,
                sys::RECVFROM.raw(),
                [first, got.arg(), 16, LINUX_MSG_DONTWAIT as u64, 0, 0],
            ),
            LINUX_EAGAIN.guest_retval(),
        );
        let out = GuestUserBuffer::from_bytes(b"send");
        expect.served(
            "send",
            call(Root, sys::SENDTO.raw(), [second, out.arg(), 4, 0, 0, 0]),
            4,
        );
        expect.served(
            "recv(MSG_PEEK)",
            call(
                Root,
                sys::RECVFROM.raw(),
                [first, got.arg(), 16, LINUX_MSG_PEEK as u64, 0, 0],
            ),
            4,
        );
        let source = GuestUserBuffer::from_bytes(&[0xa5; 16]);
        let source_len = GuestUserBuffer::from_value(16u32);
        expect.served(
            "recvfrom with a source address",
            call(
                Root,
                sys::RECVFROM.raw(),
                [first, got.arg(), 16, 0, source.arg(), source_len.arg()],
            ),
            4,
        );
        expect.bytes("received", &got.as_bytes()[..4], b"send");
        expect.bytes(
            "an unnamed peer's address length",
            source_len.as_bytes(),
            &0u32.to_ne_bytes(),
        );
        let destination = GuestUserBuffer::from_bytes(&[1, 0, b'x', 0]);
        expect.served(
            "sendto a destination on a connected stream",
            call(
                Root,
                sys::SENDTO.raw(),
                [second, out.arg(), 4, 0, destination.arg(), 4],
            ),
            LINUX_EISCONN.guest_retval(),
        );
        let header = GuestUserBuffer::zeroed(56);
        for (what, nr) in [("sendmsg", sys::SENDMSG), ("recvmsg", sys::RECVMSG)] {
            expect.served(
                what,
                call(Root, nr.raw(), [first, header.arg(), 0, 0, 0, 0]),
                LINUX_EOPNOTSUPP.guest_retval(),
            );
        }
        expect.served(
            "bind",
            call(
                Root,
                sys::BIND.raw(),
                [first, destination.arg(), 4, 0, 0, 0],
            ),
            LINUX_EOPNOTSUPP.guest_retval(),
        );
        expect.served(
            "listen",
            call(Root, sys::LISTEN.raw(), [first, 1, 0, 0, 0, 0]),
            LINUX_EINVAL.guest_retval(),
        );
        expect.served(
            "accept4",
            call(Root, sys::ACCEPT4.raw(), [first, 0, 0, 0, 0, 0]),
            LINUX_EINVAL.guest_retval(),
        );
        expect.served(
            "connect",
            call(
                Root,
                sys::CONNECT.raw(),
                [first, destination.arg(), 4, 0, 0, 0],
            ),
            LINUX_EISCONN.guest_retval(),
        );
        let value = GuestUserBuffer::from_value(1i32);
        expect.served(
            "setsockopt",
            call(
                Root,
                sys::SETSOCKOPT.raw(),
                [
                    first,
                    LINUX_SOL_SOCKET as u64,
                    LINUX_SO_SNDBUF as u64,
                    value.arg(),
                    4,
                    0,
                ],
            ),
            LINUX_ENOPROTOOPT.guest_retval(),
        );
        let pipe = GuestUserBuffer::zeroed(8);
        let (_, made) = call(Root, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]);
        assert_eq!(made, 0, "pipe2");
        let [_, writer] = fd_pair_of(&pipe);
        expect.served(
            "send on a ring pipe",
            call(Root, sys::SENDTO.raw(), [writer, out.arg(), 4, 0, 0, 0]),
            LINUX_ENOTSOCK.guest_retval(),
        );
        expect.served(
            "close the first end",
            call(Root, sys::CLOSE.raw(), [first, 0, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "send(MSG_NOSIGNAL) after the peer closed",
            call(
                Root,
                sys::SENDTO.raw(),
                [second, out.arg(), 4, LINUX_MSG_NOSIGNAL as u64, 0, 0],
            ),
            LINUX_EPIPE.guest_retval(),
        );
        expect
    });
    expect.assert_empty("a ring stream end's send, receive and refusals left Linux's contract");
}

/// #2385 review P0-1: MSG_WAITALL stops at a terminal receive state. Once
/// this end has shut its reads (shutdown(2) SHUT_RD), what the peer sent
/// before stays readable, and a WAITALL read returns that prefix at once
/// rather than waiting for bytes no write may add: native Linux returns 3
/// and "abc" for a 6-byte WAITALL read, then 0. A read of the empty
/// shut end is 0 too, never a wait.
#[test]
fn arm_root_socketpair_waitall_after_shut_rd_returns_buffered_prefix() {
    use ArmCaller::Root;
    use carrick_abi::{LINUX_MSG_WAITALL, LINUX_SHUT_RD};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let [first, second] = arm_root_spawn_socketpair(call);
        let out = GuestUserBuffer::from_bytes(b"abc");
        expect.served(
            "the peer writes",
            call(Root, sys::WRITE.raw(), [second, out.arg(), 3, 0, 0, 0]),
            3,
        );
        expect.served(
            "shutdown(SHUT_RD)",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [first, LINUX_SHUT_RD as u64, 0, 0, 0, 0],
            ),
            0,
        );
        let got = GuestUserBuffer::zeroed(6);
        let waitall = [first, got.arg(), 6, LINUX_MSG_WAITALL as u64, 0, 0];
        let read = call(Root, sys::RECVFROM.raw(), waitall);
        expect.served("recv(MSG_WAITALL) after SHUT_RD", read, 3);
        expect.bytes(
            "the buffered prefix",
            &got.as_bytes()[..read.1.clamp(0, 6) as usize],
            b"abc",
        );
        expect.served(
            "recv(MSG_WAITALL) of the drained shut end",
            call(Root, sys::RECVFROM.raw(), waitall),
            0,
        );
        expect.served(
            "read of the drained shut end",
            call(Root, sys::READ.raw(), [first, got.arg(), 6, 0, 0, 0]),
            0,
        );
        for fd in [first, second] {
            expect.served(
                "close",
                call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }
        expect
    });
    expect.assert_empty("MSG_WAITALL after SHUT_RD left Linux's contract");
}

/// #2385 review P0-1, the sibling terminal states of a stream read: a
/// MSG_WAITALL read returns the delivered prefix once the peer has closed
/// or shut its writes (EOF follows), and a WAITALL read of an empty end
/// that shut its reads is 0 at once. Native Linux: 3, 0; 3, 0; 0.
#[test]
fn arm_root_socketpair_waitall_stops_at_eof_and_empty_shut_rd() {
    use ArmCaller::Root;
    use carrick_abi::{LINUX_MSG_WAITALL, LINUX_SHUT_RD, LINUX_SHUT_WR};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let got = GuestUserBuffer::zeroed(6);
        let out = GuestUserBuffer::from_bytes(b"abc");
        for (what, close_peer) in [("the peer closed", true), ("the peer's SHUT_WR", false)] {
            let [first, second] = arm_root_spawn_socketpair(call);
            expect.served(
                &format!("the peer writes ({what})"),
                call(Root, sys::WRITE.raw(), [second, out.arg(), 3, 0, 0, 0]),
                3,
            );
            let ended = if close_peer {
                call(Root, sys::CLOSE.raw(), [second, 0, 0, 0, 0, 0])
            } else {
                call(
                    Root,
                    sys::SHUTDOWN.raw(),
                    [second, LINUX_SHUT_WR as u64, 0, 0, 0, 0],
                )
            };
            expect.served(what, ended, 0);
            let waitall = [first, got.arg(), 6, LINUX_MSG_WAITALL as u64, 0, 0];
            let read = call(Root, sys::RECVFROM.raw(), waitall);
            expect.served(&format!("recv(MSG_WAITALL) after {what}"), read, 3);
            expect.bytes(
                &format!("the prefix after {what}"),
                &got.as_bytes()[..read.1.clamp(0, 6) as usize],
                b"abc",
            );
            expect.served(
                &format!("recv(MSG_WAITALL) at EOF after {what}"),
                call(Root, sys::RECVFROM.raw(), waitall),
                0,
            );
            let open: &[u64] = if close_peer {
                &[first]
            } else {
                &[first, second]
            };
            for &fd in open {
                expect.served(
                    "close",
                    call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                    0,
                );
            }
        }
        let [first, second] = arm_root_spawn_socketpair(call);
        expect.served(
            "shutdown(SHUT_RD) of an empty end",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [first, LINUX_SHUT_RD as u64, 0, 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "recv(MSG_WAITALL) of an empty shut end",
            call(
                Root,
                sys::RECVFROM.raw(),
                [first, got.arg(), 6, LINUX_MSG_WAITALL as u64, 0, 0],
            ),
            0,
        );
        for fd in [first, second] {
            expect.served(
                "close",
                call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }
        expect
    });
    expect.assert_empty("MSG_WAITALL at a terminal receive state left Linux's contract");
}

/// #2385 review P0-2: a zero-length write to a stream socket still checks
/// the socket's state (send(2)): after the peer closed, after the peer's
/// SHUT_RD, or after this end's SHUT_WR it is EPIPE, `sendto` with
/// MSG_NOSIGNAL and `write(fd, buf, 0)` alike; while the peer still reads
/// it is 0, even with the lane full, and so after the peer's SHUT_WR. A
/// pipe's zero-length write stays 0, even with its reader gone (pipe(7)).
/// Native Linux gives exactly these results.
#[test]
fn arm_root_socketpair_zero_length_write_checks_the_stream_state() {
    use ArmCaller::Root;
    use carrick_abi::{
        LINUX_EPIPE, LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_SHUT_RD, LINUX_SHUT_WR,
    };
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let buf = GuestUserBuffer::from_bytes(b"x");
        let pipe = GuestUserBuffer::zeroed(8);
        let (_, made) = call(Root, sys::PIPE2.raw(), [pipe.arg(), 0, 0, 0, 0, 0]);
        assert_eq!(made, 0, "pipe2");
        let [reader, writer] = fd_pair_of(&pipe);
        expect.served(
            "a pipe's zero-length write",
            call(Root, sys::WRITE.raw(), [writer, buf.arg(), 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "close the pipe's reader",
            call(Root, sys::CLOSE.raw(), [reader, 0, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "a pipe's zero-length write without a reader",
            call(Root, sys::WRITE.raw(), [writer, buf.arg(), 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "close the pipe's writer",
            call(Root, sys::CLOSE.raw(), [writer, 0, 0, 0, 0, 0]),
            0,
        );
        let nosignal = LINUX_MSG_NOSIGNAL as u64;
        let zero_send = |fd: u64| [fd, buf.arg(), 0, nosignal, 0, 0];

        let [first, second] = arm_root_spawn_socketpair(call);
        expect.served(
            "a zero-length send while the peer reads",
            call(Root, sys::SENDTO.raw(), zero_send(first)),
            0,
        );
        // Fill the first end's lane: a zero-length write never waits.
        let fill = GuestUserBuffer::zeroed(carrick_el1_abi::ipc::IPC_STREAM_LANE_BYTES);
        let (_, filled) = call(
            Root,
            sys::SENDTO.raw(),
            [
                first,
                fill.arg(),
                fill.as_bytes().len() as u64,
                LINUX_MSG_DONTWAIT as u64,
                0,
                0,
            ],
        );
        assert!(filled > 0, "fill the lane: {filled}");
        expect.served(
            "a zero-length write to a full lane",
            call(Root, sys::WRITE.raw(), [first, buf.arg(), 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "the peer's SHUT_WR",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [second, LINUX_SHUT_WR as u64, 0, 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "a zero-length send after the peer's SHUT_WR",
            call(Root, sys::SENDTO.raw(), zero_send(first)),
            0,
        );
        expect.served(
            "the peer's SHUT_RD",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [second, LINUX_SHUT_RD as u64, 0, 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "a zero-length send after the peer's SHUT_RD",
            call(Root, sys::SENDTO.raw(), zero_send(first)),
            LINUX_EPIPE.guest_retval(),
        );
        for fd in [first, second] {
            expect.served(
                "close",
                call(Root, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }

        let [first, second] = arm_root_spawn_socketpair(call);
        expect.served(
            "this end's SHUT_WR",
            call(
                Root,
                sys::SHUTDOWN.raw(),
                [first, LINUX_SHUT_WR as u64, 0, 0, 0, 0],
            ),
            0,
        );
        expect.served(
            "a zero-length send after this end's SHUT_WR",
            call(Root, sys::SENDTO.raw(), zero_send(first)),
            LINUX_EPIPE.guest_retval(),
        );
        expect.served(
            "close the peer",
            call(Root, sys::CLOSE.raw(), [second, 0, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "close",
            call(Root, sys::CLOSE.raw(), [first, 0, 0, 0, 0, 0]),
            0,
        );

        let [first, second] = arm_root_spawn_socketpair(call);
        expect.served(
            "close the peer",
            call(Root, sys::CLOSE.raw(), [second, 0, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "sendto(fd, buf, 0, MSG_NOSIGNAL) after the peer closed",
            call(Root, sys::SENDTO.raw(), zero_send(first)),
            LINUX_EPIPE.guest_retval(),
        );
        // write(2) has no MSG_NOSIGNAL: EPIPE comes with SIGPIPE, which
        // may be delivered off the ring, as for a non-empty write.
        expect.result(
            "write(fd, buf, 0) after the peer closed",
            call(Root, sys::WRITE.raw(), [first, buf.arg(), 0, 0, 0, 0]),
            LINUX_EPIPE.guest_retval(),
        );
        expect.served(
            "close",
            call(Root, sys::CLOSE.raw(), [first, 0, 0, 0, 0, 0]),
            0,
        );
        expect
    });
    expect.assert_empty("a zero-length stream write left Linux's contract");
}

/// #2361: a guest wait on a ring stream end releases execution capacity.
/// A ring fork child's read of its empty end parks as an owned operation
/// (the call is Suspended, no worker holds it); the parent's write wakes
/// it with the bytes, and the parent's close then gives the child EOF.
// Linux only, as `arm_root_fork_child_writes_its_socket_stdout`.
#[cfg(not(target_os = "macos"))]
#[test]
fn arm_root_fork_child_parks_on_its_empty_socket_until_the_parent_writes() {
    use ArmCaller::Root;
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    let (expect, _) = with_arm_process_host_dispatch(|call| {
        let expect = ArmExpect::new();
        let [parent, child_end] = arm_root_spawn_socketpair(call);
        let (route, pid) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        expect.served(
            "the child closes the parent's end",
            call(child, sys::CLOSE.raw(), [parent, 0, 0, 0, 0, 0]),
            0,
        );
        let got = GuestUserBuffer::zeroed(16);
        call(child, ARM_LEAVE_ON_PARK, [0; 6]);
        let parked = call(child, sys::READ.raw(), [child_end, got.arg(), 16, 0, 0, 0]);
        if parked.0 != CompletionRoute::Suspended {
            expect.0.borrow_mut().push(format!(
                "the child's read of its empty end: got {parked:?}, want Suspended"
            ));
        }
        let input = GuestUserBuffer::from_bytes(b"input");
        expect.served(
            "the parent writes",
            call(Root, sys::WRITE.raw(), [parent, input.arg(), 5, 0, 0, 0]),
            5,
        );
        if parked.0 == CompletionRoute::Suspended {
            // The woken child re-enters its read with its registers as they
            // were; its owned operation completes it.
            let mut resumed = call(child, ARM_RESUME, [0; 6]);
            if resumed.1 == i64::MIN {
                resumed = call(child, sys::READ.raw(), [child_end, got.arg(), 16, 0, 0, 0]);
            }
            expect.result("the child's read resumes", resumed, 5);
            expect.bytes("the child's bytes", &got.as_bytes()[..5], b"input");
        }
        expect.served(
            "the parent closes its end",
            call(Root, sys::CLOSE.raw(), [parent, 0, 0, 0, 0, 0]),
            0,
        );
        expect.served(
            "the child reads EOF",
            call(child, sys::READ.raw(), [child_end, got.arg(), 16, 0, 0, 0]),
            0,
        );
        expect
    });
    expect.assert_empty("a ring stream wait left the owned-continuation contract");
}

/// #1671 round 2, a hypothesis for the `uv__io_poll` EINTR abort that
/// follows the failed `execSync`: libuv forks with every loop's epoll open,
/// and exec's close-on-exec sweep in the child closes its copies. Linux:
/// the descriptions live on in the parent. The spawn loop's epoll (adopted
/// by the host for its socket member, #2338) and the main loop's ring-only
/// epoll both keep reporting to the parent after the child's sweep.
#[test]
fn arm_root_fork_child_sweep_keeps_the_parents_loop_epolls() {
    use ArmCaller::Root;
    use carrick_abi::{LINUX_EPOLL_CTL_ADD, LINUX_EPOLLIN, LINUX_O_CLOEXEC, LINUX_O_NONBLOCK};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    const PIPE_COOKIE: u64 = 0x1671_0000_0000_0011;
    const SOCKET_COOKIE: u64 = 0x1671_0000_0000_0012;
    const ASYNC_COOKIE: u64 = 0x1671_0000_0000_0013;
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        let mismatches = core::cell::RefCell::new(Vec::new());
        let expect = |what: &str, got: (CompletionRoute, i64), want: i64| {
            if got.1 != want {
                mismatches
                    .borrow_mut()
                    .push(format!("{what}: got {} ({:?}), want {want}", got.1, got.0));
            }
        };
        let ctl = sys::EPOLL_CTL.raw();
        let create_epoll =
            |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64)| {
                let (_, epoll) = call(
                    Root,
                    sys::EPOLL_CREATE1.raw(),
                    [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0],
                );
                assert!(epoll >= 0, "epoll_create1: {epoll}");
                epoll as u64
            };
        // The spawn loop: a ring signal pipe and the parent's socket end.
        let spawn_loop = create_epoll(call);
        let [parent, child_end] = arm_root_host_socketpair(call);
        let pipe = GuestUserBuffer::zeroed(8);
        let (_, made) = call(
            Root,
            sys::PIPE2.raw(),
            [pipe.arg(), LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
        assert_eq!(made, 0, "pipe2");
        let [reader, writer] = fd_pair_of(&pipe);
        let pipe_in = epoll_event_buffer(LINUX_EPOLLIN, PIPE_COOKIE);
        let socket_in = epoll_event_buffer(LINUX_EPOLLIN, SOCKET_COOKIE);
        expect(
            "ADD the ring pipe",
            call(
                Root,
                ctl,
                [spawn_loop, LINUX_EPOLL_CTL_ADD, reader, pipe_in.arg(), 0, 0],
            ),
            0,
        );
        expect(
            "ADD the host socket",
            call(
                Root,
                ctl,
                [
                    spawn_loop,
                    LINUX_EPOLL_CTL_ADD,
                    parent,
                    socket_in.arg(),
                    0,
                    0,
                ],
            ),
            0,
        );
        // The main loop stays ring-only: an eventfd (uv_async).
        let main_loop = create_epoll(call);
        let (_, async_fd) = call(
            Root,
            sys::EVENTFD2.raw(),
            [0, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
        assert!(async_fd >= 0, "eventfd2: {async_fd}");
        let async_fd = async_fd as u64;
        let async_in = epoll_event_buffer(LINUX_EPOLLIN, ASYNC_COOKIE);
        expect(
            "ADD the main loop's eventfd",
            call(
                Root,
                ctl,
                [
                    main_loop,
                    LINUX_EPOLL_CTL_ADD,
                    async_fd,
                    async_in.arg(),
                    0,
                    0,
                ],
            ),
            0,
        );

        let (route, pid) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);
        expect(
            "child dup3(socket, 1)",
            call(child, sys::DUP3.raw(), [child_end, 1, 0, 0, 0, 0]),
            1,
        );
        // exec's close-on-exec sweep of the loops' descriptors.
        for (what, fd) in [
            ("spawn loop epoll", spawn_loop),
            ("socket", parent),
            ("socket child end", child_end),
            ("pipe reader", reader),
            ("pipe writer", writer),
            ("main loop epoll", main_loop),
            ("main loop eventfd", async_fd),
        ] {
            expect(
                &format!("child close({what})"),
                call(child, sys::CLOSE.raw(), [fd, 0, 0, 0, 0, 0]),
                0,
            );
        }

        let events = GuestUserBuffer::zeroed(16 * 4);
        let harvest = |call: &mut dyn FnMut(ArmCaller, u64, [u64; 6]) -> (CompletionRoute, i64),
                       epoll: u64| {
            let (route, ready) = call(
                Root,
                sys::EPOLL_PWAIT.raw(),
                [epoll, events.arg(), 4, 0, 0, 8],
            );
            let mut cookies: Vec<u64> = (0..ready.max(0) as usize)
                .map(|n| {
                    u64::from_ne_bytes(
                        events.as_bytes()[n * 16 + 8..n * 16 + 16]
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect();
            cookies.sort_unstable();
            (route, ready, cookies)
        };
        let signal = GuestUserBuffer::from_bytes(b"s");
        expect(
            "parent signal-pipe write",
            call(Root, sys::WRITE.raw(), [writer, signal.arg(), 1, 0, 0, 0]),
            1,
        );
        let (route, ready, cookies) = harvest(call, spawn_loop);
        if (ready, &cookies[..]) != (1, &[PIPE_COOKIE][..]) {
            mismatches.borrow_mut().push(format!(
                "parent spawn-loop epoll_pwait: got {ready} {cookies:x?} ({route:?}), want the pipe"
            ));
        }
        let one = GuestUserBuffer::from_value(1u64);
        expect(
            "parent uv_async_send",
            call(Root, sys::WRITE.raw(), [async_fd, one.arg(), 8, 0, 0, 0]),
            8,
        );
        let (route, ready, cookies) = harvest(call, main_loop);
        if (ready, &cookies[..]) != (1, &[ASYNC_COOKIE][..]) {
            mismatches.borrow_mut().push(format!(
                "parent main-loop epoll_pwait: got {ready} {cookies:x?} ({route:?}), want the eventfd"
            ));
        }
        mismatches.into_inner()
    });
    assert!(
        mismatches.is_empty(),
        "a fork child's exec sweep reached the parent's loops:\n{}",
        mismatches.join("\n")
    );
}

/// #1671 round 2, a hypothesis for the `uv__io_poll` EINTR abort: Node's
/// platform thread parks in its loop's ring epoll while the main thread's
/// `execSync` forks, and the child's exec sweep closes its inherited copies
/// of that epoll and its eventfd. Linux: the parent's wait is untouched (the
/// descriptions live on in the parent); no close wakes it.
#[test]
fn arm_root_fork_child_close_keeps_the_parents_parked_epoll_wait() {
    use carrick_abi::{LINUX_EPOLL_CTL_ADD, LINUX_EPOLLIN, LINUX_O_CLOEXEC, LINUX_O_NONBLOCK};
    use carrick_personality_linux::crossing::nr as sys;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_test_support::GuestUserBuffer;

    const ASYNC_COOKIE: u64 = 0x1671_0000_0000_0021;
    let (mismatches, _) = with_arm_process_host_dispatch(|call| {
        use ArmCaller::Root;
        let mut mismatches = Vec::new();
        let (_, epoll) = call(
            Root,
            sys::EPOLL_CREATE1.raw(),
            [LINUX_O_CLOEXEC, 0, 0, 0, 0, 0],
        );
        assert!(epoll >= 0, "epoll_create1: {epoll}");
        let epoll = epoll as u64;
        let (_, async_fd) = call(
            Root,
            sys::EVENTFD2.raw(),
            [0, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
        assert!(async_fd >= 0, "eventfd2: {async_fd}");
        let async_fd = async_fd as u64;
        let async_in = epoll_event_buffer(LINUX_EPOLLIN, ASYNC_COOKIE);
        let (_, added) = call(
            Root,
            sys::EPOLL_CTL.raw(),
            [epoll, LINUX_EPOLL_CTL_ADD, async_fd, async_in.arg(), 0, 0],
        );
        assert_eq!(added, 0, "ADD the eventfd");
        let (route, pid) = call(Root, 220, [17, 0, 0, 0, 0, 0]);
        assert!(pid > 0, "clone: {pid} ({route:?})");
        let child = ArmCaller::Child(pid as u32);

        let events = GuestUserBuffer::zeroed(16 * 4);
        let (route, _) = call(
            Root,
            sys::EPOLL_PWAIT.raw(),
            [epoll, events.arg(), 4, u64::MAX, 0, 8],
        );
        assert_eq!(route, CompletionRoute::Suspended, "the parent's wait parks");
        // Each step of the child's life leaves the parent's wait parked:
        // `ARM_RESUME` finds it still waiting.
        let mut still_parked = |what: &str, nr: u64, args: [u64; 6], want: i64| {
            let got = call(child, nr, args);
            if got.1 != want {
                mismatches.push(format!("{what}: got {} ({:?}), want {want}", got.1, got.0));
            }
            let resumed = call(Root, ARM_RESUME, [0; 6]);
            if resumed != (CompletionRoute::Suspended, 0) {
                mismatches.push(format!(
                    "after {what}, the parent's wait returned {resumed:?}"
                ));
            }
        };
        still_parked(
            "child close(epoll)",
            sys::CLOSE.raw(),
            [epoll, 0, 0, 0, 0, 0],
            0,
        );
        still_parked(
            "child close(eventfd)",
            sys::CLOSE.raw(),
            [async_fd, 0, 0, 0, 0, 0],
            0,
        );
        mismatches
    });
    assert!(
        mismatches.is_empty(),
        "a fork child's close reached the parent's epoll wait:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn arm_root_shell_redirect_then_clone_serves_child_stdout_fstat_and_write() {
    use carrick_abi::{
        LINUX_AT_FDCWD, LINUX_F_DUPFD, LINUX_O_CREAT, LINUX_O_TRUNC, LINUX_O_WRONLY, LinuxStat,
    };
    use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_personality_linux::native_host_file::{DescriptionAccess, NativeDescriptor};
    use carrick_test_support::GuestUserBuffer;
    use std::sync::Arc;

    struct HostPointerMemory;
    impl GuestMemory for HostPointerMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            if address == 0 {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            // SAFETY: test passes live GuestUserBuffer host addresses.
            let slice = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
            Ok(slice.to_vec())
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            if address == 0 {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }
            // SAFETY: test passes live GuestUserBuffer host addresses.
            let slice = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, bytes.len()) };
            slice.copy_from_slice(bytes);
            Ok(())
        }
    }
    impl CurrentMmMemory for HostPointerMemory {}

    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let owner: &'static _ = Box::leak(Box::new(context.kernel().ipc().unwrap()));
    let files = context.resources().files();

    let root_table_key = files.id().raw();
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::with_file_table(
        0x10000,
        asid(1),
        root_table_key,
    )));

    let map = unsafe {
        &*fixture
            .region
            .ptr
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    files.publish_ipc(Arc::clone(owner), map).unwrap();

    let pages: Vec<_> = (0..16).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = Box::new(TestStockCrossing::new(&pages));
    crossing.ipc = Some((Arc::clone(owner), map));
    let crossing: &'static TestStockCrossing = Box::leak(crossing);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let tables: &'static _ = Box::leak(Box::new(crate::ipc::MapTables(map)));
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables,
    };
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let mut host_mem = HostPointerMemory;
    let reporter = carrick_kernel::compat::CompatReporter::default();

    let mut call_root = |nr: u64, args: [u64; 6]| -> (CompletionRoute, i64) {
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            elr: 0x4000,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let route =
            super::dispatch::dispatch_arm_syscall_with_native_process(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                crossing.fd_map(),
                &[],
                crossing.open_table(),
                &[],
                &cache,
                None::<
                    crate::dispatch::Zone<
                        '_,
                        crate::sched::FakeCpu,
                        crate::sched::HardwareUserWord,
                    >,
                >,
                Some(&venue),
                Some(fixture),
                fixture.page,
                fixture.control,
                &ThreadCtx::ZERO,
                ttbr0,
                &mut service,
                |_| core::ptr::null_mut(),
            )
            .unwrap();
        let ret = if route == CompletionRoute::Forward {
            match dispatcher
                .dispatch(
                    &context,
                    carrick_kernel::dispatch::SyscallRequest::new(
                        nr,
                        carrick_kernel::compat::SyscallArgs(args),
                    ),
                    &mut host_mem,
                    &reporter,
                )
                .unwrap()
            {
                carrick_kernel::dispatch::DispatchOutcome::Returned { value } => value,
                carrick_kernel::dispatch::DispatchOutcome::Errno { errno } => errno.guest_retval(),
                other => panic!("unexpected host dispatch outcome for nr={nr}: {other:?}"),
            }
        } else {
            frame.x[0] as i64
        };
        (route, ret)
    };

    let out_path = GuestUserBuffer::from_bytes(b"/dev/null\0");
    let (open_route, opened_fd) = call_root(
        56,
        [
            LINUX_AT_FDCWD,
            out_path.arg(),
            LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_TRUNC,
            0o600,
            0,
            0,
        ],
    );
    assert_eq!(open_route, CompletionRoute::Forward);
    assert_eq!(opened_fd, 3);

    // Shell builtin redirection sequence:
    // fcntl(1, F_DUPFD, 10) -> dup3(3, 1, 0) -> dup3(10, 1, 0) -> close(10).
    let (dupfd_route, saved_stdout) = call_root(25, [1, LINUX_F_DUPFD, 10, 0, 0, 0]);
    assert_eq!(saved_stdout, 10);
    let (redir_route, redir_ret) = call_root(24, [3, 1, 0, 0, 0, 0]);
    assert_eq!(redir_ret, 1);
    let (restore_route, restore_ret) = call_root(24, [10, 1, 0, 0, 0, 0]);
    assert_eq!(restore_ret, 1);
    let (close_route, close_ret) = call_root(57, [10, 0, 0, 0, 0, 0]);
    assert_eq!(close_ret, 0);

    // Clone child through production ARM native process admission/fork.
    let (clone_route, child_pid) = call_root(220, [17, 0, 0, 0, 0, 0]);
    assert_eq!(clone_route, CompletionRoute::WithWork);
    assert!(child_pid > 0, "clone failed with {child_pid}");
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = fixture.task.linux.take_served_boundary();

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .expect("clone admitted root into production registry");
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime
        .namespace_child_key(parent_key, child_pid as u32)
        .unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();
    let child_identity = fixture.zone.record(child_binding.record.id).identity();
    let selected = activate_target(source, &fixture.task, &child_binding);
    assert_eq!(selected.record, child_binding.record.id);

    let child_table = crate::ipc::native_table(&venue, &fixture.task)
        .expect("fork child owns a published ring descriptor table");
    assert_eq!(
        crate::ipc::native_descriptor(&venue, child_table, 1),
        Some(NativeDescriptor::HostBacked {
            access: DescriptionAccess::ReadWrite,
        }),
        "child fd 1 resolves in fd-core as HostBacked (not None)"
    );
    assert_eq!(
        crate::ipc::native_descriptor(&venue, child_table, 10),
        Some(NativeDescriptor::Absent),
        "closed saved stdout fd 10 must be absent in child"
    );

    let mut cpu = crate::sched::FakeCpu::default();
    let mut run_child_host_file = |nr: u64, args: [u64; 6]| -> i64 {
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            elr: 0x4004,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let saved = unsafe { runtime.record_binding(child_binding.record) }
            .unwrap()
            .words;
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                child_binding.address,
                &saved,
                &mut service,
            )
            .unwrap();
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            crossing.fd_map(),
            &[],
            crossing.open_table(),
            &[],
            &cache,
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
        drop(entry);
        assert_eq!(
            route,
            CompletionRoute::Forward,
            "child syscall {nr} must decline in-ring pipe family to stage host-file request"
        );
        serve_child_host_file(
            &frame,
            &fixture.task,
            &venue,
            &dispatcher,
            &carrick_personality_linux::identity::TaskCredentials::ROOT,
            None,
        )
        .unwrap_or_else(|| panic!("child syscall {nr} staged nothing"))
    };

    let stat_buf = GuestUserBuffer::zeroed(core::mem::size_of::<LinuxStat>());
    let fstat_ret = run_child_host_file(80, [1, stat_buf.arg(), 0, 0, 0, 0]);
    let msg = GuestUserBuffer::from_bytes(b"child-ok\n");
    let write_ret = run_child_host_file(64, [1, msg.arg(), 9, 0, 0, 0]);

    assert_eq!(
        fstat_ret, 0,
        "child fstat(1) after root redirect+restore returned {fstat_ret} (ENOSYS = -38)"
    );
    assert_eq!(
        write_ret, 9,
        "child write(1) after root redirect+restore returned {write_ret} (ENOSYS = -38)"
    );
    assert_eq!(dispatcher.stdout(), b"child-ok\n");
    assert_eq!(
        (dupfd_route, redir_route, restore_route, close_route),
        (
            CompletionRoute::Forward,
            CompletionRoute::Forward,
            CompletionRoute::Forward,
            CompletionRoute::Forward,
        ),
        "root host-backed dup/fcntl/close keep the host FileTable as their one owner"
    );
    assert_ne!(child_identity.file_table, root_table_key);
    registry().unregister_root_for_test(&runtime);
}

#[test]
fn arm_two_live_processes_dup_and_close_isolate_tables() {
    use carrick_abi::{LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_SETFD, LINUX_FD_CLOEXEC};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let owner: &'static _ = Box::leak(Box::new(context.kernel().ipc().unwrap()));
    let files = context.resources().files();

    let root_table_key = files.id().raw();
    let fixture: &'static Fixture = Box::leak(Box::new(Fixture::with_file_table(
        0x10000,
        asid(1),
        root_table_key,
    )));

    let map = unsafe {
        &*fixture
            .region
            .ptr
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    files.publish_ipc(Arc::clone(owner), map).unwrap();

    let pages: Vec<_> = (0..16).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = Box::new(TestStockCrossing::new(&pages));
    crossing.ipc = Some((Arc::clone(owner), map));
    let crossing: &'static TestStockCrossing = Box::leak(crossing);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let tables: &'static _ = Box::leak(Box::new(crate::ipc::MapTables(map)));
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables,
    };
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let ttbr0 = (u64::from(asid(1).raw()) << 48) | fixture.address.root.address().raw();
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();

    // Clone so root and child are two live processes with distinct tables.
    let mut clone_frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        elr: 0x4000,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    clone_frame.x[0] = 17;
    clone_frame.x[8] = 220;
    let clone_route = super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut clone_frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        crossing.fd_map(),
        &[],
        crossing.open_table(),
        &[],
        &cache,
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        Some(&venue),
        Some(fixture),
        fixture.page,
        fixture.control,
        &ThreadCtx::ZERO,
        ttbr0,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert_eq!(clone_route, CompletionRoute::WithWork);
    let child_pid = clone_frame.x[0] as i64;
    assert!(child_pid > 0);
    if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = fixture.task.linux.take_served_boundary();

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime
        .namespace_child_key(parent_key, child_pid as u32)
        .unwrap();
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    let mut cpu = crate::sched::FakeCpu::default();

    let mut call_process = |target: &super::native_process_runtime::NativeRecordBinding<
        AddressContext<RootGpa>,
        Aarch64ParkedContext,
    >,
                            nr: u64,
                            args: [u64; 6]|
     -> (CompletionRoute, i64) {
        if fixture.zone.slot(fixture.slot).current() != Some(target.record.id) {
            if let Some(current) = fixture.zone.slot(fixture.slot).current() {
                assert!(
                    fixture
                        .zone
                        .requeue_preempted(fixture.slot, current)
                        .is_queued()
                );
            }
            activate_target(source, &fixture.task, target);
        }
        let ctx = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, target.address);
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x15 << 26,
            elr: 0x4008,
            slot: u64::from(fixture.slot.raw()),
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
        let mut entry = runtime
            .enter(source, &fixture.task, ctx, &mut service)
            .unwrap();
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            crossing.fd_map(),
            &[],
            crossing.open_table(),
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            Some(&venue),
            Some(fixture),
            Some(&mut entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        drop(entry);
        (route, frame.x[0] as i64)
    };

    // Root duplicates fd 1 -> 3, marks fd 3 CLOEXEC, closes fd 1.
    assert_eq!(
        call_process(&parent_binding, 23, [1, 0, 0, 0, 0, 0]),
        (CompletionRoute::Served, 3)
    );
    assert_eq!(
        call_process(
            &parent_binding,
            25,
            [3, LINUX_F_SETFD, LINUX_FD_CLOEXEC, 0, 0, 0]
        ),
        (CompletionRoute::Served, 0)
    );
    assert_eq!(
        call_process(&parent_binding, 57, [1, 0, 0, 0, 0, 0]),
        (CompletionRoute::Served, 0)
    );

    // Child's table is unaffected: fd 1 is still open (F_GETFD == 0) and fd 3 is absent (-EBADF).
    assert_eq!(
        call_process(&child_binding, 25, [1, LINUX_F_GETFD, 0, 0, 0, 0]),
        (CompletionRoute::Served, 0)
    );
    assert_eq!(
        call_process(&child_binding, 25, [3, LINUX_F_GETFD, 0, 0, 0, 0]),
        (CompletionRoute::Served, -9)
    );

    // Child duplicates fd 1 -> 12 with F_DUPFD_CLOEXEC and closes fd 2; root is unaffected.
    assert_eq!(
        call_process(&child_binding, 25, [1, LINUX_F_DUPFD_CLOEXEC, 12, 0, 0, 0]),
        (CompletionRoute::Served, 12)
    );
    assert_eq!(
        call_process(&child_binding, 57, [2, 0, 0, 0, 0, 0]),
        (CompletionRoute::Served, 0)
    );
    assert_eq!(
        call_process(&parent_binding, 25, [2, LINUX_F_GETFD, 0, 0, 0, 0]),
        (CompletionRoute::Served, 0)
    );
    assert_eq!(
        call_process(&parent_binding, 25, [12, LINUX_F_GETFD, 0, 0, 0, 0]),
        (CompletionRoute::Served, -9)
    );
    assert_eq!(
        call_process(&parent_binding, 25, [3, LINUX_F_GETFD, 0, 0, 0, 0]),
        (CompletionRoute::Served, LINUX_FD_CLOEXEC as i64)
    );

    registry().unregister_root_for_test(&runtime);
}
