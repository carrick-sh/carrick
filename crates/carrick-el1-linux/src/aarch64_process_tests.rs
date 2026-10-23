//! Red-first VM-free tests for [`Aarch64NativeProcessService`] and the shared process owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
mod native_child_handoff_tests;
#[cfg(test)]
mod native_fault_supply_tests;

use super::aarch64_process::{Aarch64NativeProcessService, ForkStockCrossing};
#[cfg(test)]
use super::aarch64_process::{
    Mm, admit_entry, map_resume, observed_entry_address, process_record_for_call, registry,
    resume_selected, with_process_entry,
};
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
use carrick_personality_linux::lifecycle::{LinuxWaitOptions, LinuxWaitStatus, ProcessWaitPid};
#[cfg(test)]
use carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
use carrick_sched_core::process::{TaskKey, TaskSerial};
use carrick_sched_core::{Aarch64ParkedContext, ThreadCtx, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
    fn save(&mut self, frame: &carrick_el1_abi::TrapFrame, ctx: &mut Aarch64ParkedContext) {
        self.inner.save(frame, ctx);
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

struct TestStockCrossing {
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
    #[cfg(test)]
    commit_fault: std::sync::Mutex<CommitFault>,
    pending_loan: std::sync::Mutex<Option<ForkStockLoan>>,
    retirements: AtomicUsize,
    zone: std::sync::Mutex<Option<&'static ZoneTables<Aarch64ParkedContext>>>,
    child: std::sync::Mutex<Option<(carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>)>>,
    handbacks: AtomicUsize,
    root_exits: AtomicUsize,
    root_exit_status: AtomicU64,
    #[cfg(all(test, target_os = "linux"))]
    require_stack_commit: bool,
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
            settlements_reserved: AtomicUsize::new(0),
            settlements_committed: AtomicUsize::new(0),
            settlements_aborted: AtomicUsize::new(0),
            reserved_custody_rows: AtomicUsize::new(0),
            refuse_reserve: std::sync::Mutex::new(None),
            #[cfg(test)]
            commit_fault: std::sync::Mutex::new(CommitFault::None),
            pending_loan: std::sync::Mutex::new(None),
            retirements: AtomicUsize::new(0),
            zone: std::sync::Mutex::new(None),
            child: std::sync::Mutex::new(None),
            handbacks: AtomicUsize::new(0),
            root_exits: AtomicUsize::new(0),
            root_exit_status: AtomicU64::new(u64::MAX),
            #[cfg(all(test, target_os = "linux"))]
            require_stack_commit: false,
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
                for control in controls.iter() {
                    // SAFETY: these leaked fixture controls share one host/guest alias.
                    unsafe {
                        control.publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
                            core::ptr::from_ref(control).expose_provenance() as u64,
                        ));
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
                if !settlement.accept(loan) {
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
                if let Some(loan) = self.pending_loan.lock().unwrap().take()
                    && !settlement.accept(loan)
                {
                    return Err(NativeProcessError::Invalid);
                }
                Ok(())
            }
            Some(ForkStockKind::Abort) => {
                self.settlements_aborted.fetch_add(1, Ordering::AcqRel);
                self.reserved_custody_rows.store(0, Ordering::Release);
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
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        Self::with_identity(
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
        )
    }
    fn with_identity(
        root_gpa: u64,
        asid: carrick_guest_arch::Asid,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        leader: ThreadIdentity,
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
        task.publish_visible_pid(leader.tid as u32);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);

        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root_gpa)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(leader.mm).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(101).unwrap()),
        };
        zone.mm_issuer().observe_existing(address.mm);
        task.publish_root_generation(address.generation);

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
        owner.finish_import().unwrap();
        drop(owner);

        let tables = crate::mm_portal::test_support::Tables::new(root_gpa, IPA, 2);
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
            &mut dyn carrick_personality_linux::lifecycle::ProcessNative<Aarch64ParkedContext>,
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
    }

    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
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

#[cfg(test)]
#[test]
fn arm_terminal_child_retirement_and_parent_handback_once() {
    arm_child_wait_wake(false, false);
}

#[cfg(test)]
#[test]
fn arm_in_ring_wait4_wake_resumes_owner_before_eret() {
    arm_child_wait_wake(true, false);
}

#[cfg(test)]
#[test]
fn arm_registered_sibling_wait4_wakes_through_owner_in_ring() {
    arm_child_wait_wake(true, true);
}

#[cfg(test)]
fn arm_child_wait_wake(in_ring: bool, sibling: bool) {
    let fixture = Fixture::new(0x10000, asid(1));
    if in_ring {
        fixture.zone.spaces.set_idle_ttbr(0x30000);
    }
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
        run_as(&fixture, 43, 13, 103, control);
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
    let mut status_storage = 0i32;
    let status_va = UserVa::new(&raw mut status_storage as u64);
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
    assert!(
        fixture
            .zone
            .spaces
            .find(child_binding.address.mm.raw().get())
            .is_none(),
        "child exit must retire its reservation root without waiting for another fork"
    );

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
        assert!(matches!(
            parent_entry.resume_pending_wait(),
            Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == child_pid as i64
        ));
    }
    assert_eq!(
        status_storage,
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
    assert!(
        matches!(
            refused,
            LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::Busy.errno()
        ),
        "munmap-during-fork reservation refusal must roll back to a counted EAGAIN failure"
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
    assert_eq!(error.errno(), NativeProcessError::Busy.errno());
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
    assert_eq!(error.errno(), -11);
    assert_eq!(
        error.run_failure_reason(),
        NativeProcessError::Busy.run_failure_reason()
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
    assert_eq!(error.errno(), -11);
    assert_eq!(
        error.run_failure_reason(),
        NativeProcessError::Busy.run_failure_reason()
    );
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
    assert_eq!(error, NativeProcessError::Quarantined);
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
        .finish(&carrick_sched_core::ShortLockSpin)
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
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent.record.id);
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
    fn wake_unplaceable_wait(
        &self,
        channel: super::native_process_runtime::ProcessWaitChannel,
        _slot: SlotId,
    ) -> Result<(), super::native_process_runtime::NativeProcessError> {
        let mut transfers = Vec::new();
        let guard = self
            .zone
            .lock(
                ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(
                    channel.mm.raw(),
                    channel.address.get(),
                ),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        let _ = self.zone.wake_host(
            &guard,
            channel.mm.raw(),
            channel.address.get(),
            u32::MAX,
            u32::MAX,
            false,
            &mut |transfer| transfers.push(transfer),
            &mut |_| panic!("must hand back unplaceable wait to host"),
        );
        drop(guard);
        for transfer in transfers {
            assert!(
                transfer
                    .finish(&carrick_sched_core::ShortLockSpin)
                    .is_some()
            );
        }
        self.task.linux.mark_pending_host_work();
        Ok(())
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
    let mask = Box::new(u64::MAX);
    let old_mask = Box::new(core::cell::UnsafeCell::new(0xdead_beef_u64));
    for (nr, args, expected) in [
        (
            135,
            [
                0,
                &*mask as *const u64 as u64,
                old_mask.get() as u64,
                8,
                0,
                0,
            ],
            0,
        ),
        // musl's _Fork sets only x0/x1. Linux ignores x2..x5 without their
        // matching CLONE_* flags; the preceding sigprocmask leaves them live.
        (220, [17, 0, 0xdead_beef, 8, 0x1234, 0x5678], 42),
    ] {
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr;
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
    // SAFETY: the owned cell outlives the production UserCopy call and no
    // concurrent actor can write it in this single-threaded fixture.
    assert_eq!(unsafe { *old_mask.get() }, 0);
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 1);
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
    fixture.zone.requeue_preempted(slot, record);
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
    fixture.zone.requeue_preempted(fixture.slot, record);
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
fn arm_call_with_cpu(
    fixture: &'static Fixture,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
) -> Result<carrick_personality_linux::dispatch::CompletionRoute, NativeProcessError> {
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
    let mut setup = carrick_el1_abi::TrapFrame::default();
    setup.x[8] = 134;
    setup.x[0] = 13;
    setup.x[3] = 8;
    arm_call(fixture, fixture.control, &mut service, &mut setup).unwrap();
    assert_eq!(setup.x[0], 0);

    let word = core::sync::atomic::AtomicU32::new(0);
    let timeout = [0_u64, 1_000_000];
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 98;
    frame.x[0] = word.as_ptr() as u64;
    frame.x[1] = 128;
    frame.x[3] = timeout.as_ptr() as u64;
    let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
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
fn arm_signal_wait_stays_unported_until_owned_wait_slice() {
    use carrick_personality_linux::dispatch::{Family, route_aarch64};
    assert_eq!(route_aarch64(133, u64::MAX), Family::Unported);
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
    // The leader-TID rejection case keeps a sibling binding while claiming
    // the leader's visible TID; other callers need distinct exact identities.
    let binding_tid = if visible_tid == 41 { 42 } else { visible_tid };
    let generation = u64::from(binding_tid - 30);
    let thread_generation = u64::from(binding_tid + 60);
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
    fixture.zone.requeue_preempted(fixture.slot, record);
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
fn arm_two_live_threads_robust_exit_routes_host_custody_without_abort() {
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
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody
    );
    assert_eq!(
        arm_route_action(fixture, route, &mut frame),
        carrick_el1_abi::Action::HostCustody
    );
    assert_eq!(frame.x[0], 0, "never rewritten to -ENOSYS");
    assert_eq!(carrick_el1_abi::Lifecycle::live(fixture.page), 2);
    assert!(registry().for_record(fixture.zone, record).is_some());
    assert!(control.host_exit_requested());
    fixture.zone.clear_current(fixture.slot);
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
    run_as_leader(fixture);
    registry()
        .for_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            fixture.address,
        )
        .unwrap();
    fixture.zone.free_record(record.id);
    assert!(!leader_sees_thread(fixture, &mut service, 42));
    assert!(leader_sees_thread(fixture, &mut service, 41));
}

#[test]
fn arm_raw_exit_decline_after_membership_reservation_restores_live() {
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
    // A failed clear_child_tid copy is checked only after the nonfinal
    // membership reservation. The host must still see both page memberships.
    let mut child_tid = 42_u32;
    control.set_clear_child_tid((&raw mut child_tid).addr() as u64);
    let live = fixture.page.live();
    let entry = control.entry().unwrap();
    let state = fixture.page.state(entry.index());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 93;
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let route = arm_call(fixture, control, &mut service, &mut frame);
    super::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    let route = route.unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody
    );
    assert_eq!(fixture.page.live(), live);
    assert_eq!(child_tid, 42);
    fixture.zone.clear_current(fixture.slot);
    assert_eq!(fixture.page.state(entry.index()), state);
    assert!(leader_sees_thread(fixture, &mut service, 42));
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
                .retire_published_host_member(control.entry().unwrap(), control, retirement)
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
        .retire_published_host_member(entry, control, membership)
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
        page.retire_published_host_member(entry, control, membership)
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
        .retire_published_host_member(entry, control, membership)
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
        .retire_published_host_member(entry, control, retirement)
        .unwrap();
    let _ = fixture.zone.claim_for_host(
        record,
        None,
        carrick_el1_abi::Handback::Cancelled,
        &carrick_sched_core::ShortLockSpin,
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
            arm_call(fixture, control, &mut worker_service, &mut failed_frame),
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
                arm_call(fixture, fixture.control, service, &mut frame).unwrap(),
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
        None::<&mut dyn carrick_personality_linux::lifecycle::ProcessNative<Aarch64ParkedContext>>,
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
            .retire_published_host_member(entry, sibling, membership)
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
fn arm_concurrent_exit_group_callers_wake_all_and_settle_owner() {
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
    fixture.zone.requeue_preempted(fixture.slot, record3);

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
                    //    and park_pending_exit. Sibling 2 therefore parks FIRST at
                    //    the head of the exit-wait channel.
                    let fixture = unsafe { &*(fixture_address as *const Fixture) };
                    let service2 = unsafe {
                        &mut *(service2_address
                            as *mut Aarch64NativeProcessService<'static, TestStockCrossing>)
                    };
                    run_as(fixture, 42, 12, 102, control2);
                    let mut sibling2_exit_frame = carrick_el1_abi::TrapFrame::default();
                    sibling2_exit_frame.x[0] = 9;
                    sibling2_exit_frame.x[8] = 94;
                    assert_eq!(
                        arm_call(fixture, control2, service2, &mut sibling2_exit_frame).unwrap(),
                        carrick_personality_linux::dispatch::CompletionRoute::Suspended
                    );
                    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 0);
                    run_as_leader(fixture);
                }));
            }));

            // 1. Leader (tid 41) calls exit_group(7) on slot 0, becomes the closing
            //    owner, and parks on the exit-wait channel BEHIND sibling 2
            //    ([sibling 2, leader]) while sibling 3 is still uncommitted.
            let mut leader_exit_frame = carrick_el1_abi::TrapFrame::default();
            leader_exit_frame.x[0] = 7;
            leader_exit_frame.x[8] = 94;
            assert_eq!(
                arm_call(fixture, fixture.control, service, &mut leader_exit_frame).unwrap(),
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);

            run_as(fixture, 43, 0, 103, control3);
        }),
    );

    // 3. Sibling 3 (tid 43) commits raw SYS_exit(0). Its terminal notification
    //    must bump wake_generation to 1 and wake ALL waiters (both sibling 2
    //    at the head of the channel and leader behind it).
    let mut raw_exit_frame = carrick_el1_abi::TrapFrame::default();
    raw_exit_frame.x[8] = 93;
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut cpu = crate::sched::FakeCpu::default();
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
        None::<&mut dyn carrick_personality_linux::lifecycle::ProcessNative<Aarch64ParkedContext>>,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
            | carrick_personality_linux::dispatch::CompletionRoute::Served
    ));
    assert_eq!(fixture.zone.counters.el1_wakes.load(Ordering::Acquire), 2);

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    run_as_leader(fixture);
    let runtime = registry()
        .for_entry(source, &fixture.task, fixture.address)
        .unwrap();

    // Sibling 2 was at the head of the channel; sibling 3's SYS_exit(0)
    // run_next switched it into fixture.slot. Resuming it must retire its
    // record via Left(None) (never NoPending) without settling root exit.
    let first_woken = fixture
        .zone
        .slot(fixture.slot)
        .current()
        .expect("sibling 2 woken from channel head");
    assert_eq!(first_woken, record2.id);
    run_as(fixture, 42, 12, 102, control2);
    let resumed_sibling2 = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        first_woken,
        service,
    );
    assert!(
        matches!(
            resumed_sibling2,
            super::native_process_runtime::NativeResume::Left(None)
        ),
        "second exit_group caller must retire via Left(None)"
    );
    assert!(matches!(
        super::aarch64_process::map_resume(resumed_sibling2, service, &fixture.task, fixture.slot,),
        crate::sched::ResumeAction::Left
    ));
    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 0);
    assert_eq!(service2.crossing.root_exits.load(Ordering::Acquire), 0);

    // Leader was behind sibling 2 on the channel; it must ALSO have been woken
    // by u32::MAX and must now settle group exit with leader's status 7.
    let second_woken = fixture
        .zone
        .switch_in_full(fixture.slot)
        .expect("owner must not stay parked while second caller absorbs wake")
        .record;
    run_as_leader(fixture);
    let resumed_leader = super::aarch64_process::resume_selected(
        &runtime,
        registry(),
        source,
        &fixture.task,
        second_woken,
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
            // Make the parked closing owner unplaceable in the zone so the
            // unadopted sibling's venue-absent terminal notification must take
            // the unplaceable host-handback branch.
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
        None::<&mut dyn carrick_personality_linux::lifecycle::ProcessNative<Aarch64ParkedContext>>,
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
            carrick_el1_abi::Claim::Host { .. }
        ),
        "venue-absent unplaceable wake must hand the closing owner back to host"
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
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
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

// VM-free binding for kernel.el1.signal-delivery-owner: the scheduler must
// preserve the original wait4 context across a fresh signal-delivery entry.
// No guest instructions or hardware user-memory translation execute here.
#[cfg(test)]
#[repr(C, align(16))]
struct ArmWaitSignalStack([u8; 16384]);

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
    let mut stack = Box::new(ArmWaitSignalStack([0; 16384]));
    let stack_base = stack.0.as_mut_ptr() as u64;
    let user_sp = UserVa::new(stack_base + stack.0.len() as u64);
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
    fixture
        .zone
        .requeue_preempted(fixture.slot, child_binding.record.id);

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
    crate::sched::ThreadCpu::save(&mut cpu.inner, &frame, &mut saved);
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
        super::signal_delivery::deliver_signal_with_control(
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
        &stack.0[offset..],
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
        super::signal_delivery::deliver_signal_with_control(
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
