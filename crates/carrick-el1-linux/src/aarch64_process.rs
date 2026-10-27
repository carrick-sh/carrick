//! Machine custody for the shared AArch64 native process owner.
//!
//! Implements [`NativeProcessService`] for [`Aarch64ParkedContext`] over [`carrick_mmu_core::owner_mmu::Aarch64Mmu`].
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
use carrick_core::mm::transaction::OwnerVenue;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_core::mm::transaction::{
    SelectionVenues, UserWriteError, UserWriteRequest, UserWriteVenue,
};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, ForkStockExchange, ForkStockLoan, ForkStockRequest,
    ForkStockSettlement, PortalForkCustody, PortalOperation, ReservationMm, ReservationRange,
    ThreadControlSlot, ThreadLifecyclePage,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, SlotId, UserVa,
};
use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_personality_linux::lifecycle::LinuxWaitStatus;
use carrick_personality_linux::mm::{LinuxReservationPolicy, MmErrorLinux};
use carrick_sched_core::{
    AARCH64_ROOT_ADDRESS_MASK, Aarch64ParkedContext, RecordId, SpaceIndex, WakeEffects, ZoneTables,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use super::common_entry;
use super::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use super::native_fork_refusal::{NativeForkStage, refused};
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
use super::native_process_runtime::NativeResume;
use super::native_process_runtime::{
    ExecSuccessorSlot, FallibleBox, NativeExecSuccessor, NativeForkPreparation,
    NativeLifecycleResources, NativeProcessError, NativeProcessRegistry, NativeProcessRuntime,
    NativeProcessService,
};
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_el1::memory::reservations;
use carrick_el1::memory::reservations::{NativeReservationGeometry, SharedReservations};

pub type Mm = AddressContext<RootGpa>;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct CurrentMmMaintenance;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for CurrentMmMaintenance {
    fn publish_barrier(&self) {
        let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
        crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, ttbr0);
    }
    fn invalidate_range(&self, _va: u64, _len: u64) {
        self.publish_barrier();
    }
}
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
static CURRENT_MM_MAINTENANCE: CurrentMmMaintenance = CurrentMmMaintenance;

pub enum PreparedWords<'a> {
    Borrowed(&'a dyn LiveDescriptorWords),
    Owned(Box<dyn LiveDescriptorWords + 'a>),
}
impl<'a> core::ops::Deref for PreparedWords<'a> {
    type Target = dyn LiveDescriptorWords + 'a;
    fn deref(&self) -> &(dyn LiveDescriptorWords + 'a) {
        match self {
            Self::Borrowed(words) => *words,
            Self::Owned(words) => &**words,
        }
    }
}

type Runtime = NativeProcessRuntime<'static, Mm, Aarch64ParkedContext>;
static REGISTRY: NativeProcessRegistry<'static, Mm, Aarch64ParkedContext> =
    NativeProcessRegistry::new();

pub fn registry() -> &'static NativeProcessRegistry<'static, Mm, Aarch64ParkedContext> {
    &REGISTRY
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
fn drain_native_signal_ingress<'a, X: ForkStockCrossing>(
    owner_registry: &NativeProcessRegistry<'a, Mm, Aarch64ParkedContext>,
    source: BornInZoneSource<'a, Aarch64ParkedContext>,
    service: &mut Aarch64NativeProcessService<'a, X>,
) {
    owner_registry
        .drain_external_ingress(
            source.zone,
            carrick_el1::isa::signal_ingress_guest(),
            source.slot,
            service,
        )
        .unwrap_or_else(|_| fatal());
}

/// Re-enter the already admitted owner for a scheduler-selected record.
/// The source and task outlive this call; the record has exclusive OnCpu
/// custody until this checkpoint completes or parks again.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
pub(super) fn resume_selected<'a, X: ForkStockCrossing>(
    runtime: &NativeProcessRuntime<'a, Mm, Aarch64ParkedContext>,
    owner_registry: &NativeProcessRegistry<'a, Mm, Aarch64ParkedContext>,
    source: BornInZoneSource<'a, Aarch64ParkedContext>,
    task: &'a CurrentTask,
    record: RecordId,
    service: &mut Aarch64NativeProcessService<'a, X>,
) -> NativeResume {
    if owner_registry
        .for_record(source.zone, source.zone.record_ref(record))
        .is_none()
        && matches!(
            source.zone.record(record).resume_disposition(),
            carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(_)
        )
    {
        // SAFETY: switch_in_full gave this slot exclusive record custody.
        unsafe {
            source.zone.record(record).consume_owner_continuation();
        }
        let _ =
            source
                .zone
                .release_current(source.slot, record, &carrick_sched_core::ShortLockSpin);
        return NativeResume::Left(None);
    }
    // The scheduler publishes the execution identity; the native owner also
    // owns the namespace PID and MM incarnation for this selected record.
    // SAFETY: switch_in_full gave this slot exclusive record custody.
    let visible_pid = unsafe { runtime.resume_visible_pid(source.zone.record_ref(record)) }
        .unwrap_or_else(|| fatal());
    // SAFETY: the scheduler selected this exact record and holds its context
    // exclusively until it returns or publishes a new wait handoff.
    let context = unsafe { source.zone.record(record).ctx_mut() };
    let address = context.address_context().unwrap_or_else(|| fatal());
    task.publish_visible_pid(visible_pid);
    task.publish_root_generation(address.generation);
    let mut entry = {
        // Copy directly into heap storage: materializing the full parked
        // context here retains another context-sized frame across wait copy.
        let mut words = Box::<Aarch64ParkedContext>::new_uninit();
        // SAFETY: the selected record is exclusively held, its context is
        // initialized and Copy, and this allocation is distinct from it.
        let words = unsafe {
            core::ptr::copy_nonoverlapping(context, words.as_mut_ptr(), 1);
            words.assume_init()
        };
        #[cfg(target_os = "none")]
        drain_native_signal_ingress(owner_registry, source, service);
        runtime
            .enter_registered(owner_registry, source, task, address, &words, service)
            .unwrap_or_else(|_| fatal())
    };
    entry
        .import_in_zone_standard_signals()
        .unwrap_or_else(|_| fatal());
    entry.resume_checkpoint().unwrap_or_else(|reason| {
        super::native_run_failure::complete_native_run_failure(
            common_entry::execution_binding(task),
            reason,
        )
    })
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
pub fn resume_production(
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    task: &'static CurrentTask,
    slot: SlotId,
    record: RecordId,
) -> crate::sched::ResumeAction {
    let Some(runtime) = registry().for_record(zone, zone.record_ref(record)) else {
        if matches!(
            zone.record(record).resume_disposition(),
            carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(_)
        ) {
            // SAFETY: this exact record is selected by the execution owner.
            unsafe {
                zone.record(record).consume_owner_continuation();
            }
            let _ = zone.release_current(slot, record, &carrick_sched_core::ShortLockSpin);
            return crate::sched::ResumeAction::Left;
        }
        return crate::sched::ResumeAction::NoPending;
    };
    let source = BornInZoneSource { zone, slot };
    let mut service = Aarch64NativeProcessService::new(task, slot).unwrap_or_else(|_| fatal());
    map_resume(
        resume_selected(&runtime, registry(), source, task, record, &mut service),
        &mut service,
        task,
        slot,
    )
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn map_resume<X: ForkStockCrossing>(
    outcome: NativeResume,
    service: &mut Aarch64NativeProcessService<'_, X>,
    task: &CurrentTask,
    slot: SlotId,
) -> crate::sched::ResumeAction {
    match outcome {
        NativeResume::NoPending => crate::sched::ResumeAction::NoPending,
        NativeResume::RetrySyscall => crate::sched::ResumeAction::RetrySyscall,
        NativeResume::Returned(result) => crate::sched::ResumeAction::Returned(
            carrick_guest_arch::NativeReturnWord(result.raw() as u64),
        ),
        NativeResume::Left(status) => {
            if let Some(status) = status {
                cross_root_exit(&mut service.crossing, task, status, u32::from(slot.raw()))
                    .unwrap_or_else(|_| fatal());
            }
            crate::sched::ResumeAction::Left
        }
        NativeResume::Invalid => fatal(),
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn process_record_for_call(
    source: BornInZoneSource<'_, Aarch64ParkedContext>,
    task: &CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    control: &ThreadControlSlot,
) -> Result<RecordId, NativeProcessError> {
    let lane = source.zone.slot(source.slot);
    if let Some(record) = lane.current() {
        return Ok(record);
    }
    let host_record = lane.host_record();
    if let Some(record) = host_record
        && unsafe { source.zone.record(record).ctx_mut() }
            .address_context()
            .is_some()
    {
        return Ok(record);
    }
    init_process_record(source, task, native, ttbr0, host_record, control)
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
fn init_process_record(
    source: BornInZoneSource<'_, Aarch64ParkedContext>,
    task: &CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    host_record: Option<RecordId>,
    control: &ThreadControlSlot,
) -> Result<RecordId, NativeProcessError> {
    let lane = source.zone.slot(source.slot);
    let address = Mm {
        root: RootGpa::page_aligned(FrameGpa::new(ttbr0 & AARCH64_ROOT_ADDRESS_MASK))
            .ok_or(NativeProcessError::Stale)?,
        mm: MmGeneration::new(
            NonZeroU64::new(task.mm.key.load(Ordering::Acquire))
                .ok_or(NativeProcessError::Stale)?,
        ),
        generation: task.root_generation().ok_or(NativeProcessError::Stale)?,
    };
    let record = match host_record {
        Some(record) => record,
        None => source
            .zone
            .current_or_new(
                source.slot,
                crate::sched::identity_of(task, lane.affinity()),
            )
            .map_err(|_| NativeProcessError::Exhausted)?,
    };
    // SAFETY: the current host lane owns its unpublished home record.
    unsafe {
        *source.zone.record(record).ctx_mut() = Aarch64ParkedContext::from_parts(*native, address);
    }
    // Only the task's own published control slot names this home record.
    if task.metadata.control_slot.load(Ordering::Acquire)
        == core::ptr::from_ref(control).addr() as u64
    {
        control.bind_zone_record(source.zone.record_ref(record));
    }
    Ok(record)
}

/// Admit only an exact published leader or thread-group member. The root
/// address is checked by the shared owner against the zone's live MM grant.
#[allow(clippy::too_many_arguments)]
pub fn admit_entry(
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    record: RecordId,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
) -> Result<(Arc<Runtime>, Mm, Aarch64ParkedContext), NativeProcessError> {
    let (runtime, address) =
        admit_entry_runtime(source, task, native, ttbr0, record, page, control)?;
    let words = Aarch64ParkedContext::from_register(
        *native,
        ttbr0,
        address.mm.raw().get(),
        address.generation.raw().get(),
    );
    Ok((runtime, address, words))
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn admit_entry_runtime(
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    record: RecordId,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
) -> Result<(Arc<Runtime>, Mm), NativeProcessError> {
    // SAFETY: the EL1 caller owns the running slot and its record until the
    // process route returns to the vector.
    let observed = unsafe { observed_entry_address(source, task, ttbr0, record)? };
    let address = if control.entry().is_some() {
        REGISTRY
            .group_address(
                source.zone,
                observed,
                page,
                task.visible_pid().ok_or(NativeProcessError::Stale)?,
            )
            .filter(|address| *address == observed)
            .ok_or(NativeProcessError::Stale)?
    } else {
        observed
    };
    if let Ok(runtime) = REGISTRY.for_entry(source, task, address)
        && REGISTRY
            .for_record(source.zone, source.zone.record_ref(record))
            .is_some_and(|retained| Arc::ptr_eq(&retained, &runtime))
    {
        return Ok((runtime, address));
    }
    if control.entry().is_some()
        || REGISTRY
            .group_address(
                source.zone,
                address,
                page,
                task.visible_pid().ok_or(NativeProcessError::Stale)?,
            )
            .is_some()
    {
        let runtime = match REGISTRY.rehome_entry(source, task, address, page, control)? {
            Some(runtime) => runtime,
            None => REGISTRY.register_thread(source, task, address, page, control)?,
        };
        return Ok((runtime, address));
    }
    let words = Aarch64ParkedContext::from_register(
        *native,
        ttbr0,
        address.mm.raw().get(),
        address.generation.raw().get(),
    );
    let runtime = Arc::new(NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source, task, page, control, address, address, words,
    )?);
    REGISTRY.register_root(runtime.clone(), source, task, address)?;
    Ok((runtime, address))
}

/// Unpublished admission custody is scoped to this call: a home left in a
/// host-loaded lane is otherwise interpreted as a zone park at the next HVC.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
struct AdmissionHome {
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    record: carrick_sched_core::RecordRef,
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
impl Drop for AdmissionHome {
    fn drop(&mut self) {
        let owned = self.source.zone.record(self.record.id);
        // A genuine park/switch owns its publication; a retired/reused record
        // is somebody else's custody. Neither may be undone by this entry.
        if owned.incarnation() == self.record.incarnation
            && owned.claim() == carrick_sched_core::Claim::Free
            && owned.home() == Some(self.source.slot)
            && !owned.has_object_operation()
        {
            self.source
                .zone
                .discard_unpublished(self.source.slot, self.record.id);
        }
    }
}

/// The production ARM entry boundary, shared by the VM-free admission witness.
/// The callback receives the exact native venue retained for this SVC.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
pub(super) fn with_process_entry<X: ForkStockCrossing, R>(
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, X>,
    dispatch: impl FnOnce(
        &mut super::native_process_runtime::NativeProcessEntry<
            '_,
            'static,
            Mm,
            Aarch64ParkedContext,
            Aarch64NativeProcessService<'static, X>,
        >,
    ) -> R,
) -> Result<R, NativeProcessError> {
    let record = process_record_for_call(source, task, native, ttbr0, control)?;
    let _home = AdmissionHome {
        source,
        record: source.zone.record_ref(record),
    };
    let (runtime, address) =
        admit_entry_runtime(source, task, native, ttbr0, record, page, control)?;
    task.publish_root_generation(address.generation);
    let (result, root_exit) = {
        let mut process = {
            let words = Box::new(Aarch64ParkedContext::from_register(
                *native,
                ttbr0,
                address.mm.raw().get(),
                address.generation.raw().get(),
            ));
            #[cfg(target_os = "none")]
            drain_native_signal_ingress(registry(), source, service);
            runtime.enter_registered(registry(), source, task, address, &words, service)?
        };
        process.import_in_zone_standard_signals()?;
        let result = dispatch(&mut process);
        (result, process.take_root_exit())
    };
    if let Some(status) = root_exit {
        // A successful terminal crossing never re-enters this guest stack.
        drop(runtime);
        drop(_home);
        // The exit is already published: an Err here would let the caller's
        // unadmitted fallback replay it, so a refused crossing fail-stops.
        if cross_root_exit(
            &mut service.crossing,
            task,
            status,
            u32::from(source.slot.raw()),
        )
        .is_err()
        {
            super::dispatch::invalid_completion(super::dispatch::NativeInvariant::PhysicalCustody(
                "root exit crossing refused",
            ));
        }
    }
    Ok(result)
}

/// Read the MM's root incarnation from the parked execution context. The
/// scheduler record incarnation only names reuse of that record slot.
///
/// # Safety
/// The caller must own the stopped/running record exclusively.
pub(super) unsafe fn observed_entry_address(
    source: BornInZoneSource<'_, Aarch64ParkedContext>,
    task: &CurrentTask,
    ttbr0: u64,
    record: RecordId,
) -> Result<Mm, NativeProcessError> {
    let zone_record = source.zone.record(record);
    let binding = common_entry::execution_binding(task);
    let identity = zone_record.identity();
    // SAFETY: required by this function's caller contract.
    let address = unsafe { zone_record.ctx_mut() }
        .address_context()
        .ok_or(NativeProcessError::Stale)?;
    ((binding.issued() || carrick_core::entry::admit_born_in_zone(binding, source).is_some())
        && identity.tid == binding.task.raw()
        && identity.generation == binding.generation.raw()
        && identity.serial == binding.thread_generation.raw()
        && identity.mm == binding.mm.raw()
        && source.zone.installed_space(source.slot) == binding.mm.raw()
        && address.mm.raw().get() == binding.mm.raw()
        && address.root.address().raw() == ttbr0 & AARCH64_ROOT_ADDRESS_MASK)
        .then_some(address)
        .ok_or(NativeProcessError::Stale)
}

pub struct AdmittedCustodyToken {
    loan: ForkStockLoan,
    commit: ForkStockSettlement,
    index: carrick_sched_core::SpaceIndex,
}

impl core::fmt::Debug for AdmittedCustodyToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmittedCustodyToken")
            .field("index", &self.index)
            .finish()
    }
}

impl AdmittedCustodyToken {
    fn reserve<X: ForkStockCrossing>(
        crossing: &X,
        worker: u32,
        loan: ForkStockLoan,
        completion: carrick_el1_abi::PortalForkCompletion,
        rows: &[PortalForkCustody],
        index: carrick_sched_core::SpaceIndex,
    ) -> Result<Box<Self>, NativeProcessError> {
        let boxed = FallibleBox::try_reserve()?;
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(rows.len())
            .map_err(|_| NativeProcessError::Exhausted)?;
        custody.extend(rows.iter().copied().map(PortalForkCustody::words));
        let mut reserve = ForkStockSettlement::reserve(
            loan,
            completion,
            KernelVa::new(custody.as_ptr() as u64),
            custody.len() as u64,
        )
        .ok_or(NativeProcessError::Stale)?;
        let crossed =
            crossing.cross_fork_stock(&raw mut reserve as *mut _ as u64, u64::from(worker));
        match reserve.take(loan) {
            Some(Ok(())) => {
                crossed?;
            }
            Some(Err(reply)) => {
                return Err(refused(
                    NativeForkStage::Reserve,
                    super::native_fork_refusal::NativeForkCause::StockReservation(reply),
                ));
            }
            None => {
                crossed?;
                return Err(NativeProcessError::Stale);
            }
        }
        let commit = ForkStockSettlement::commit_reserved(loan, completion)
            .ok_or(NativeProcessError::Stale)?;
        Ok(boxed.put(Self {
            loan,
            commit,
            index,
        }))
    }

    #[allow(clippy::boxed_local)]
    fn consume<X: ForkStockCrossing>(
        self: Box<Self>,
        crossing: &X,
        slot: SlotId,
        zone: &ZoneTables<Aarch64ParkedContext>,
    ) -> Result<(), Box<Self>> {
        // The physical crossing admits only a complete stopped-CPU stack
        // record. The retained token and its loan stay boxed until acceptance;
        // its heap-resident wire template is never the crossing argument.
        let mut commit = self.commit;
        let crossed =
            crossing.cross_fork_stock(&raw mut commit as *mut _ as u64, u64::from(slot.raw()));
        if crossed.is_err() || !matches!(commit.take(self.loan), Some(Ok(()))) {
            return Err(self);
        }
        carrick_core::wait::space_access(zone, slot, release).open(self.index);
        Ok(())
    }
}

fn abort_loan<X: ForkStockCrossing>(crossing: &X, worker: u32, loan: &ForkStockLoan) -> bool {
    // SAFETY: the loan never published a birth; no reader remains.
    unsafe { super::fork_loan::clear_lifecycle(loan) };
    let mut settlement = carrick_el1_abi::ForkStockSettlement::abort(*loan);
    let _ = crossing.cross_fork_stock(&raw mut settlement as *mut _ as u64, u64::from(worker));
    matches!(settlement.take(*loan), Some(Ok(())))
}

fn abandon_loan<X: ForkStockCrossing>(
    crossing: &X,
    worker: u32,
    loan: &ForkStockLoan,
    scrub: Option<&(dyn LiveDescriptorWords + '_)>,
    error: NativeProcessError,
) -> NativeProcessError {
    if let Some(words) = scrub
        && !super::fork_loan::scrub_tables(words, loan)
    {
        return NativeProcessError::Quarantined;
    }
    if abort_loan(crossing, worker, loan) {
        error
    } else {
        NativeProcessError::Quarantined
    }
}

pub struct Prepared<'a> {
    pub loan: ForkStockLoan,
    pub child: UnpublishedEl1Child<Aarch64Mmu>,
    pub words: PreparedWords<'a>,
    pub address: Mm,
    pub admitted: Box<AdmittedCustodyToken>,
}

impl core::fmt::Debug for Prepared<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Prepared")
            .field("loan", &self.loan)
            .field("address", &self.address)
            .field("admitted", &self.admitted)
            .finish()
    }
}

pub struct Born {
    pub admitted: Box<AdmittedCustodyToken>,
}

impl core::fmt::Debug for Born {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Born")
            .field("admitted", &self.admitted)
            .finish()
    }
}

pub trait ForkStockCrossing {
    /// The carrier's complete shared descriptor namespace, if admitted.
    fn ipc_binding(
        &self,
    ) -> Option<(
        carrick_el1_abi::ipc::IpcRegion<'_>,
        &carrick_el1_abi::ipc_tables::IpcTableMap,
    )> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let map = carrick_el1_abi::ipc_table_map_guest();
            if !map.window_published() {
                return None;
            }
            Some((carrick_el1_abi::ipc_window_guest()?.attach().ok()?, map))
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            None
        }
    }
    /// The carrier's shared descriptor metadata, owned by the guest kernel.
    fn open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            unsafe {
                &*(carrick_el1_abi::EL1_OPEN_FILE_TABLE_BASE
                    as *const [carrick_el1_abi::DelegatedOpenFile;
                        carrick_el1_abi::MAX_ZONE_OPEN_FILES])
            }
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            &[]
        }
    }
    fn fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            unsafe {
                &*(carrick_el1_abi::EL1_FD_MAP_BASE
                    as *const [carrick_el1_abi::FdMapSlot; carrick_el1_abi::FD_MAP_CAPACITY])
            }
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            &[]
        }
    }

    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_root_exit(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_child_reclaim(&self, mm: ReservationMm, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_exec_adopt(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        let _ = (record_gpa, cpu);
        Err(NativeProcessError::Unsupported)
    }
    fn cross_exec_cancel(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        let _ = (record_gpa, cpu);
        Err(NativeProcessError::Unsupported)
    }
    fn cross_exec_settle(
        &self,
        predecessor: ReservationMm,
        successor: ReservationMm,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        let _ = (predecessor, successor, cpu);
        Err(NativeProcessError::Unsupported)
    }
    fn cross_wait_channel_wake(
        &self,
        channel: super::native_process_runtime::ProcessWaitChannel,
        cpu: u64,
    ) -> Result<(), NativeProcessError>;
    fn cross_cow_supply(&self, address: UserVa, cpu: u64) -> Result<(), NativeProcessError> {
        let _ = (address, cpu);
        Err(NativeProcessError::Unsupported)
    }
}

impl<T: ForkStockCrossing> ForkStockCrossing for &T {
    fn ipc_binding(
        &self,
    ) -> Option<(
        carrick_el1_abi::ipc::IpcRegion<'_>,
        &carrick_el1_abi::ipc_tables::IpcTableMap,
    )> {
        T::ipc_binding(self)
    }
    fn cross_child_reclaim(&self, mm: ReservationMm, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_child_reclaim(mm, cpu)
    }
    fn cross_exec_adopt(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_exec_adopt(record_gpa, cpu)
    }
    fn cross_exec_cancel(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_exec_cancel(record_gpa, cpu)
    }
    fn cross_exec_settle(
        &self,
        predecessor: ReservationMm,
        successor: ReservationMm,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        (**self).cross_exec_settle(predecessor, successor, cpu)
    }
    fn cross_cow_supply(&self, address: UserVa, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_cow_supply(address, cpu)
    }
    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_child_retire(record_gpa, cpu)
    }
    fn cross_wait_channel_wake(
        &self,
        channel: super::native_process_runtime::ProcessWaitChannel,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        (**self).cross_wait_channel_wake(channel, cpu)
    }

    fn open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
        (**self).open_table()
    }
    fn fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        (**self).fd_map()
    }

    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_fork_stock(record_gpa, cpu)
    }

    fn cross_root_exit(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_root_exit(record_gpa, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HvcForkStockCrossing;

impl ForkStockCrossing for HvcForkStockCrossing {
    fn cross_exec_adopt(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_exec_adopt(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Stale)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_exec_cancel(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_exec_cancel(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Stale)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_exec_settle(
        &self,
        predecessor: ReservationMm,
        successor: ReservationMm,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_exec_settle(
                predecessor.raw(),
                successor.raw(),
                cpu,
            )
            .map_err(|_| NativeProcessError::Stale)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (predecessor, successor, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_child_reclaim(&self, mm: ReservationMm, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_child_reclaim(mm.raw(), cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (mm, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_cow_supply(&self, address: UserVa, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_cow_supply(address.raw(), cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (address, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_child_retire(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
    fn cross_wait_channel_wake(
        &self,
        channel: super::native_process_runtime::ProcessWaitChannel,
        cpu: u64,
    ) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_wait_channel_wake(
                channel.mm.raw(),
                channel.address.get(),
                cpu,
            )
            .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (channel, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }

    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_fork_stock(record_gpa, cpu).map_err(|status| {
                // SAFETY: the synchronous crossing retains its owned,
                // aligned loan or settlement record on this EL1 stack.
                let tag = unsafe { *(record_gpa as *const u64) };
                let kind = carrick_el1_abi::ForkStockKind::decode(tag);
                let reply = if kind == Some(carrick_el1_abi::ForkStockKind::Loan) {
                    // Only consume an already refused reply. A malformed
                    // transport status must not consume a successful loan.
                    let exchange = unsafe { &mut *(record_gpa as *mut ForkStockExchange) };
                    if exchange.status == 2 {
                        exchange
                            .request()
                            .and_then(|request| exchange.take(request))
                            .and_then(Result::err)
                    } else {
                        None
                    }
                } else {
                    None
                };
                refused(
                    if kind == Some(carrick_el1_abi::ForkStockKind::Reserve) {
                        NativeForkStage::Reserve
                    } else {
                        NativeForkStage::StockCrossing
                    },
                    super::native_fork_refusal::NativeForkCause::StockCrossing { status, reply },
                )
            })
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }

    fn cross_root_exit(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            carrick_el1::isa::aarch64::cross_hvc_root_exit(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
}

static RETIRED_SPACES: super::retired_spaces::RetiredSpaces =
    super::retired_spaces::RetiredSpaces::new();

pub struct Aarch64Venue;

impl OwnerVenue<Aarch64ParkedContext> for Aarch64Venue {
    fn space_access(
        zone: &ZoneTables<Aarch64ParkedContext>,
        slot: SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, Aarch64ParkedContext> {
        carrick_core::wait::space_access(zone, slot, release)
    }

    fn deliver_completion(
        zone: &ZoneTables<Aarch64ParkedContext>,
        slot: SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
    ) {
        crate::sched::object_wait::deliver_completion(zone, slot, effects);
    }

    fn encode_error(error: carrick_core::mm::transaction::MmError) -> u32 {
        error.errno()
    }

    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}

fn release(
    zone: &ZoneTables<Aarch64ParkedContext>,
    waker: carrick_sched_core::Waker,
    effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
) {
    match waker {
        carrick_sched_core::Waker::El1 { slot } => {
            crate::sched::object_wait::deliver_completion(zone, slot, effects);
        }
        carrick_sched_core::Waker::Host => {
            crate::sched::object_wait::deliver_host_completion(zone, effects);
        }
    }
}

#[cfg(target_os = "none")]
pub type PinnedExtent = super::mm_portal::production::GuestMetadataPin;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy, Debug)]
pub enum HostGuestMetadataPin {}

#[cfg(not(target_os = "none"))]
unsafe impl carrick_el1_abi::PinnedMetadataExtent for HostGuestMetadataPin {
    fn extent(&self) -> carrick_el1_abi::MetadataExtent {
        match *self {}
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        match *self {}
    }
}

#[cfg(not(target_os = "none"))]
pub type PinnedExtent = HostGuestMetadataPin;

pub type Portal<'a> = carrick_core::mm::transaction::MmPortal<
    'a,
    PinnedExtent,
    LinuxReservationPolicy,
    NativeReservationGeometry,
    Aarch64Venue,
    Aarch64Mmu,
    Aarch64ParkedContext,
>;

pub struct Aarch64NativeProcessService<'a, X = HvcForkStockCrossing> {
    pub task: &'a CurrentTask,
    pub slot: SlotId,
    pub zone: &'a ZoneTables<Aarch64ParkedContext>,
    pub roots: &'a SharedReservations,
    pub carrier: NonZeroU64,
    pub crossing: X,
    pub words: Option<&'a (dyn LiveDescriptorWords + 'a)>,
    residency: Option<&'a carrick_el1_abi::FrameGrantResidencyTable>,
}

struct Aarch64ExecSuccessorSlot<'a> {
    zone: &'a ZoneTables<Aarch64ParkedContext>,
    roots: &'a SharedReservations,
    carrier: NonZeroU64,
    worker: u32,
    index: SpaceIndex,
    mm: ReservationMm,
    generation: NonZeroU64,
    armed: bool,
}

impl ExecSuccessorSlot for Aarch64ExecSuccessorSlot<'_> {
    fn mm(&self) -> ReservationMm {
        self.mm
    }

    fn root_generation(&self) -> NonZeroU64 {
        self.generation
    }

    fn prepare_adoption(&self) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
        let portal: Portal<'_> =
            carrick_core::mm::transaction::MmPortal::for_zone(self.carrier, self.roots, self.zone);
        let mut root = portal
            .root_any(self.mm, self.worker)
            .map_err(|_| NativeProcessError::Stale)?;
        if root.incarnation().raw() != self.generation.get() {
            return Err(NativeProcessError::Stale);
        }
        root.finish_import()
            .map_err(|_| NativeProcessError::Stale)?;
        // SAFETY: this token owns the exact root just admitted above.
        Ok(unsafe {
            carrick_core_abi::El1MmHandle::from_admitted_owner(
                self.carrier,
                self.mm,
                self.generation,
            )
        })
    }

    fn commit(mut self: Box<Self>) {
        self.armed = false;
    }
}

impl Drop for Aarch64ExecSuccessorSlot<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let portal: Portal<'_> =
            carrick_core::mm::transaction::MmPortal::for_zone(self.carrier, self.roots, self.zone);
        if let Ok(root) = portal.root_any(self.mm, self.worker) {
            let _ = root.retire();
        }
        self.zone.spaces.free(self.index);
    }
}

/// ARM mechanics for the shared exact-MM native user-write continuation.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct NativeWriteVenue<'a, X> {
    task: &'a CurrentTask,
    slot: SlotId,
    crossing: &'a X,
    slots: &'a carrick_el1_abi::MmPortalSlots,
    prepared: carrick_el1::fault::HardwarePreparedResolver,
    cow: crate::cow_resolver::HardwareCowResolver,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl<X: ForkStockCrossing> UserWriteVenue<Aarch64ParkedContext> for NativeWriteVenue<'_, X> {
    type Prepared = carrick_el1::fault::HardwarePreparedResolver;
    type Cow = crate::cow_resolver::HardwareCowResolver;
    type Error = NativeProcessError;

    fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow> {
        SelectionVenues {
            prepared: &mut self.prepared,
            cow: &mut self.cow,
            residency: carrick_el1::isa::frame_grant_residency_guest(),
            slot: u32::from(self.slot.raw()),
        }
    }

    fn settle_completions(&mut self, _: &UserWriteRequest<'_>) -> Result<(), Self::Error> {
        // Host settlement runs at the next exact-MM exclusion; provisioning
        // adds an unmapped inventory extent and does not inspect old mappings.
        Ok(())
    }

    fn supply_cow(
        &mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<(), Self::Error> {
        let slot = self
            .slots
            .grant(usize::from(self.slot.raw()))
            .ok_or(NativeProcessError::Stale)?;
        if !slot.publish_cow_fault_selection(window.operation.sequence.get(), window) {
            return Err(NativeProcessError::Busy);
        }
        self.crossing
            .cross_cow_supply(UserVa::new(window.fault_page), u64::from(self.slot.raw()))
    }

    fn copy(
        &mut self,
        fence: &carrick_core::mm::transfer::ValidatedChunk<'_, Aarch64ParkedContext>,
        bytes: &[u8],
    ) -> bool {
        let mut copy = crate::lifecycle::LinuxUserCopy(crate::file::ValidatedCopy {
            task: self.task,
            validator: &crate::file::HardwareValidator,
        });
        carrick_personality_linux::lifecycle::UserCopy::copy_out(
            &mut copy,
            UserVa::new(fence.selected().va.raw()),
            bytes,
        )
    }
}

impl<'a> Aarch64NativeProcessService<'a, HvcForkStockCrossing> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    pub fn new(task: &'a CurrentTask, slot: SlotId) -> Result<Self, NativeProcessError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let carrier = slots.carrier().ok_or(NativeProcessError::Stale)?;
        let zone = unsafe {
            &*(carrick_el1_abi::EL1_ZONE_BASE
                as *const carrick_sched_core::ZoneTables<Aarch64ParkedContext>)
        };
        let roots = reservations::shared_guest();
        Ok(Self {
            task,
            slot,
            zone,
            roots,
            carrier,
            crossing: HvcForkStockCrossing,
            words: None,
            residency: None,
        })
    }
}

impl<'a, X: ForkStockCrossing> Aarch64NativeProcessService<'a, X> {
    pub fn with_crossing(
        task: &'a CurrentTask,
        slot: SlotId,
        zone: &'a ZoneTables<Aarch64ParkedContext>,
        roots: &'a SharedReservations,
        carrier: NonZeroU64,
        crossing: X,
    ) -> Self {
        Self {
            task,
            slot,
            zone,
            roots,
            carrier,
            crossing,
            words: None,
            residency: None,
        }
    }

    pub fn with_words(mut self, words: &'a (dyn LiveDescriptorWords + 'a)) -> Self {
        self.words = Some(words);
        self
    }

    pub fn with_fault_residency(
        mut self,
        residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
    ) -> Self {
        self.residency = Some(residency);
        self
    }

    fn worker(&self) -> u32 {
        u32::from(self.slot.raw())
    }

    fn portal(&self) -> Result<Portal<'_>, NativeProcessError> {
        Ok(carrick_core::mm::transaction::MmPortal::for_zone(
            self.carrier,
            self.roots,
            self.zone,
        ))
    }
}

impl<'a, X: ForkStockCrossing> NativeProcessService<'a, Aarch64ParkedContext>
    for Aarch64NativeProcessService<'a, X>
{
    type Mm = Mm;
    // Boxed: fork moves the prepared MM through several frames and refusal
    // paths; by value each move held another copy on the EL1 stack (#705).
    type PreparedMm = Box<Prepared<'a>>;
    type Born = Born;
    fn prepare_exec_successor_slot(
        &self,
        mm: ReservationMm,
    ) -> Result<Box<dyn ExecSuccessorSlot + 'a>, NativeProcessError> {
        let heap = ReservationRange::new(
            carrick_personality_linux::mm::LINUX_HEAP_BASE,
            carrick_personality_linux::mm::LINUX_HEAP_BASE
                + carrick_personality_linux::mm::LINUX_HEAP_SIZE,
        )
        .ok_or(NativeProcessError::Invalid)?;
        let arena = ReservationRange::new(
            carrick_personality_linux::mm::LINUX_MMAP_BASE,
            carrick_personality_linux::mm::LINUX_MMAP_BASE
                + carrick_personality_linux::mm::LINUX_MMAP_SIZE_MAX,
        )
        .ok_or(NativeProcessError::Invalid)?;
        let index = self
            .zone
            .spaces
            .publish_closed_with_layout(mm.raw(), 0, 0, heap.start(), arena.start())
            .ok_or(NativeProcessError::Exhausted)?;
        if !self.zone.spaces.mark_initial_bindable(index) {
            self.zone.spaces.free(index);
            return Err(NativeProcessError::Stale);
        }
        if self
            .roots
            .publish(
                index.index(),
                mm,
                carrick_el1::memory::reservations::Layout {
                    heap,
                    arena,
                    brk: heap.start(),
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .is_err()
        {
            self.zone.spaces.free(index);
            return Err(NativeProcessError::Stale);
        }
        let generation = match self.portal()?.root_any(mm, self.worker()) {
            Ok(root) => NonZeroU64::new(root.incarnation().raw()),
            Err(_) => None,
        };
        let Some(generation) = generation else {
            if let Ok(root) = self.portal()?.root_any(mm, self.worker()) {
                let _ = root.retire();
            }
            self.zone.spaces.free(index);
            return Err(NativeProcessError::Stale);
        };
        Ok(Box::new(Aarch64ExecSuccessorSlot {
            zone: self.zone,
            roots: self.roots,
            carrier: self.carrier,
            worker: self.worker(),
            index,
            mm,
            generation,
            armed: true,
        }))
    }
    fn cancel_exec_successor(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
    ) -> Result<(), NativeProcessError> {
        let mut cancellation = carrick_el1_abi::NativeExecCancellation::new(receipt);
        let crossed = self.crossing.cross_exec_cancel(
            &raw mut cancellation as *mut _ as u64,
            u64::from(self.worker()),
        );
        let accepted = cancellation.take(receipt);
        if crossed.is_ok() && accepted == Some(Ok(())) {
            Ok(())
        } else {
            Err(NativeProcessError::Stale)
        }
    }
    #[inline(never)]
    fn adopt_exec_successor(
        &self,
        identity: carrick_core_abi::service::ServiceIdentity,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        manifest: &carrick_core_abi::service::ExecSuccessorManifest,
    ) -> Result<NativeExecSuccessor<Self::Mm, Aarch64ParkedContext>, NativeProcessError> {
        let successor = manifest
            .open(identity, receipt)
            .ok_or(NativeProcessError::Stale)?;
        let index = self
            .zone
            .spaces
            .find(successor.successor_mm.raw())
            .ok_or(NativeProcessError::Stale)?;
        let manifest_address = KernelVa::new(core::ptr::from_ref(manifest).addr() as u64);
        let mut adoption = carrick_el1_abi::NativeExecAdoption::new(receipt, manifest_address)
            .ok_or(NativeProcessError::Invalid)?;
        let crossed = self
            .crossing
            .cross_exec_adopt(&raw mut adoption as *mut _ as u64, u64::from(self.worker()));
        let accepted = adoption.take(receipt, manifest_address);
        if crossed.is_err() || accepted != Some(Ok(())) {
            return Err(NativeProcessError::Stale);
        }
        let expected_ttbr =
            (u64::from(successor.asid.raw()) << 48) | successor.root.address().raw();
        if self
            .zone
            .spaces
            .closed_root_identity(index, successor.successor_mm.raw())
            != Some(expected_ttbr)
        {
            return Err(NativeProcessError::Stale);
        }
        let address = AddressContext {
            root: successor.root,
            mm: MmGeneration::new(
                NonZeroU64::new(successor.successor_mm.raw()).ok_or(NativeProcessError::Stale)?,
            ),
            generation: ContextGeneration::new(successor.root_generation),
        };
        let mut native = carrick_sched_core::ThreadCtx::ZERO;
        native.pc = successor.entry.raw();
        native.sp_el0 = successor.stack_pointer.raw();
        Ok(NativeExecSuccessor {
            mm: address,
            address,
            words: Box::new(Aarch64ParkedContext::from_parts(native, address)),
        })
    }
    #[inline(never)]
    fn finish_exec_successor(
        &self,
        predecessor: AddressContext<RootGpa>,
        successor: AddressContext<RootGpa>,
    ) -> Result<(), NativeProcessError> {
        let predecessor_mm = ReservationMm::new(predecessor.mm.raw().get())
            .ok_or(NativeProcessError::Quarantined)?;
        let successor_mm =
            ReservationMm::new(successor.mm.raw().get()).ok_or(NativeProcessError::Quarantined)?;
        let predecessor_index = self
            .zone
            .spaces
            .find(predecessor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        let successor_index = self
            .zone
            .spaces
            .find(successor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        let predecessor_grant = self
            .zone
            .spaces
            .grant(predecessor_index, predecessor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        self.zone.spaces.close(predecessor_index);

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let idle = self.zone.spaces.idle_ttbr();
            if idle == 0 {
                return Err(NativeProcessError::Quarantined);
            }
            crate::sched::ThreadCpu::set_translation(&mut crate::sched::HardwareCpu, idle, idle);
        }
        self.zone.release_space(self.slot);
        Aarch64Venue::space_access(self.zone, self.slot).open(successor_index);
        let successor_grant = self
            .zone
            .install_space(self.slot, successor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            crate::sched::ThreadCpu::set_translation(
                &mut crate::sched::HardwareCpu,
                successor_grant.ttbr0,
                successor_grant.ttbr1,
            );
            crate::sched::ThreadCpu::invalidate_asid(
                &mut crate::sched::HardwareCpu,
                predecessor_grant.ttbr0,
            );
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        let _ = (successor_grant, predecessor_grant);

        RETIRED_SPACES.push(super::retired_spaces::RetiredSpace {
            carrier: self.carrier,
            zone: core::ptr::from_ref(self.zone).addr(),
            roots: core::ptr::from_ref(self.roots).addr(),
            mm: predecessor_mm,
        });
        {
            let owner = self.portal().map_err(|_| NativeProcessError::Quarantined)?;
            RETIRED_SPACES
                .drain_portal(
                    &owner,
                    self.zone,
                    carrick_sched_core::ZONE_SLOTS,
                    self.worker(),
                )
                .map_err(|_| NativeProcessError::Quarantined)?;
        }
        self.crossing
            .cross_exec_settle(predecessor_mm, successor_mm, u64::from(self.worker()))
    }
    fn exec_fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        self.crossing.fd_map()
    }
    fn exec_open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
        self.crossing.open_table()
    }
    #[inline(never)]
    fn apply_fault_reply(
        &mut self,
        slot: &carrick_el1_abi::PortalGrantSlot,
    ) -> Result<(), carrick_core::mm::transaction::MmError> {
        use carrick_core::mm::transaction::MmError;
        let owner = self.portal().map_err(|_| MmError::Stale)?;
        // `Supplied` authenticates the host's retained reply, not continued
        // ownership of the faulting instruction. Replacement can make any
        // pre-claim identity below stale. Retry the unchanged fault so the
        // current mapping, rather than this old reply, decides its validity.
        let Some(window) = slot.window() else {
            return Ok(());
        };
        let target = match carrick_core::mm::frames::grant_target(&owner, window, self.worker()) {
            Ok(target) => target,
            Err(MmError::Stale) => return Ok(()),
            Err(error) => return Err(error),
        };
        let root = target.grant().ttbr0;
        let live = if let Some(words) = self.words {
            PreparedWords::Borrowed(words)
        } else {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            {
                let words = match super::mm_portal::production::current_mm_words(
                    carrick_el1::isa::aarch64::hardware_live_ttbr(),
                    root,
                    &CURRENT_MM_MAINTENANCE,
                ) {
                    Ok(words) => words,
                    Err(_) => return Ok(()),
                };
                PreparedWords::Owned(Box::new(words))
            }
            #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
            {
                return Err(MmError::Core);
            }
        };
        let residency = if let Some(residency) = self.residency {
            residency
        } else {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            {
                carrick_el1::isa::frame_grant_residency_guest()
            }
            #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
            {
                return Err(MmError::Core);
            }
        };
        let receipt = carrick_core::mm::frames::apply_grant::<Aarch64Mmu, _>(
            slot,
            &*live,
            residency,
            target,
            || {
                #[cfg(all(target_os = "none", target_arch = "aarch64"))]
                crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, root);
                #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
                let _ = root;
            },
        );
        let owner_handle = unsafe {
            // SAFETY: the portal authenticated this exact window and owner
            // before the descriptor was claimed. The carrier reauthenticates
            // the stopped execution and root during settlement.
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                window.operation.carrier,
                window.operation.mm,
                window.operation.incarnation,
            )
        };
        let reply_address =
            carrick_guest_arch::KernelVa::new(core::ptr::from_ref(slot).addr() as u64);
        // Keep the aligned wire record in one caller-owned slot. Returning it
        // through Option and moving it through error adapters retains several
        // aggregate buffers beneath the backing-reply descriptor path.
        let mut settlement = carrick_el1_abi::NativeDescriptorSettlement::EMPTY;
        settlement
            .initialize(owner_handle, window.operation.sequence, reply_address)
            .ok_or(MmError::Stale)?;
        let crossed = self.crossing.cross_fork_stock(
            &raw mut settlement as *mut _ as u64,
            u64::from(self.worker()),
        );
        match settlement.take(owner_handle, window.operation.sequence, reply_address) {
            Some(Ok(())) => crossed.map_err(|_| MmError::Stale)?,
            Some(Err(())) => return Err(MmError::Stale),
            None => {
                crossed.map_err(|_| MmError::Stale)?;
                return Err(MmError::Stale);
            }
        }
        let Some(receipt) = receipt else {
            return Ok(());
        };
        if matches!(
            receipt.outcome,
            carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_)
                | carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Refused(
                    carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::Occupied
                        | carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::StaleRoot
                )
        ) {
            // A competing publication or changed reservation invalidates this
            // reply, not the instruction. Retry under the current mapping;
            // the ordinary fault policy decides whether access is still valid.
            Ok(())
        } else {
            Err(MmError::Stale)
        }
    }

    fn service_mm_handle(
        &self,
        mm: &Mm,
    ) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
        self.portal()?
            .admitted_handle(
                ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?,
                u32::from(self.slot.raw()),
            )
            .map_err(|_| NativeProcessError::Stale)
    }

    /// The HVC root exit crossing becomes the host's whole-process terminal
    /// (`TrapError::NativeRootExit`), which ends every host and zone thread.
    fn root_exit_ends_run(&self) -> bool {
        true
    }

    fn prepare_mm(
        &mut self,
        parent: &Self::Mm,
        words: &Aarch64ParkedContext,
        child_mm: MmGeneration,
    ) -> Result<Self::PreparedMm, NativeProcessError> {
        if !words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        let owner = self.portal()?;
        // As on x86, a refused drain keeps its entry queued for the next
        // drain; an earlier child's retirement never refuses this fork.
        let _retry_at_next_drain = RETIRED_SPACES.drain_portal(
            &owner,
            self.zone,
            carrick_sched_core::ZONE_SLOTS,
            self.worker(),
        );
        let mm = ReservationMm::new(parent.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let live = if let Some(words) = self.words {
            PreparedWords::Borrowed(words)
        } else {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            {
                let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
                let words = super::mm_portal::production::current_mm_words(
                    ttbr0,
                    ttbr0,
                    &CURRENT_MM_MAINTENANCE,
                )
                .map_err(|_| NativeProcessError::Stale)?;
                PreparedWords::Owned(Box::new(words))
            }
            #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
            {
                return Err(NativeProcessError::Stale);
            }
        };
        let capacity = owner
            .fork_mapping_count(mm, self.worker())
            .map_err(|e| refused(NativeForkStage::MappingCount, e))?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(capacity)
            .map_err(|_| NativeProcessError::Exhausted)?;
        let (operation, generation, count, layout) = {
            let index = owner
                .spaces
                .find(mm.raw())
                .ok_or(NativeProcessError::Stale)?;
            let access = owner
                .space_access(self.worker())
                .map_err(|e| refused(NativeForkStage::SpaceAccess, e))?;
            let _editor = access
                .try_begin_edit(
                    index,
                    mm.raw(),
                    NonZeroU64::new(u64::from(self.worker()) + 1)
                        .ok_or(NativeProcessError::Stale)?,
                )
                .ok_or_else(|| {
                    super::native_fork_refusal::busy(NativeForkStage::ParentSpaceEdit)
                })?;
            let mut root = owner
                .root(mm, self.worker())
                .map_err(|e| refused(NativeForkStage::ParentRoot, e))?;
            if !root.fork_ready() {
                return Err(super::native_fork_refusal::busy(
                    NativeForkStage::ParentForkReady,
                ));
            }
            let mut full = false;
            root.observe_mappings(&mut |mapping| {
                if mappings.len() == mappings.capacity() {
                    full = true;
                } else {
                    mappings.push(mapping);
                }
            })
            .map_err(|e| refused(NativeForkStage::ObserveMappings, e))?;
            if full {
                return Err(NativeProcessError::Exhausted);
            }
            let operation = PortalOperation {
                carrier: owner.carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())
                    .ok_or(NativeProcessError::Stale)?,
                sequence: root
                    .next_transfer_sequence()
                    .map_err(|e| refused(NativeForkStage::TransferSequence, e))?,
            };
            let mut count = ForkCensus {
                child: 0,
                parent: 0,
                live: 0,
                custody: mappings
                    .iter()
                    .filter(|m| {
                        m.host_backing.is_some()
                            && !m.flags.intersects(
                                carrick_el1_abi::ReservationNodeFlags::DONTFORK
                                    .union(carrick_el1_abi::ReservationNodeFlags::WIPEONFORK),
                            )
                    })
                    .count(),
            };
            census_table::<Aarch64Mmu, _, _>(
                &LinuxForkPolicy,
                &*live,
                &mappings,
                parent.root.address().raw(),
                0,
                0,
                &mut count,
            )
            .map_err(|e| refused(NativeForkStage::Census, e))?;
            (operation, root.generation(), count, root.layout())
        };
        let request = ForkStockRequest {
            binding: common_entry::execution_binding(self.task),
            context: *parent,
            operation,
            parent_generation: generation,
            child_mm: ReservationMm::new(child_mm.raw().get()).ok_or(NativeProcessError::Stale)?,
            child_bytes: (count.child as u64)
                .checked_mul(8)
                .ok_or(NativeProcessError::Exhausted)?,
            parent_bytes: (count.parent as u64)
                .checked_mul(8)
                .ok_or(NativeProcessError::Exhausted)?
                .max(4096),
        };
        let mut exchange = ForkStockExchange::new(request).ok_or(NativeProcessError::Invalid)?;
        let crossed = self
            .crossing
            .cross_fork_stock(&raw mut exchange as *mut _ as u64, u64::from(self.worker()));
        let loan = match exchange.take(request) {
            Some(Ok(loan)) => {
                crossed?;
                loan
            }
            Some(Err(_)) => return Err(NativeProcessError::Exhausted),
            None => {
                crossed?;
                return Err(NativeProcessError::Stale);
            }
        };
        if loan.lifecycle.page.raw() == self.task.metadata.lifecycle_page.load(Ordering::Acquire) {
            return Err(NativeProcessError::Stale);
        }
        unsafe {
            ThreadLifecyclePage::initialize_at(
                loan.lifecycle.page.raw() as *mut ThreadLifecyclePage
            );
            let controls = loan.lifecycle.controls.raw() as *mut ThreadControlSlot;
            for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
                // The accepted loan already carries the owner's retained aliases.
                if (&*controls.add(index))
                    .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
                    .is_err()
                {
                    return Err(abandon_loan(
                        &self.crossing,
                        self.worker(),
                        &loan,
                        None,
                        NativeProcessError::Stale,
                    ));
                }
            }
        }
        let Some(asid) = loan.asid else {
            return Err(abandon_loan(
                &self.crossing,
                self.worker(),
                &loan,
                None,
                NativeProcessError::Stale,
            ));
        };
        let ttbr0 = (u64::from(asid.raw()) << 48)
            | (loan.request.child_tables.base & AARCH64_ROOT_ADDRESS_MASK);
        let Some(index) = owner
            .spaces
            .publish_closed(child_mm.raw().get(), ttbr0, ttbr0)
        else {
            return Err(abandon_loan(
                &self.crossing,
                self.worker(),
                &loan,
                None,
                NativeProcessError::Exhausted,
            ));
        };
        let boxed_prepared = match FallibleBox::try_reserve() {
            Ok(slot) => slot,
            Err(_) => {
                owner.spaces.free(index);
                return Err(abandon_loan(
                    &self.crossing,
                    self.worker(),
                    &loan,
                    None,
                    NativeProcessError::Exhausted,
                ));
            }
        };
        if let Err(e) = owner
            .roots
            .publish(index.index(), loan.request.child_mm, layout)
        {
            owner.spaces.free(index);
            return Err(abandon_loan(
                &self.crossing,
                self.worker(),
                &loan,
                None,
                refused(NativeForkStage::PublishRoot, e),
            ));
        }
        let scratch = match ForkScratch::bounded(
            loan.request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        ) {
            Ok(scratch) => scratch,
            Err(e) => {
                owner.spaces.free(index);
                return Err(abandon_loan(
                    &self.crossing,
                    self.worker(),
                    &loan,
                    None,
                    refused(NativeForkStage::Scratch, e),
                ));
            }
        };
        let plan = match owner.prepare_fork(loan.request, scratch, &*live, self.worker()) {
            Ok(plan) => plan,
            Err(e) => {
                #[cfg(all(target_os = "none", target_arch = "aarch64"))]
                let alias = {
                    use carrick_mmu_core::aarch64::owner_fork::{
                        STAGE1_TABLES_ALIAS_BASE, STAGE1_TABLES_PRIMARY_SIZE,
                    };
                    use carrick_mmu_core::owner_mmu::OwnerMmu;
                    (e == carrick_core::mm::transaction::MmError::NoMemory
                        && loan.request.child_tables.len < STAGE1_TABLES_PRIMARY_SIZE)
                        .then(|| {
                            let va = UserVa::new(
                                STAGE1_TABLES_ALIAS_BASE + loan.request.child_tables.len,
                            );
                            (
                                va,
                                Aarch64Mmu::translate(
                                    &*live,
                                    parent.root,
                                    va,
                                    carrick_mmu_core::aarch64::LeafAccess::Read,
                                    false,
                                )
                                .map(|translation| {
                                    translation.map(|translation| translation.output)
                                }),
                            )
                        })
                };
                #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
                let alias = None;
                owner.spaces.free(index);
                return Err(abandon_loan(
                    &self.crossing,
                    self.worker(),
                    &loan,
                    None,
                    super::native_fork_refusal::refused_prepare(e, &loan.request, alias),
                ));
            }
        };
        let mut custody = Vec::new();
        if custody.try_reserve_exact(plan.custody().len()).is_err() {
            owner.spaces.free(index);
            return Err(abandon_loan(
                &self.crossing,
                self.worker(),
                &loan,
                None,
                NativeProcessError::Exhausted,
            ));
        }
        custody.extend_from_slice(plan.custody());
        let mut child = match owner.publish_fork(plan, &*live, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(index);
                if matches!(e, carrick_core::mm::transaction::MmError::Core) {
                    return Err(NativeProcessError::Quarantined);
                }
                return Err(abandon_loan(
                    &self.crossing,
                    self.worker(),
                    &loan,
                    Some(&*live),
                    refused(NativeForkStage::Publish, e),
                ));
            }
        };
        let completion = child.completion();
        let Some(root) = RootGpa::page_aligned(FrameGpa::new(
            loan.request.child_tables.base & AARCH64_ROOT_ADDRESS_MASK,
        )) else {
            if child.abort(&owner, &*live, self.worker()).is_err() {
                return Err(NativeProcessError::Quarantined);
            }
            owner.spaces.free(index);
            return Err(abandon_loan(
                &self.crossing,
                self.worker(),
                &loan,
                Some(&*live),
                NativeProcessError::Stale,
            ));
        };
        let admitted = match AdmittedCustodyToken::reserve(
            &self.crossing,
            self.worker(),
            loan,
            completion,
            &custody,
            index,
        ) {
            Ok(admitted) => admitted,
            Err(e) => {
                if child.abort(&owner, &*live, self.worker()).is_err() {
                    return Err(NativeProcessError::Quarantined);
                }
                owner.spaces.free(index);
                return Err(abandon_loan(
                    &self.crossing,
                    self.worker(),
                    &loan,
                    Some(&*live),
                    e,
                ));
            }
        };
        let address = AddressContext {
            mm: child_mm,
            root,
            generation: ContextGeneration::new(completion.child.incarnation()),
        };
        Ok(boxed_prepared.put(Prepared {
            loan,
            child,
            words: live,
            address,
            admitted,
        }))
    }

    fn prepared_mm(&self, prepared: &Self::PreparedMm) -> Self::Mm {
        prepared.address
    }

    fn prepared_context(&self, prepared: &Self::PreparedMm) -> AddressContext<RootGpa> {
        prepared.address
    }

    fn child_lifecycle(&self, prepared: &Self::PreparedMm) -> NativeLifecycleResources<'a> {
        unsafe {
            NativeLifecycleResources {
                page: &*(prepared.loan.lifecycle.page.raw() as *const ThreadLifecyclePage),
                controls: core::slice::from_raw_parts(
                    prepared.loan.lifecycle.controls.raw() as *const ThreadControlSlot,
                    carrick_el1_abi::THREAD_POOL_ENTRIES + 1,
                ),
            }
        }
    }

    fn commit_mm(
        &mut self,
        mut prepared: Self::PreparedMm,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
        let result = self.portal().and_then(|owner| {
            prepared
                .child
                .commit(&owner, self.worker())
                .map_err(|e| refused(NativeForkStage::Commit, e))
        });
        match result {
            Ok(_) => Ok(Born {
                admitted: prepared.admitted,
            }),
            Err(e) => Err((e, prepared)),
        }
    }

    fn abort_mm(
        &mut self,
        mut prepared: Self::PreparedMm,
    ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
        let owner = match self.portal() {
            Ok(owner) => owner,
            Err(e) => return Err((e, prepared)),
        };
        if let Err(e) = prepared
            .child
            .abort(&owner, &*prepared.words, self.worker())
        {
            return Err((refused(NativeForkStage::Abort, e), prepared));
        }
        owner.spaces.free(prepared.admitted.index);
        if !super::fork_loan::scrub_tables(&*prepared.words, &prepared.loan) {
            return Err((NativeProcessError::Quarantined, prepared));
        }
        if !abort_loan(&self.crossing, self.worker(), &prepared.loan) {
            return Err((NativeProcessError::Quarantined, prepared));
        }
        Ok(())
    }

    fn settle_mm(&mut self, born: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
        if let Err(admitted) = born.admitted.consume(&self.crossing, self.slot, self.zone) {
            return Err((NativeProcessError::Quarantined, Born { admitted }));
        }
        Ok(())
    }

    fn copy_status(
        &mut self,
        parent: &Self::Mm,
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        let bytes = status.raw().to_ne_bytes();
        self.copy_signal_bytes(parent, address, &bytes)
    }

    fn quarantine_prepared(&mut self, prepared: Self::PreparedMm) {
        core::mem::forget(prepared);
        fatal();
    }

    fn quarantine_fork(
        &mut self,
        prepared: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, Aarch64ParkedContext>,
    ) {
        core::mem::forget(prepared);
        fatal();
    }

    fn quarantine_born(&mut self, born: Self::Born) {
        core::mem::forget(born);
        super::dispatch::invalid_completion(super::dispatch::NativeInvariant::PhysicalCustody(
            "admitted fork custody commit refused",
        ));
    }

    fn retire_mm(&mut self, mm: Self::Mm) {
        let binding = common_entry::execution_binding(self.task);
        let source = carrick_el1_abi::BornInZoneSource {
            zone: self.zone,
            slot: self.slot,
        };
        if !carrick_core::entry::terminal_matches(
            binding,
            source,
            carrick_sched_core::TerminalPhase::PendingRetirement,
        ) || binding.mm.raw() != mm.mm.raw().get()
        {
            fatal();
        }
        let Some(index) = self.zone.spaces.find(binding.mm.raw()) else {
            fatal();
        };
        self.zone.spaces.close(index);
        let Some(mut retire) = carrick_el1_abi::NativeChildRetire::new(binding, mm) else {
            fatal();
        };
        if self
            .crossing
            .cross_child_retire(&raw mut retire as u64, u64::from(self.worker()))
            .is_err()
            || !matches!(retire.take(binding, mm), Some(Ok(())))
        {
            fatal();
        }
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let live = carrick_el1::isa::aarch64::hardware_live_ttbr();
            let idle = self.zone.spaces.idle_ttbr();
            if live & AARCH64_ROOT_ADDRESS_MASK != mm.root.address().raw() || idle == 0 {
                fatal();
            }
            crate::sched::ThreadCpu::set_translation(&mut crate::sched::HardwareCpu, idle, idle);
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, live);
        }
        self.zone.release_space(self.slot);
        RETIRED_SPACES.push(super::retired_spaces::RetiredSpace {
            carrier: self.carrier,
            zone: core::ptr::from_ref(self.zone).addr(),
            roots: core::ptr::from_ref(self.roots).addr(),
            mm: ReservationMm::new(binding.mm.raw()).unwrap_or_else(|| fatal()),
        });
        // The final child may be the run's last fork. Once its translation
        // has been released, let the shared MM owner retire the closed root
        // now; a still-borrowed root remains in the existing retirement queue.
        {
            let owner = self.portal().unwrap_or_else(|_| fatal());
            let _retained_for_later_drain = RETIRED_SPACES.drain_portal(
                &owner,
                self.zone,
                carrick_sched_core::ZONE_SLOTS,
                self.worker(),
            );
        }
        // The portal borrow ends before physical table/lifecycle clearing.
        if self
            .crossing
            .cross_child_reclaim(
                ReservationMm::new(binding.mm.raw()).unwrap_or_else(|| fatal()),
                u64::from(self.worker()),
            )
            .is_err()
        {
            fatal();
        }
    }
    fn wake_unplaceable_wait(
        &mut self,
        channel: super::native_process_runtime::ProcessWaitChannel,
    ) -> Result<(), NativeProcessError> {
        self.crossing
            .cross_wait_channel_wake(channel, u64::from(self.worker()))
    }

    fn copy_signal_bytes(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        if self.task.mm.key.load(Ordering::Acquire) != mm.mm.raw().get() {
            return Err(NativeProcessError::Stale);
        }
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
            if ttbr0 & AARCH64_ROOT_ADDRESS_MASK != mm.root.address().raw() {
                return Err(NativeProcessError::Stale);
            }
            let owner = self.portal()?;
            let mm_key = ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
            let handle = owner
                .admitted_handle(mm_key, self.worker())
                .map_err(|_| NativeProcessError::Stale)?;
            let live = if let Some(words) = self.words {
                PreparedWords::Borrowed(words)
            } else {
                PreparedWords::Owned(Box::new(
                    super::mm_portal::production::current_mm_words(
                        ttbr0,
                        ttbr0,
                        &CURRENT_MM_MAINTENANCE,
                    )
                    .map_err(|_| NativeProcessError::Stale)?,
                ))
            };
            // SAFETY: the running carrier retains the fixed atomic portal
            // slots until this native checkpoint finishes.
            let slots = unsafe {
                &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
            };
            let mut venue = NativeWriteVenue {
                task: self.task,
                slot: self.slot,
                crossing: &self.crossing,
                slots,
                prepared: carrick_el1::fault::HardwarePreparedResolver,
                cow: crate::cow_resolver::HardwareCowResolver {
                    service_slot: Some(carrick_el1_abi::SlotId::new(self.slot.raw())),
                    completion: None,
                    publication: None,
                },
            };
            owner
                .write_user_bytes(
                    UserWriteRequest {
                        handle,
                        address,
                        bytes,
                        slot: self.slot,
                    },
                    &*live,
                    &mut venue,
                )
                .map_err(|failure| match failure {
                    UserWriteError::Owner(_) => NativeProcessError::Fault,
                    UserWriteError::Mechanics(error) => error,
                    UserWriteError::Busy => NativeProcessError::Busy,
                    UserWriteError::InvalidSource => NativeProcessError::Invalid,
                    UserWriteError::Fault => NativeProcessError::Fault,
                    UserWriteError::UnsupportedSupply => NativeProcessError::Unsupported,
                })
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let mut copy = crate::lifecycle::LinuxUserCopy(crate::file::ValidatedCopy {
                task: self.task,
                validator: &crate::file::HardwareValidator,
            });
            if !carrick_personality_linux::lifecycle::UserCopy::copy_out(&mut copy, address, bytes)
            {
                return Err(NativeProcessError::Fault);
            }
            Ok(())
        }
    }
    fn copy_syscall_output(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        if self.task.mm.key.load(Ordering::Acquire) != mm.mm.raw().get() {
            return Err(NativeProcessError::Stale);
        }
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
            if ttbr0 & AARCH64_ROOT_ADDRESS_MASK != mm.root.address().raw() {
                return Err(NativeProcessError::Stale);
            }
        }
        let mut copy = crate::lifecycle::LinuxUserCopy(crate::file::ValidatedCopy {
            task: self.task,
            validator: &crate::file::HardwareValidator,
        });
        if carrick_personality_linux::lifecycle::UserCopy::copy_out(&mut copy, address, bytes) {
            Ok(())
        } else {
            Err(NativeProcessError::Fault)
        }
    }
    fn copy_siginfo(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        info: &carrick_syscall_abi::LinuxSiginfo,
    ) -> Result<(), NativeProcessError> {
        // SAFETY: this canonical initialized ABI record owns all wire bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts(info as *const _ as *const u8, core::mem::size_of_val(info))
        };
        self.copy_signal_bytes(mm, address, bytes)
    }
    fn wake_effects(&mut self, effects: WakeEffects) {
        crate::sched::object_wait::deliver_wake_effects(self.zone, self.slot, effects);
    }
    fn request_ingress_producer_boundary(&mut self) {
        self.task.linux.mark_pending_host_work();
    }
    fn fork_fd_table(
        &mut self,
        parent_table: u64,
        child_table: u64,
    ) -> Result<(), NativeProcessError> {
        if !super::file_table::fork_fd_map(
            self.crossing.fd_map(),
            self.crossing.open_table(),
            parent_table,
            child_table,
        ) {
            return Err(NativeProcessError::Exhausted);
        }
        if let Some((region, map)) = self.crossing.ipc_binding()
            && let Some(parent) = map.lookup_authoritative(parent_table)
        {
            let result = region
                .fork_descriptors(
                    carrick_el1_abi::ipc::fd::TableId::from_raw(parent),
                    &carrick_sched_core::ShortLockSpin,
                    |child| {
                        map.publish_owned(child_table, child.to_raw())
                            .map_err(|_| carrick_el1_abi::ipc::fd::Error::NoMemory)
                    },
                )
                .map_err(|_| NativeProcessError::Exhausted);
            if let Err(error) = result {
                super::file_table::retire_fd_map(
                    self.crossing.fd_map(),
                    self.crossing.open_table(),
                    child_table,
                );
                return Err(error);
            }
        }
        Ok(())
    }
    fn retire_fd_table(&mut self, table: u64) {
        if let Some((region, map)) = self.crossing.ipc_binding()
            && let Some(raw) = map.take_owned(table)
        {
            super::ipc::retire_namespace(
                &region,
                carrick_el1_abi::ipc::fd::TableId::from_raw(raw),
                self.task,
            )
            .unwrap_or_else(|_| fatal());
        }
        super::file_table::retire_fd_map(self.crossing.fd_map(), self.crossing.open_table(), table);
        self.task.linux.mark_pending_host_work();
    }
}

pub fn cross_root_exit<X: ForkStockCrossing>(
    crossing: &mut X,
    task: &CurrentTask,
    status: LinuxWaitStatus,
    worker: u32,
) -> Result<(), NativeProcessError> {
    let binding = common_entry::execution_binding(task);
    let exit = carrick_core_abi::NativeRootExit::new(
        binding,
        status
            .terminal_status()
            .map_err(|_| NativeProcessError::Invalid)?,
    )
    .ok_or(NativeProcessError::Invalid)?;
    crossing.cross_root_exit(&exit as *const _ as u64, u64::from(worker))
}

fn fatal() -> ! {
    panic!("native aarch64 process service failure")
}
