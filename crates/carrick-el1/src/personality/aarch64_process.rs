//! Machine custody for the shared AArch64 native process owner.
//!
//! Implements [`NativeProcessService`] for [`Aarch64ParkedContext`] over [`carrick_mmu_core::owner_mmu::Aarch64Mmu`].
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use carrick_core::mm::fork::{ForkCensus, ForkScratch, PreparedOwnerFork, census_table};
use carrick_core::mm::transaction::OwnerVenue;
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, ForkStockExchange, ForkStockLoan, ForkStockRequest,
    ForkStockSettlement, PortalForkCustody, PortalOperation, ReservationMm, ThreadControlSlot,
    ThreadLifecyclePage,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, SlotId, UserVa,
};
use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_personality_linux::mm::{LinuxReservationPolicy, MmErrorLinux};
use carrick_sched_core::process::LinuxWaitStatus;
use carrick_sched_core::{
    AARCH64_ROOT_ADDRESS_MASK, Aarch64ParkedContext, SpaceIndex, WakeEffects, ZoneTables,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use super::common_entry;
use super::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use super::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
    NativeProcessRuntime, NativeProcessService,
};
use super::retired_spaces::{RetiredSpace, RetiredSpaces};
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use crate::memory::reservations;
use crate::memory::reservations::{NativeReservationGeometry, SharedReservations};

pub type Mm = AddressContext<RootGpa>;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct CurrentMmMaintenance;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for CurrentMmMaintenance {
    fn publish_barrier(&self) {
        let ttbr0 = crate::isa::aarch64::hardware_live_ttbr();
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
/// Closed child spaces awaiting retirement (shared protocol).
static RETIRED_SPACES: RetiredSpaces = RetiredSpaces::new();

fn drain_retired_spaces(
    owner: &Portal<'_>,
    zone: &ZoneTables<Aarch64ParkedContext>,
    worker: u32,
) -> Result<(), NativeProcessError> {
    RETIRED_SPACES.drain_portal(owner, zone, carrick_el1_abi::ZONE_SLOTS, worker)
}

pub fn registry() -> &'static NativeProcessRegistry<'static, Mm, Aarch64ParkedContext> {
    &REGISTRY
}

fn fork_progress(stage: carrick_el1_abi::NativeForkProgress) {
    #[cfg(target_os = "none")]
    carrick_el1_abi::record_native_fork_progress(stage);
    #[cfg(not(target_os = "none"))]
    let _ = stage;
}

fn fork_failure(stage: carrick_el1_abi::NativeForkFailureStage) {
    #[cfg(target_os = "none")]
    carrick_el1_abi::record_native_fork_failure(stage);
    #[cfg(not(target_os = "none"))]
    let _ = stage;
}

/// Admit only an exact published leader or thread-group member. The root
/// address is checked by the shared owner against the zone's live MM grant.
pub fn admit_entry(
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    record_incarnation: u64,
) -> Result<(Arc<Runtime>, Mm, Box<Aarch64ParkedContext>), NativeProcessError> {
    let (page, control) = task.lifecycle_refs().ok_or(NativeProcessError::Stale)?;
    let observed = Mm {
        root: RootGpa::page_aligned(FrameGpa::new(ttbr0 & AARCH64_ROOT_ADDRESS_MASK))
            .ok_or(NativeProcessError::Stale)?,
        mm: MmGeneration::new(
            NonZeroU64::new(task.mm.key.load(Ordering::Acquire))
                .ok_or(NativeProcessError::Stale)?,
        ),
        generation: ContextGeneration::new(
            NonZeroU64::new(record_incarnation).ok_or(NativeProcessError::Stale)?,
        ),
    };
    let address = if control.entry().is_some() {
        REGISTRY
            .group_address(
                source.zone,
                observed,
                page,
                task.visible_pid().ok_or(NativeProcessError::Stale)?,
            )
            .ok_or(NativeProcessError::Stale)?
    } else {
        observed
    };
    let words = Box::new(Aarch64ParkedContext::from_register(
        *native,
        ttbr0,
        address.mm.raw().get(),
        address.generation.raw().get(),
    ));
    if let Ok(runtime) = REGISTRY.for_entry(source, task, address) {
        if task.visible_pid() != Some(1) {
            fork_progress(carrick_el1_abi::NativeForkProgress::ChildEntered);
        }
        return Ok((runtime, address, words));
    }
    if control.entry().is_some() {
        let runtime = REGISTRY.register_thread(source, task, address, page, control)?;
        return Ok((runtime, address, words));
    }
    let runtime = Arc::new(NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source, task, page, control, address, address, *words,
    )?);
    REGISTRY.register_root(runtime.clone(), source, task, address)?;
    Ok((runtime, address, words))
}

pub struct Prepared<'a> {
    pub loan: ForkStockLoan,
    pub child: UnpublishedEl1Child<Aarch64Mmu>,
    pub words: PreparedWords<'a>,
    pub address: Mm,
    pub ttbr0: u64,
    pub custody: Vec<PortalForkCustody>,
}
/// Retained fork plan between census/stock preparation and guest-MM
/// publication. The first phase's stack frame is gone before publication.
pub struct PreparedStart<'a> {
    loan: Box<ForkStockLoan>,
    words: PreparedWords<'a>,
    plan: Option<Box<PreparedOwnerFork<Aarch64Mmu>>>,
    child: Option<UnpublishedEl1Child<Aarch64Mmu>>,
    index: SpaceIndex,
    child_mm: MmGeneration,
    ttbr0: u64,
    root: RootGpa,
    custody: Vec<PortalForkCustody>,
}

impl core::fmt::Debug for Prepared<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Prepared")
            .field("loan", &self.loan)
            .field("address", &self.address)
            .field("custody", &self.custody)
            .finish()
    }
}

pub struct Born<'a> {
    pub prepared: Box<Prepared<'a>>,
}

impl core::fmt::Debug for Born<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Born")
            .field("prepared", &self.prepared)
            .finish()
    }
}

pub trait ForkStockCrossing {
    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_root_exit(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError>;
}

impl<T: ForkStockCrossing> ForkStockCrossing for &T {
    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_fork_stock(record_gpa, cpu)
    }

    fn cross_root_exit(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_root_exit(record_gpa, cpu)
    }

    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        (**self).cross_child_retire(record_gpa, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HvcForkStockCrossing;

impl ForkStockCrossing for HvcForkStockCrossing {
    fn cross_fork_stock(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            crate::isa::aarch64::cross_hvc_fork_stock(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Fault)
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
            crate::isa::aarch64::cross_hvc_root_exit(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }

    fn cross_child_retire(&self, record_gpa: u64, cpu: u64) -> Result<(), NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            crate::isa::aarch64::cross_hvc_child_retire(record_gpa, cpu)
                .map_err(|_| NativeProcessError::Fault)
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (record_gpa, cpu);
            Err(NativeProcessError::Unsupported)
        }
    }
}

pub struct Aarch64Venue;

impl OwnerVenue<Aarch64ParkedContext> for Aarch64Venue {
    fn space_access(
        zone: &ZoneTables<Aarch64ParkedContext>,
        slot: SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, Aarch64ParkedContext> {
        carrick_core::wait::space_access(zone, slot, release)
    }

    fn deliver_completion(
        _: &ZoneTables<Aarch64ParkedContext>,
        _: SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
    ) {
        let (_, effects) = effects.deliver_handbacks(&mut |_| fatal());
        deliver_wakes(effects);
    }

    fn encode_error(error: carrick_core::mm::transaction::MmError) -> u32 {
        error.errno()
    }

    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}

fn release(
    _: &ZoneTables<Aarch64ParkedContext>,
    _: carrick_sched_core::Waker,
    effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
) {
    let (_, effects) = effects.deliver_handbacks(&mut |_| fatal());
    deliver_wakes(effects);
}

fn deliver_wakes(effects: WakeEffects) {
    for _slot in effects.sgi_slots() {
        // vCPU reschedule signaling
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
        }
    }

    pub fn with_words(mut self, words: &'a (dyn LiveDescriptorWords + 'a)) -> Self {
        self.words = Some(words);
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

    /// Clear the never-committed loan's lifecycle record and abort it. True
    /// when the carrier accepted the abort and holds no pending loan.
    fn abort_loan(&self, loan: &ForkStockLoan) -> bool {
        // SAFETY: the loan never published a birth; no reader remains.
        unsafe { super::fork_loan::clear_lifecycle(loan) };
        let mut settlement = carrick_el1_abi::ForkStockSettlement::abort(*loan);
        self.crossing
            .cross_fork_stock(
                &raw mut settlement as *mut _ as u64,
                u64::from(self.worker()),
            )
            .is_ok()
            && matches!(settlement.take(*loan), Some(Ok(())))
    }

    /// Every error after the stock crossing ends here, so a failed fork
    /// never strands this CPU's pending loan (each later fork on the CPU
    /// would be refused for capacity). `scrub` names the words of a refused
    /// publish that may have stored into the loaned tables; they are zeroed
    /// first so the abort's cleanliness check holds. Returns `error`, or
    /// `Quarantined` when the loan could not be returned and stays pending.
    fn abandon_loan(
        &self,
        loan: &ForkStockLoan,
        scrub: Option<&dyn LiveDescriptorWords>,
        error: NativeProcessError,
    ) -> NativeProcessError {
        if let Some(words) = scrub
            && !super::fork_loan::scrub_tables(words, loan)
        {
            return NativeProcessError::Quarantined;
        }
        if self.abort_loan(loan) {
            error
        } else {
            NativeProcessError::Quarantined
        }
    }

    /// The part of `prepare_mm_start` after the stock crossing granted
    /// `loan`. Any error returns with the space index it took freed; the
    /// caller then aborts the loan.
    #[allow(clippy::too_many_arguments)]
    fn prepare_loaned(
        &self,
        owner: &Portal<'_>,
        loan: Box<ForkStockLoan>,
        live: PreparedWords<'a>,
        layout: carrick_el1_abi::Layout,
        mapping_count: usize,
        count: ForkCensus,
        child_mm: MmGeneration,
    ) -> Result<Box<PreparedStart<'a>>, NativeProcessError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        let live = if self.words.is_none() {
            let child_window =
                carrick_el1_abi::fork_stock_table_window(loan.request.child_tables.base)
                    .ok_or(NativeProcessError::Stale)?;
            let parent_window =
                carrick_el1_abi::fork_stock_table_window(loan.request.parent_tables.base)
                    .ok_or(NativeProcessError::Stale)?;
            if child_window.physical_base != parent_window.physical_base {
                return Err(NativeProcessError::Stale);
            }
            let ttbr0 = crate::isa::aarch64::hardware_live_ttbr();
            let words = super::mm_portal::production::current_mm_words(
                ttbr0,
                ttbr0,
                &CURRENT_MM_MAINTENANCE,
                Some(loan.request.child_tables.base),
            )
            .map_err(|_| NativeProcessError::Stale)?;
            PreparedWords::Owned(Box::new(words))
        } else {
            live
        };
        // SAFETY: the carrier loaned this cold record exclusively to the fork.
        unsafe {
            (loan.lifecycle.page.raw() as *mut ThreadLifecyclePage)
                .write(ThreadLifecyclePage::new());
            let controls = loan.lifecycle.controls.raw() as *mut ThreadControlSlot;
            for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
                controls.add(index).write(ThreadControlSlot::new());
            }
        }
        let asid = loan.asid.ok_or(NativeProcessError::Stale)?;
        let ttbr0 = (u64::from(asid.raw()) << 48)
            | (loan.request.child_tables.base & AARCH64_ROOT_ADDRESS_MASK);
        let root = RootGpa::page_aligned(FrameGpa::new(
            loan.request.child_tables.base & AARCH64_ROOT_ADDRESS_MASK,
        ))
        .ok_or(NativeProcessError::Stale)?;
        let index = owner
            .spaces
            .publish_closed(child_mm.raw().get(), ttbr0, ttbr0)
            .ok_or(NativeProcessError::Exhausted)?;
        let free = |error: NativeProcessError| {
            owner.spaces.free(index);
            error
        };
        if let Err(e) = owner
            .roots
            .publish(index.index(), loan.request.child_mm, layout)
        {
            return Err(free(err(
                carrick_el1_abi::NativeForkFailureStage::RootPublication,
                e,
            )));
        }
        let scratch = ForkScratch::bounded(
            loan.request,
            mapping_count,
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(|e| free(err(carrick_el1_abi::NativeForkFailureStage::Scratch, e)))?;
        let plan = owner
            .prepare_fork(loan.request, scratch, &*live, self.worker())
            .map_err(|e| free(err(prepare_error_stage(e), e)))?;
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(plan.custody().len())
            .map_err(|_| free(NativeProcessError::Exhausted))?;
        custody.extend_from_slice(plan.custody());
        fork_progress(carrick_el1_abi::NativeForkProgress::Prepare);
        Ok(Box::new(PreparedStart {
            loan,
            words: live,
            plan: Some(Box::new(plan)),
            child: None,
            index,
            child_mm,
            ttbr0,
            root,
            custody,
        }))
    }
}

#[allow(dead_code)]
fn err(
    stage: carrick_el1_abi::NativeForkFailureStage,
    _e: impl core::fmt::Debug,
) -> NativeProcessError {
    #[cfg(target_os = "none")]
    carrick_el1_abi::record_native_fork_failure(stage);
    #[cfg(not(target_os = "none"))]
    let _ = stage;
    NativeProcessError::Fault
}

fn prepare_error_stage(
    error: carrick_core::mm::transaction::MmError,
) -> carrick_el1_abi::NativeForkFailureStage {
    use carrick_core::mm::transaction::MmError;
    use carrick_el1_abi::NativeForkFailureStage as Stage;
    match error {
        MmError::Invalid => Stage::PrepareInvalid,
        MmError::Stale => Stage::PrepareStale,
        MmError::Busy => Stage::PrepareBusy,
        MmError::NoMemory => Stage::PrepareNoMemory,
        MmError::MetadataRequired => Stage::PrepareMetadataRequired,
        MmError::Fault => Stage::PrepareFault,
        MmError::Core => Stage::PrepareCore,
        MmError::Table(_) => Stage::PrepareTable,
        MmError::Reservation(_) => Stage::PrepareReservation,
        MmError::Wait(_) => Stage::PrepareWait,
        MmError::UnsupportedExecutableCow => Stage::PrepareUnsupportedExecutableCow,
    }
}

fn publish_error_stage(
    error: carrick_core::mm::transaction::MmError,
) -> carrick_el1_abi::NativeForkFailureStage {
    use carrick_core::mm::transaction::MmError;
    use carrick_el1_abi::NativeForkFailureStage as Stage;
    match error {
        MmError::Invalid => Stage::PublishInvalid,
        MmError::Stale => Stage::PublishStale,
        MmError::Busy => Stage::PublishBusy,
        MmError::NoMemory => Stage::PublishNoMemory,
        MmError::MetadataRequired => Stage::PublishMetadataRequired,
        MmError::Fault => Stage::PublishFault,
        MmError::Core => Stage::PublishCore,
        MmError::Table(_) => Stage::PublishTable,
        MmError::Reservation(_) => Stage::PublishReservation,
        MmError::Wait(_) => Stage::PublishWait,
        MmError::UnsupportedExecutableCow => Stage::PublishUnsupportedExecutableCow,
    }
}

impl<'a, X: ForkStockCrossing> NativeProcessService<'a, Aarch64ParkedContext>
    for Aarch64NativeProcessService<'a, X>
{
    type Mm = Mm;
    type PreparedMmStart = Box<PreparedStart<'a>>;
    type PreparedMmPublished = Box<PreparedStart<'a>>;
    type PreparedMm = Box<Prepared<'a>>;
    type Born = Box<Born<'a>>;

    fn prepare_mm_start(
        &mut self,
        parent: &Self::Mm,
        words: Aarch64ParkedContext,
        child_mm: MmGeneration,
    ) -> Result<Self::PreparedMmStart, NativeProcessError> {
        if !words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        let owner = self.portal()?;
        drain_retired_spaces(&owner, self.zone, self.worker())?;
        let mm = ReservationMm::new(parent.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let live = if let Some(words) = self.words {
            PreparedWords::Borrowed(words)
        } else {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            {
                let ttbr0 = crate::isa::aarch64::hardware_live_ttbr();
                let words = super::mm_portal::production::current_mm_words(
                    ttbr0,
                    ttbr0,
                    &CURRENT_MM_MAINTENANCE,
                    None,
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
            .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::MappingCount, e))?;
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
                .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::SpaceAccess, e))?;
            let _editor = access
                .try_begin_edit(
                    index,
                    mm.raw(),
                    NonZeroU64::new(u64::from(self.worker()) + 1)
                        .ok_or(NativeProcessError::Stale)?,
                )
                .ok_or(NativeProcessError::Busy)?;
            let mut root = owner
                .root(mm, self.worker())
                .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Root, e))?;
            if !root.fork_ready() {
                return Err(NativeProcessError::Busy);
            }
            let mut full = false;
            root.observe_mappings(&mut |mapping| {
                if mappings.len() == mappings.capacity() {
                    full = true;
                } else {
                    mappings.push(mapping);
                }
            })
            .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::ObserveMappings, e))?;
            if full {
                return Err(NativeProcessError::Exhausted);
            }
            let operation = PortalOperation {
                carrier: owner.carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())
                    .ok_or(NativeProcessError::Stale)?,
                sequence: root.next_transfer_sequence().map_err(|e| {
                    err(carrick_el1_abi::NativeForkFailureStage::TransferSequence, e)
                })?,
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
            .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Census, e))?;
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
        let mut exchange =
            Box::new(ForkStockExchange::new(request).ok_or(NativeProcessError::Invalid)?);
        self.crossing.cross_fork_stock(
            &raw mut *exchange as *mut _ as u64,
            u64::from(self.worker()),
        )?;
        let loan = Box::new(
            exchange
                .take(request)
                .ok_or(NativeProcessError::Stale)?
                .map_err(|_| NativeProcessError::Exhausted)?,
        );
        // The carrier never loans a record a live MM uses (the parent's is
        // charged to it), so this refusal is a carrier custody fault. It is
        // the one post-crossing error that keeps the loan: an abort would
        // have the carrier clear this task's live record.
        if loan.lifecycle.page.raw() == self.task.metadata.lifecycle_page.load(Ordering::Acquire) {
            return Err(NativeProcessError::Stale);
        }
        let granted = *loan;
        self.prepare_loaned(&owner, loan, live, layout, mappings.len(), count, child_mm)
            .map_err(|error| self.abandon_loan(&granted, None, error))
    }

    fn prepare_mm_publish(
        &mut self,
        mut start: Self::PreparedMmStart,
    ) -> Result<Self::PreparedMmPublished, NativeProcessError> {
        let owner = self.portal()?;
        let Some(plan) = start.plan.take() else {
            owner.spaces.free(start.index);
            return Err(self.abandon_loan(&start.loan, None, NativeProcessError::Stale));
        };
        let child = match owner.publish_fork_boxed(plan, &*start.words, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(start.index);
                let error = err(publish_error_stage(e), e);
                // A refused publish may have stored into the loaned tables;
                // it rolled its parent edits back, so they are unlinked and
                // are scrubbed before the abort. `Core` means that rollback
                // itself failed: the parent may still link a loaned page, so
                // the loan stays pending rather than be scrubbed or reused.
                if matches!(e, carrick_core::mm::transaction::MmError::Core) {
                    return Err(NativeProcessError::Quarantined);
                }
                return Err(self.abandon_loan(&start.loan, Some(&*start.words), error));
            }
        };
        start.child = Some(child);
        fork_progress(carrick_el1_abi::NativeForkProgress::Publish);
        Ok(start)
    }

    fn prepare_mm_finish(
        &mut self,
        published: Self::PreparedMmPublished,
    ) -> Result<Self::PreparedMm, NativeProcessError> {
        let PreparedStart {
            loan,
            words,
            plan,
            child,
            index,
            child_mm,
            ttbr0,
            root,
            custody,
        } = *published;
        // Only a published child reaches here; a start whose publish never
        // ran stored nothing into the loaned tables and returns its loan.
        let Some(child) = child.filter(|_| plan.is_none()) else {
            self.portal()?.spaces.free(index);
            return Err(self.abandon_loan(&loan, None, NativeProcessError::Stale));
        };
        let completion = child.completion();
        let address = AddressContext {
            mm: child_mm,
            root,
            generation: ContextGeneration::new(completion.child.incarnation()),
        };
        Ok(Box::new(Prepared {
            loan: *loan,
            child,
            words,
            address,
            ttbr0,
            custody,
        }))
    }

    fn prepared_mm(&self, prepared: &Self::PreparedMm) -> Self::Mm {
        prepared.address
    }

    fn prepared_context(&self, prepared: &Self::PreparedMm) -> AddressContext<RootGpa> {
        prepared.address
    }

    fn fork_child_context(
        &self,
        parent: Aarch64ParkedContext,
        prepared: &Self::PreparedMm,
    ) -> Aarch64ParkedContext {
        parent.fork_child_with_register(prepared.address, prepared.ttbr0)
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
                .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Commit, e))
        });
        match result {
            Ok(_) => {
                fork_progress(carrick_el1_abi::NativeForkProgress::Commit);
                Ok(Box::new(Born { prepared }))
            }
            Err(e) => Err((e, prepared)),
        }
    }

    fn abort_mm(
        &mut self,
        mut prepared: Self::PreparedMm,
    ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
        let result = self.portal().and_then(|owner| {
            prepared
                .child
                .abort(&owner, &*prepared.words, self.worker())
                .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Abort, e))
        });
        if let Err(e) = result {
            return Err((e, prepared));
        }
        // The child was never executable, but invalidate its reserved ASID
        // before returning the table stock to a future address space.
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, prepared.ttbr0);
        // The graph rollback removed every possible reader of the record.
        if !self.abort_loan(&prepared.loan) {
            return Err((NativeProcessError::Quarantined, prepared));
        }
        Ok(())
    }

    fn settle_mm(&mut self, born: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
        let p = &born.prepared;
        let mut custody = Vec::new();
        if custody.try_reserve_exact(p.custody.len()).is_err() {
            fork_failure(carrick_el1_abi::NativeForkFailureStage::SettleCustody);
            return Err((NativeProcessError::Exhausted, born));
        }
        custody.extend(p.custody.iter().copied().map(PortalForkCustody::words));
        let Some(mut settlement) = ForkStockSettlement::new(
            p.loan,
            p.child.completion(),
            KernelVa::new(custody.as_ptr() as u64),
            custody.len() as u64,
        ) else {
            fork_failure(carrick_el1_abi::NativeForkFailureStage::SettleRecord);
            return Err((NativeProcessError::Stale, born));
        };
        if let Err(e) = self.crossing.cross_fork_stock(
            &raw mut settlement as *mut _ as u64,
            u64::from(self.worker()),
        ) {
            fork_failure(carrick_el1_abi::NativeForkFailureStage::SettleCrossing);
            return Err((e, born));
        }
        if !matches!(settlement.take(p.loan), Some(Ok(()))) {
            fork_failure(carrick_el1_abi::NativeForkFailureStage::SettleReply);
            return Err((NativeProcessError::Quarantined, born));
        }
        let owner = match self.portal() {
            Ok(owner) => owner,
            Err(error) => {
                fork_failure(carrick_el1_abi::NativeForkFailureStage::SettlePortal);
                return Err((error, born));
            }
        };
        let Some(index) = owner.spaces.find(p.address.mm.raw().get()) else {
            fork_failure(carrick_el1_abi::NativeForkFailureStage::SettleSpace);
            return Err((NativeProcessError::Stale, born));
        };
        let access = match owner.space_access(self.worker()) {
            Ok(access) => access,
            Err(e) => {
                return Err((
                    err(carrick_el1_abi::NativeForkFailureStage::BornSpaceAccess, e),
                    born,
                ));
            }
        };
        access.open(index);
        fork_progress(carrick_el1_abi::NativeForkProgress::Settle);
        Ok(())
    }

    fn copy_status(
        &mut self,
        parent: &Self::Mm,
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        if self.task.mm.key.load(Ordering::Acquire) != parent.mm.raw().get() {
            return Err(NativeProcessError::Stale);
        }
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let ttbr0 = crate::isa::aarch64::hardware_live_ttbr();
            if (ttbr0 & AARCH64_ROOT_ADDRESS_MASK) != parent.root.address().raw() {
                return Err(NativeProcessError::Stale);
            }
        }
        let bytes = status.raw().to_ne_bytes();
        let copied = unsafe {
            crate::file::copy_to_user_guarded(
                self.task,
                address.raw() as *mut u8,
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        if !copied {
            return Err(NativeProcessError::Fault);
        }
        Ok(())
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
        fatal();
    }

    fn retire_mm(&mut self, mm: Self::Mm) {
        // The runtime calls this only for a fork-born process's final exit.
        if mm.mm.raw().get() != self.task.mm.key.load(Ordering::Acquire) {
            fatal();
        }
        let owner = self.portal().unwrap_or_else(|_| fatal());
        let index = owner
            .spaces
            .find(mm.mm.raw().get())
            .unwrap_or_else(|| fatal());
        owner.spaces.close(index);
        let binding = common_entry::execution_binding(self.task);
        let Some(mut retire) = carrick_el1_abi::NativeChildRetire::new(binding, mm) else {
            fatal();
        };
        let crossed = self
            .crossing
            .cross_child_retire(&raw mut retire as u64, u64::from(self.worker()))
            .is_ok();
        // x0 and the record's typed reply must agree. A refusal fails only
        // this process's stock return (it stays charged, never reissued);
        // the exit still completes. Disagreement is a crossing integrity
        // fault.
        match retire.take(binding, mm) {
            Some(Ok(())) if crossed => {
                fork_progress(carrick_el1_abi::NativeForkProgress::ChildRetired);
            }
            Some(Err(_)) if !crossed => {
                fork_failure(carrick_el1_abi::NativeForkFailureStage::ChildRetireRefused);
            }
            _ => fatal(),
        }
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let live = crate::isa::aarch64::hardware_live_ttbr();
            if live & AARCH64_ROOT_ADDRESS_MASK != mm.root.address().raw() {
                fatal();
            }
            let idle = self.zone.spaces.idle_ttbr();
            if idle == 0 {
                fatal();
            }
            crate::sched::ThreadCpu::set_translation(&mut crate::sched::HardwareCpu, idle, idle);
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, live);
            // Publish absence only after the broadcast TLBI completed. The
            // host can drain this MM's quarantined stock on any later request.
            self.zone.release_space(self.slot);
        }
        RETIRED_SPACES.push(RetiredSpace {
            carrier: self.carrier,
            zone: core::ptr::from_ref(self.zone).addr(),
            roots: core::ptr::from_ref(self.roots).addr(),
            mm: ReservationMm::new(mm.mm.raw().get()).unwrap_or_else(|| fatal()),
        });
        // A refused drain is not fatal: the failed entry and every entry
        // after it stay queued (`RetiredSpaces::drain`), and the next drain
        // (the next fork's `prepare_mm_start`, or the next child exit)
        // retries them. `prepare_mm_start` already lowers its own drain
        // failure to a counted refusal; the exit path never aborts on it.
        let _retry_at_next_drain = drain_retired_spaces(&owner, self.zone, self.worker());
    }

    fn wake_effects(&mut self, effects: WakeEffects) {
        deliver_wakes(effects);
    }
}

pub fn cross_root_exit<X: ForkStockCrossing>(
    crossing: &mut X,
    task: &CurrentTask,
    status: LinuxWaitStatus,
    worker: u32,
) -> Result<(), NativeProcessError> {
    let binding = common_entry::execution_binding(task);
    let exit =
        carrick_el1_abi::NativeRootExit::new(binding, status).ok_or(NativeProcessError::Invalid)?;
    crossing.cross_root_exit(&exit as *const _ as u64, u64::from(worker))
}

fn fatal() -> ! {
    panic!("native aarch64 process service failure")
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use crate::memory::reservations::Layout;
    use carrick_el1_abi::ReservationRange;

    struct Crossing;
    impl ForkStockCrossing for Crossing {
        fn cross_fork_stock(&self, _: u64, _: u64) -> Result<(), NativeProcessError> {
            Ok(())
        }
        fn cross_root_exit(&self, _: u64, _: u64) -> Result<(), NativeProcessError> {
            Ok(())
        }
        fn cross_child_retire(&self, record: u64, _: u64) -> Result<(), NativeProcessError> {
            // Like the carrier: quarantine and reply in the typed word.
            // SAFETY: the service passes its live, aligned stack record.
            let record = unsafe { &mut *(record as *mut carrick_el1_abi::NativeChildRetire) };
            assert!(record.accept());
            Ok(())
        }
    }

    #[test]
    fn retired_child_releases_space_and_reservation_slot_beyond_capacity() {
        let region = carrick_test_support::TestEl1Region::zeroed();
        let base = region.as_ptr() as usize;
        // SAFETY: the typed fixture owns aligned, zeroed EL1 storage for the
        // complete test lifetime; both offsets name disjoint ABI records.
        let zone = unsafe {
            &*((base + carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                as *const ZoneTables<Aarch64ParkedContext>)
        };
        let roots = unsafe {
            &*((base + carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
                as *const SharedReservations)
        };
        let task = CurrentTask::new();
        task.execution.task.store(2, Ordering::Release);
        task.execution.generation.store(1, Ordering::Release);
        task.mm.thread_generation.store(1, Ordering::Release);
        task.publish_visible_pid(2);
        let slot = SlotId::new(0);
        let layout = Layout {
            heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
            arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
            brk: 0x1000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        };
        let mut service = Aarch64NativeProcessService::with_crossing(
            &task,
            slot,
            zone,
            roots,
            NonZeroU64::MIN,
            Crossing,
        );
        for cycle in 1..=carrick_sched_core::spaces::ADDRESS_SPACES + 1 {
            let mm = cycle as u64 + 1;
            task.mm.key.store(mm, Ordering::Release);
            let context = AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
                root: RootGpa::page_aligned(FrameGpa::new(0x4000)).unwrap(),
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            let index = zone
                .spaces
                .publish_closed(mm, 0x4000, 0x4000)
                .expect("retired child must not consume all space slots");
            roots
                .publish(index.index(), ReservationMm::new(mm).unwrap(), layout)
                .unwrap();
            if cycle == 1 {
                assert!(zone.occupancy.replace(
                    carrick_sched_core::ExecutionSlot::zone(slot),
                    0,
                    mm
                ));
            }
            service.retire_mm(context);
            if cycle == 1 {
                assert!(
                    zone.spaces.find(mm).is_some(),
                    "resident MM stays quarantined"
                );
                zone.release_space(slot);
                let owner = service.portal().unwrap();
                drain_retired_spaces(&owner, zone, u32::from(slot.raw())).unwrap();
            }
            assert!(zone.spaces.find(mm).is_none());
        }
    }

    /// A refused drain inside the child's own `retire_mm` is not fatal:
    /// the entries stay queued and the next drain retires them.
    #[test]
    fn refused_drain_in_retire_mm_keeps_entries_queued_for_the_next_drain() {
        // Leaked so no later fixture reuses this zone's address while an
        // entry naming it could still be queued.
        let region = Box::leak(Box::new(carrick_test_support::TestEl1Region::zeroed()));
        let base = region.as_ptr() as usize;
        // SAFETY: the leaked typed fixture owns aligned, zeroed EL1 storage;
        // both offsets name disjoint ABI records.
        let zone = unsafe {
            &*((base + carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                as *const ZoneTables<Aarch64ParkedContext>)
        };
        let roots = unsafe {
            &*((base + carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
                as *const SharedReservations)
        };
        let task = CurrentTask::new();
        task.execution.task.store(2, Ordering::Release);
        task.execution.generation.store(1, Ordering::Release);
        task.mm.thread_generation.store(1, Ordering::Release);
        task.publish_visible_pid(2);
        let slot = SlotId::new(0);
        let layout = Layout {
            heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
            arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
            brk: 0x1000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        };
        let mut service = Aarch64NativeProcessService::with_crossing(
            &task,
            slot,
            zone,
            roots,
            NonZeroU64::MIN,
            Crossing,
        );
        let mm = 7;
        task.mm.key.store(mm, Ordering::Release);
        let index = zone.spaces.publish_closed(mm, 0x4000, 0x4000).unwrap();
        roots
            .publish(index.index(), ReservationMm::new(mm).unwrap(), layout)
            .unwrap();
        // Another slot holds the child's reservation root, so the retire
        // inside the child's own drain is refused (Busy).
        let held = roots
            .lock_el1_with_context::<Aarch64ParkedContext>(
                index.index(),
                ReservationMm::new(mm).unwrap(),
                1,
            )
            .unwrap();
        service.retire_mm(AddressContext {
            mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
            root: RootGpa::page_aligned(FrameGpa::new(0x4000)).unwrap(),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        });
        assert!(zone.spaces.find(mm).is_some(), "child entry stays queued");
        drop(held);
        let owner = service.portal().unwrap();
        drain_retired_spaces(&owner, zone, u32::from(slot.raw())).unwrap();
        assert!(zone.spaces.find(mm).is_none());
    }
}
