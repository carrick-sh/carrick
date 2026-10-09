//! Machine custody for the shared AArch64 native process owner.
//!
//! Implements [`NativeProcessService`] for [`Aarch64ParkedContext`] over [`carrick_mmu_core::owner_mmu::Aarch64Mmu`].
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
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
    AARCH64_ROOT_ADDRESS_MASK, Aarch64ParkedContext, WakeEffects, ZoneTables,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

use super::common_entry;
use super::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use super::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
    NativeProcessRuntime, NativeProcessService,
};
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

pub fn registry() -> &'static NativeProcessRegistry<'static, Mm, Aarch64ParkedContext> {
    &REGISTRY
}

/// Admit only an exact published leader or thread-group member. The root
/// address is checked by the shared owner against the zone's live MM grant.
pub fn admit_entry(
    source: BornInZoneSource<'static, Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    record_incarnation: u64,
) -> Result<(Arc<Runtime>, Mm, Aarch64ParkedContext), NativeProcessError> {
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
    let words = Aarch64ParkedContext::from_register(
        native,
        ttbr0,
        address.mm.raw().get(),
        address.generation.raw().get(),
    );
    if let Ok(runtime) = REGISTRY.for_entry(source, task, address) {
        return Ok((runtime, address, words));
    }
    if control.entry().is_some() {
        let runtime = REGISTRY.register_thread(source, task, address, page, control)?;
        return Ok((runtime, address, words));
    }
    let runtime = Arc::new(NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source, task, page, control, address, address, words,
    )?);
    REGISTRY.register_root(runtime.clone(), source, task, address)?;
    Ok((runtime, address, words))
}

pub struct Prepared<'a> {
    pub loan: ForkStockLoan,
    pub child: UnpublishedEl1Child<Aarch64Mmu>,
    pub words: PreparedWords<'a>,
    pub address: Mm,
    pub custody: Vec<PortalForkCustody>,
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
    pub prepared: Prepared<'a>,
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
    type PreparedMm = Prepared<'a>;
    type Born = Box<Born<'a>>;

    fn prepare_mm(
        &mut self,
        parent: &Self::Mm,
        words: Aarch64ParkedContext,
        child_mm: MmGeneration,
    ) -> Result<Self::PreparedMm, NativeProcessError> {
        if !words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        let owner = self.portal()?;
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
        let mut exchange = ForkStockExchange::new(request).ok_or(NativeProcessError::Invalid)?;
        self.crossing
            .cross_fork_stock(&raw mut exchange as *mut _ as u64, u64::from(self.worker()))?;
        let loan = exchange
            .take(request)
            .ok_or(NativeProcessError::Stale)?
            .map_err(|_| NativeProcessError::Exhausted)?;
        if loan.lifecycle.page.raw() == self.task.metadata.lifecycle_page.load(Ordering::Acquire) {
            return Err(NativeProcessError::Stale);
        }
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
        let index = owner
            .spaces
            .publish_closed(child_mm.raw().get(), ttbr0, ttbr0)
            .ok_or(NativeProcessError::Exhausted)?;
        if let Err(e) = owner
            .roots
            .publish(index.index(), loan.request.child_mm, layout)
        {
            owner.spaces.free(index);
            return Err(err(
                carrick_el1_abi::NativeForkFailureStage::RootPublication,
                e,
            ));
        }
        let scratch = ForkScratch::bounded(
            loan.request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Scratch, e))?;
        let plan = match owner.prepare_fork(loan.request, scratch, &*live, self.worker()) {
            Ok(plan) => plan,
            Err(e) => {
                owner.spaces.free(index);
                return Err(err(prepare_error_stage(e), e));
            }
        };
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(plan.custody().len())
            .map_err(|_| NativeProcessError::Exhausted)?;
        custody.extend_from_slice(plan.custody());
        let child = match owner.publish_fork(plan, &*live, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(index);
                return Err(err(publish_error_stage(e), e));
            }
        };
        let completion = child.completion();
        let address = AddressContext {
            mm: child_mm,
            root: RootGpa::page_aligned(FrameGpa::new(
                loan.request.child_tables.base & AARCH64_ROOT_ADDRESS_MASK,
            ))
            .ok_or(NativeProcessError::Stale)?,
            generation: ContextGeneration::new(completion.child.incarnation()),
        };
        Ok(Prepared {
            loan,
            child,
            words: live,
            address,
            custody,
        })
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
                .map_err(|e| err(carrick_el1_abi::NativeForkFailureStage::Commit, e))
        });
        match result {
            Ok(_) => Ok(Box::new(Born { prepared })),
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
        let mut settlement = carrick_el1_abi::ForkStockSettlement::abort(prepared.loan);
        let _ = self.crossing.cross_fork_stock(
            &raw mut settlement as *mut _ as u64,
            u64::from(self.worker()),
        );
        let _ = settlement.take(prepared.loan);
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err((e, prepared)),
        }
    }

    fn settle_mm(&mut self, born: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
        let p = &born.prepared;
        let mut custody = Vec::new();
        if custody.try_reserve_exact(p.custody.len()).is_err() {
            return Err((NativeProcessError::Exhausted, born));
        }
        custody.extend(p.custody.iter().copied().map(PortalForkCustody::words));
        let Some(mut settlement) = ForkStockSettlement::new(
            p.loan,
            p.child.completion(),
            KernelVa::new(custody.as_ptr() as u64),
            custody.len() as u64,
        ) else {
            return Err((NativeProcessError::Stale, born));
        };
        if let Err(e) = self.crossing.cross_fork_stock(
            &raw mut settlement as *mut _ as u64,
            u64::from(self.worker()),
        ) {
            return Err((e, born));
        }
        if !matches!(settlement.take(p.loan), Some(Ok(()))) {
            return Err((NativeProcessError::Quarantined, born));
        }
        let owner = match self.portal() {
            Ok(owner) => owner,
            Err(error) => return Err((error, born)),
        };
        let Some(index) = owner.spaces.find(p.address.mm.raw().get()) else {
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
        // The root uses the terminal root-exit crossing after graph exit.
        // Only fork-born children own lifecycle and table stock to quarantine.
        if self.task.visible_pid() == Some(1) {
            return;
        }
        if mm.mm.raw().get() != self.task.mm.key.load(Ordering::Acquire) {
            fatal();
        }
        let binding = common_entry::execution_binding(self.task);
        let Some(retire) = carrick_el1_abi::NativeChildRetire::new(binding, mm) else {
            fatal();
        };
        if self
            .crossing
            .cross_child_retire(&retire as *const _ as u64, u64::from(self.worker()))
            .is_err()
        {
            fatal();
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
