//! Machine custody for the shared AArch64 native process owner.
//!
//! Implements [`NativeProcessService`] for [`Aarch64ParkedContext`] over [`carrick_mmu_core::owner_mmu::Aarch64Mmu`].
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
use carrick_core::mm::transaction::OwnerVenue;
use carrick_el1_abi::{
    CurrentTask, ForkStockExchange, ForkStockLoan, ForkStockRequest, ForkStockSettlement,
    PortalForkCustody, PortalOperation, ReservationMm, ThreadControlSlot, ThreadLifecyclePage,
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
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessService,
};
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use crate::memory::reservations;
use crate::memory::reservations::{NativeReservationGeometry, SharedReservations};

pub type Mm = AddressContext<RootGpa>;

pub struct Prepared<'a> {
    pub loan: ForkStockLoan,
    pub child: UnpublishedEl1Child<Aarch64Mmu>,
    pub words: &'a (dyn LiveDescriptorWords + 'a),
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
}

impl<T: ForkStockCrossing> ForkStockCrossing for &T {
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
fn err(_loc: &'static str, _e: impl core::fmt::Debug) -> NativeProcessError {
    NativeProcessError::Fault
}

fn error(e: impl core::fmt::Debug) -> NativeProcessError {
    err("unspecified", e)
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
        let live = self.words.ok_or(NativeProcessError::Stale)?;
        let capacity = owner
            .fork_mapping_count(mm, self.worker())
            .map_err(|e| err("fork_mapping_count", e))?;
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
                .map_err(|e| err("space_access", e))?;
            let _editor = access
                .try_begin_edit(
                    index,
                    mm.raw(),
                    NonZeroU64::new(u64::from(self.worker()) + 1)
                        .ok_or(NativeProcessError::Stale)?,
                )
                .ok_or(NativeProcessError::Busy)?;
            let mut root = owner.root(mm, self.worker()).map_err(|e| err("root", e))?;
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
            .map_err(|e| err("observe_mappings", e))?;
            if full {
                return Err(NativeProcessError::Exhausted);
            }
            let operation = PortalOperation {
                carrier: owner.carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())
                    .ok_or(NativeProcessError::Stale)?,
                sequence: root.next_transfer_sequence().map_err(error)?,
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
                live,
                &mappings,
                parent.root.address().raw(),
                0,
                0,
                &mut count,
            )
            .map_err(|e| err("census_table", e))?;
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
            return Err(err("roots.publish", e));
        }
        let scratch = ForkScratch::bounded(
            loan.request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(|e| err("ForkScratch::bounded", e))?;
        let plan = match owner.prepare_fork(loan.request, scratch, live, self.worker()) {
            Ok(plan) => plan,
            Err(e) => {
                owner.spaces.free(index);
                return Err(err("prepare_fork", e));
            }
        };
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(plan.custody().len())
            .map_err(|_| NativeProcessError::Exhausted)?;
        custody.extend_from_slice(plan.custody());
        let child = match owner.publish_fork(plan, live, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(index);
                return Err(err("publish_fork", e));
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
        let result = self
            .portal()
            .and_then(|owner| prepared.child.commit(&owner, self.worker()).map_err(error));
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
                .abort(&owner, prepared.words, self.worker())
                .map_err(|e| err("child.abort", e))
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
            Err(e) => return Err((error(e), born)),
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

    fn retire_mm(&mut self, _mm: Self::Mm) {}

    fn copy_signal_bytes(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        if self.task.mm.key.load(Ordering::Acquire) != mm.mm.raw().get() {
            return Err(NativeProcessError::Stale);
        }
        let mut copy = crate::file::ValidatedCopy {
            task: self.task,
            validator: &crate::file::HardwareValidator,
        };
        if !carrick_personality_linux::lifecycle::UserCopy::copy_out(&mut copy, address, bytes) {
            return Err(NativeProcessError::Fault);
        }
        Ok(())
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
