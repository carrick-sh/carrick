// Machine custody for the sole shared native process owner. Physical OUTs
// happen after guest MM editors and process admission guards are released.
use super::{InitialWords, anonymous};
use crate::rust_alloc::{boxed::Box, vec::Vec};
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
use carrick_core::mm::transaction::{MmPortal, OwnerVenue, SelectionVenues, TransferStep};
use carrick_el1::lock::SpinLock;
use carrick_el1::memory::reservations::{
    X86Cpl0ReservationGeometry, X86Cpl0Zone, shared_x86_cpl0_guest,
};
use carrick_el1::personality::mm_portal::production::GuestMetadataPin;
use carrick_el1::personality::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use carrick_el1::personality::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRuntime,
    NativeProcessService,
};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, KernelFaultVenues, MmPortalSlots, PortalForkCustody,
    PortalOperation, ReservationMm, ThreadControlSlot, ThreadLifecyclePage, X86_FORK_STOCK_PORT,
    X86ForkStockExchange, X86ForkStockLoan, X86ForkStockRequest, X86ForkStockSettlement,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, UserVa,
};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::mm::{LinuxReservationPolicy, MmErrorLinux};
use carrick_sched_core::process::LinuxWaitStatus;
use carrick_sched_core::{ParkedContextWords, SlotId, WakeEffects, ZoneTables};
use core::{marker::PhantomData, num::NonZeroU64, sync::atomic::Ordering};

pub(super) type Mm = AddressContext<RootGpa>;
type Runtime = NativeProcessRuntime<'static, Mm>;
static RUNTIME: SpinLock<Option<&'static Runtime>> = SpinLock::new(None);
static RETIRED: SpinLock<Vec<Mm>> = SpinLock::new(Vec::new());

pub(super) fn runtime() -> &'static Runtime {
    RUNTIME.lock().as_ref().copied().unwrap_or_else(|| fatal())
}
pub(super) fn admit_root(
    words: ParkedContextWords,
    source: BornInZoneSource<'static, ParkedContextWords>,
    task: &'static CurrentTask,
) -> Result<(), NativeProcessError> {
    let mut retained = RUNTIME.lock();
    if retained.is_some() {
        return Ok(());
    }
    let root =
        carrick_el1::isa::x86::hardware_live_root().map_err(|_| NativeProcessError::Stale)?;
    let mm = MmGeneration::new(
        NonZeroU64::new(task.mm.key.load(Ordering::Acquire)).ok_or(NativeProcessError::Stale)?,
    );
    let address = anonymous::live_context(mm, root).ok_or(NativeProcessError::Stale)?;
    // SAFETY: the authenticated admitted root's boot metadata is retained
    // throughout the native lane; the shared constructor rechecks both pointers.
    let (page, control) = unsafe {
        (
            &*(task.metadata.lifecycle_page.load(Ordering::Acquire) as *const ThreadLifecyclePage),
            &*(task.metadata.control_slot.load(Ordering::Acquire) as *const ThreadControlSlot),
        )
    };
    let owner = NativeProcessRuntime::admit_fresh_root(
        source, task, page, control, address, address, words,
    )?;
    *retained = Some(Box::leak(Box::new(owner)));
    Ok(())
}

struct Venue;
impl OwnerVenue<ParkedContextWords> for Venue {
    fn space_access(
        zone: &ZoneTables<ParkedContextWords>,
        slot: SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, ParkedContextWords> {
        carrick_core::wait::space_access(zone, slot, release)
    }
    fn deliver_completion(
        _: &ZoneTables<ParkedContextWords>,
        _: SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, ParkedContextWords>,
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
    _: &X86Cpl0Zone,
    _: carrick_sched_core::Waker,
    effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, ParkedContextWords>,
) {
    let (_, effects) = effects.deliver_handbacks(&mut |_| fatal());
    deliver_wakes(effects);
}
fn deliver_wakes(effects: WakeEffects) {
    for slot in effects.sgi_slots() {
        if carrick_el1::isa::x86::interrupt::send_resched(slot).is_err() {
            fatal();
        }
    }
    // Native execution handles its own queued/misplaced work after leaving
    // the current entry; a worker never waits synchronously for another task.
}
type Portal = MmPortal<
    'static,
    GuestMetadataPin,
    LinuxReservationPolicy,
    X86Cpl0ReservationGeometry,
    Venue,
    X86Mmu,
    ParkedContextWords,
>;
fn portal() -> Result<Portal, NativeProcessError> {
    let layout = carrick_el1::isa::x86_kernel_layout();
    // SAFETY: the boot owner retains the one compact native portal region.
    let slots = unsafe { &*(layout.portal.raw() as *const MmPortalSlots) };
    Ok(Portal {
        backend: PhantomData,
        carrier: slots.carrier().ok_or(NativeProcessError::Stale)?,
        roots: shared_x86_cpl0_guest(),
        spaces: &runtime().zone().spaces,
        nodes: None,
        zone: Some(runtime().zone()),
    })
}
fn error(_: impl core::fmt::Debug) -> NativeProcessError {
    NativeProcessError::Fault
}

pub(super) struct Prepared {
    loan: X86ForkStockLoan,
    child: UnpublishedEl1Child<X86Mmu>,
    words: InitialWords,
    address: Mm,
    custody: Vec<PortalForkCustody>,
}
pub(super) struct Born {
    prepared: Prepared,
}
pub(super) struct Service {
    task: &'static CurrentTask,
    slot: SlotId,
}
impl Service {
    pub(super) fn new(task: &'static CurrentTask, slot: SlotId) -> Self {
        Self { task, slot }
    }
    fn worker(&self) -> u32 {
        u32::from(self.slot.raw())
    }

}

impl NativeProcessService<'static> for Service {
    type Mm = Mm;
    type PreparedMm = Prepared;
    type Born = Box<Born>;
    fn prepare_mm(
        &mut self,
        parent: &Mm,
        words: ParkedContextWords,
        child_mm: MmGeneration,
    ) -> Result<Prepared, NativeProcessError> {
        if !words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        let owner = portal()?;
        let mm = ReservationMm::new(parent.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let live = anonymous::live_words(mm).ok_or(NativeProcessError::Stale)?;
        let capacity = owner.fork_mapping_count(mm, self.worker()).map_err(error)?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(capacity)
            .map_err(|_| NativeProcessError::Exhausted)?;
        let (operation, generation, count, layout) = {
            let index = owner
                .spaces
                .find(mm.raw())
                .ok_or(NativeProcessError::Stale)?;
            let access = owner.space_access(self.worker()).map_err(error)?;
            let _editor = access
                .try_begin_edit(
                    index,
                    mm.raw(),
                    NonZeroU64::new(u64::from(self.worker()) + 1)
                        .ok_or(NativeProcessError::Stale)?,
                )
                .ok_or(NativeProcessError::Busy)?;
            let mut root = owner.root(mm, self.worker()).map_err(error)?;
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
            .map_err(error)?;
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
            census_table::<X86Mmu, _, _>(
                &LinuxForkPolicy,
                &live,
                &mappings,
                parent.root.address().raw(),
                0,
                0,
                &mut count,
            )
            .map_err(error)?;
            (operation, root.generation(), count, root.layout())
        };
        let request = X86ForkStockRequest {
            binding: carrick_el1::personality::common_entry::execution_binding(self.task),
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
        let mut exchange = X86ForkStockExchange::new(request).ok_or(NativeProcessError::Invalid)?;
        // SAFETY: aligned exclusive supervisor stack record remains live
        // through stopped host authentication; DX is always the hardware port.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") X86_FORK_STOCK_PORT, in("rax") &raw mut exchange, options(nostack));
        }
        let loan = exchange
            .take(request)
            .ok_or(NativeProcessError::Stale)?
            .map_err(|_| NativeProcessError::Exhausted)?;
        if loan.lifecycle.page.raw() == self.task.metadata.lifecycle_page.load(Ordering::Acquire) {
            return Err(NativeProcessError::Stale);
        }
        // SAFETY: the physical owner loaned zero exclusive cold metadata.
        // Guest shared records alone initialize census and issue identities.
        unsafe {
            (loan.lifecycle.page.raw() as *mut ThreadLifecyclePage)
                .write(ThreadLifecyclePage::new());
            let controls = loan.lifecycle.controls.raw() as *mut ThreadControlSlot;
            for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
                controls.add(index).write(ThreadControlSlot::new());
            }
        }
        let index = owner
            .spaces
            .publish_closed(child_mm.raw().get(), loan.request.child_tables.base, 0)
            .ok_or(NativeProcessError::Exhausted)?;
        if let Err(e) = owner
            .roots
            .publish(index.index(), loan.request.child_mm, layout)
        {
            owner.spaces.free(index);
            return Err(error(e));
        }
        let scratch = ForkScratch::bounded(
            loan.request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(error)?;
        let plan = match owner.prepare_fork(loan.request, scratch, &live, self.worker()) {
            Ok(plan) => plan,
            Err(e) => {
                owner.spaces.free(index);
                return Err(error(e));
            }
        };
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(plan.custody().len())
            .map_err(|_| NativeProcessError::Exhausted)?;
        custody.extend_from_slice(plan.custody());
        let child = match owner.publish_fork(plan, &live, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(index);
                return Err(error(e));
            }
        };
        let completion = child.completion();
        let address = AddressContext {
            mm: child_mm,
            root: RootGpa::page_aligned(FrameGpa::new(loan.request.child_tables.base))
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
    fn prepared_mm(&self, p: &Prepared) -> Mm {
        p.address
    }
    fn prepared_context(&self, p: &Prepared) -> Mm {
        p.address
    }
    fn child_lifecycle(&self, p: &Prepared) -> NativeLifecycleResources<'static> {
        // SAFETY: physical loan retains exclusive, fresh supervisor metadata
        // mapped into both roots; runtime alone issues shared birth entries.
        unsafe {
            NativeLifecycleResources {
                page: &*(p.loan.lifecycle.page.raw() as *const ThreadLifecyclePage),
                controls: core::slice::from_raw_parts(
                    p.loan.lifecycle.controls.raw() as *const ThreadControlSlot,
                    carrick_el1_abi::THREAD_POOL_ENTRIES + 1,
                ),
            }
        }
    }
    fn commit_mm(&mut self, mut p: Prepared) -> Result<Box<Born>, (NativeProcessError, Prepared)> {
        let result =
            portal().and_then(|owner| p.child.commit(&owner, self.worker()).map_err(error));
        match result {
            Ok(_) => Ok(Box::new(Born { prepared: p })),
            Err(e) => Err((e, p)),
        }
    }
    fn abort_mm(&mut self, mut p: Prepared) -> Result<(), (NativeProcessError, Prepared)> {
        let result = portal().and_then(|owner| {
            p.child
                .abort(&owner, &p.words, self.worker())
                .map_err(error)
        });
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err((e, p)),
        }
    }
    fn settle_mm(&mut self, born: Box<Born>) -> Result<(), (NativeProcessError, Box<Born>)> {
        settle(born, self.worker())
    }
    fn copy_status(
        &mut self,
        mm: &Mm,
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        if carrick_el1::isa::x86::hardware_live_root().map_err(error)? != mm.root {
            return Err(NativeProcessError::Stale);
        }
        let owner = portal()?;
        let mm_key = ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let words = anonymous::live_words(mm_key).ok_or(NativeProcessError::Stale)?;
        let handle = owner
            .admitted_handle(mm_key, self.worker())
            .map_err(error)?;
        let mut continuation = owner
            .begin(
                handle,
                carrick_core::mm::transfer::GuestVa::new(address.raw()),
                4,
                carrick_el1_abi::PortalTransferIntent::UserWrite,
                self.worker(),
            )
            .map_err(error)?;
        let venues = KernelFaultVenues::derive(carrick_el1::isa::x86_kernel_layout())
            .and_then(KernelFaultVenues::require_upper_half)
            .ok_or(NativeProcessError::Stale)?;
        // SAFETY: boot retains the actual residency and physical replacement
        // pool; the Core owner authenticates each exact source before using it.
        let (residency, pool, slots) = unsafe {
            (
                &*(venues.residency.raw() as *const carrick_el1_abi::FrameGrantResidencyTable),
                &*(venues.cow_pool.raw() as *const carrick_el1_abi::CowGrantPool),
                &*(carrick_el1::isa::x86_kernel_layout().portal.raw() as *const MmPortalSlots),
            )
        };
        let bytes = status.raw().to_ne_bytes();
        while !continuation.is_complete() {
            // SAFETY: select acquires the exact editor before using this leaf.
            let mut prepared = unsafe {
                carrick_el1::fault::X86PreparedResolver::under_editor(mm.mm.raw(), &words)
            };
            let mut cow = carrick_el1::fault::X86CowResolver {
                words: &words,
                pool,
                residency,
                completion: None,
            };
            let step = owner
                .select(
                    &continuation,
                    &words,
                    SelectionVenues {
                        prepared: &mut prepared,
                        cow: &mut cow,
                        residency,
                        slot: self.worker(),
                    },
                )
                .map_err(error)?;
            if pool.has_completions_for(mm.mm.raw().get()) {
                super::cross_owner_grant(carrick_guest_arch::CpuId::new(self.worker()), address);
            }
            match step {
                TransferStep::CowSupply(window) => {
                    if !slots
                        .grant(usize::from(self.slot.raw()))
                        .ok_or(NativeProcessError::Stale)?
                        .publish_cow_fault_selection(window.operation.sequence.get(), window)
                    {
                        return Err(NativeProcessError::Busy);
                    }
                    super::cross_owner_grant(carrick_guest_arch::CpuId::new(self.worker()), address);
                }
                TransferStep::Selected(selected) => {
                    let fence = owner
                        .revalidate(&continuation, selected, &words, self.worker())
                        .map_err(error)?
                        .ok_or(NativeProcessError::Busy)?;
                    let offset = usize::try_from(continuation.offset())
                        .map_err(|_| NativeProcessError::Invalid)?;
                    let count =
                        usize::try_from(selected.len).map_err(|_| NativeProcessError::Invalid)?;
                    // SAFETY: shared exact-MM fence retains the authorized
                    // user-write span; kernel bytes are live for this call.
                    let copied = unsafe {
                        carrick_el1::isa::x86::user_access::copy(
                            self.task,
                            selected.va.raw() as *mut u8,
                            bytes.as_ptr().add(offset),
                            count,
                            selected.va.raw(),
                            true,
                        )
                    };
                    if !copied {
                        return Err(NativeProcessError::Fault);
                    }
                    fence.complete(&mut continuation).map_err(error)?;
                }
                TransferStep::Supply(_) => return Err(NativeProcessError::Unsupported),
                TransferStep::Suspended => return Err(NativeProcessError::Busy),
                TransferStep::Complete => break,
            }
        }
        Ok(())
    }
    fn quarantine_prepared(&mut self, p: Prepared) {
        core::mem::forget(p);
        fatal();
    }
    fn quarantine_fork(&mut self, p: NativeForkPreparation<'static, Mm, Prepared>) {
        core::mem::forget(p);
        fatal();
    }
    fn quarantine_born(&mut self, p: Box<Born>) {
        core::mem::forget(p);
        fatal();
    }
    fn retire_mm(&mut self, mm: Mm) {
        RETIRED.lock().push(mm);
    }
    fn wake_effects(&mut self, effects: WakeEffects) {
        deliver_wakes(effects);
    }
}

fn settle(born: Box<Born>, worker: u32) -> Result<(), (NativeProcessError, Box<Born>)> {
    let p = &born.prepared;
    let mut custody = Vec::new();
    if custody.try_reserve_exact(p.custody.len()).is_err() {
        return Err((NativeProcessError::Exhausted, born));
    }
    custody.extend(p.custody.iter().copied().map(PortalForkCustody::words));
    let Some(mut exchange) = X86ForkStockSettlement::new(
        p.loan,
        p.child.completion(),
        KernelVa::new(custody.as_ptr() as u64),
        custody.len() as u64,
    ) else {
        return Err((NativeProcessError::Stale, born));
    };
    // SAFETY: exact completion and original four-word custody records remain
    // owned across the stopped crossing; graph and MM editors were released.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") X86_FORK_STOCK_PORT, in("rax") &raw mut exchange, options(nostack));
    }
    if !matches!(exchange.take(p.loan), Some(Ok(()))) {
        return Err((NativeProcessError::Quarantined, born));
    }
    anonymous::admit_context(p.address);
    let owner = match portal() {
        Ok(owner) => owner,
        Err(error) => return Err((error, born)),
    };
    let Some(index) = owner.spaces.find(p.address.mm.raw().get()) else {
        return Err((NativeProcessError::Stale, born));
    };
    let access = match owner.space_access(worker) {
        Ok(access) => access,
        Err(e) => return Err((error(e), born)),
    };
    access.open(index);
    Ok(())
}
fn fatal() -> ! {
    super::initial_boot::fatal_boot()
}
