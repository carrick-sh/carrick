// Machine custody for the sole shared native process owner. Physical OUTs
// happen after guest MM editors and process admission guards are released.
mod user_copy;

use super::anonymous;
use crate::rust_alloc::{boxed::Box, sync::Arc, vec::Vec};
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
use carrick_core::mm::transaction::{MmPortal, OwnerVenue};
use carrick_el1::memory::reservations::{
    X86Cpl0ReservationGeometry, X86Cpl0Zone, shared_x86_cpl0_guest,
};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, FORK_STOCK_PORT, ForkStockExchange, ForkStockLoan,
    ForkStockRequest, ForkStockSettlement, Lifecycle, MmPortalSlots, NATIVE_CHILD_RETIRE_PORT,
    NativeChildRetire, PortalForkCustody, PortalOperation, ReservationMm, ThreadControlSlot,
    ThreadLifecyclePage,
};
use carrick_el1_linux::mm_portal::production::GuestMetadataPin;
use carrick_el1_linux::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use carrick_el1_linux::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
    NativeProcessRuntime, NativeProcessService,
};
use carrick_el1_linux::retired_spaces::{RetiredSpace, RetiredSpaces};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, KernelVa, MmGeneration, RootGpa, UserVa,
};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::lifecycle::LinuxWaitStatus;
use carrick_personality_linux::mm::{LinuxReservationPolicy, MmErrorLinux};
use carrick_sched_core::{ParkedContextWords, SlotId, WakeEffects, ZoneTables};
use carrick_x86_carrier::entry::InitialWords;
use core::{marker::PhantomData, num::NonZeroU64, sync::atomic::Ordering};

pub(super) type Mm = AddressContext<RootGpa>;
type Runtime = NativeProcessRuntime<'static, Mm, ParkedContextWords>;
static REGISTRY: NativeProcessRegistry<'static, Mm, ParkedContextWords> =
    NativeProcessRegistry::new();

/// Closed child spaces awaiting retirement (the protocol shared with the
/// AArch64 owner).
static RETIRED_SPACES: RetiredSpaces = RetiredSpaces::new();

fn drain_retired_spaces(owner: &Portal, worker: u32) -> Result<(), NativeProcessError> {
    let zone = owner.zone.ok_or(NativeProcessError::Stale)?;
    RETIRED_SPACES.drain_portal(
        owner,
        zone,
        carrick_el1::isa::x86::context::native::CPL0_CPU_COUNT,
        worker,
    )
}

pub(super) fn registry() -> &'static NativeProcessRegistry<'static, Mm, ParkedContextWords> {
    &REGISTRY
}
pub(super) fn drain_external_ingress(
    source: BornInZoneSource<'static, ParkedContextWords>,
    service: &mut Service,
) -> Result<usize, NativeProcessError> {
    REGISTRY.drain_external_ingress(
        source.zone,
        carrick_el1::isa::signal_ingress_guest(),
        source.slot,
        service,
    )
}
pub(super) fn runtime(
    source: BornInZoneSource<'static, ParkedContextWords>,
    task: &'static CurrentTask,
) -> Result<(Arc<Runtime>, Mm), NativeProcessError> {
    let root =
        carrick_el1::isa::x86::hardware_live_root().map_err(|_| NativeProcessError::Stale)?;
    let mm = MmGeneration::new(
        NonZeroU64::new(task.mm.key.load(Ordering::Acquire)).ok_or(NativeProcessError::Stale)?,
    );
    let address = anonymous::live_context(mm, root).ok_or(NativeProcessError::Stale)?;
    Ok((REGISTRY.for_entry(source, task, address)?, address))
}
pub(super) fn runtime_for_record(
    zone: &ZoneTables<ParkedContextWords>,
    record: carrick_sched_core::RecordRef,
) -> Arc<Runtime> {
    REGISTRY.for_record(zone, record).unwrap_or_else(|| fatal())
}
pub(super) fn is_admitted() -> bool {
    !REGISTRY.is_empty()
}
pub(super) fn admit_root(
    words: ParkedContextWords,
    source: BornInZoneSource<'static, ParkedContextWords>,
    task: &'static CurrentTask,
) -> Result<(), NativeProcessError> {
    let root =
        carrick_el1::isa::x86::hardware_live_root().map_err(|_| NativeProcessError::Stale)?;
    let mm = MmGeneration::new(
        NonZeroU64::new(task.mm.key.load(Ordering::Acquire)).ok_or(NativeProcessError::Stale)?,
    );
    let address = anonymous::live_context(mm, root).ok_or(NativeProcessError::Stale)?;
    if REGISTRY.for_entry(source, task, address).is_ok() {
        return Ok(());
    }
    // SAFETY: the authenticated admitted root's boot metadata is retained
    // throughout the native lane; the shared constructor rechecks both pointers.
    let (page, control) = unsafe {
        (
            &*(task.metadata.lifecycle_page.load(Ordering::Acquire) as *const ThreadLifecyclePage),
            &*(task.metadata.control_slot.load(Ordering::Acquire) as *const ThreadControlSlot),
        )
    };
    if control.entry().is_some() {
        REGISTRY.register_thread(source, task, address, page, control)?;
        return Ok(());
    }
    // The stopped-host x86 bootstrap retains a temporary extra leader count.
    // This fresh launch adapter owns that census; the shared owner never
    // normalizes arbitrary live membership supplied by another execution lane.
    match page.live() {
        1 => {}
        2 => {
            page.release_live(1)
                .map_err(|_| NativeProcessError::Stale)?;
        }
        _ => return Err(NativeProcessError::Invalid),
    }
    let owner = NativeProcessRuntime::admit_fresh_root::<X86Mmu>(
        source, task, page, control, address, address, words,
    )?;
    REGISTRY.register_root(Arc::new(owner), source, task, address)?;
    let binding =
        carrick_el1::isa::x86::context::current_cpu_binding().ok_or(NativeProcessError::Stale)?;
    let files = crate::linux_personality::file_tables(binding);
    crate::linux_personality::admit_stdio_cached(binding, task, &files);
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
    let zone =
        carrick_x86_carrier::native_execution::source(carrick_guest_arch::SlotId::new(0)).zone;
    Ok(Portal {
        backend: PhantomData,
        carrier: slots.carrier().ok_or(NativeProcessError::Stale)?,
        roots: shared_x86_cpl0_guest(),
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
    })
}
fn error(_: impl core::fmt::Debug) -> NativeProcessError {
    NativeProcessError::Fault
}

pub(super) struct Prepared {
    loan: ForkStockLoan,
    child: UnpublishedEl1Child<X86Mmu>,
    words: InitialWords,
    address: Mm,
}
pub(super) struct Born {
    prepared: Prepared,
    child_task: u64,
    child_execution: u64,
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

    /// The part of `prepare_mm_start` after the stock crossing granted
    /// `loan`. Every error frees the space index it took and returns the
    /// loan ([`abandon_loan`]), so a failed fork never strands this CPU's
    /// pending loan (each later fork on the CPU would be refused).
    #[allow(clippy::too_many_arguments)]
    fn prepare_loaned(
        &self,
        owner: &Portal,
        loan: ForkStockLoan,
        live: &InitialWords,
        layout: carrick_el1_abi::Layout,
        mapping_count: usize,
        count: ForkCensus,
        child_mm: MmGeneration,
    ) -> Result<(UnpublishedEl1Child<X86Mmu>, Mm), NativeProcessError> {
        let abandon = |error| abandon_loan(&loan, None, error);
        // SAFETY: the physical owner loaned zero exclusive cold metadata.
        // Guest shared records alone initialize census and issue identities.
        unsafe {
            ThreadLifecyclePage::initialize_at(
                loan.lifecycle.page.raw() as *mut ThreadLifecyclePage
            );
            let controls = loan.lifecycle.controls.raw() as *mut ThreadControlSlot;
            for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
                controls.add(index).write(ThreadControlSlot::new());
            }
        }
        let root = RootGpa::page_aligned(FrameGpa::new(loan.request.child_tables.base))
            .ok_or_else(|| abandon(NativeProcessError::Stale))?;
        let index = owner
            .spaces
            .publish_closed(child_mm.raw().get(), loan.request.child_tables.base, 0)
            .ok_or_else(|| abandon(NativeProcessError::Exhausted))?;
        let free = |error| {
            owner.spaces.free(index);
            abandon(error)
        };
        owner
            .roots
            .publish(index.index(), loan.request.child_mm, layout)
            .map_err(|e| free(error(e)))?;
        let scratch = ForkScratch::bounded(
            loan.request,
            mapping_count,
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(|e| free(error(e)))?;
        let plan = owner
            .prepare_fork(loan.request, scratch, live, self.worker())
            .map_err(|e| free(error(e)))?;
        let mut custody = Vec::new();
        custody
            .try_reserve_exact(plan.custody().len())
            .map_err(|_| free(NativeProcessError::Exhausted))?;
        custody.extend(plan.custody().iter().copied().map(PortalForkCustody::words));
        let mut child = match owner.publish_fork(plan, live, self.worker()) {
            Ok(child) => child,
            Err(e) => {
                owner.spaces.free(index);
                // A refused publish may have stored into the loaned tables;
                // it rolled its parent edits back, so they are unlinked and
                // are scrubbed before the abort. `Core` means that rollback
                // itself failed: the parent may still link a loaned page, so
                // the loan stays pending rather than be scrubbed or reused.
                if matches!(e, carrick_core::mm::transaction::MmError::Core) {
                    return Err(NativeProcessError::Quarantined);
                }
                return Err(abandon_loan(&loan, Some(live), error(e)));
            }
        };
        let abort_published = |child: &mut UnpublishedEl1Child<X86Mmu>, err: NativeProcessError| {
            abort_child(owner, self.worker(), child, live, &loan)
                .map_or(NativeProcessError::Quarantined, |()| err)
        };
        let Some(mut reserve) = ForkStockSettlement::reserve(
            loan,
            child.completion(),
            KernelVa::new(custody.as_ptr() as u64),
            custody.len() as u64,
        ) else {
            return Err(abort_published(&mut child, NativeProcessError::Stale));
        };
        // SAFETY: exact completion and original four-word custody records remain
        // owned across the stopped crossing; graph and MM editors were released.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") FORK_STOCK_PORT, in("rax") &raw mut reserve, options(nostack));
        }
        match reserve.take(loan) {
            Some(Ok(())) => {}
            Some(Err(carrick_el1_abi::ForkStockRefusal::Capacity)) => {
                return Err(abort_published(&mut child, NativeProcessError::Exhausted));
            }
            Some(Err(carrick_el1_abi::ForkStockRefusal::Inventory)) => {
                return Err(abort_published(&mut child, NativeProcessError::Busy));
            }
            Some(Err(carrick_el1_abi::ForkStockRefusal::Stale)) => {
                return Err(abort_published(&mut child, NativeProcessError::Stale));
            }
            Some(Err(carrick_el1_abi::ForkStockRefusal::Invalid)) => {
                return Err(abort_published(&mut child, NativeProcessError::Invalid));
            }
            None => return Err(abort_published(&mut child, NativeProcessError::Quarantined)),
        }
        let address = AddressContext {
            mm: child_mm,
            root,
            generation: ContextGeneration::new(child.completion().child.incarnation()),
        };
        Ok((child, address))
    }
}

/// Clear a never-committed loan's lifecycle record and abort it over the
/// stock port. True when the carrier accepted the abort.
fn abort_loan(loan: &ForkStockLoan) -> bool {
    // SAFETY: the loan never published a birth; no reader remains.
    unsafe { carrick_el1_linux::fork_loan::clear_lifecycle(loan) };
    let mut settlement = carrick_el1_abi::ForkStockSettlement::abort(*loan);
    // SAFETY: the aborted loan is still exclusively owned across this
    // stopped crossing; the host authenticates its exact execution key.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") FORK_STOCK_PORT, in("rax") &raw mut settlement, options(nostack));
    }
    matches!(settlement.take(*loan), Some(Ok(())))
}

/// Return a granted loan after a failed fork; see the AArch64 owner's
/// `abandon_loan` for the shared contract. `scrub` names the words of a
/// refused publish that may have stored into the loaned tables. Returns
/// `error`, or `Quarantined` when the loan stays pending.
fn abandon_loan(
    loan: &ForkStockLoan,
    scrub: Option<&InitialWords>,
    error: NativeProcessError,
) -> NativeProcessError {
    return_loan(loan, scrub).err().unwrap_or(error)
}

fn return_loan(
    loan: &ForkStockLoan,
    scrub: Option<&InitialWords>,
) -> Result<(), NativeProcessError> {
    if let Some(words) = scrub
        && !carrick_el1_linux::fork_loan::scrub_tables(words, loan)
    {
        return Err(NativeProcessError::Quarantined);
    }
    if abort_loan(loan) {
        Ok(())
    } else {
        Err(NativeProcessError::Quarantined)
    }
}

fn abort_child(
    owner: &Portal,
    worker: u32,
    child: &mut UnpublishedEl1Child<X86Mmu>,
    words: &InitialWords,
    loan: &ForkStockLoan,
) -> Result<(), NativeProcessError> {
    child.abort(owner, words, worker).map_err(error)?;
    let index = owner
        .spaces
        .find(child.completion().child.mm().raw())
        .ok_or(NativeProcessError::Stale)?;
    owner.spaces.free(index);
    return_loan(loan, Some(words))
}

impl NativeProcessService<'static, ParkedContextWords> for Service {
    type Mm = Mm;
    type PreparedMm = Prepared;
    type Born = Box<Born>;
    fn prepare_mm(
        &mut self,
        parent: &Mm,
        words: &ParkedContextWords,
        child_mm: MmGeneration,
    ) -> Result<Prepared, NativeProcessError> {
        if !words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        let owner = portal()?;
        let _ = drain_retired_spaces(&owner, self.worker());
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
        let request = ForkStockRequest {
            binding: carrick_el1_linux::common_entry::execution_binding(self.task),
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
        // SAFETY: aligned exclusive supervisor stack record remains live
        // through stopped host authentication; DX is always the hardware port.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") FORK_STOCK_PORT, in("rax") &raw mut exchange, options(nostack));
        }
        let loan = exchange
            .take(request)
            .ok_or(NativeProcessError::Stale)?
            .map_err(|_| NativeProcessError::Exhausted)?;
        // The carrier never loans a record a live MM uses (the parent's is
        // charged to it), so this refusal is a carrier custody fault. It is
        // the one post-crossing error that keeps the loan: an abort would
        // have the carrier clear this task's live record.
        if loan.lifecycle.page.raw() == self.task.metadata.lifecycle_page.load(Ordering::Acquire) {
            return Err(NativeProcessError::Stale);
        }
        let (child, address) =
            self.prepare_loaned(&owner, loan, &live, layout, mappings.len(), count, child_mm)?;
        Ok(Prepared {
            loan,
            child,
            words: live,
            address,
        })
    }
    fn prepared_mm(&self, p: &Prepared) -> Mm {
        p.address
    }
    fn prepared_context(&self, p: &Prepared) -> Mm {
        p.address
    }
    fn fork_child_context(
        &self,
        parent: ParkedContextWords,
        prepared: &Prepared,
    ) -> ParkedContextWords {
        parent.fork_child(prepared.address)
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
    fn commit_mm(&mut self, p: Prepared) -> Result<Box<Born>, (NativeProcessError, Prepared)> {
        let child_task = p.address.mm.raw().get();
        let child_execution = carrick_core_abi::SnapshotGeneration::INITIAL.raw();
        self.commit_child(
            p,
            NonZeroU64::new(child_task).unwrap_or(NonZeroU64::MIN),
            NonZeroU64::new(child_execution).unwrap_or(NonZeroU64::MIN),
        )
    }
    fn commit_child(
        &mut self,
        mut p: Prepared,
        child_task: core::num::NonZeroU64,
        child_execution: core::num::NonZeroU64,
    ) -> Result<Box<Born>, (NativeProcessError, Prepared)> {
        let result =
            portal().and_then(|owner| p.child.commit(&owner, self.worker()).map_err(error));
        match result {
            Ok(_) => Ok(Box::new(Born {
                prepared: p,
                child_task: child_task.get(),
                child_execution: child_execution.get(),
            })),
            Err(e) => Err((e, p)),
        }
    }
    fn abort_mm(&mut self, mut p: Prepared) -> Result<(), (NativeProcessError, Prepared)> {
        let result = portal()
            .and_then(|owner| abort_child(&owner, self.worker(), &mut p.child, &p.words, &p.loan));
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
        self.copy_signal_bytes(mm, address, &status.raw().to_ne_bytes())
    }
    fn copy_signal_bytes(
        &mut self,
        mm: &Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        self.copy_user_bytes(mm, address, bytes)
    }
    fn quarantine_prepared(&mut self, p: Prepared) {
        core::mem::forget(p);
        fatal();
    }
    fn quarantine_fork(
        &mut self,
        p: NativeForkPreparation<'static, Mm, Prepared, ParkedContextWords>,
    ) {
        core::mem::forget(p);
        fatal();
    }
    fn quarantine_born(&mut self, p: Box<Born>) {
        core::mem::forget(p);
        fatal();
    }
    fn retire_mm(&mut self, mm: Mm) {
        // The runtime calls this only for a fork-born process's final exit.
        let source = carrick_x86_carrier::native_execution::source(self.slot);
        // Fork stock is only ever loaned by a carrier that also published
        // its maintenance root; a child cannot exist without both.
        if mm.mm.raw().get() != self.task.mm.key.load(Ordering::Acquire)
            || carrick_el1::isa::x86::hardware_live_root().ok() != Some(mm.root)
            || source.zone.spaces.idle_ttbr() == 0
        {
            fatal();
        }
        // Close the child's gate first: nothing installs this MM again.
        let owner = portal().unwrap_or_else(|_| fatal());
        let index = owner
            .spaces
            .find(mm.mm.raw().get())
            .unwrap_or_else(|| fatal());
        owner.spaces.close(index);
        let binding = carrick_el1_linux::common_entry::execution_binding(self.task);
        let Some(mut retire) = NativeChildRetire::new(binding, mm) else {
            fatal();
        };
        // SAFETY: the aligned record stays on this CPU's supervisor stack
        // through the stopped host crossing, which authenticates the live
        // binding and root and writes its typed reply into the record.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") NATIVE_CHILD_RETIRE_PORT, in("rax") &raw mut retire, options(nostack));
        }
        // A refusal fails only this process's stock return: the stock stays
        // charged and is never reissued, and the exit still completes. A
        // missing reply is a crossing integrity fault.
        match retire.take(binding, mm) {
            Some(Ok(())) => {}
            Some(Err(carrick_el1_abi::ChildRetireRefusal::Stale)) => {
                carrick_el1_abi::record_native_fork_failure(
                    carrick_el1_abi::NativeForkFailureStage::ChildRetireRefusedStale,
                );
            }
            Some(Err(carrick_el1_abi::ChildRetireRefusal::Invalid)) => {
                carrick_el1_abi::record_native_fork_failure(
                    carrick_el1_abi::NativeForkFailureStage::ChildRetireRefusedInvalid,
                );
            }
            None => fatal(),
        }
        // The MM never runs again (its gate is closed): forget its live
        // context before publishing slot absence, so a concurrent fork that
        // reclaims this root page from quarantine after `leave_space` can
        // admit it for the next child without racing `LIVE_CONTEXTS`.
        if !anonymous::retire_context(mm) {
            fatal();
        }
        if !carrick_x86_carrier::native_execution::leave_space(source) {
            fatal();
        }
        let roots = core::ptr::from_ref(owner.roots).addr();
        RETIRED_SPACES.push(RetiredSpace {
            carrier: owner.carrier,
            zone: core::ptr::from_ref(source.zone).addr(),
            roots,
            mm: ReservationMm::new(mm.mm.raw().get()).unwrap_or_else(|| fatal()),
        });
        // A refused drain is not fatal: the failed entry and every entry
        // after it stay queued (`RetiredSpaces::drain`), and the next drain
        // (the next fork's `prepare_mm_start`, or the next child exit)
        // retries them, as on the AArch64 owner.
        let _retry_at_next_drain = drain_retired_spaces(&owner, self.worker());
    }
    fn copy_siginfo(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        info: &carrick_abi::LinuxSiginfo,
    ) -> Result<(), NativeProcessError> {
        // SAFETY: the canonical ABI record has a fully initialized wire image.
        let bytes = unsafe {
            core::slice::from_raw_parts(info as *const _ as *const u8, core::mem::size_of_val(info))
        };
        self.copy_signal_bytes(mm, address, bytes)
    }
    fn wake_effects(&mut self, mut effects: WakeEffects) {
        if effects.queued_own {
            effects.request_reschedule(self.slot);
        }
        deliver_wakes(effects);
    }
    fn request_ingress_producer_boundary(&mut self) {
        self.task.linux.mark_pending_host_work();
    }
    fn child_file_table(&self, _parent_table: u64, issued: u64) -> u64 {
        issued
    }
    fn fork_fd_table(
        &mut self,
        parent_table: u64,
        child_table: u64,
    ) -> Result<(), NativeProcessError> {
        let files = crate::linux_personality::file_tables(
            carrick_el1::isa::x86::context::current_cpu_binding()
                .ok_or(NativeProcessError::Stale)?,
        );
        carrick_el1_linux::file_table::fork_fd_map(
            files.fd_map(),
            files.opens(),
            parent_table,
            child_table,
        )
        .then_some(())
        .ok_or(NativeProcessError::Exhausted)
    }
    fn retire_fd_table(&mut self, table: u64) {
        let binding =
            carrick_el1::isa::x86::context::current_cpu_binding().unwrap_or_else(|| fatal());
        let files = crate::linux_personality::file_tables(binding);
        carrick_el1_linux::file_table::retire_fd_map(files.fd_map(), files.opens(), table);
        self.task.linux.mark_pending_host_work();
    }
}

fn settle(born: Box<Born>, worker: u32) -> Result<(), (NativeProcessError, Box<Born>)> {
    let p = &born.prepared;
    let Some(mut exchange) = ForkStockSettlement::commit_reserved_with_child_identity(
        p.loan,
        p.child.completion(),
        born.child_task,
        born.child_execution,
    ) else {
        return Err((NativeProcessError::Stale, born));
    };
    // SAFETY: exact completion record remains owned across the stopped crossing;
    // graph and MM editors were released.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") FORK_STOCK_PORT, in("rax") &raw mut exchange, options(nostack));
    }
    if !matches!(exchange.take(p.loan), Some(Ok(()))) {
        return Err((NativeProcessError::Quarantined, born));
    }
    // The child's first syscall capture authenticates this context. A root
    // reissued from fork stock is free here because the retired child that
    // held it left `LIVE_CONTEXTS` in `retire_mm`; a refusal is an owner
    // custody fault, reported rather than discovered at that capture.
    if !anonymous::admit_context(p.address) {
        return Err((NativeProcessError::Stale, born));
    }
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
    carrick_x86_carrier::entry::fatal_boot()
}
