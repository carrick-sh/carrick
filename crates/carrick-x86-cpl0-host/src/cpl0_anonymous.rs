//! Physical custody service for CPL0-selected anonymous windows. No host VMA
//! selection or live descriptor store occurs at this boundary.
use super::*;
use carrick_el1_abi::{MmPortalSlots, PortalGrantWindow};
use carrick_guest_arch::KernelVa;
use carrick_hal::fork_stock::{
    ForkStockServiceError, GrantExecution, LifecycleWindow, NoTableLedger, SlotAbsence,
    lifecycle_slots,
};
use carrick_hal::guest_arch_binding::{
    GuestArchBinding,
    core_arch::{ExecutionGeneration, TaskIdentity, TaskSerial},
};
use carrick_hal::{FrameEventCapacity, FrameInventoryEvent};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp as WireOp, DescriptorTxn as WireTxn, TableGrants,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

fn decode_fork_custody(bytes: &[u8]) -> Option<carrick_el1_abi::PortalForkCustody> {
    if bytes.len() != 32 {
        return None;
    }
    carrick_el1_abi::PortalForkCustody::decode(std::array::from_fn(|i| {
        u64::from_ne_bytes(std::array::from_fn(|byte| bytes[i * 8 + byte]))
    }))
}

/// Every I/O port this CPL0 carrier decodes from one VM; each must be
/// distinct. `carrick_x86::FP_STUB_DOORBELL_PORT` (0xc6) is deliberately
/// absent: only the legacy no-FP-getter x86 engine in a bhyve VM decodes
/// it (`run_fp_stub`), never a hardware CPL0 VM, so its number is shared with
/// [`carrick_core_abi::X86_INITIAL_BOOT_PORT`] without aliasing.
pub const CPL0_CARRIER_PORTS: [u16; 22] = [
    FAULT_DOORBELL_PORT,
    FORWARD_PORT,
    CONTROL_PORT,
    ENTRY_KICK_PORT,
    RETURN_KICK_PORT,
    WORK_PORT,
    NATIVE_SERVICE_PORT,
    FATAL_PORT,
    YIELD_PORT,
    OWNER_GRANT_PORT,
    carrick_core_abi::X86_INITIAL_BOOT_PORT,
    carrick_x86::cpl0_scheduler::PROGRESS_ENTRY_PORT,
    carrick_x86::cpl0_scheduler::PROGRESS_RETURN_PORT,
    carrick_x86::cpl0_scheduler::PROGRESS_DONE_PORT,
    carrick_el1_abi::FORK_STOCK_PORT,
    carrick_core_abi::NATIVE_ROOT_EXIT_PORT,
    carrick_el1_abi::NATIVE_PEER_READY_PORT,
    carrick_core_abi::NATIVE_RUN_FAILURE_PORT,
    carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
    carrick_el1_abi::NATIVE_SPACE_RETIRED_PORT,
    carrick_core_abi::X86_INITIAL_RUNNER_READY_PORT,
    carrick_el1_abi::NATIVE_EXEC_PORT,
];

const _: () = {
    let ports = CPL0_CARRIER_PORTS;
    let mut i = 0;
    while i < ports.len() {
        let mut j = 0;
        while j < i {
            assert!(
                ports[i] != ports[j],
                "CPL0 carrier ports must be pairwise distinct"
            );
            j += 1;
        }
        i += 1;
    }
};

/// Immutable physical storage licensed by the supervisor image's ELF loads.
/// This qualifies transport bytes without importing process or MM policy.
pub struct KernelPodStorage {
    start: carrick_guest_arch::KernelVa,
    len: u64,
    physical: FrameGpa,
}
impl KernelPodStorage {
    /// The global allocator admits exactly this ABI-declared aperture;
    /// physical bootstrap owns its private window at the matching offset.
    pub(super) fn for_bootstrap() -> Self {
        Self {
            start: carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE),
            len: EL1_BOOTSTRAP_METADATA_SIZE,
            physical: FrameGpa::new(ALLOCATOR_GPA),
        }
    }

    pub(super) fn from_load(segment: &carrick_mem::elf::LoadSegment) -> Option<Self> {
        let end = segment.virtual_address.checked_add(segment.memory_size)?;
        if !segment.perms.read
            || !segment.perms.write
            || segment.perms.execute
            || segment.memory_size == 0
            || segment.virtual_address < IMAGE_VA
            || end > IMAGE_VA + IMAGE_SIZE
        {
            return None;
        }
        Some(Self {
            start: carrick_guest_arch::KernelVa::new(segment.virtual_address),
            len: segment.memory_size,
            physical: FrameGpa::new(IMAGE_GPA.checked_add(segment.virtual_address - IMAGE_VA)?),
        })
    }
}

pub fn retained_kernel_pod_storage(
    segments: &[carrick_mem::elf::LoadSegment],
) -> Vec<KernelPodStorage> {
    let mut storage: Vec<_> = segments
        .iter()
        .filter_map(KernelPodStorage::from_load)
        .collect();
    storage.push(KernelPodStorage::for_bootstrap());
    storage
}

fn kernel_pod_physical(
    storage: &[KernelPodStorage],
    address: carrick_guest_arch::KernelVa,
    len: usize,
    alignment: usize,
) -> Option<FrameGpa> {
    if len == 0 || alignment == 0 || !address.raw().is_multiple_of(alignment as u64) {
        return None;
    }
    let end = address.raw().checked_add(u64::try_from(len).ok()?)?;
    let source = storage.iter().find(|source| {
        address.raw() >= source.start.raw()
            && source
                .start
                .raw()
                .checked_add(source.len)
                .is_some_and(|limit| end <= limit)
    })?;
    Some(FrameGpa::new(
        source
            .physical
            .raw()
            .checked_add(address.raw() - source.start.raw())?,
    ))
}

pub type PrepareTableSpan = carrick_core_abi::X86PrepareTableSpan;

pub fn prepare_table_working_bytes() -> Option<usize> {
    let lanes = core::num::NonZeroUsize::new(carrick_x86::cpl0_entry::CPL0_CPU_COUNT)?;
    usize::try_from(PrepareTableSpan::working_bytes(lanes)?.raw()).ok()
}

pub fn prepare_table_suffix(extent_bytes: usize, occupied_end: usize) -> Option<PrepareTableSpan> {
    PrepareTableSpan::derive(
        carrick_guest_arch::GuestLen::new(u64::try_from(extent_bytes).ok()?),
        FrameGpa::new(INITIAL_EXTENT_GPA.checked_add(u64::try_from(occupied_end).ok()?)?),
        core::num::NonZeroUsize::new(carrick_x86::cpl0_entry::CPL0_CPU_COUNT)?,
    )
}

/// The never-issued page-table reserve between the occupied boot records
/// and grants (`occupied_end`, an extent offset) and the Prepare working
/// suffix: the span the CPL0 editor licenses as tables at boot
/// ([`carrick_core_abi::X86TableReserve`]), as the fork stock draws it.
pub fn initial_table_reserve(
    occupied_end: usize,
    working: PrepareTableSpan,
) -> Option<carrick_hal::fork_stock::TableReserve> {
    let occupied_end = INITIAL_EXTENT_GPA.checked_add(u64::try_from(occupied_end).ok()?)?;
    let span = carrick_core_abi::X86TableReserve::derive(FrameGpa::new(occupied_end), working)?;
    carrick_hal::fork_stock::TableReserve::new(span.start(), span.end())
}

/// What preparing an owner-selected window produced.
pub(super) enum BackingPreparation {
    /// Submitted to the slot for the ring to apply and settle.
    Prepared(Box<PendingPrepare>),
    /// Selected page lies at or past the file's end: leave a user fault's
    /// selection pending so the guest cancels it into `SIGBUS`, or answer
    /// `false` on a staged syscall copy.
    FilePastEnd,
    /// The carrier's table stock and reserve are genuinely spent into live
    /// committed MM custody (`returnable_tables == 0`): counted refusal.
    TablesExhausted,
    /// The read-only plan met another CPU's publication in the selected
    /// window (the shared policy's inherited-Prepared or MM-release decline).
    Raced,
}

/// Why preparing an owner-selected window must wait and rerun ("not now")
/// rather than refuse or fail: either the MM's EL1 editor was held under the
/// outer exclusion (#2941), or returnable custody in `ForkStock` temporarily
/// holds the remaining page tables (#3017).
#[derive(::core::fmt::Debug)]
pub(super) enum PlanBusy {
    Editor,
    TableStock,
}

/// Why the read-only table plan made nothing guest-visible.
enum PlanDecline {
    Refused(carrick_mmu_core::descriptor_refusal::DescriptorRefusal),
    EditorBusy,
}

/// What an owner grant publishes (#1338).
pub(super) enum GrantBacking {
    /// Fresh private frames, owned by this grant until it settles or is
    /// cancelled.
    Private {
        inventory: Box<InitialInventory>,
        handle: BackingHandle,
    },
    /// One page of a shared file window slot. The carrier keeps the slot for
    /// the run, so the grant owns nothing to cancel.
    Window,
}

struct BackingGrant {
    op: WireOp,
    backing: GrantBacking,
}

impl GrantBacking {
    /// The guest may now name this backing: keep it through teardown unless
    /// an exact receipt proves otherwise.
    fn submitted(&mut self) {
        if let Self::Private { inventory, .. } = self {
            inventory.expected = 1;
            inventory.guest_exposed = true;
        }
    }

    /// An exact withdrawn or refused receipt proved no guest descriptor
    /// names this backing.
    fn unexposed(&mut self) {
        if let Self::Private { inventory, .. } = self {
            inventory.guest_exposed = false;
        }
    }
}

/// A shared file window page has no frame inventory: its bytes are the
/// file's, held by the window slot's host mapping.
struct WindowInventory;
impl crate::carrier_memory::InventoryTransaction for WindowInventory {
    fn publish(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        Ok(())
    }
    fn commit(
        &mut self,
        _publication: &GuestMmuPublication,
    ) -> Result<(), crate::carrier_memory::MemoryError> {
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        Ok(())
    }
}

pub(super) struct PendingPrepare {
    peer: crate::cpl0_private_witness::PeerActivity,
    window: PortalGrantWindow,
    txn: WireTxn,
    backing: GrantBacking,
    execution: GrantExecution,
    owner: carrick_el1_abi::El1MmHandle,
}

impl PendingPrepare {
    pub(super) fn authenticates_native_reply(
        &self,
        execution: GrantExecution,
        owner: carrick_el1_abi::El1MmHandle,
        generation: NonZeroU64,
    ) -> bool {
        execution.context == self.execution.context
            && execution.binding.task == self.execution.binding.task
            && execution.binding.thread_generation == self.execution.binding.thread_generation
            && owner.carrier() == self.window.operation.carrier
            && owner.mm() == self.window.operation.mm
            && owner.incarnation() == self.window.operation.incarnation
            && generation == self.txn.id.generation
    }
}

/// One copy-on-write replacement grant the carrier published in an MM's pool
/// and has not settled. The grant is the MM's: any member holding the MM's
/// editor may claim it, for any of the MM's copy-on-write pages, from either
/// CPU. So the record names no CPU, execution or page; the guest's completion
/// receipt supplies the page and the source at settlement (#2749).
pub(super) struct SuppliedCow {
    inventory: InitialInventory,
    handle: BackingHandle,
    grant: carrick_el1_abi::CowGrant,
}
impl carrick_core::mm::own::GrantPayload for SuppliedCow {
    type Key = carrick_el1_abi::CowGrant;
    fn key(&self) -> &carrick_el1_abi::CowGrant {
        &self.grant
    }
}

/// The carrier's memory-ownership core (#3061). PR 1a moves the MMs, their
/// editor record and their copy-on-write grants into it; the backend
/// mappings and extents stay in `CarrierMemory` until PR 1b.
pub(super) type X86MmCore = carrick_core::mm::own::CarrierCore<X86CoreVenue, (), (), SuppliedCow>;

/// The x86 carrier's answer to a broken core invariant: end the carrier.
pub(super) struct X86CoreVenue;

impl carrick_core::mm::own::CoreVenue for X86CoreVenue {
    fn dropped_holding(_: carrick_core::mm::own::Holding) -> ! {
        carrick_el1_linux::dispatch::invalid_completion(
            carrick_el1_linux::dispatch::NativeInvariant::PhysicalCustody(
                carrick_el1_linux::dispatch::PhysicalCustodyInvariant::CoreDroppedHolding,
            ),
        )
    }
}

/// A fresh core for a new carrier, under the carrier VM's own identity.
pub(super) fn new_mm_core(vm: crate::carrier_memory::CarrierVmId) -> X86MmCore {
    X86MmCore::new(vm.carrier())
}

/// The core's view of the guest exclusion the shell holds.
fn core_excluded<'a>(
    excluded: &'a carrick_el1_abi::ExcludedEditor<'_>,
) -> Result<carrick_core::mm::own::ExcludedMm<'a>, TrapError> {
    carrick_core::mm::own::ExcludedMm::of(excluded).ok_or_else(|| fail("owner COW null MM"))
}

/// Whether `receipt` is a well-formed user-write completion of exactly
/// `grant`: one page, moved out of a compound other than the grant's, into
/// the grant's compound at the source's offset. The page and the source are
/// the receipt's own; the live leaf and the residency row authenticate them.
fn exact_cow_receipt(
    grant: carrick_el1_abi::CowGrant,
    receipt: &carrick_el1_abi::CowGrantCompletion,
) -> bool {
    receipt.is_well_formed()
        && receipt.purpose == carrick_el1_abi::CowGrantPurpose::UserWrite
        && receipt.grant == grant
        && receipt.span_va & 0xfff == 0
        && receipt.span_len == 4096
        && receipt.old_ipa & 0xfff == 0
        && receipt.new_ipa == grant.physical_ipa + (receipt.old_ipa & 0x3fff)
        && receipt.old_ipa & !0x3fff != grant.physical_ipa
}

pub(super) fn retained_cow_zone(ram: &GuestRam) -> Result<&X86Cpl0Zone, TrapError> {
    let ptr = ram
        .host_ptr(
            META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
            size_of::<X86Cpl0Zone>(),
        )
        .ok_or_else(|| fail("owner COW zone"))?;
    // SAFETY: boot initialized aligned production zone retained by this RAM.
    Ok(unsafe { &*ptr.cast::<X86Cpl0Zone>() })
}

struct HostCowWake<'a, M: CarrierMemoryIo> {
    routes: &'a PublishedApicIds,
    vm: Arc<M>,
    error: std::cell::RefCell<Option<TrapError>>,
}
impl<'a, M: CarrierMemoryIo> HostCowWake<'a, M> {
    fn new(ram: &'a GuestRam, vm: Arc<M>) -> Result<Self, TrapError> {
        let pointer = ram
            .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
            .ok_or_else(|| fail("owner COW retained APIC routes"))?;
        // SAFETY: bootstrap initialized this retained aligned atomic record.
        let routes = unsafe { &*pointer.cast::<PublishedApicIds>() };
        Ok(Self {
            routes,
            vm,
            error: std::cell::RefCell::new(None),
        })
    }
    fn deliver(
        &self,
        zone: &X86Cpl0Zone,
        _: Waker,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        // A waiter no guest slot could take (its CPUs stopped, one of them
        // in this exit; for example a member parked on the gate this
        // release lowers) goes back to its native ring owner's queue, as a
        // host IPC release's does. A host thread never completes it.
        let (_, effects) = owned.deliver_handbacks(&mut |record| {
            zone.hand_back_to_owner(record, &mut |slot| {
                if let Err(error) = signal_resched(self.routes, &*self.vm, slot) {
                    self.error.borrow_mut().get_or_insert(error);
                }
            });
        });
        if effects.owes_host_boundary() || effects.queued_own {
            self.error
                .borrow_mut()
                .get_or_insert_with(|| fail("host COW release produced guest-own wake effects"));
        }
        for slot in effects.sgi_slots() {
            if let Err(error) = signal_resched(self.routes, &*self.vm, slot) {
                self.error.borrow_mut().get_or_insert(error);
            }
        }
    }
    fn finish(&self) -> Result<(), TrapError> {
        self.error.borrow_mut().take().map_or(Ok(()), Err)
    }
}

/// The x86 ISA mechanic of a host reschedule: an APIC MSI carrying the
/// reschedule vector to `slot`'s published APIC destination. A halted CPU
/// wakes; a stopped one takes it when it next enters the guest.
fn signal_resched<M: CarrierMemoryIo>(
    routes: &PublishedApicIds,
    vm: &M,
    slot: SlotId,
) -> Result<(), TrapError> {
    let apic = routes
        .destination(carrick_guest_arch::CpuId::new(u32::from(slot.raw())))
        .ok_or_else(|| fail("host wake APIC route absent"))?;
    let address_lo = 0xfee0_0000 | (u32::from(apic.0) << 12);
    let data = u32::from(carrick_x86::interrupts::RESCHED_VECTOR);
    vm.signal_msi(address_lo, data)
        .map_err(|error| fail(format!("host wake MSI: {error}")))
}

/// Test-support seam over the carrier sink's MSI delivery: every carrier
/// reschedule fails once armed. The production sink has no such toggle.
#[cfg(feature = "test-support")]
static FAIL_CARRIER_RESCHED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Arm the failed-MSI seam for the rest of this process (test-support only).
#[cfg(feature = "test-support")]
pub fn fail_carrier_resched_for_test() {
    FAIL_CARRIER_RESCHED.store(true, std::sync::atomic::Ordering::Release);
}

/// Where [`editor_hold`] holds an MM's editor.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorHoldSite {
    /// #2941: a native first-touch backing plan's own exclusion.
    BackingPlan,
    /// #3061 PR 1a: a copy-on-write supply's exclusion, for an EL0 write or
    /// a kernel user copy alike.
    CowSupply,
}

/// Witness seam (test-support only): an exclusion of an MM at the armed
/// site finds the MM's editor held by a real borrow (a maintenance borrow
/// under a plan's raised gate, an in-ring edit at a COW supply). The borrow
/// is released through its production release right after that probe. The
/// seam stays armed until it actually holds the editor: a probe that finds
/// the editor already held elsewhere leaves it armed for the next.
///
/// At a COW supply it holds exactly one demand, the `nth` supply probe of
/// one MM, and records that demand: its MM, its page and the member
/// (execution binding) that asked. It then counts, for that exact demand
/// only, the supplies published for it, and the carrier work the same member
/// rang while its demand stayed unsupplied. A sibling's supply of the page,
/// or another member's carrier work, is not counted (#3061 PR 1a).
#[cfg(feature = "test-support")]
pub(super) mod editor_hold {
    use super::EditorHoldSite;
    use carrick_core_abi::ExecutionBinding;
    use carrick_sched_core::spaces::notification::SpaceReleaseVenue;
    use core::num::NonZeroU64;
    use std::sync::Mutex;

    /// The one COW demand the seam held.
    #[derive(Clone, Copy, Debug)]
    struct HeldCow {
        mm: u64,
        page: u64,
        member: ExecutionBinding,
        /// No supply has been published for it yet.
        outstanding: bool,
    }
    #[derive(Debug, Default)]
    struct Site {
        /// The supply probe of one MM to hold at (1: the first); 0: unarmed.
        armed_nth: u64,
        /// Per MM, the supply probes seen while armed.
        seen: Vec<(u64, u64)>,
        holds: u64,
        held: Option<HeldCow>,
        /// Further probes of the held demand to refuse after its first.
        again: u64,
        supplied: u64,
        carrier_work_while_held: u64,
    }
    static BACKING_PLAN: Mutex<Site> = Mutex::new(site());
    static COW_SUPPLY: Mutex<Site> = Mutex::new(site());
    const fn site() -> Site {
        Site {
            armed_nth: 0,
            seen: Vec::new(),
            holds: 0,
            held: None,
            again: 0,
            supplied: 0,
            carrier_work_while_held: 0,
        }
    }
    fn of(at: EditorHoldSite) -> std::sync::MutexGuard<'static, Site> {
        match at {
            EditorHoldSite::BackingPlan => &BACKING_PLAN,
            EditorHoldSite::CowSupply => &COW_SUPPLY,
        }
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// The borrower: no member of the zone.
    const HOLDER: NonZeroU64 = NonZeroU64::MAX;

    /// The demand an exclusion probes for: a COW supply names its page and
    /// member; a backing plan names none.
    #[derive(Clone, Copy, Debug)]
    pub(in super::super) struct Demand {
        pub page: u64,
        pub member: ExecutionBinding,
    }

    pub(in super::super) fn take<'a>(
        at: EditorHoldSite,
        venue: SpaceReleaseVenue<'a, carrick_sched_core::ParkedContextWords>,
        mm: NonZeroU64,
        demand: Option<Demand>,
    ) -> Option<carrick_sched_core::spaces::SpaceEditor<'a, carrick_sched_core::ParkedContextWords>>
    {
        let mut site = of(at);
        // The held demand's own later probes, while it has refusals left.
        let again = site.again > 0
            && site.held.is_some_and(|held| {
                held.outstanding
                    && held.mm == mm.get()
                    && demand.is_some_and(|d| d.page == held.page && d.member == held.member)
            });
        if again {
            let index = venue.zone.spaces.find(mm.get())?;
            let editor = venue
                .zone
                .spaces
                .try_begin_edit_cause(index, mm.get(), HOLDER, Some(venue))
                .ok()?;
            site.again -= 1;
            site.holds += 1;
            return Some(editor);
        }
        if site.armed_nth == 0 {
            return None;
        }
        let seen = match site.seen.iter_mut().find(|(key, _)| *key == mm.get()) {
            Some((_, seen)) => *seen,
            None => {
                site.seen.push((mm.get(), 0));
                0
            }
        };
        // Not this MM's armed probe yet: count it and let it run.
        if seen + 1 < site.armed_nth {
            if let Some((_, seen)) = site.seen.iter_mut().find(|(key, _)| *key == mm.get()) {
                *seen += 1;
            }
            return None;
        }
        let index = venue.zone.spaces.find(mm.get())?;
        let spaces = &venue.zone.spaces;
        let editor = match at {
            // Under the plan caller's outer exclusion the gate is raised, so
            // only a maintenance borrow is admitted there.
            EditorHoldSite::BackingPlan => {
                spaces.try_begin_maintenance_edit(index, mm.get(), HOLDER, Some(venue))
            }
            // A COW supply excludes from an open gate: the editor is held as
            // a guest member's in-ring edit holds it.
            EditorHoldSite::CowSupply => {
                spaces.try_begin_edit_cause(index, mm.get(), HOLDER, Some(venue))
            }
        }
        // Held elsewhere already: stay armed, uncounted, for this demand's
        // rerun.
        .ok()?;
        site.armed_nth = 0;
        site.holds += 1;
        site.held = demand.map(|demand| HeldCow {
            mm: mm.get(),
            page: demand.page,
            member: demand.member,
            outstanding: true,
        });
        Some(editor)
    }
    /// A COW supply of `mm`'s `page`, asked by `member`, was published.
    pub(in super::super) fn supplied(mm: NonZeroU64, page: u64, member: ExecutionBinding) {
        let mut site = of(EditorHoldSite::CowSupply);
        let Some(held) = site.held.as_mut() else {
            return;
        };
        if held.mm == mm.get() && held.page == page && held.member == member {
            held.outstanding = false;
            site.supplied += 1;
        }
    }
    /// `member` rang carrier work (a bare "not now" re-ring).
    pub(in super::super) fn carrier_work(member: ExecutionBinding) {
        let mut site = of(EditorHoldSite::CowSupply);
        if site
            .held
            .is_some_and(|held| held.outstanding && held.member == member)
        {
            site.carrier_work_while_held += 1;
        }
    }
    pub(in super::super) fn arm(at: EditorHoldSite, nth: u64, probes: u64) {
        let mut state = of(at);
        *state = site();
        state.armed_nth = nth.max(1);
        state.again = probes.saturating_sub(1);
    }
    pub(in super::super) fn holds(at: EditorHoldSite) -> u64 {
        of(at).holds
    }
    /// The held COW demand's supplies, and the carrier work its member rang
    /// while it stayed unsupplied.
    pub(in super::super) fn held_cow() -> (u64, u64) {
        let site = of(EditorHoldSite::CowSupply);
        (site.supplied, site.carrier_work_while_held)
    }
}

/// Arm [`editor_hold`] for the next exclusion at `at` in this process
/// (test-support only).
#[cfg(feature = "test-support")]
pub fn hold_editor_at_next_for_test(at: EditorHoldSite) {
    editor_hold::arm(at, 1, 1);
}

/// Arm [`editor_hold`] for the `nth` copy-on-write supply probe of one MM in
/// this process, and hold that same demand's editor for `probes` probes in a
/// row (test-support only). Each refused probe must park the demand on the
/// editor's release; none may re-ring the carrier.
#[cfg(feature = "test-support")]
pub fn hold_editor_at_nth_cow_supply_for_test(nth: u64, probes: u64) {
    editor_hold::arm(EditorHoldSite::CowSupply, nth, probes);
}

/// Exclusions at `at` that met the armed borrow.
#[cfg(feature = "test-support")]
pub fn editor_holds_for_test(at: EditorHoldSite) -> u64 {
    editor_hold::holds(at)
}

/// For the exact COW demand whose supply editor the seam held: the supplies
/// published for it, and the carrier work its member rang while it stayed
/// unsupplied.
#[cfg(feature = "test-support")]
pub fn held_cow_demand_for_test() -> (u64, u64) {
    editor_hold::held_cow()
}

/// The carrier-scoped zone host IPC releases wake into (#2031). The zone
/// and APIC routes live in guest RAM this sink retains; the host IPC owner
/// delivers through it when no process-global zone serves.
struct CarrierZoneWakeSink<M: CarrierMemoryIo> {
    _ram: Arc<GuestRam>,
    zone: std::ptr::NonNull<X86Cpl0Zone>,
    routes: std::ptr::NonNull<PublishedApicIds>,
    vm: Arc<M>,
    /// The first reschedule this carrier could not deliver since the host
    /// IPC owner last asked ([`carrick_sched_core::CarrierZoneWake::take_undelivered`]).
    resched_fault: std::sync::Mutex<Option<carrick_sched_core::WakeUndelivered>>,
}
// SAFETY: both pointers name retained, aligned, atomic-only records inside
// `_ram`, which this sink keeps alive; they are only read through shared
// references.
unsafe impl<M: CarrierMemoryIo> Send for CarrierZoneWakeSink<M> {}
// SAFETY: as above.
unsafe impl<M: CarrierMemoryIo> Sync for CarrierZoneWakeSink<M> {}
impl<M: CarrierMemoryIo> carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>
    for CarrierZoneWakeSink<M>
{
    fn zone(&self) -> &X86Cpl0Zone {
        // SAFETY: validated at creation; retained by `_ram`.
        unsafe { self.zone.as_ref() }
    }
    fn resched(&self, slot: SlotId) {
        // SAFETY: validated at creation; retained by `_ram`.
        let routes = unsafe { self.routes.as_ref() };
        #[cfg(feature = "test-support")]
        let delivered = if FAIL_CARRIER_RESCHED.load(std::sync::atomic::Ordering::Acquire) {
            Err(fail("injected carrier reschedule failure"))
        } else {
            signal_resched(routes, &*self.vm, slot)
        };
        #[cfg(not(feature = "test-support"))]
        let delivered = signal_resched(routes, &*self.vm, slot);
        if delivered.is_err() {
            self.resched_fault
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_or_insert(carrick_sched_core::WakeUndelivered(
                    "APIC route absent or reschedule MSI not delivered",
                ));
        }
    }
    fn take_undelivered(&self) -> Option<carrick_sched_core::WakeUndelivered> {
        self.resched_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    /// The carrier zone wake sink this carrier's host IPC owner binds.
    pub(crate) fn carrier_zone_wake(
        &self,
    ) -> Result<
        Arc<dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>>,
        TrapError,
    > {
        let zone = std::ptr::NonNull::from(retained_cow_zone(&self.ram)?);
        let routes =
            std::ptr::NonNull::from(HostCowWake::new(&self.ram, self._vm.clone_vm())?.routes);
        Ok(Arc::new(CarrierZoneWakeSink {
            _ram: Arc::clone(&self.ram),
            zone,
            routes,
            vm: self._vm.clone_vm(),
            resched_fault: std::sync::Mutex::new(None),
        }))
    }
}
pub(super) fn retained_reservations(ram: &GuestRam) -> Result<&X86Cpl0Reservations, TrapError> {
    let ptr = ram
        .host_ptr(
            META_GPA + carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET,
            size_of::<X86Cpl0Reservations>(),
        )
        .ok_or_else(|| fail("owner reservation table"))?;
    // SAFETY: boot initialized aligned production reservation table retained
    // by this RAM; a retired MM's owed slots are settled only by its receipt.
    Ok(unsafe { &*ptr.cast::<X86Cpl0Reservations>() })
}

/// Which carrier-wide release a child gets: a retired child's spends its
/// release receipt on the owed returns its retired root left; a fork child
/// that never ran owes none.
pub(super) enum ChildRelease<'a> {
    Retired {
        returns: &'a dyn carrick_el1_abi::RetiredReturns,
        zone: &'a X86Cpl0Zone,
        /// The carrier's core: the retired MM's copy-on-write grants leave
        /// with it (#2749).
        mms: &'a mut X86MmCore,
    },
    Unrun,
}

fn resolve_cpl0_residency<M: CarrierMemoryIo>(
    memory: &CarrierMemory<M>,
) -> Result<
    carrick_core_abi::mm::residency::ResolvedResidencyTable<
        carrick_core_abi::mm::residency::NoDynamicResidencyPin,
    >,
    TrapError,
> {
    // SAFETY: the retained aligned residency table initialized at boot.
    let table = unsafe {
        memory.retained_record::<carrick_el1_abi::FrameGrantResidencyTable>(FrameGpa::new(
            KERNEL_REGION_GPA + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
        ))
    }
    .map_err(|e| fail(e.to_string()))?;
    let bootstrap_size = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE as usize;
    let bootstrap_ptr = memory
        .retained_bytes_ptr(FrameGpa::new(ALLOCATOR_GPA), bootstrap_size)
        .map_err(|e| fail(e.to_string()))?;
    let mut resolved = carrick_core_abi::mm::residency::ResolvedResidencyTable::new();
    // SAFETY: `table` and `bootstrap_ptr` belong to this live carrier's
    // retained RAM and remain mapped while `memory` is borrowed.
    unsafe {
        resolved.refresh(
            table,
            &carrick_core_abi::mm::residency::NoDynamicResidencyResolver,
            Some((
                X86_CPL0_BOOTSTRAP_METADATA_BASE,
                bootstrap_size,
                bootstrap_ptr,
            )),
        )
    }
    .map_err(|e| fail(format!("cpl0 residency extension resolution: {e:?}")))?;
    Ok(resolved)
}

/// A release that quarantined the carrier found a broken invariant (#3132:
/// a released slot that a frame still names): that ends the run, never the
/// deferral the stock counts and retries on its next drain, which could
/// only loop while the guest kept running. The stock's release callbacks
/// answer a bool, so each drain asks this once the stock returns.
pub(super) fn fatal_if_quarantined<M: CarrierMemoryIo>(
    memory: &CarrierMemory<M>,
) -> Result<(), TrapError> {
    if memory.is_quarantined() {
        return Err(fail(
            "carrier memory quarantined (a broken invariant) at a retired-child release drain",
        ));
    }
    Ok(())
}

/// Release a reclaimed child's carrier-wide state: its frame-inventory rows
/// and COW residency (shared composition), then its CR3/alias registrations
/// and the memslots admitted only for it.
pub(super) fn release_retired_child<M: CarrierMemoryIo>(
    memory: &mut CarrierMemory<M>,
    inventory: &dyn carrick_hal::PhysicalFrameInventory,
    absence: &SlotAbsence,
    release: ChildRelease<'_>,
) -> Result<crate::carrier_memory::RetiredChild, TrapError> {
    let residency = resolve_cpl0_residency(memory)?;
    let residency_view = residency
        .view()
        .ok_or_else(|| fail("cpl0 residency view unavailable"))?;
    let released = match release {
        ChildRelease::Retired { returns, zone, mms } => {
            match zone.spaces.unpublished(absence.mm().raw()) {
                Some(absent) => {
                    // The retired MM's replacement grants, claimed or not, go
                    // with it: no member is left to claim one and no exclusion
                    // will settle one. Its inventory release below retires
                    // their frames with the rest of its mappings.
                    // SAFETY: retained aligned atomic-only kernel record
                    // initialized at boot.
                    let pool: &carrick_el1_abi::CowGrantPool = unsafe {
                        memory.retained_record(FrameGpa::new(
                            KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
                        ))
                    }
                    .map_err(|error| fail(error.to_string()))?;
                    pool.release_mm(&absent);
                    let key = NonZeroU64::new(absent.key())
                        .ok_or_else(|| fail("retired child null MM"))?;
                    drop(
                        mms.retire_mm(carrick_core::mm::own::MmKey::new(key))
                            .map_err(|refusal| {
                                fail(format!("retired child COW grants: {refusal:?}"))
                            })?,
                    );
                    carrick_hal::fork_stock::release_child_mm(
                        inventory,
                        &residency_view,
                        returns,
                        &absent,
                    )
                }
                None => false,
            }
        }
        ChildRelease::Unrun => carrick_hal::fork_stock::release_unrun_child_mm(
            inventory,
            &residency_view,
            absence.mm(),
        ),
    };
    if !released {
        return Err(fail("retired child inventory or residency release"));
    }
    memory
        .retire_child(absence, inventory)
        .map_err(|e| fail(e.to_string()))
}

/// The residency rows one fork publishes: a one-page row in the parent and
/// in the child for each inherited page no parent grant window covers, and
/// one child row per covering window.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
struct ForkResidencyDemand {
    rows: usize,
}

impl ForkResidencyDemand {
    fn count<S: carrick_core_abi::mm::residency::FrameGrantResidencyAccess>(
        residency: &carrick_el1_abi::FrameGrantResidencyTable<S>,
        parent_mm: u64,
        pages: impl Iterator<Item = u64>,
    ) -> Self {
        let mut windows = std::collections::BTreeSet::new();
        let mut uncovered = 0usize;
        for va in pages {
            match residency.lookup(parent_mm, va) {
                Some(page) => {
                    windows.insert(page.identity.semantic_base);
                }
                None => uncovered += 1,
            }
        }
        Self {
            rows: uncovered.saturating_mul(2).saturating_add(windows.len()),
        }
    }

    /// Admit only when the table stays at most half full with this fork's
    /// rows. `try_publish` gives up after a bounded probe chain in every
    /// segment, and measured chains fill at 80% occupancy (#2655), so a
    /// fuller table would refuse part-way through the fork.
    fn admitted<S: carrick_core_abi::mm::residency::FrameGrantResidencyAccess>(
        self,
        residency: &carrick_el1_abi::FrameGrantResidencyTable<S>,
    ) -> bool {
        residency
            .observed_slots_used()
            .saturating_add(self.rows)
            .saturating_mul(2)
            <= residency.slot_capacity()
    }
}

fn rollback_fork_parent_residency<S: carrick_core_abi::mm::residency::FrameGrantResidencyAccess>(
    residency: &carrick_el1_abi::FrameGrantResidencyTable<S>,
    publications: &[(usize, carrick_el1_abi::FrameGrantResidencyIdentity)],
) -> Result<(), TrapError> {
    for &(slot, identity) in publications.iter().rev() {
        if !residency.retire(slot, identity) {
            return Err(fail("physical fork parent residency rollback"));
        }
    }
    Ok(())
}

/// The fork stock exactly as carrier boot stocks it.
struct BootForkStock {
    /// The dedicated maintenance-root grant (`MAINTENANCE_ROOT_TABLE_CREDITS`).
    maintenance: RootGpa,
    /// The remaining unused initial table grants.
    tables: Vec<RootGpa>,
    /// `FORK_LIFECYCLE_SLOTS` records in the metadata window.
    lifecycles: Vec<carrick_el1_abi::ForkLifecycleLoan>,
}

/// Split the unused initial table grants into the maintenance root (the
/// first, which boot counted as its own credit) and the fork table stock,
/// and lay out the lifecycle records.
fn boot_fork_stock(mut unused: Vec<RootGpa>) -> Result<BootForkStock, TrapError> {
    if unused.len() <= super::MAINTENANCE_ROOT_TABLE_CREDITS {
        return Err(fail(
            "no initial table grant left after the maintenance root",
        ));
    }
    let maintenance = unused.remove(0);
    // The guest reads both roots through their retained supervisor aliases
    // to verify the shared entries before every maintenance install.
    if !maintenance_root_admitted(maintenance) {
        return Err(fail("maintenance root has no CPL0 supervisor alias"));
    }
    let lifecycles = lifecycle_slots(
        METADATA_VA,
        METADATA_VA + FORK_LIFECYCLE_OFFSET,
        FORK_LIFECYCLE_SLOTS,
    )
    .ok_or_else(|| fail("fork lifecycle stock layout"))?;
    Ok(BootForkStock {
        maintenance,
        tables: unused,
        lifecycles,
    })
}

/// The guest must reach the maintenance root through a retained supervisor
/// alias (the shared CPL0 table-alias rule) to verify it.
fn maintenance_root_admitted(root: RootGpa) -> bool {
    carrick_el1_abi::x86_cpl0_table_alias(root.address()).is_some()
}

/// One PML4 page as its 512 descriptor words.
fn root_words(page: &[u8]) -> Option<[u64; 512]> {
    if page.len() != 4096 {
        return None;
    }
    let mut words = [0u64; 512];
    for (word, bytes) in words.iter_mut().zip(page.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().ok()?);
    }
    Some(words)
}

/// The carrier maintenance root for `initial`: only its shared supervisor
/// entries. The copy is taken once, at fork-stock installation. That is
/// sound because shared PML4 entries are fixed at boot: every MM root
/// already holds its own by-value copy of them (`initial_mm`, fork), so a
/// shared entry published later would have to update every root, this one
/// included; the guest's `install_maintenance_root` refuses a stale copy.
fn maintenance_root_page(initial: &[u8]) -> Option<Vec<u8>> {
    use carrick_mmu_core::owner_mmu::OwnerForkMmu;
    let live = root_words(initial)?;
    let mut root = vec![0u8; 4096];
    for index in (256..512).filter(|index| X86Mmu::is_shared_root_entry(*index)) {
        root[index * 8..index * 8 + 8].copy_from_slice(&live[index].to_le_bytes());
    }
    carrick_mmu_core::x86::owner_mmu::maintenance_root_matches(&live, &root_words(&root)?)
        .then_some(root)
}

fn tables_resolve<M: CarrierMemoryIo>(memory: &CarrierMemory<M>, pages: &[RootGpa]) -> bool {
    pages
        .iter()
        .all(|page| memory.read(page.address(), 4096).is_ok())
}

fn tables_are_zero<M: CarrierMemoryIo>(memory: &CarrierMemory<M>, pages: &[RootGpa]) -> bool {
    pages.iter().all(|page| {
        memory
            .read(page.address(), 4096)
            .is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
    })
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    pub(super) fn physical_execution<I: CarrierCpuIo>(
        &self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<GrantExecution, TrapError> {
        let task = self.task(lease.cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("physical loan MM"))?;
        let context = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("physical loan root"))?;
        let native = self.binding(lease.cpu);
        let live_root = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("physical loan root alignment"))?;
        let generation = ContextGeneration::new(
            NonZeroU64::new(native.mm_owner_generation.load(Ordering::Acquire))
                .ok_or_else(|| fail("physical loan incarnation"))?,
        );
        admit_forward_execution(
            lease.cpu,
            carrick_guest_arch::CpuId::new(native.cpu_slot),
            binding,
            context,
            live_root,
            generation,
        )?;
        Ok(GrantExecution {
            cpu: lease.cpu,
            binding,
            context,
        })
    }

    pub(super) fn stack_record_physical<T, I: CarrierCpuIo>(
        &self,
        lease: &StoppedCpuLease<'_, I>,
        context: AddressContext<RootGpa>,
        address: u64,
    ) -> Result<FrameGpa, TrapError> {
        let top = self
            .binding(lease.cpu)
            .kernel_stack
            .checked_add(carrick_el1_abi::X86_CPL0_KERNEL_STACK_TOP_RESERVE)
            .ok_or_else(|| fail("physical stack top"))?;
        let base = top
            .checked_sub(carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE)
            .ok_or_else(|| fail("physical stack base"))?;
        let end = address
            .checked_add(size_of::<T>() as u64)
            .ok_or_else(|| fail("physical record overflow"))?;
        if address < base || end > top || !address.is_multiple_of(align_of::<T>() as u64) {
            return Err(fail(format!(
                "physical record outside stopped CPU stack: cpu={} address={address:#x} end={end:#x} base={base:#x} top={top:#x} size={} alignment={} rsp={:#x}",
                lease.cpu.raw(),
                size_of::<T>(),
                align_of::<T>(),
                lease.io.get_gpr(X86Reg::Rsp)?
            )));
        }
        let mut page = address & !4095;
        while page < end {
            let leaf = translate_leaf(
                &self._vm.words(),
                context.root,
                UserVa::new(page),
                Access::Write,
                false,
            )
            .map_err(|reason| fail(format!("physical stack record translation: {reason:?}")))?;
            if leaf.output.raw()
                != page
                    .checked_sub(DIRECT_VA)
                    .ok_or_else(|| fail("physical record direct address"))?
            {
                return Err(fail("physical stack record alias mismatch"));
            }
            page += 4096;
        }
        Ok(FrameGpa::new(address - DIRECT_VA))
    }

    /// T must be a fully initialized, padding-free POD physical ABI record.
    pub(super) unsafe fn read_stack_record<T, I: CarrierCpuIo>(
        &self,
        lease: &StoppedCpuLease<'_, I>,
        context: AddressContext<RootGpa>,
        address: u64,
    ) -> Result<(FrameGpa, T), TrapError> {
        let physical = self.stack_record_physical::<T, I>(lease, context, address)?;
        let bytes = self
            ._vm
            .read(physical, size_of::<T>())
            .map_err(|error| fail(error.to_string()))?;
        let mut record = std::mem::MaybeUninit::<T>::uninit();
        // SAFETY: caller supplies an all-bit-pattern-valid POD record; aligned
        // local storage and exact retained byte count establish its storage.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        Ok((physical, unsafe { record.assume_init() }))
    }

    pub(super) fn sources_mut(
        &mut self,
        context: AddressContext<RootGpa>,
    ) -> Result<&mut carrick_hal::fork_stock::ForkHostBackingCustody, TrapError> {
        if self._vm.root(context.mm.raw()) != Some(context) {
            return Err(fail("private file source address context changed"));
        }
        let mm = carrick_el1_abi::ReservationMm::new(context.mm.raw().get())
            .ok_or_else(|| fail("source MM"))?;
        if self
            .initial_task
            .is_some_and(|initial| initial.mm == context.mm)
        {
            let (owner, sources) = self
                .initial_sources
                .get_or_insert_with(|| (context, Default::default()));
            return (*owner == context)
                .then_some(sources)
                .ok_or_else(|| fail("initial source incarnation changed"));
        }
        if self.fork_stock.is_quarantined(mm)
            || self
                .fork_stock
                .child_owner(mm)
                .is_none_or(|owner| owner.incarnation() != context.generation.raw())
        {
            return Err(fail("private file source owner changed"));
        }
        self.fork_stock
            .child_physical_mut(mm, context.root)
            .ok_or_else(|| fail("private file source root changed"))
    }

    fn read_kernel_pod_bytes(
        &self,
        context: AddressContext<RootGpa>,
        address: carrick_guest_arch::KernelVa,
        len: usize,
        alignment: usize,
    ) -> Result<Vec<u8>, TrapError> {
        let physical = kernel_pod_physical(&self.kernel_pod_storage, address, len, alignment)
            .ok_or_else(|| fail(format!(
                "physical kernel POD outside retained storage: va={:#x} len={len:#x} alignment={alignment} mm={} root={:#x} spans={:?}",
                address.raw(), context.mm.raw(), context.root.address().raw(),
                self.kernel_pod_storage.iter().map(|span| format!("{:#x}..{:#x}->{:#x}", span.start.raw(), span.start.raw() + span.len, span.physical.raw())).collect::<Vec<_>>()
            )))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| fail("physical kernel POD allocation"))?;
        while bytes.len() < len {
            let offset = bytes.len();
            let va = address
                .raw()
                .checked_add(offset as u64)
                .ok_or_else(|| fail("physical kernel POD address"))?;
            let count = ((4096 - (va & 4095)) as usize).min(len - offset);
            let leaf = translate_leaf(
                &self._vm.words(),
                context.root,
                UserVa::new(va),
                Access::Write,
                false,
            )
            .map_err(|e| fail(format!("physical kernel POD translation: {e:?}")))?;
            let expected = FrameGpa::new(
                physical
                    .raw()
                    .checked_add(offset as u64)
                    .ok_or_else(|| fail("physical kernel POD output"))?,
            );
            if leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::USER != 0
                || leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::WRITE == 0
                || !leaf.ancestors_writable
                || leaf.executable
                || leaf.output != expected
            {
                return Err(fail(
                    "physical kernel POD supervisor permission/physical identity",
                ));
            }
            bytes.extend(
                self._vm
                    .read(expected, count)
                    .map_err(|e| fail(e.to_string()))?,
            );
        }
        Ok(bytes)
    }

    pub fn service_run_failure<I: CarrierCpuIo>(
        &self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<carrick_core_abi::NativeRunFailureReport, TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the record consists of initialized u64s, valid for all bit patterns.
        let (_, record) = unsafe {
            self.read_stack_record::<carrick_core_abi::NativeRunFailure, I>(
                lease,
                execution.context,
                lease.io.get_gpr(X86Reg::Rax)?,
            )
        }?;
        record
            .cause_for(execution.binding)
            .ok_or_else(|| fail("native run failure execution/reason"))
    }

    pub fn service_root_exit<I: CarrierCpuIo>(
        &self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<carrick_sched_core::process::TerminationStatus, TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the root exit record consists of eight fully initialized u64s.
        let (_, record) = unsafe {
            self.read_stack_record::<carrick_core_abi::NativeRootExit, I>(
                lease,
                execution.context,
                lease.io.get_gpr(X86Reg::Rax)?,
            )
        }?;
        let status = record
            .status_for(execution.binding)
            .ok_or_else(|| fail("native root exit execution/status"))?;
        Ok(status)
    }

    /// Seed the bounded fork stock after the initial MM is published. One
    /// unused initial table grant becomes the carrier's maintenance root:
    /// only the initial root's shared supervisor branches, published as the
    /// zone's idle root so a CPU can leave every process root before its
    /// slot reports no installed MM. The rest become fork table stock, with
    /// the extent's never-issued table `reserve` behind it.
    pub fn install_fork_stock(
        &mut self,
        context: AddressContext<RootGpa>,
        unused: Vec<RootGpa>,
        reserve: carrick_hal::fork_stock::TableReserve,
    ) -> Result<(), TrapError> {
        let initial_root = context.root;
        let BootForkStock {
            maintenance,
            tables,
            lifecycles,
        } = boot_fork_stock(unused)?;
        // Every issued record must be provably cold; a record that is not
        // zero at boot is a stocking fault, named here, never a refused fork.
        let window = self.lifecycle_window();
        if let Some(dirty) = lifecycles.iter().find(|life| !window.is_zero(**life)) {
            return Err(fail(format!(
                "fork lifecycle stock at {:#x} is not zero storage",
                dirty.page.raw()
            )));
        }
        let source = self
            ._vm
            .read(initial_root.address(), 4096)
            .map_err(|e| fail(e.to_string()))?;
        let root = maintenance_root_page(&source)
            .ok_or_else(|| fail("maintenance root does not match the initial root"))?;
        if self
            ._vm
            .read(maintenance.address(), 4096)
            .map_err(|e| fail(e.to_string()))?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(fail("maintenance root grant is not zero storage"));
        }
        self._vm
            .write(maintenance.address(), &root)
            .map_err(|e| fail(e.to_string()))?;
        // Boot-time assertion of the invariant each guest exit re-checks:
        // the published copy holds exactly the initial root's shared
        // entries (see `maintenance_root_page`).
        let published = self
            ._vm
            .read(maintenance.address(), 4096)
            .map_err(|e| fail(e.to_string()))?;
        if !root_words(&source)
            .zip(root_words(&published))
            .is_some_and(|(live, copy)| {
                carrick_mmu_core::x86::owner_mmu::maintenance_root_matches(&live, &copy)
            })
        {
            return Err(fail(
                "published maintenance root diverged from the initial root",
            ));
        }
        retained_cow_zone(&self.ram)?
            .spaces
            .set_idle_ttbr(maintenance.address().raw());
        self.maintenance_root = Some(maintenance);
        self.fork_stock
            .install(tables, reserve, lifecycles)
            .map_err(|e| fail(format!("fork stock install: {e:?}")))?;
        let mm = carrick_el1_abi::ReservationMm::new(context.mm.raw().get())
            .ok_or_else(|| fail("initial root MM"))?;
        // SAFETY: the boot reply and installed address context admit this exact root.
        let owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                self.fork_stock.carrier(),
                mm,
                context.generation.raw(),
            )
        };
        self.fork_stock
            .register_root(owner, initial_root)
            .map_err(|e| fail(format!("fork stock root registration: {e:?}")))
    }

    /// The retained metadata window holding the fork lifecycle stock.
    fn lifecycle_window(&self) -> LifecycleWindow {
        // SAFETY: `metadata_base` retains META_LEN host bytes backing
        // METADATA_VA for the VM lifetime.
        unsafe { LifecycleWindow::new(self.metadata_base.0, METADATA_VA, META_LEN) }
    }

    /// Return quarantined child stock whose MM no zone slot has installed.
    /// The servicing CPU's own MM is never a candidate. Inside the shared
    /// reclaim, before any of the child's stock can be reissued, the child's
    /// carrier state is released (frame inventory, COW residency, CR3 and
    /// aliases, private memslots); a refused release keeps it quarantined.
    pub(super) fn drain_fork_quarantine(
        &mut self,
        execution: GrantExecution,
    ) -> Result<(), TrapError> {
        let active = ReservationMm::new(execution.binding.mm.raw())
            .ok_or_else(|| fail("fork quarantine active MM"))?;
        self.drain_fork_quarantine_in(active.into())
    }

    pub(super) fn drain_fork_quarantine_in(
        &mut self,
        venue: carrick_hal::fork_stock::ReclaimExecution,
    ) -> Result<(), TrapError> {
        let zone = retained_cow_zone(&self.ram)?;
        // `CPL0_CPU_COUNT` has one definition (`cpl0_entry.rs`), compiled
        // into the guest by `#[path]`; the guest drain scans the same slots.
        const _: () =
            assert!(carrick_x86::cpl0_entry::CPL0_CPU_COUNT <= carrick_sched_core::ZONE_SLOTS);
        let installed: Vec<u64> = (0..carrick_x86::cpl0_entry::CPL0_CPU_COUNT)
            .filter_map(|slot| u8::try_from(slot).ok())
            .map(|slot| zone.installed_space(SlotId::new(slot)))
            .collect();
        let returns = retained_reservations(&self.ram)?;
        let window = self.lifecycle_window();
        let inventory = Arc::clone(&self.frame_inventory);
        let memory = std::cell::RefCell::new(&mut self._vm);
        let mms = std::cell::RefCell::new(&mut self.mm_core);
        let zero = [0u8; 4096];
        self.fork_stock
            .reclaim(
                &mut NoTableLedger,
                venue,
                |mm| SlotAbsence::scan(mm, installed.iter().copied()),
                |tables| {
                    let mut memory = memory.borrow_mut();
                    tables
                        .iter()
                        .all(|page| memory.write(page.address(), &zero).is_ok())
                },
                |lifecycle| window.clear(lifecycle),
                |absence| {
                    release_retired_child(
                        &mut memory.borrow_mut(),
                        &*inventory,
                        absence,
                        ChildRelease::Retired {
                            returns,
                            zone,
                            mms: &mut mms.borrow_mut(),
                        },
                    )
                    .is_ok()
                },
            )
            .map(|_| ())
            // A refused release, clear or tag retirement defers only that
            // child (counted as `reclaim_deferral`, retried next drain).
            // What remains is a broken custody invariant, never guest input.
            .map_err(|e| fail(format!("fork quarantine custody invariant: {e:?}")))?;
        fatal_if_quarantined(&self._vm)?;
        // An adopted exec's predecessor whose release was deferred settles
        // with the same drain.
        self.settle_exec_predecessors()
    }

    /// A fork child left the shared owner graph: quarantine its stock. The
    /// record must name this stopped CPU's live binding and child root. A
    /// refusal is a typed reply in the record (the guest fails only that
    /// process's stock return); only an unreadable record stops the carrier.
    pub fn service_child_retire<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<(), TrapError> {
        let live_root = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("physical child retire root alignment"))?;
        let context = self
            ._vm
            .context_by_root(live_root)
            .ok_or_else(|| fail("physical child retire unbacked root"))?;
        // SAFETY: the retire record consists of eight fully initialized u64s.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeChildRetire, I>(
                lease,
                context,
                lease.io.get_gpr(X86Reg::Rax)?,
            )
        }?;
        if record.words[0] != carrick_el1_abi::NativeChildRetire::MAGIC
            || record.words[5] != context.root.address().raw()
            || record.words[3] != context.mm.raw().get()
            || record.words[6] != context.generation.raw().get()
        {
            return Err(fail("physical child retire record mismatch"));
        }
        let binding = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(record.words[1]),
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(record.words[2]),
            mm: carrick_el1_abi::EntryMmKey::from_raw(record.words[3]),
            thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(record.words[4]),
        };
        let execution = GrantExecution::new(lease.cpu, binding, context);
        // Refusal is recorded in the reply word and counted by the stock.
        let _ = self.fork_stock.retire_child(execution, &mut record);
        // An adopted exec whose successor retires before its settlement
        // leaves the exec owner unsettled.
        if let Some(successor) = ReservationMm::new(binding.mm.raw()) {
            self.exec_owner.abandon_settling(successor);
        }
        // SAFETY: the record is a fully initialized array of eight u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<carrick_el1_abi::NativeChildRetire>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))?;
        self.drain_fork_quarantine(execution)
    }

    /// The guest's retired-space drain unpublished at least one closed
    /// space's entry and crossed (#3030). A retired fork child's quarantine
    /// was waiting for exactly that: drain it, which returns its tables to
    /// the stock and wakes every waiter enrolled on the stock's release (a
    /// parked fault or exec; the crossing's end probes the execs). From a process
    /// root the stopped execution's MM is excluded, as on every crossing;
    /// from the maintenance root, none is.
    pub fn service_space_retired<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<(), TrapError> {
        self.space_retired_crossings = self
            .space_retired_crossings
            .checked_add(1)
            .ok_or_else(|| fail("physical crossing counter exhausted"))?;
        if let Ok(execution) = self.physical_execution(lease) {
            self.drain_fork_quarantine(execution)?;
        } else {
            let maintenance = self
                .maintenance_root
                .ok_or_else(|| fail("space retired without a maintenance root"))?;
            let live = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
                .ok_or_else(|| fail("space retired root alignment"))?;
            let venue =
                carrick_hal::fork_stock::ReclaimExecution::maintenance_root(live, maintenance)
                    .ok_or_else(|| fail("space retired off any authenticated root"))?;
            self.drain_fork_quarantine_in(venue)?;
        }
        Ok(())
    }

    /// Counters of the shared fork stock (loans, counted refusals, returns).
    pub fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.fork_stock.counters()
    }

    /// What this carrier's exec owner reserved, sealed and retired.
    pub fn exec_owner_census(&self) -> carrick_hal::exec_owner::ExecOwnerCensus {
        self.exec_owner.census()
    }

    pub fn service_fork_stock<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<Option<(GuestArchBinding, carrick_el1_abi::EntryTaskKey)>, TrapError> {
        use carrick_el1_abi::ForkStockExchange;
        let execution = self.physical_execution(lease)?;
        self.drain_fork_quarantine(execution)?;
        let address = lease.io.get_gpr(X86Reg::Rax)?;
        let (_, tag) =
            unsafe { self.read_stack_record::<u64, I>(lease, execution.context, address) }?;
        match carrick_el1_abi::ForkStockKind::decode(tag) {
            Some(carrick_el1_abi::ForkStockKind::Loan) => {}
            Some(carrick_el1_abi::ForkStockKind::Descriptor) => {
                self.settle_native_descriptor_reply(lease, execution, address)?;
                return Ok(None);
            }
            Some(carrick_el1_abi::ForkStockKind::Reserve) => {
                self.reserve_fork_stock(lease, execution, address)?;
                return Ok(None);
            }
            Some(
                carrick_el1_abi::ForkStockKind::Commit | carrick_el1_abi::ForkStockKind::Abort,
            ) => {
                return self.settle_fork_stock(lease, execution, address);
            }
            None => {
                return Err(fail("physical fork stock unknown record tag"));
            }
        }
        let physical =
            self.stack_record_physical::<ForkStockExchange, I>(lease, execution.context, address)?;
        let bytes = self
            ._vm
            .read(physical, size_of::<ForkStockExchange>())
            .map_err(|error| fail(error.to_string()))?;
        let mut record = std::mem::MaybeUninit::<ForkStockExchange>::uninit();
        // SAFETY: this ABI record consists solely of u64 words, so every bit
        // pattern is valid. Local typed storage supplies the record alignment.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        let mut record = unsafe { record.assume_init() };
        if record.request().is_none() {
            return Err(fail("physical fork stock malformed request"));
        }
        // Lifecycle stock is cold zero storage until the guest initializes
        // its typed census. The shared policy withdraws a dirty record and
        // answers with a typed Inventory refusal (same on every carrier).
        let window = self.lifecycle_window();
        let _ = self
            .fork_stock
            .loan(&mut NoTableLedger, execution, &mut record, |lifecycle| {
                window.is_zero(lifecycle)
            });
        // SAFETY: expose only initialized u64 fields/padding in the copied ABI
        // record. The stopped CPU exclusively owns these validated stack bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ForkStockExchange>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))?;
        Ok(None)
    }

    /// Settle native table stock by the same exact reply receipt as HVF.
    /// Refused or withdrawn submissions return all grants; applied receipts
    /// retain only their linked prefix in the shared fork stock.
    fn settle_native_descriptor_reply<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        execution: GrantExecution,
        address: u64,
    ) -> Result<(), TrapError> {
        use carrick_el1_abi::{NativeDescriptorSettlement, PortalGrantSlot};
        // SAFETY: the wire record consists entirely of initialized u64 words.
        let (physical, mut settlement) = unsafe {
            self.read_stack_record::<NativeDescriptorSettlement, I>(
                lease,
                execution.context,
                address,
            )
        }?;
        let native_reply = settlement
            .request()
            .filter(|(_, _, address)| self.native_backing_pending.contains_key(address));
        let accepted = if let Some((owner, generation, reply_address)) = native_reply {
            self.settle_native_backing_reply(execution, owner, generation, reply_address)?
        } else {
            (|| -> Option<()> {
                let (owner, generation, reply_address) = settlement.request()?;
                if execution.binding.mm.raw() != owner.mm().raw()
                    || self.fork_stock.child_owner(owner.mm()) != Some(owner)
                    || self.fork_stock.child_root(owner.mm()) != Some(execution.context.root)
                {
                    return None;
                }
                let txn = self.fork_stock.pending_native_descriptor_transaction(
                    owner,
                    execution.context.root,
                    generation,
                )?;
                let reply_physical = kernel_pod_physical(
                    &self.kernel_pod_storage,
                    reply_address,
                    size_of::<PortalGrantSlot>(),
                    align_of::<PortalGrantSlot>(),
                )?;
                // SAFETY: declared writable kernel storage retains the complete
                // aligned atomic-only reply slot for this synchronous crossing.
                let reply =
                    unsafe { self._vm.retained_record::<PortalGrantSlot>(reply_physical) }.ok()?;
                let window = reply.window()?;
                if window.operation.carrier != owner.carrier()
                    || window.operation.mm != owner.mm()
                    || window.operation.incarnation != owner.incarnation()
                    || window.operation.sequence != generation
                {
                    return None;
                }
                if let Some(receipt) = reply.take_receipt(window, &txn) {
                    self.fork_stock
                        .settle_native_descriptor_tables(
                            &mut NoTableLedger,
                            owner,
                            execution.context.root,
                            &receipt,
                        )
                        .ok()?;
                } else if reply.withdraw(window, &txn) {
                    self.fork_stock
                        .cancel_submitted_native_descriptor_tables(
                            &mut NoTableLedger,
                            owner,
                            execution.context.root,
                            generation,
                        )
                        .ok()?;
                } else {
                    return None;
                }
                Some(())
            })()
            .is_some()
        };
        if !accepted && native_reply.is_none() {
            // Only a retained native reply's editor contention uses REFUSED.
            // Unknown or stale descriptors are invariants, never owner waits
            // with no release source.
            return Err(fail("native descriptor settlement owner changed"));
        }
        if accepted {
            settlement.accept();
        } else {
            settlement.refuse();
        }
        // SAFETY: copy only the initialized words of the aligned wire record
        // back to the validated stack owned exclusively by the stopped CPU.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const settlement).cast::<u8>(),
                size_of::<NativeDescriptorSettlement>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))
    }

    fn reserve_fork_stock<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        execution: GrantExecution,
        address: u64,
    ) -> Result<(), TrapError> {
        use carrick_el1_abi::{ForkStockRefusal, ForkStockSettlement, PortalForkCustody};
        let loan = self
            .fork_stock
            .settlement_loan(execution)
            .map_err(|e| fail(format!("physical fork reservation: {e:?}")))?;
        let (physical, mut record) = unsafe {
            self.read_stack_record::<ForkStockSettlement, I>(lease, execution.context, address)
        }?;
        let (completion, custody, count) = record
            .reservation(loan)
            .ok_or_else(|| fail("physical fork reservation receipt"))?;
        let len = count
            .checked_mul(32)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| fail("physical fork custody length"))?;
        let wire = self.read_kernel_pod_bytes(execution.context, custody, len, 8)?;
        let frame_inventory = Arc::clone(&self.frame_inventory);
        let mut trap_error: Option<TrapError> = None;
        let inventory_published = std::cell::Cell::new(false);
        let root_installed = std::cell::Cell::new(false);
        let mut parent_residency = Vec::new();
        let has_host_backing = wire.chunks_exact(32).any(|row| {
            matches!(
                decode_fork_custody(row),
                Some(PortalForkCustody::HostBacking { .. })
            )
        });
        // The raw hardware bootstrap has no initial task to seed and needs
        // source custody only when its fork record actually names a backing.
        let sources = (self.initial_task.is_some() || has_host_backing)
            .then(|| self.sources_mut(execution.context))
            .transpose()?;
        let executable = sources.as_deref().and_then(|sources| sources.executable());
        let parent_sources = sources.as_deref().filter(|_| has_host_backing).cloned();
        let refused = {
            let vm = std::cell::RefCell::new(&mut self._vm);
            self.fork_stock
                .reserve_custody(
                    execution,
                    &mut record,
                    |pages| tables_resolve(&vm.borrow(), pages),
                    |pages| tables_are_zero(&vm.borrow(), pages),
                    |_request, _custody_va, _count| {
                        let mut vm = vm.borrow_mut();
                        let child = AddressContext {
                            mm: carrick_guest_arch::MmGeneration::new(
                                NonZeroU64::new(loan.request.child_mm.raw()).ok_or_else(|| {
                                    trap_error = Some(fail("physical child MM"));
                                    ForkStockRefusal::Invalid
                                })?,
                            ),
                            root: RootGpa::page_aligned(FrameGpa::new(
                                loan.request.child_tables.base,
                            ))
                            .ok_or_else(|| {
                                trap_error = Some(fail("physical child root"));
                                ForkStockRefusal::Invalid
                            })?,
                            generation: carrick_guest_arch::ContextGeneration::new(
                                completion.child.incarnation(),
                            ),
                        };
                        let mut inherited_sources = carrick_hal::fork_stock::ForkHostBackingCustody::default();
                        if let Some(executable) = executable {
                            inherited_sources.bind_executable(executable);
                        }
                        let mut edges = Vec::new();
                        let mut windows = Vec::new();
                        let mut spans = std::collections::BTreeSet::new();
                        for words in wire.chunks_exact(32) {
                            let selected = decode_fork_custody(words).ok_or_else(|| {
                                trap_error = Some(fail("physical fork custody encoding"));
                                ForkStockRefusal::Invalid
                            })?;
                            if let PortalForkCustody::HostBacking { handle, generation } = selected {
                                let identity = carrick_el1_abi::HostBackingIdentity::new(handle, generation, 0);
                                let parent = parent_sources.as_ref();
                                let source = parent
                                    .and_then(|sources| sources.retain(identity, || None))
                                    .ok_or(ForkStockRefusal::Invalid)?;
                                // The child's later faults on an inherited
                                // window must reach the file, never a copy.
                                if parent.is_some_and(|sources| sources.is_window(identity)) {
                                    inherited_sources.inherit_window(source);
                                } else {
                                    inherited_sources.inherit(source);
                                }
                                continue;
                            }
                            // A shared file window leaf has no frame
                            // inventory: the child keeps it and joins the
                            // window slot (#1338).
                            let window = vm
                                .select_inherited_window(execution.context, selected)
                                .map_err(|error| {
                                    trap_error = Some(fail(error.to_string()));
                                    ForkStockRefusal::Invalid
                                })?;
                            if let Some(window) = window {
                                if !spans.insert(window.span().va) {
                                    trap_error =
                                        Some(fail("physical fork duplicate inherited page"));
                                    return Err(ForkStockRefusal::Invalid);
                                }
                                windows.push(window);
                                continue;
                            }
                            let selected_edges = vm
                                .select_inherited_frames(
                                    execution.context,
                                    selected,
                                    &*frame_inventory,
                                )
                                .map_err(|error| match error {
                                    crate::carrier_memory::InheritedFrameSelectionError::MappingGone => {
                                        ForkStockRefusal::Inventory
                                    }
                                    crate::carrier_memory::InheritedFrameSelectionError::Invariant(
                                        error,
                                    ) => {
                                        trap_error = Some(fail(error.to_string()));
                                        ForkStockRefusal::Invalid
                                    }
                                })?;
                            for edge in selected_edges {
                                if !spans.insert(edge.span().va) {
                                    trap_error =
                                        Some(fail("physical fork duplicate inherited page"));
                                    return Err(ForkStockRefusal::Invalid);
                                }
                                edges.push(edge);
                            }
                        }
                        let parent_inventory = frame_inventory.bind(execution.context.into());
                        let child_inventory = frame_inventory.bind(child.into());
                        parent_residency
                            .try_reserve_exact(edges.len())
                            .map_err(|_| ForkStockRefusal::Capacity)?;
                        let mut rows = std::collections::BTreeMap::new();
                        for edge in &edges {
                            let identity = edge.identity();
                            let mapping = MappingId::from_kernel_allocation(identity.mapping_id);
                            let Some(row) = parent_inventory.live_mapping_row(mapping) else {
                                return Err(ForkStockRefusal::Inventory);
                            };
                            if row.frame != FrameId::from_kernel_allocation(identity.frame_id)
                                || row.generation
                                    != MappingGeneration::from_backend_counter(
                                        identity.owner_generation,
                                    )
                                || edge.physical().raw() < row.gpa.raw()
                                || edge.physical().raw().checked_add(4096).is_none_or(|end| {
                                    row.gpa
                                        .raw()
                                        .checked_add(row.length.raw())
                                        .is_none_or(|limit| end > limit)
                                })
                            {
                                trap_error = Some(fail("physical fork source mapping identity"));
                                return Err(ForkStockRefusal::Invalid);
                            }
                            rows.insert(identity.mapping_id, row);
                        }
                        // Residency admission, before the first carrier side
                        // effect: a table that cannot hold this fork's rows
                        // refuses "not now" and the guest grows it.
                        {
                            let resolved_residency = resolve_cpl0_residency(&vm).map_err(|e| {
                                trap_error = Some(e);
                                ForkStockRefusal::Inventory
                            })?;
                            let residency = resolved_residency.view().ok_or_else(|| {
                                trap_error = Some(fail("physical fork residency view"));
                                ForkStockRefusal::Inventory
                            })?;
                            if !ForkResidencyDemand::count(
                                &residency,
                                execution.context.mm.raw().get(),
                                edges.iter().map(|edge| edge.span().va),
                            )
                            .admitted(&residency)
                            {
                                return Err(ForkStockRefusal::Residency);
                            }
                        }
                        let capacity = FrameEventCapacity::for_event_count(
                            rows.len().checked_mul(2).ok_or_else(|| {
                                trap_error = Some(fail("physical fork inventory capacity"));
                                ForkStockRefusal::Invalid
                            })?,
                        )
                        .map_err(|e| {
                            trap_error = Some(fail(e.to_string()));
                            ForkStockRefusal::Invalid
                        })?;
                        let mut reservation = child_inventory
                            .reserve(0, rows.len(), capacity.get())
                            .map_err(|e| {
                                trap_error = Some(fail(e.to_string()));
                                ForkStockRefusal::Inventory
                            })?;
                        let transaction = reservation.transaction();
                        let generation = MappingGeneration::from_backend_counter(NonZeroU64::MIN);
                        let mut mappings = std::collections::BTreeMap::new();
                        for (source, row) in &rows {
                            let mapping = reservation.claim_mapping().map_err(|e| {
                                trap_error = Some(fail(e.to_string()));
                                ForkStockRefusal::Inventory
                            })?;
                            reservation
                                .push(FrameInventoryEvent::PrepareMapping {
                                    transaction,
                                    frame: row.frame,
                                    mapping,
                                    generation,
                                    gpa: row.gpa,
                                    length: row.length,
                                    permissions: row.permissions,
                                })
                                .map_err(|e| {
                                    trap_error = Some(fail(e.to_string()));
                                    ForkStockRefusal::Inventory
                                })?;
                            reservation
                                .push(FrameInventoryEvent::PublishMapping {
                                    transaction,
                                    mapping,
                                    generation,
                                })
                                .map_err(|e| {
                                    trap_error = Some(fail(e.to_string()));
                                    ForkStockRefusal::Inventory
                                })?;
                            mappings.insert(*source, mapping);
                        }
                        let receipt = child_inventory
                            .apply_with_receipt(reservation.commit(()))
                            .map_err(|e| {
                                trap_error = Some(fail(e.to_string()));
                                ForkStockRefusal::Inventory
                            })?;
                        inventory_published.set(true);
                        vm.install_root(child.mm.raw(), child).map_err(|e| {
                            trap_error = Some(fail(e.to_string()));
                            ForkStockRefusal::Inventory
                        })?;
                        root_installed.set(true);
                        for window in &windows {
                            vm.attach_inherited_window(child, window).map_err(|e| {
                                trap_error = Some(fail(e.to_string()));
                                ForkStockRefusal::Invalid
                            })?;
                        }
                        let mut resident_windows = std::collections::BTreeSet::new();
                        for edge in &edges {
                            let source = edge.identity();
                            let mapping = mappings.get(&source.mapping_id).ok_or_else(|| {
                                trap_error = Some(fail("physical fork mapping selection"));
                                ForkStockRefusal::Invalid
                            })?;
                            let identity = BackingIdentity {
                                frame_id: source.frame_id,
                                mapping_id: NonZeroU64::new(mapping.raw()).ok_or_else(|| {
                                    trap_error = Some(fail("physical fork mapping identity"));
                                    ForkStockRefusal::Invalid
                                })?,
                                owner_generation: NonZeroU64::MIN,
                                inventory_revision: NonZeroU64::new(receipt.revision())
                                    .ok_or_else(|| {
                                        trap_error = Some(fail("physical fork inventory revision"));
                                        ForkStockRefusal::Invalid
                                    })?,
                            };
                            vm.attach_inherited_frame(
                                child,
                                edge,
                                identity,
                                &receipt,
                                &*frame_inventory,
                            )
                            .map_err(|e| {
                                trap_error = Some(fail(e.to_string()));
                                ForkStockRefusal::Inventory
                            })?;
                            let resolved_residency = resolve_cpl0_residency(&vm).map_err(|e| {
                                trap_error = Some(e);
                                ForkStockRefusal::Inventory
                            })?;
                            let residency = resolved_residency.view().ok_or_else(|| {
                                trap_error = Some(fail("physical fork residency view"));
                                ForkStockRefusal::Inventory
                            })?;
                            let parent =
                                residency.lookup(execution.context.mm.raw().get(), edge.span().va);
                            let mut resident = parent.map(|page| page.identity).unwrap_or(
                                carrick_el1_abi::FrameGrantResidencyIdentity {
                                    mm_key: execution.context.mm.raw().get(),
                                    semantic_base: edge.span().va,
                                    physical_ipa: edge.physical().raw(),
                                    len: 4096,
                                    frame_id: source.frame_id.get(),
                                    mapping_id: source.mapping_id.get(),
                                    owner_generation: source.owner_generation.get(),
                                    inventory_revision: source.inventory_revision.get(),
                                },
                            );
                            if parent.is_none() {
                                // A probe chain can fill below the admitted
                                // load. The rows published so far roll back
                                // below, and the guest grows the table.
                                let slot = residency
                                    .publish(resident)
                                    .ok_or(ForkStockRefusal::Residency)?;
                                parent_residency.push((slot, resident));
                                let page = residency
                                    .lookup(resident.mm_key, edge.span().va)
                                    .ok_or_else(|| {
                                        trap_error = Some(fail(
                                            "physical fork source residency publication",
                                        ));
                                        ForkStockRefusal::Inventory
                                    })?;
                                if edge.is_resident() && !residency.record_commit(page) {
                                    trap_error = Some(fail("physical fork source commit proof"));
                                    return Err(ForkStockRefusal::Inventory);
                                }
                            }
                            resident.mm_key = child.mm.raw().get();
                            resident.mapping_id = identity.mapping_id.get();
                            resident.owner_generation = identity.owner_generation.get();
                            resident.inventory_revision = identity.inventory_revision.get();
                            if resident_windows.insert(resident.semantic_base) {
                                residency
                                    .publish(resident)
                                    .ok_or(ForkStockRefusal::Residency)?;
                            }
                            let page = residency
                                .lookup(resident.mm_key, edge.span().va)
                                .ok_or_else(|| {
                                    trap_error =
                                        Some(fail("physical fork child residency publication"));
                                    ForkStockRefusal::Inventory
                                })?;
                            if page.expected_ipa != edge.physical().raw()
                                || (edge.is_resident() && !residency.record_commit(page))
                            {
                                trap_error = Some(fail("physical fork child commit proof"));
                                return Err(ForkStockRefusal::Inventory);
                            }
                        }
                        Ok(inherited_sources)
                    },
                )
                .is_err()
        };
        if refused && !parent_residency.is_empty() {
            let residency = self.cow_residency()?;
            let view = residency
                .view()
                .ok_or_else(|| fail("physical fork rollback residency view"))?;
            rollback_fork_parent_residency(&view, &parent_residency)?;
        }
        if refused && inventory_published.get() {
            if root_installed.get() {
                let absence = SlotAbsence::scan(loan.request.child_mm, [])
                    .ok_or_else(|| fail("unpublished child MM slot absence"))?;
                release_retired_child(
                    &mut self._vm,
                    &*frame_inventory,
                    &absence,
                    ChildRelease::Unrun,
                )?;
            } else {
                let residency = self.cow_residency()?;
                let view = residency
                    .view()
                    .ok_or_else(|| fail("unpublished child rollback residency view"))?;
                if !carrick_hal::fork_stock::release_unrun_child_mm(
                    &*frame_inventory,
                    &view,
                    loan.request.child_mm,
                ) {
                    return Err(fail("unpublished child inventory rollback"));
                }
            }
        }
        if let Some(err) = trap_error {
            return Err(err);
        }
        // SAFETY: settlement is a fully initialized array of sixteen u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ForkStockSettlement>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))
    }

    fn settle_fork_stock<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        execution: GrantExecution,
        address: u64,
    ) -> Result<Option<(GuestArchBinding, carrick_el1_abi::EntryTaskKey)>, TrapError> {
        use carrick_el1_abi::ForkStockSettlement;
        let loan = self
            .fork_stock
            .settlement_loan(execution)
            .map_err(|e| fail(format!("physical fork settlement: {e:?}")))?;
        let (physical, mut record) = unsafe {
            self.read_stack_record::<ForkStockSettlement, I>(lease, execution.context, address)
        }?;
        let had_admitted = self
            .fork_stock
            .pending(execution.cpu)
            .and_then(|pending| pending.admitted_custody())
            .is_some();
        let is_abort = record.abort_matches(loan);
        let committed_child = if !is_abort {
            let (completion, _custody, _count) = record
                .request(loan)
                .ok_or_else(|| fail("physical fork settlement receipt"))?;
            Some(AddressContext {
                mm: carrick_guest_arch::MmGeneration::new(
                    NonZeroU64::new(loan.request.child_mm.raw())
                        .ok_or_else(|| fail("physical child MM"))?,
                ),
                root: RootGpa::page_aligned(FrameGpa::new(loan.request.child_tables.base))
                    .ok_or_else(|| fail("physical child root"))?,
                generation: carrick_guest_arch::ContextGeneration::new(
                    completion.child.incarnation(),
                ),
            })
        } else {
            None
        };
        let window = self.lifecycle_window();
        let memory = &self._vm;
        self.fork_stock
            .settle(
                &mut NoTableLedger,
                execution,
                &mut record,
                |pages| tables_resolve(memory, pages),
                |pages| tables_are_zero(memory, pages),
                |lifecycle| window.clear(lifecycle),
            )
            .map_err(|e: ForkStockServiceError| fail(format!("physical fork settlement: {e:?}")))?;
        if is_abort && had_admitted {
            let absence = SlotAbsence::scan(loan.request.child_mm, [])
                .ok_or_else(|| fail("aborted child MM slot absence"))?;
            release_retired_child(
                &mut self._vm,
                &*self.frame_inventory,
                &absence,
                ChildRelease::Unrun,
            )?;
        }
        // SAFETY: settlement is a fully initialized array of sixteen u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ForkStockSettlement>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))?;
        let child_binding = if let Some(child) = committed_child {
            let carrier = self._vm.identity().nonzero();
            let entry_task = record
                .child_entry_task()
                .ok_or_else(|| fail("physical child entry key missing from settlement"))?;
            let (child_task, child_execution) = record
                .child_task_identity()
                .ok_or_else(|| fail("physical child task identity missing from settlement"))?;
            Some((
                GuestArchBinding::x86(
                    TaskIdentity {
                        carrier: carrick_guest_arch::CarrierGeneration::new(carrier),
                        task: TaskSerial::new(child_task),
                        execution: ExecutionGeneration::new(child_execution),
                    },
                    child,
                ),
                entry_task,
            ))
        } else {
            None
        };
        // The loan no longer names the parent (or its committed child): a
        // settlement doorbell refused `ForkLoanPending` waits for exactly
        // this `PendingEdit` release (#1369 slice 3, L1).
        let parent = carrick_el1_abi::ReservationMm::new(execution.context.mm.raw().get())
            .ok_or_else(|| fail("physical fork parent MM"))?;
        self.publish_space_release(
            parent,
            carrick_sched_core::spaces::notification::SpaceWaitCause::PendingEdit,
        )?;
        if let Some(child) = committed_child
            .and_then(|child| carrick_el1_abi::ReservationMm::new(child.mm.raw().get()))
        {
            self.publish_space_release(
                child,
                carrick_sched_core::spaces::notification::SpaceWaitCause::PendingEdit,
            )?;
        }
        Ok(child_binding)
    }

    fn cow_pool(&self) -> Result<&carrick_el1_abi::CowGrantPool, TrapError> {
        // SAFETY: retained aligned atomic-only kernel record initialized at boot.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    fn cow_residency(
        &self,
    ) -> Result<
        carrick_core_abi::mm::residency::ResolvedResidencyTable<
            carrick_core_abi::mm::residency::NoDynamicResidencyPin,
        >,
        TrapError,
    > {
        resolve_cpl0_residency(&self._vm)
    }

    fn supply_cow_grant(
        &mut self,
        index: usize,
        execution: GrantExecution,
        window: PortalGrantWindow,
    ) -> Result<(), TrapError> {
        let mm = execution.context.mm.raw();
        if !window.valid()
            || self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.operation.mm.raw() != mm.get()
            || window.range.len() != 4096
            || window.range.start() != window.fault_page
            || window.host_backing.is_some()
        {
            return Err(fail("owner COW selection identity"));
        }
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        use carrick_mmu_core::x86::descriptor_txn::CowClass;
        use carrick_sched_core::spaces::notification::ExclusionRefusal;
        let venue = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        };
        #[cfg(feature = "test-support")]
        let maintenance = editor_hold::take(
            EditorHoldSite::CowSupply,
            venue,
            mm,
            Some(editor_hold::Demand {
                page: window.fault_page,
                member: execution.binding,
            }),
        );
        let probe = self.settled_pause(venue, window.operation.mm);
        // The seam's borrow ends through its own release, before this
        // venue's wakes are finished.
        #[cfg(feature = "test-support")]
        drop(maintenance);
        let pause = match probe? {
            Ok((pause, _)) => pause,
            // Another CPU holds this MM's editor: not now. Nothing is
            // supplied and the selection stays published, which tells its
            // member to withdraw it and park on that editor's release.
            Err(ExclusionRefusal::Busy) => return wake.finish(),
            Err(ExclusionRefusal::Stale) => return Err(fail("owner COW MM retired")),
        };
        let run = match carrick_mmu_core::x86::descriptor_txn::classify_guest_cow_write(
            &self._vm.words(),
            execution.context.root,
            UserVa::new(window.fault_page),
            // x86 instruction fetch is coherent with stores to the frame:
            // an executable source needs no publication step (#2668).
            true,
        ) {
            Ok(run) => run,
            // A sibling resolved, remapped or unmapped the page after this
            // member selected it and released the editor. The selection is
            // consumed with nothing supplied; the member's rerun reads the
            // page as it now stands.
            Err(
                CowClass::AlreadyWritable
                | CowClass::NotCowArmed
                | CowClass::NoWriteIntent
                | CowClass::Unmapped,
            ) => {
                if !self
                    .grant_portal()?
                    .grant(index)
                    .ok_or_else(|| fail("owner COW slot"))?
                    .take_cow_fault_selection(window)
                {
                    return Err(fail("owner COW demand changed under its exclusion"));
                }
                drop(pause);
                return wake.finish();
            }
            Err(reason) => return Err(fail(format!("owner COW source: {reason:?}"))),
        };
        // One supplied grant repoints one page: a block's split tables are
        // not supplied on this lane, and a table-less grant never serves it.
        if run.split_tables != 0 {
            return Err(fail("owner COW source is an armed block"));
        }
        let leaf = translate_leaf(
            &self._vm.words(),
            execution.context.root,
            UserVa::new(window.fault_page),
            Access::Read,
            true,
        )
        .map_err(|reason| fail(format!("owner COW leaf: {reason:?}")))?;
        if leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::PRIVATE == 0
            || run.va != window.fault_page
            || run.len != 4096
        {
            return Err(fail("owner COW source is not exact private page"));
        }
        let source_identity = self
            ._vm
            .frame_identity(mm, run.old_ipa)
            .map_err(|error| fail(error.to_string()))?;
        let residency = self.cow_residency()?;
        let residency_view = residency
            .view()
            .ok_or_else(|| fail("owner COW source residency view"))?;
        let resident = residency_view
            .lookup(mm.get(), run.va)
            .ok_or_else(|| fail("owner COW source residency"))?;
        let identity = resident.identity;
        if resident.expected_ipa != run.old_ipa.raw()
            || identity.frame_id != source_identity.frame_id.get()
            || identity.mapping_id != source_identity.mapping_id.get()
            || identity.owner_generation != source_identity.owner_generation.get()
            || identity.inventory_revision != source_identity.inventory_revision.get()
            || !residency_view.is_guest_committed(mm.get(), run.va)
        {
            return Err(fail("owner COW source custody mismatch"));
        }
        let size = carrick_el1_abi::COW_GRANT_SIZE;
        // The core owns the grant from here: one supply transition for an
        // EL0 write and a kernel user copy alike, under this exclusion. It
        // carves the replacement from the MM's arena, and asks for a chunk
        // only when the arena has no room (#3099).
        let excluded = core_excluded(pause.proof())?;
        let (ticket, staged) = match self
            .mm_core
            .supply_cow(&excluded, window.fault_page)
            .map_err(|refusal| fail(format!("owner COW supply refused: {refusal:?}")))?
        {
            carrick_core::mm::own::CowSupply::Carved(ticket) => (ticket, None),
            carrick_core::mm::own::CowSupply::NeedsChunk(demand) => {
                let (ticket, staged) = self.map_cow_chunk(execution, mm, demand)?;
                (ticket, Some(staged))
            }
        };
        let physical = ticket.extent().ipa();
        let supplied =
            if physical == run.old_ipa.raw() & !(size - 1) || ticket.extent().len().get() != size {
                Err(fail("owner COW source/replacement physical alias"))
            } else {
                self.publish_cow_supply(execution, physical, size, mm, staged)
            };
        let outcome = match supplied {
            Ok(cow) => carrick_core::mm::own::Supplied::Published(cow),
            Err(error) => {
                if self
                    .mm_core
                    .finish_supply_cow(ticket, carrick_core::mm::own::Supplied::Failed)
                    .is_err()
                {
                    return Err(fail("owner COW supply ticket refused"));
                }
                return Err(error);
            }
        };
        if self.mm_core.finish_supply_cow(ticket, outcome).is_err() {
            return Err(fail("owner COW supply ticket refused"));
        }
        if !self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner COW slot"))?
            .take_cow_fault_selection(window)
        {
            return Err(fail("owner COW demand changed during physical publication"));
        }
        #[cfg(feature = "test-support")]
        editor_hold::supplied(mm, window.fault_page, execution.binding);
        drop(pause);
        wake.finish()
    }

    /// Stage one replacement grant's frame in the physical inventory.
    fn stage_cow_grant(
        &self,
        execution: GrantExecution,
        physical: u64,
        size: u64,
    ) -> Result<(InitialInventory, BackingIdentity), TrapError> {
        let (inventory, _) = InitialInventory::stage(
            Arc::clone(&self.initial_rollback_fault),
            Arc::clone(&self.frame_inventory),
            [FrameGpa::new(physical)],
            0,
            size,
            execution.context.into(),
        )?;
        let backing = inventory
            .frames
            .first()
            .ok_or_else(|| fail("owner COW identity"))?
            .1;
        Ok((inventory, backing))
    }

    /// The MM's arena has no room: map one chunk (one memslot for every
    /// grant it holds, #3099) at fresh GPA, admit it to the core, and stage
    /// the first grant the core carves from it. A failure before the core
    /// admits the chunk cancels the demand, so the MM's editor is free.
    fn map_cow_chunk(
        &mut self,
        execution: GrantExecution,
        mm: NonZeroU64,
        demand: carrick_core::mm::own::ChunkDemand,
    ) -> Result<
        (
            carrick_core::mm::own::SupplyTicket,
            (InitialInventory, BackingIdentity),
        ),
        TrapError,
    > {
        let grant = self.mm_core.cow_geometry().grant();
        let len = demand.chunk_len();
        let base = self
            .anonymous_next_gpa
            .raw()
            .checked_add(grant - 1)
            .map(|next| next & !(grant - 1));
        let installed = base
            .and_then(|base| Some((base, base.checked_add(len)?)))
            .ok_or_else(|| fail("owner COW GPA exhausted"))
            .and_then(|(base, end)| {
                let staged = self.stage_cow_grant(execution, base, grant)?;
                let extent = BackingExtent::private(FrameGpa::new(base), len as usize)
                    .map_err(|error| fail(error.to_string()))?;
                let handle = self
                    ._vm
                    .install_arena_chunk(
                        mm,
                        PreparedBacking {
                            extent: Arc::new(extent),
                            identity: staged.1,
                        },
                    )
                    .map_err(|error| fail(error.to_string()))?;
                Ok((base, end, staged, handle))
            });
        let (base, end, staged, _chunk) = match installed {
            Ok(installed) => installed,
            Err(error) => {
                if self.mm_core.cancel_chunk(demand).is_err() {
                    return Err(fail("owner COW chunk demand refused"));
                }
                return Err(error);
            }
        };
        self.anonymous_next_gpa = FrameGpa::new(end);
        let extent = carrick_core::mm::own::GpaExtent::new(base, len)
            .ok_or_else(|| fail("owner COW chunk extent"))?;
        // A refusal here is a broken invariant: the chunk is fresh GPA. The
        // carrier ends, its editor still recorded as the shell's.
        let ticket = self
            .mm_core
            .admit_chunk(demand, extent)
            .map_err(|refused| fail(format!("owner COW chunk refused: {:?}", refused.reason)))?;
        if ticket.extent().ipa() != base {
            return Err(fail("owner COW chunk's first grant is not at its base"));
        }
        Ok((ticket, staged))
    }

    /// Bind one replacement grant inside its MM's arena chunk and publish
    /// it to the MM's pool: no memslot change and no host mapping call. A
    /// failure leaves nothing exposed to the guest.
    fn publish_cow_supply(
        &mut self,
        execution: GrantExecution,
        physical: u64,
        size: u64,
        mm: NonZeroU64,
        staged: Option<(InitialInventory, BackingIdentity)>,
    ) -> Result<SuppliedCow, TrapError> {
        let (mut inventory, backing) = match staged {
            Some(staged) => staged,
            None => self.stage_cow_grant(execution, physical, size)?,
        };
        let gpa = FrameGpa::new(physical);
        let handle = self
            ._vm
            .adopt_frames(mm, gpa, size, backing, &mut inventory)
            .map_err(|error| fail(error.to_string()))?;
        let Some(grant) = self.cow_pool()?.publish(mm.get(), physical, backing) else {
            // SAFETY: no grant exposed this fresh physical extent to the guest.
            unsafe {
                self._vm
                    .cancel_adopted(handle, gpa, size, backing, &mut inventory)
            }
            .map_err(|error| fail(error.to_string()))?;
            return Err(fail("owner COW pool full"));
        };
        // The original pool record now permits a guest copy/repoint. On any
        // subsequent failure retain the extent through carrier teardown.
        inventory.expected = 1;
        inventory.guest_exposed = true;
        // Whichever member claims it, for whichever page, its completion
        // settles at the MM's next exclusion.
        Ok(SuppliedCow {
            inventory,
            handle,
            grant,
        })
    }

    /// The CPL0 venue's COW step of every exclusion (#1482 P0-3): publish
    /// every completion of the excluded MM that is in the pool, whichever
    /// member claimed its grant and whichever CPU asked for it (#2749). A
    /// sibling may already have retired a replacement leaf; that retirement
    /// is an owed return the same exclusion settles only after this. A
    /// supplied grant no member has completed stays in the ledger.
    pub(super) fn settle_cow_completions(
        &mut self,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        let pool = self.cow_pool()?;
        if !pool.any_completed() {
            return Ok(());
        }
        if pool.claimed_by(excluded) {
            return Err(fail("owner COW grant claimed under its MM's exclusion"));
        }
        let mut completions: Vec<_> = pool.completions(excluded).collect();
        carrick_el1_abi::order_cow_settlement(&mut completions);
        let proof = self
            .mm_core
            .begin_settle(&core_excluded(excluded)?)
            .map_err(|refusal| fail(format!("owner COW settlement refused: {refusal:?}")))?;
        let settled = completions
            .into_iter()
            .try_for_each(|receipt| self.publish_cow_completion(&proof, excluded, receipt));
        if self.mm_core.finish_settle(proof).is_err() {
            return Err(fail("owner COW settlement proof refused"));
        }
        settled
    }

    /// A member's settlement crossing: it completed a copy-on-write, or saw
    /// a completion of its MM, and asks the carrier to settle the MM's
    /// completions now, while the leaves still stand as the receipts say.
    /// The exclusion itself settles them ([`Self::settle_cow_completions`]).
    /// The crossing is the MM's, not a CPU's: any member may ring it, from
    /// either CPU, and one that finds nothing left to settle is not an
    /// error (#2749).
    fn settle_cow_grants(&mut self, mm: carrick_el1_abi::ReservationMm) -> Result<(), TrapError> {
        use carrick_sched_core::spaces::notification::ExclusionRefusal;
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        match self.settled_pause(
            SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &delivery,
                ),
            },
            mm,
        )? {
            Ok((pause, _)) => drop(pause),
            // Another CPU holds this MM's editor: not now. The completions
            // stay in the pool, which tells the member to park on that
            // editor's release and ring again.
            Err(ExclusionRefusal::Busy) => {}
            Err(ExclusionRefusal::Stale) => return Err(fail("owner COW settlement MM retired")),
        }
        wake.finish()
    }

    fn publish_cow_completion(
        &mut self,
        proof: &carrick_core::mm::own::SettleProof,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
        receipt: carrick_el1_abi::CowGrantCompletion,
    ) -> Result<(), TrapError> {
        let mm = NonZeroU64::new(excluded.key()).ok_or_else(|| fail("owner COW settlement MM"))?;
        let context = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("owner COW settlement root"))?;
        let Ok(mut supplied) = self.mm_core.settle_cow(proof, &receipt.grant) else {
            return Err(fail("owner COW completion names no supplied grant"));
        };
        if !exact_cow_receipt(supplied.grant, &receipt) {
            return Err(fail("owner COW exact completed receipt absent"));
        }
        // The page moved out of a frame this MM holds.
        let source = FrameGpa::new(receipt.old_ipa);
        self._vm
            .frame_identity(mm, source)
            .map_err(|error| fail(format!("owner COW completed source: {error}")))?;
        let residency = self.cow_residency()?;
        let residency_view = residency
            .view()
            .ok_or_else(|| fail("owner COW replacement residency view"))?;
        match residency_view.lookup(receipt.grant.mm_key, receipt.span_va) {
            Some(resident) => {
                if resident.expected_ipa != receipt.new_ipa
                    || resident.identity.frame_id != receipt.grant.backing.frame_id.get()
                    || resident.identity.mapping_id != receipt.grant.backing.mapping_id.get()
                    || resident.identity.owner_generation
                        != receipt.grant.backing.owner_generation.get()
                    || resident.identity.inventory_revision
                        != receipt.grant.backing.inventory_revision.get()
                    || !residency_view.is_guest_committed(receipt.grant.mm_key, receipt.span_va)
                {
                    return Err(fail("owner COW replacement residency identity"));
                }
            }
            None => {
                // A sibling unmapped the page while this completion was
                // outstanding: its retirement took the residency row and
                // left the replacement leaf retired in place, still naming
                // the replacement frame. Publication accepts exactly that
                // leaf; the owed return settles after it.
                use carrick_mmu_core::x86::descriptor_txn::{
                    ADDRESS, PREPARED, PRESENT, RETIRED, read_terminal_descriptor,
                };
                let retired = read_terminal_descriptor(
                    &self._vm.words(),
                    context.root,
                    UserVa::new(receipt.span_va),
                )
                .is_ok_and(|(entry, _)| {
                    entry & (PRESENT | PREPARED | RETIRED) == RETIRED
                        && entry & ADDRESS == receipt.new_ipa & ADDRESS
                });
                if !retired {
                    return Err(fail("owner COW replacement residency absent"));
                }
            }
        }
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: mm,
                generation: NonZeroU64::new(receipt.grant.epoch)
                    .ok_or_else(|| fail("owner COW grant epoch"))?,
            },
            root: context.root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(receipt.span_va, receipt.span_len),
                old: source,
                new: FrameGpa::new(receipt.new_ipa),
                backing: supplied.grant.backing,
            },
            tables: &[],
        };
        let publication = GuestMmuPublication::from_x86_cow_completion(&txn, &receipt)
            .ok_or_else(|| fail("owner COW publication identity"))?;
        self._vm
            .publish(&txn, publication, &mut supplied.inventory)
            .map_err(|error| fail(error.to_string()))?;
        supplied.inventory.finish()?;
        if !self.cow_pool()?.finish(excluded, &supplied.grant) {
            return Err(fail("owner COW completion changed after settlement"));
        }
        let _retained = supplied.handle;
        Ok(())
    }

    pub(super) fn grant_portal(&self) -> Result<&MmPortalSlots, TrapError> {
        // SAFETY: the boot owner zero-initializes this atomic-only record in
        // the retained supervisor kernel region before either vCPU runs.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    pub fn bind_grant_portal(&self) -> Result<(), TrapError> {
        let carrier = self._vm.identity().nonzero();
        if !self.grant_portal()?.bind_carrier(carrier) {
            return Err(fail("carrier portal already bound"));
        }
        Ok(())
    }

    pub(in crate::cpl0_boot) fn file_supply_request<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        native_service: bool,
    ) -> Result<Option<FileSupplyRequest>, TrapError> {
        let execution = self.physical_execution(lease)?;
        let index = lease.cpu.raw() as usize;
        if self.anonymous_pending[index].is_some() {
            return Ok(None);
        }
        let slot = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("file supply grant slot"))?;
        let selected = if native_service {
            slot.pending_fault_selection_for_mm(
                carrick_el1_abi::ReservationMm::new(execution.context.mm.raw().get())
                    .ok_or_else(|| fail("file supply native MM"))?,
            )
        } else {
            slot.pending_fault_selection(
                execution.context.mm.raw().get(),
                lease.io.get_gpr(X86Reg::Rdi)?,
            )
        };
        let Some((_, window)) = selected else {
            return Ok(None);
        };
        let Some(identity) = window.host_backing else {
            return Ok(None);
        };
        let sources = self.sources_mut(execution.context)?;
        // A shared file window's fault must reach the file's own pages; a
        // private copy here would drop every store (#1338).
        let shared = sources.is_window(identity);
        let source = sources
            .retain(identity, || None)
            .ok_or_else(|| fail("file fault source identity"))?;
        Ok(Some(FileSupplyRequest {
            execution,
            window,
            source,
            shared,
        }))
    }

    pub(super) fn service_anonymous_grant<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        file: Option<FileSupply>,
    ) -> Result<(), TrapError> {
        let cpu = lease.cpu;
        let index = cpu.raw() as usize;
        let lane = &*lease.io;
        if lane.get_gpr(X86Reg::Rax)? != u64::from(cpu.raw()) {
            return Err(fail("owner grant CPU identity"));
        }
        let task = self.task(cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("owner grant MM"))?;
        let context = self._vm.root(mm).ok_or_else(|| fail("owner grant root"))?;
        if !binding.issued()
            || binding.thread_generation.raw() == 0
            || context.mm.raw() != mm
            || lane.get_gpr(X86Reg::Cr3)? != context.root.address().raw()
        {
            return Err(fail("owner grant inactive execution/root"));
        }
        let native = self.binding(cpu);
        if native.cpu_slot != cpu.raw()
            || native.mm_owner_generation.load(Ordering::Acquire) != context.generation.raw().get()
        {
            return Err(fail("owner grant address incarnation"));
        }
        let execution = GrantExecution {
            cpu,
            binding,
            context,
        };
        if let Some(pending) = &self.anonymous_pending[index]
            && !pending.execution.matches(execution)
        {
            return Err(fail("owner grant stale execution/root"));
        }
        // The settlement op names no selected address; a CPU with a grant
        // still pending never rings it (its syscall path holds none).
        if lane.get_gpr(X86Reg::Rdi)? == OWNER_GRANT_SETTLE_RETURNS {
            if self.anonymous_pending[index].is_some() {
                return Err(fail("owed-return settlement with a grant pending"));
            }
            return self.service_return_settlement(lease, execution);
        }
        if let Some(pending) = self.anonymous_pending[index].take() {
            use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
            let reply = self
                .grant_portal()?
                .grant(index)
                .ok_or_else(|| fail("owner grant slot"))?
                as *const carrick_el1_abi::PortalGrantSlot;
            // SAFETY: the carrier retains this initialized physical reply.
            let reply = unsafe { &*reply };
            let applied = reply
                .inspect_receipt(pending.window, &pending.txn)
                .is_some_and(|receipt| matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
            if applied {
                if !self.settle_backing_grant(pending, reply, None)? {
                    return Err(fail("owner grant refused"));
                }
                return Ok(());
            }
            // The guest settles a refused receipt, or a window it could not
            // serve, before it parks: this CPU's slot is per-CPU custody and
            // its member may resume elsewhere. The refused or withdrawn
            // backing is cancelled at this exclusion, or at the MM's next one.
            let ram = Arc::clone(&self.ram);
            let zone = retained_cow_zone(&ram)?;
            let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
            let delivery = |zone: &X86Cpl0Zone,
                            waker: Waker,
                            owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >| wake.deliver(zone, waker, owned);
            let release = SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &delivery,
                ),
            };
            match self.settled_pause(release, pending.window.operation.mm)? {
                Ok((pause, _)) => {
                    self.settle_backing_grant(pending, reply, Some(&pause))?;
                    drop(pause);
                }
                Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => {
                    self.settle_backing_grant(pending, reply, None)?;
                }
                Err(_) => return Err(fail("owner grant settlement MM changed")),
            }
            wake.finish()?;
            return Ok(());
        }
        // Hardware faults and kernel-owned user copies share this crossing.
        // Its selected address is explicit; CR2 may name an unrelated fault.
        let far = lease.io.get_gpr(X86Reg::Rdi)?;
        if let Some((_, window)) = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner COW slot"))?
            .pending_cow_fault_selection(mm.get(), far)
        {
            return self.supply_cow_grant(index, execution, window);
        }
        let Some((generation, window)) = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner grant slot"))?
            .pending_fault_selection(mm.get(), far)
        else {
            // No selection is published: the member asks for its MM's
            // copy-on-write completions to be settled.
            return self.settle_cow_grants(
                carrick_el1_abi::ReservationMm::new(mm.get())
                    .ok_or_else(|| fail("owner COW settlement MM"))?,
            );
        };
        let reply = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner grant slot"))?
            as *const carrick_el1_abi::PortalGrantSlot;
        // SAFETY: the carrier retains this initialized slot across staging.
        let reply = unsafe { &*reply };
        match self.prepare_native_backing_grant(execution, window, file, reply)? {
            Ok(BackingPreparation::Prepared(pending)) => {
                self.anonymous_pending[index] = Some(*pending);
            }
            Ok(BackingPreparation::FilePastEnd) => {
                // Leave the authenticated file selection pending so the ring
                // cancels it into SIGBUS (BUS_ADRERR).
            }
            Ok(BackingPreparation::TablesExhausted) => {
                if !reply.refuse_fault_selection(window, generation) {
                    return Err(fail("exhausted owner fault selection changed"));
                }
            }
            // Another CPU holds this MM's editor, or published into this
            // window after its selection: the selection is returned unserved
            // and its member reruns the access after that editor's release.
            Ok(BackingPreparation::Raced) => {
                if !reply.cancel_fault_selection(window, generation) {
                    return Err(fail("contended owner fault selection changed"));
                }
            }
            Err(wait) if wait.cause() == carrick_core_abi::PortalWaitCause::Editor => {
                if !reply.cancel_fault_selection(window, generation) {
                    return Err(fail("contended owner fault selection changed"));
                }
            }
            Err(wait) => {
                if !reply.complete_pool_wait(window, generation, wait) {
                    return Err(fail("contended owner fault selection changed"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn settle_native_backing_reply(
        &mut self,
        execution: carrick_hal::fork_stock::GrantExecution,
        owner: carrick_el1_abi::El1MmHandle,
        generation: core::num::NonZeroU64,
        address: KernelVa,
    ) -> Result<bool, TrapError> {
        if !self
            .native_backing_pending
            .get(&address)
            .is_some_and(|pending| pending.authenticates_native_reply(execution, owner, generation))
        {
            return Err(fail("native backing reply owner changed"));
        }
        let pointer = self.native_service_pointer(
            execution.context,
            address,
            size_of::<carrick_el1_abi::PortalGrantSlot>(),
            align_of::<carrick_el1_abi::PortalGrantSlot>(),
        )?;
        // SAFETY: exact stopped task/MM and retained reply authenticate the complete
        // slot. The ring owns it until this receipt or withdrawal is settled.
        let reply = unsafe { &*pointer.cast::<carrick_el1_abi::PortalGrantSlot>() };
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        let release = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        };
        let pause = match self.settled_pause(release, owner.mm())? {
            Ok((pause, _)) => pause,
            Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => {
                // Refusal leaves the exact reply and physical journals owned.
                // The caller observed Editor before this crossing, and parks
                // there rather than lowering this refusal to a Linux errno.
                wake.finish()?;
                return Ok(false);
            }
            Err(_) => return Err(fail("native backing settlement MM changed")),
        };
        let pending = self
            .native_backing_pending
            .remove(&address)
            .ok_or_else(|| fail("native fault retained reply absent"))?;
        self.settle_backing_grant(pending, reply, Some(&pause))?;
        drop(pause);
        wake.finish()?;
        Ok(true)
    }
    fn settle_backing_grant(
        &mut self,
        mut pending: PendingPrepare,
        reply: &carrick_el1_abi::PortalGrantSlot,
        exclusion: Option<&CowPause<'_>>,
    ) -> Result<bool, TrapError> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
        let index = pending.execution.cpu.raw() as usize;
        let (receipt, trace) = reply
            .take_receipt_with_trace(pending.window, &pending.txn)
            .map_or((None, None), |(receipt, trace)| (Some(receipt), trace));
        if let Some(receipt) = &receipt
            && (receipt.id != pending.txn.id || receipt.digest != pending.txn.digest())
        {
            return Err(fail("owner grant receipt identity"));
        }
        if let Some(event) = trace.and_then(|trace| trace.event) {
            carrick_hal::diagnostic_capture::trace_descriptor_diagnostic(
                carrick_guest_arch::GuestIsa::X86_64,
                event,
            );
        }
        let undo = match receipt.as_ref().map(|receipt| &receipt.outcome) {
            Some(DescriptorOutcome::Applied(_)) => false,
            Some(DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_)) => true,
            Some(DescriptorOutcome::Indeterminate(_)) => {
                return Err(fail("owner grant indeterminate receipt"));
            }
            None if reply.withdraw(pending.window, &pending.txn) => true,
            None => return Err(fail("owner grant receipt absent")),
        };
        if undo {
            // The exact withdrawn or rolled-back receipt proves that none of
            // these fresh bytes are named by a guest descriptor.
            pending.backing.unexposed();
            if let Some(receipt) = &receipt {
                self.fork_stock
                    .settle_native_descriptor_tables(
                        &mut NoTableLedger,
                        pending.owner,
                        pending.execution.context.root,
                        receipt,
                    )
                    .map_err(|error| {
                        fail(format!("Prepare table refusal settlement: {error:?}"))
                    })?;
            } else {
                self.fork_stock
                    .cancel_submitted_native_descriptor_tables(
                        &mut NoTableLedger,
                        pending.owner,
                        pending.execution.context.root,
                        pending.txn.id.generation,
                    )
                    .map_err(|error| fail(format!("Prepare table withdrawal: {error:?}")))?;
            }
            if let Some(pause) = exclusion {
                self.cancel_withdrawn_backing(pending, pause.proof())?;
            } else {
                self.cancelled_backing_pending.push(pending);
            }
            return Ok(false);
        }
        let receipt = receipt.ok_or_else(|| fail("owner grant applied receipt absent"))?;
        let publication = GuestMmuPublication::from_x86_owner_grant(&pending.txn, &receipt)
            .ok_or_else(|| {
                let linked = match receipt.outcome {
                    carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(applied) => Some(applied.tables_linked),
                    _ => None,
                };
                fail(format!("owner grant refused: {:?}; cpu={} mm={} root={:#x} window_va={:#x} window_len={:#x} offered_tables={} receipt_tables_linked={linked:?}", receipt.outcome, pending.execution.cpu.raw(), pending.execution.context.mm.raw(), pending.execution.context.root.address().raw(), pending.window.range.start(), pending.window.range.len(), pending.txn.tables.len()))
            })?;
        X86Mmu::project_grant(
            pending.txn.root.raw(),
            &pending.txn,
            |native| match &mut pending.backing {
                GrantBacking::Private { inventory, .. } => {
                    self._vm.publish(native, publication, &mut **inventory)
                }
                GrantBacking::Window => self._vm.publish(native, publication, &mut WindowInventory),
            },
        )
        .map_err(|error| fail(format!("owner grant projection: {error:?}")))?
        .map_err(|error| fail(error.to_string()))?;
        if let GrantBacking::Private { inventory, .. } = &mut pending.backing {
            inventory.finish()?;
        }
        // File grants settle through the same publisher, but are outside
        // the anonymous-leaf evidence population.
        if pending.window.host_backing.is_none() {
            self.private_anonymous_witness.record_settled(
                crate::cpl0_private_witness::SettledPrivateGrant {
                    memory: &self._vm,
                    inventory: &*self.frame_inventory,
                    binding: pending.execution.binding,
                    cpu: pending.execution.cpu,
                    context: pending.execution.context,
                    window: pending.window,
                    txn: &pending.txn,
                    publication,
                    peer: pending
                        .peer
                        .combine(crate::cpl0_private_witness::PeerActivity::observe(
                            &self.actual_run[1 - index],
                        )),
                },
            )?;
        }
        self.fork_stock
            .settle_native_descriptor_tables(
                &mut NoTableLedger,
                pending.owner,
                pending.execution.context.root,
                &receipt,
            )
            .map_err(|error| fail(format!("Prepare table settlement: {error:?}")))?;
        // Retained stage-2 custody now belongs to the live guest graph.
        let _retained = pending.backing;
        Ok(true)
    }

    /// Cancel a refused or withdrawn backing at an exclusion of its MM.
    pub(super) fn cancel_withdrawn_backing(
        &mut self,
        mut pending: PendingPrepare,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        if excluded.key() != pending.window.operation.mm.raw() {
            return Err(fail("withdrawn backing exclusion MM mismatch"));
        }
        pending.backing.unexposed();
        // SAFETY: `excluded` proves no guest editor of this MM is active, and
        // the exact withdrawn or refused receipt proved no guest descriptor
        // ever named the pending backing.
        unsafe { self.cancel_unexposed_backing(&mut pending.backing) }
    }

    /// Cancel a grant's backing that no guest descriptor names.
    ///
    /// # Safety
    /// No guest descriptor may name a private backing's frames, and none
    /// may come to before this returns.
    unsafe fn cancel_unexposed_backing(
        &mut self,
        backing: &mut GrantBacking,
    ) -> Result<(), TrapError> {
        match backing {
            // SAFETY: the caller's contract.
            GrantBacking::Private { inventory, handle } => {
                unsafe { self._vm.cancel_prepared(&[*handle], &mut **inventory) }
                    .map_err(|error| fail(error.to_string()))
            }
            GrantBacking::Window => Ok(()),
        }
    }

    /// Cancel every refused or withdrawn backing of the excluded MM that
    /// was settled while its exclusion was busy.
    pub(super) fn drain_cancelled_backing_for_excluded(
        &mut self,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        let mut retained = Vec::new();
        for pending in core::mem::take(&mut self.cancelled_backing_pending) {
            if pending.window.operation.mm.raw() == excluded.key() {
                self.cancel_withdrawn_backing(pending, excluded)?;
            } else {
                retained.push(pending);
            }
        }
        self.cancelled_backing_pending = retained;
        Ok(())
    }

    pub(super) fn prepare_native_backing_grant(
        &mut self,
        execution: GrantExecution,
        window: PortalGrantWindow,
        file: Option<FileSupply>,
        reply: &carrick_el1_abi::PortalGrantSlot,
    ) -> Result<Result<BackingPreparation, carrick_core_abi::PortalOwnerWait>, TrapError> {
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        let release = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        };
        let source = zone
            .space_entry(
                NonZeroU64::new(window.operation.mm.raw())
                    .ok_or_else(|| fail("native preparation MM"))?,
            )
            .ok_or_else(|| fail("native preparation space"))?;
        let observed = source
            .notifications(window.operation.incarnation)
            .map_err(|_| fail("native preparation source"))?
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
        let pool_key = carrick_sched_core::object_wait::ObjectWaitKey::reservation_pool(
            window.operation.carrier,
        );
        let sink = self.carrier_zone_wake()?;
        let pool_revision = sample_carrier_pool_revision(zone, pool_key, &*sink)?;
        let stock_observed = self.fork_stock.table_release();
        // The one wait this call can return, keyed by why the plan is busy:
        // each cause carries the revision observed from its own queue.
        let owner_wait = |busy: PlanBusy| {
            // SAFETY: the ticket retains this exact admitted window and the
            // source above authenticates its MM incarnation.
            let handle = unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    window.operation.carrier,
                    window.operation.mm,
                    window.operation.incarnation,
                )
            };
            match busy {
                // SAFETY: this Editor observation preceded every probe of
                // this call, the outer exclusion's and the table plan's.
                PlanBusy::Editor => unsafe {
                    carrick_core_abi::PortalOwnerWait::from_owner(
                        handle,
                        carrick_core_abi::PortalWaitCause::Editor,
                        observed.revision(),
                    )
                },
                // The pool revision was sampled before the table plan, whose
                // shortage `enrol_release` re-probes against `stock_observed`,
                // so any return after that probe bumps `pool_key`.
                PlanBusy::TableStock => {
                    carrick_core_abi::PortalOwnerWait::reservation_pool(handle, pool_revision)
                }
            }
        };
        let pause = match self.settled_pause(release, window.operation.mm)? {
            Ok((pause, _)) => pause,
            Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => {
                wake.finish()?;
                return Ok(Err(owner_wait(PlanBusy::Editor)));
            }
            Err(_) => return Err(fail("native preparation MM changed")),
        };
        // Keep this exclusion through allocation and the read-only table plan:
        // a contended native call waits before creating any physical journal.
        let pending = self.prepare_backing_grant(execution, window, file, reply, stock_observed)?;
        drop(pause);
        wake.finish()?;
        match pending {
            Ok(prepared) => Ok(Ok(prepared)),
            // The plan's own exclusion met the editor held: the same wait as a
            // busy outer exclusion. A release since `observed` reruns at once.
            Err(PlanBusy::Editor) => Ok(Err(owner_wait(PlanBusy::Editor))),
            // Returnable table custody holds the remaining stock: release the
            // MM editor above, enrol on the holder's release, probe once, and
            // park on the carrier's reservation-pool queue (#3017).
            Err(PlanBusy::TableStock) => {
                let stock_wake = carrier_pool_release_wake(pool_key, Arc::clone(&sink));
                self.fork_stock.enrol_release(stock_observed, stock_wake);
                if sink.take_undelivered().is_some() {
                    return Err(fail("reservation pool reschedule not delivered"));
                }
                Ok(Err(owner_wait(PlanBusy::TableStock)))
            }
        }
    }

    pub(super) fn prepare_backing_grant(
        &mut self,
        execution: GrantExecution,
        window: PortalGrantWindow,
        file: Option<FileSupply>,
        reply: &carrick_el1_abi::PortalGrantSlot,
        stock_observed: carrick_hal::fork_stock::StockRelease,
    ) -> Result<Result<BackingPreparation, PlanBusy>, TrapError> {
        let context = execution.context;
        let mm = context.mm.raw();
        if self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.range.len() > carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
        {
            return Err(fail("owner grant selection identity"));
        }
        if window.operation.mm.raw() != mm.get()
            || window.operation.incarnation != context.generation.raw()
            || window.operation.carrier != self.fork_stock.carrier()
        {
            return Err(fail("Prepare table owner differs from stopped root"));
        }
        // SAFETY: the retained portal selection and stopped context agree on
        // the admitted MM, incarnation and carrier; ForkStock checks its root.
        let owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                window.operation.carrier,
                window.operation.mm,
                window.operation.incarnation,
            )
        };
        let bytes = match (window.host_backing, file) {
            (Some(_), Some(file)) if file.execution.matches(execution) && file.window == window => {
                match file.contents {
                    FileContents::Copied(bytes) => bytes,
                    FileContents::Window(shared) => {
                        return self.prepare_window_grant(
                            execution,
                            window,
                            owner,
                            shared,
                            reply,
                            stock_observed,
                        );
                    }
                }
            }
            (None, None) => None,
            _ => return Err(fail("file supply changed while custody was released")),
        };
        let publication_len = bytes.as_ref().map_or_else(
            || {
                if window.host_backing.is_some() {
                    0
                } else {
                    window.range.len()
                }
            },
            |bytes| bytes.len() as u64,
        );
        if window.fault_page
            >= window
                .range
                .start()
                .checked_add(publication_len)
                .ok_or_else(|| fail("file supply length overflow"))?
        {
            // Leave the authenticated selection pending. The guest observes
            // no backing reply, cancels this exact selection and delivers its
            // normal backing-fault signal; EOF is not a carrier invariant.
            return Ok(Ok(BackingPreparation::FilePastEnd));
        }
        let len = publication_len.next_multiple_of(4096);
        let (mut extent, placement) =
            BackingExtent::owner_window(&mut self.anonymous_next_gpa, len as usize)
                .map_err(|error| fail(error.to_string()))?;
        if placement == crate::carrier_memory::HostPlacement::LargePage {
            self.large_page_windows += 1;
        }
        let gpa = extent.base;
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(&self.initial_rollback_fault),
            Arc::clone(&self.frame_inventory),
            [gpa],
            0,
            len,
            execution.context.into(),
        )?;
        let identity = inventory
            .frames
            .first()
            .ok_or_else(|| fail("owner grant backing identity"))?
            .1;
        if let Some(bytes) = bytes {
            extent
                .initialize(0, &bytes)
                .map_err(|error| fail(error.to_string()))?;
        }
        let handles = self
            ._vm
            .prepare(
                &[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }],
                &mut inventory,
            )
            .map_err(|error| fail(error.to_string()))?;
        let handle = handles[0];
        let grant = grants[0];
        let op = WireOp::Prepare {
            publication: GuestLeafPublication {
                va: window.range.start(),
                ipa: grant.gpa,
                len: publication_len,
                writable: window
                    .protection
                    .permits(carrick_el1_abi::ReservationProtection::WRITE),
                executable: window
                    .protection
                    .permits(carrick_el1_abi::ReservationProtection::EXECUTE),
            },
            resident: PageSpan::new(window.fault_page, 4096),
            backing: identity,
        };
        self.submit_backing_grant(
            execution,
            window,
            owner,
            BackingGrant {
                op,
                backing: GrantBacking::Private {
                    inventory: Box::new(inventory),
                    handle,
                },
            },
            reply,
            stock_observed,
        )
    }

    /// Serve one page of a shared file window (#1338): map the carrier's
    /// slot for the file's chunk, never a private copy, so the guest's
    /// stores are the file's bytes. The slot is a host `mmap(MAP_SHARED)` of
    /// the chunk installed when `HostFileOp::MapShared` replies (subject to
    /// `WindowSlotBudget`, rolled back by `ReleaseWindow` if placement fails
    /// before committing); each MM that faults it is admitted to it.
    fn prepare_window_grant(
        &mut self,
        execution: GrantExecution,
        window: PortalGrantWindow,
        owner: carrick_el1_abi::El1MmHandle,
        file: WindowFile,
        reply: &carrick_el1_abi::PortalGrantSlot,
        stock_observed: carrick_hal::fork_stock::StockRelease,
    ) -> Result<Result<BackingPreparation, PlanBusy>, TrapError> {
        use carrick_core::mm::window::WindowChunk;
        let source = window
            .host_backing
            .ok_or_else(|| fail("window fault source absent"))?;
        let offset = source
            .offset()
            .checked_add(window.fault_page - window.range.start())
            .ok_or_else(|| fail("window fault offset overflow"))?;
        if offset >= file.len {
            // Past the file's end. Leave the authenticated selection pending,
            // as a private file fault past EOF does: the guest cancels it and
            // delivers its backing-fault signal (SIGBUS).
            return Ok(Ok(BackingPreparation::FilePastEnd));
        }
        let chunk = WindowChunk::of_offset(offset);
        let key = (file.device, file.inode, chunk.index());
        let (handle, base, identity) = self
            .window_slots
            .get(&key)
            .map(|entry| (entry.handle, entry.gpa, entry.identity))
            .ok_or_else(|| fail("missing admitted window slot"))?;
        let edge = self
            ._vm
            .share(handle)
            .map_err(|error| fail(error.to_string()))?;
        self._vm
            .attach_shared(execution.context.mm.raw(), &edge)
            .map_err(|error| fail(error.to_string()))?;
        let op = WireOp::MapAlias {
            access: carrick_mmu_core::aarch64::descriptor_txn::AliasAccess::User {
                writable: window
                    .protection
                    .permits(carrick_el1_abi::ReservationProtection::WRITE),
                executable: window
                    .protection
                    .permits(carrick_el1_abi::ReservationProtection::EXECUTE),
            },
            span: PageSpan::new(window.fault_page, 4096),
            target_ipa: SubstrateGpa(base.raw() + (offset - chunk.start())),
            backing: identity,
        };
        self.submit_backing_grant(
            execution,
            window,
            owner,
            BackingGrant {
                op,
                backing: GrantBacking::Window,
            },
            reply,
            stock_observed,
        )
    }

    /// Plan, admit and submit one owner grant's descriptor transaction. Every
    /// refusal before the guest may see it cancels the grant's backing.
    fn submit_backing_grant(
        &mut self,
        execution: GrantExecution,
        window: PortalGrantWindow,
        owner: carrick_el1_abi::El1MmHandle,
        grant: BackingGrant,
        reply: &carrick_el1_abi::PortalGrantSlot,
        stock_observed: carrick_hal::fork_stock::StockRelease,
    ) -> Result<Result<BackingPreparation, PlanBusy>, TrapError> {
        let BackingGrant { op, mut backing } = grant;
        let index = execution.cpu.raw() as usize;
        let context = execution.context;
        let mm = context.mm.raw();
        let root = context.root;
        let tables: Vec<SubstrateGpa> = self
            .fork_stock
            .descriptor_table_candidates()
            .iter()
            .map(|table| SubstrateGpa(table.address().raw()))
            .collect();
        let mut txn = WireTxn {
            id: DescriptorTxnId {
                mm_key: mm,
                generation: window.operation.sequence,
            },
            root: SubstrateGpa(root.address().raw()),
            op,
            tables: TableGrants::new(&tables).ok_or_else(|| fail("owner table grant encoding"))?,
        };
        let ram = Arc::clone(&self.ram);
        let demand = (|| -> Result<Result<usize, PlanDecline>, TrapError> {
            let zone = retained_cow_zone(&ram)?;
            let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
            let delivery = |zone: &X86Cpl0Zone,
                            waker: Waker,
                            owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >| wake.deliver(zone, waker, owned);
            let venue = SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &delivery,
                ),
            };
            #[cfg(feature = "test-support")]
            let maintenance = editor_hold::take(EditorHoldSite::BackingPlan, venue, mm, None);
            let probe = self.settled_pause(venue, window.operation.mm);
            // The seam's borrow ends through its own release, before this
            // venue's wakes are finished.
            #[cfg(feature = "test-support")]
            drop(maintenance);
            let pause = match probe? {
                Ok((pause, _)) => pause,
                Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => {
                    wake.finish()?;
                    return Ok(Err(PlanDecline::EditorBusy));
                }
                Err(reason) => {
                    wake.finish()?;
                    return Err(fail(format!(
                        "owner COW editor exclusion refused: {reason:?}"
                    )));
                }
            };
            let planned = X86Mmu::project_grant(
                root.address().raw(),
                &txn,
                |native| -> Result<
                    Result<usize, carrick_mmu_core::descriptor_refusal::DescriptorRefusal>,
                    TrapError,
                > {
                    self._vm
                        .admit_guest_edit(native)
                        .map_err(|error| fail(error.to_string()))?;
                    Ok(carrick_mmu_core::x86::descriptor_txn::plan_descriptor_txn(
                        &self._vm.words(),
                        native,
                        root,
                    )
                    .map(|plan| plan.tables_linked))
                },
            )
            .map_err(|error| fail(format!("owner grant table plan projection: {error:?}")));
            drop(pause);
            wake.finish()?;
            Ok(planned??.map_err(PlanDecline::Refused))
        })();
        let required = match demand {
            Ok(Ok(required)) => required,
            Ok(Err(PlanDecline::EditorBusy)) => {
                // Nothing made this fresh backing guest-visible.
                unsafe { self.cancel_unexposed_backing(&mut backing) }?;
                return Ok(Err(PlanBusy::Editor));
            }
            Ok(Err(PlanDecline::Refused(refusal))) => {
                // Neither the read-only planner nor the release venue made
                // this fresh backing guest-visible.
                unsafe { self.cancel_unexposed_backing(&mut backing) }?;
                use carrick_core::mm::frames::{PublicationDecline, PublicationNotNow};
                return match PublicationDecline::from_descriptor(refusal) {
                    // The other CPU published into this window after it was
                    // selected: the selection is stale, not the MM. Its
                    // member reruns the access, whose reselection finds the
                    // published or inherited-Prepared output.
                    PublicationDecline::InheritedPrepared
                    | PublicationDecline::NotNow(PublicationNotNow::MmRelease) => {
                        Ok(Ok(BackingPreparation::Raced))
                    }
                    // When returnable custody still holds tables, shortage is
                    // temporary contention ("not now", never fatal or an errno):
                    // enrol on the holder's release and rerun. Only when zero
                    // returnable tables remain is the carrier's page-table
                    // window genuinely spent (#3017).
                    PublicationDecline::NotNow(PublicationNotNow::Capacity(
                        carrick_mmu_core::descriptor_refusal::DescriptorRefusal::TablesExhausted,
                    )) => match self.fork_stock.table_shortage(stock_observed) {
                        carrick_hal::fork_stock::TableShortage::Returnable => {
                            Ok(Err(PlanBusy::TableStock))
                        }
                        carrick_hal::fork_stock::TableShortage::Spent => {
                            self.fork_stock.refuse_descriptor_capacity();
                            Ok(Ok(BackingPreparation::TablesExhausted))
                        }
                    },
                    _ => Err(fail(format!(
                        "owner grant physical table plan refused: {refusal:?}; cpu={} mm={} root={:#x} window_va={:#x} window_len={:#x} available_tables={}",
                        execution.cpu.raw(),
                        mm,
                        root.address().raw(),
                        window.range.start(),
                        window.range.len(),
                        tables.len()
                    ))),
                };
            }
            Err(error) => {
                // Neither the read-only planner nor the release venue made
                // this fresh backing guest-visible.
                unsafe { self.cancel_unexposed_backing(&mut backing) }?;
                return Err(error);
            }
        };
        let owned_tables = match self.fork_stock.reserve_native_descriptor_tables(
            &mut NoTableLedger,
            owner,
            root,
            required,
        ) {
            Ok(owned) => owned,
            Err(error) => {
                unsafe { self.cancel_unexposed_backing(&mut backing) }?;
                return Err(fail(format!(
                    "owner grant physical table credit refused: {error:?}; cpu={} mm={} required={required} available={}",
                    execution.cpu.raw(),
                    mm,
                    self.fork_stock.table_stock().len()
                )));
            }
        };
        txn.tables = owned_tables.descriptor_tables();
        let admission = X86Mmu::project_grant(root.address().raw(), &txn, |native| {
            self._vm.admit_guest_edit(native)
        });
        if !matches!(admission, Ok(Ok(()))) {
            // SAFETY: the vCPU is stopped, and no descriptor submission was
            // admitted. The fresh extent has never been guest-visible.
            unsafe { self.cancel_unexposed_backing(&mut backing) }?;
            self.fork_stock
                .cancel_native_descriptor_tables(&mut NoTableLedger, owned_tables);
            return Err(fail("owner grant admission refused"));
        }
        if let Err(error) =
            self.fork_stock
                .track_native_descriptor_tables(&mut NoTableLedger, owned_tables, txn)
        {
            unsafe { self.cancel_unexposed_backing(&mut backing) }?;
            return Err(fail(format!(
                "Prepare table transaction tracking: {error:?}"
            )));
        }
        if !reply.submit_with_trace(
            window,
            &txn,
            carrick_hal::diagnostic_capture::trace_grant_refusals(),
        ) {
            unsafe { self.cancel_unexposed_backing(&mut backing) }?;
            self.fork_stock
                .cancel_submitted_native_descriptor_tables(
                    &mut NoTableLedger,
                    owner,
                    root,
                    txn.id.generation,
                )
                .map_err(|error| fail(format!("Prepare table submit cancellation: {error:?}")))?;
            return Err(fail("owner grant submission refused"));
        }
        // Once submitted, guest descriptor publication may have happened even
        // if the carrier never receives a verifiable completion. Keep physical
        // custody through carrier teardown rather than rolling inventory back.
        backing.submitted();
        Ok(Ok(BackingPreparation::Prepared(Box::new(PendingPrepare {
            peer: crate::cpl0_private_witness::PeerActivity::observe(&self.actual_run[1 - index]),
            window,
            txn,
            backing,
            execution,
            owner,
        }))))
    }
}

fn complete_carrier_pool_wake(
    sink: &dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >,
) {
    let zone = owned.zone();
    let (waker, effects) = owned.deliver_handbacks(&mut |record| {
        zone.hand_back_to_owner(record, &mut |slot| sink.resched(slot));
    });
    let own = match waker {
        Waker::El1 { slot } => Some(slot),
        Waker::Host => None,
    };
    for slot in effects
        .sgi_slots()
        .chain(own.filter(|_| effects.queued_own || effects.misplaced))
    {
        zone.owe_resched(slot);
        sink.resched(slot);
    }
}

fn sample_carrier_pool_revision(
    zone: &X86Cpl0Zone,
    pool_key: carrick_sched_core::object_wait::ObjectWaitKey,
    sink: &dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>,
) -> Result<u64, TrapError> {
    let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >| complete_carrier_pool_wake(sink, owned);
    let observe = || {
        zone.object_wait(pool_key, &carrick_sched_core::ShortLockSpin, &completion)
            .map(|queue| queue.snapshot().revision())
    };
    match observe() {
        Ok(revision) => Ok(revision),
        Err(carrick_sched_core::object_wait::ObjectWaitError::Stale) => {
            let _ =
                zone.bind_object_wait(pool_key, &carrick_sched_core::ShortLockSpin, &completion);
            observe().map_err(|_| fail("native reservation pool queue"))
        }
        Err(_) => Err(fail("native reservation pool queue")),
    }
}

fn carrier_pool_release_wake(
    pool_key: carrick_sched_core::object_wait::ObjectWaitKey,
    sink: Arc<dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>>,
) -> carrick_hal::fork_stock::StockReleaseWake {
    carrick_hal::fork_stock::StockReleaseWake::new(move || {
        let zone = sink.zone();
        let mut handed = Vec::new();
        let mut resched_slots = [0u64; 4];
        let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| complete_carrier_pool_wake(&*sink, owned);
        if let Ok(queue) =
            zone.object_wait(pool_key, &carrick_sched_core::ShortLockSpin, &completion)
        {
            let _ = queue.notify_object_host(&mut |record| handed.push(record), &mut |placed| {
                if placed.resched {
                    let index = usize::from(placed.slot.raw());
                    if let Some(word) = resched_slots.get_mut(index / 64) {
                        *word |= 1 << (index % 64);
                    }
                }
            });
        }
        for record in handed {
            zone.hand_back_to_owner(record, &mut |slot| sink.resched(slot));
        }
        for (word, mut bits) in resched_slots.into_iter().enumerate() {
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Some(slot) = SlotId::from_index(index) {
                    zone.owe_resched(slot);
                    sink.resched(slot);
                }
            }
        }
    })
}

impl<I: CarrierCpuIo, M: CarrierMemoryIo> super::ForwardVenue<'_, I, M> {
    /// Only retained supervisor POD is admitted; a guest user pointer never
    /// becomes authority to name a ring descriptor table.
    pub fn capture_host_file(
        &mut self,
        address: carrick_guest_arch::KernelVa,
        len: usize,
    ) -> Result<Vec<u8>, TrapError> {
        if len > carrick_core_abi::host_file::MAX_HOST_FILE_RECORD_BYTES as usize {
            return Err(fail("host file record length"));
        }
        let mut bytes =
            self.custody
                .read_kernel_pod_bytes(self.execution.context, address, len, 1)?;
        {
            let view = carrick_core_abi::host_file::HostFileRequestView::parse(&mut bytes)
                .map_err(|_| fail("host file record encoding"))?;
            match view.header().op {
                carrick_core_abi::host_file::HostFileOp::MapPrivate
                | carrick_core_abi::host_file::HostFileOp::MapShared => {
                    let releases =
                        carrick_core_abi::host_file::MapSourceReply::decode_releases(view.input())
                            .ok_or_else(|| fail("host file map release encoding"))?;
                    for release in releases {
                        let released = (release.handle, release.generation);
                        for entry in self.custody.window_slots.values_mut() {
                            if entry.pending_holders.remove(&released) {
                                entry.committed = true;
                            }
                        }
                    }
                }
                carrick_core_abi::host_file::HostFileOp::ReleaseWindow => {
                    let args = view.header().args;
                    let (Some(handle), Some(generation)) =
                        (NonZeroU64::new(args[0]), NonZeroU64::new(args[1]))
                    else {
                        return Err(fail("release window identity"));
                    };
                    view.reply(0, &[])
                        .map_err(|_| fail("release window reply"))?;
                    self.custody
                        .sources_mut(self.execution.context)?
                        .release(handle, generation);
                    self.rollback_unplaced_window_slots((handle, generation))?;
                    return Ok(bytes);
                }
                _ => return Err(fail("unsupported synchronous host file operation")),
            }
        }
        self.custody
            .sources_mut(self.execution.context)?
            .prepare_private_mapping(&mut bytes)
            .map_err(|_| fail("host file source admission"))?;
        Ok(bytes)
    }

    /// Revoke any unexposed, uncommitted shared file window slots whose last
    /// pending mapping holder rolled back before placing a reservation (#2975 P0 3).
    fn rollback_unplaced_window_slots(
        &mut self,
        holder: (NonZeroU64, NonZeroU64),
    ) -> Result<(), TrapError> {
        use crate::carrier_memory::{
            InventoryRetirement, MemoryError, ShootdownPlan, TranslationDrain,
        };
        use carrick_core::mm::window::WINDOW_CHUNK_BYTES;

        struct UnexposedWindowDrain;
        // SAFETY: unplaced window slots were never mapped into any guest page
        // table; fail closed if carrier custody unexpectedly recorded a drain.
        unsafe impl TranslationDrain for UnexposedWindowDrain {
            fn drain(&mut self, _: ShootdownPlan) -> Result<(), MemoryError> {
                Err(MemoryError(
                    "unexposed window slot had active translation drain".into(),
                ))
            }
        }

        struct WindowSlotRetirement;
        impl InventoryRetirement for WindowSlotRetirement {
            fn retire(&mut self, _: BackingIdentity) -> Result<(), MemoryError> {
                Ok(())
            }
            fn rollback(&mut self) -> Result<(), MemoryError> {
                Ok(())
            }
        }

        let mut candidates = Vec::new();
        for (key, entry) in &mut self.custody.window_slots {
            if entry.pending_holders.remove(&holder)
                && !entry.committed
                && entry.pending_holders.is_empty()
            {
                candidates.push((*key, entry.gpa));
            }
        }
        // Unwind highest tail GPAs first so contiguous allocations rewind
        // `anonymous_next_gpa` cleanly.
        candidates.sort_by_key(|b| std::cmp::Reverse(b.1.raw()));
        for (key, gpa) in candidates {
            let Some(handle) = self
                .custody
                .window_slots
                .get(&key)
                .map(|entry| entry.handle)
            else {
                continue;
            };
            self.custody
                ._vm
                .revoke(handle, &mut UnexposedWindowDrain, &mut WindowSlotRetirement)
                .map_err(|error| fail(error.to_string()))?;
            self.custody.window_slots.remove(&key);
            if gpa.raw() + WINDOW_CHUNK_BYTES == self.custody.anonymous_next_gpa.raw() {
                self.custody.anonymous_next_gpa = gpa;
            }
        }
        Ok(())
    }

    /// Admit and install every host-file window chunk overlapping a replied
    /// `MapShared` mapping before the guest sees the mapping reply, so slot
    /// exhaustion fails `mmap` with `-ENOSYS` instead of trapping on touch.
    fn install_window_mapping(
        &mut self,
        bytes: &mut [u8],
        source: Arc<dyn carrick_hal::fork_stock::HostBackingRetention>,
        admit_window_inode: impl FnOnce(
            std::os::fd::BorrowedFd<'_>,
        ) -> Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) -> Result<Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>, TrapError> {
        use carrick_core::mm::window::{WINDOW_CHUNK_BYTES, WindowChunk};
        use carrick_core_abi::host_file::{refuse_written_reply, replied_parts};
        use std::os::fd::AsFd;

        let Some((header, _, _)) = replied_parts(bytes) else {
            return Err(fail("replied window record absent"));
        };
        let refuse = |bytes: &mut [u8], errno: i64| -> Result<Option<_>, TrapError> {
            refuse_written_reply(bytes, errno)
                .map_err(|_| fail("host file window refusal reply"))?;
            Ok(None)
        };
        const PAGE: u64 = 4096;
        let offset = header.args[0];
        let length = header.args[1];
        let Some(aligned_len) = length.checked_next_multiple_of(PAGE) else {
            return refuse(bytes, carrick_abi::LINUX_EINVAL.guest_retval());
        };
        if aligned_len == 0 || !offset.is_multiple_of(PAGE) {
            return refuse(bytes, carrick_abi::LINUX_EINVAL.guest_retval());
        }
        let Some(end) = offset.checked_add(aligned_len) else {
            return refuse(bytes, carrick_abi::LINUX_EINVAL.guest_retval());
        };
        let last_chunk_obj = WindowChunk::of_offset(end - 1);
        let first_chunk = WindowChunk::of_offset(offset).index();
        let last_chunk = last_chunk_obj.index();
        if libc::off_t::try_from(last_chunk_obj.start()).is_err() {
            return refuse(bytes, carrick_abi::LINUX_EINVAL.guest_retval());
        }

        let Some(metadata) = source.host_file_metadata() else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };
        let device = metadata.device;
        let inode = metadata.inode;

        let available = self.custody._vm.available_window_slots();
        let span_chunks = last_chunk - first_chunk + 1;
        if span_chunks.saturating_sub(self.custody.window_slots.len() as u64) > available as u64 {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        }
        let mut missing = Vec::new();
        for chunk_index in first_chunk..=last_chunk {
            let key = (device, inode, chunk_index);
            if !self.custody.window_slots.contains_key(&key) {
                if missing.len() >= available {
                    return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
                }
                missing.push(key);
            }
        }

        let source_identity = source.identity();
        let source_id = (source_identity.handle(), source_identity.generation());
        if missing.is_empty() {
            let Some(budget) = self.custody._vm.admit_window_slots(0) else {
                return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
            };
            self.custody
                ._vm
                .install_window_slots(budget, &[])
                .map_err(|error| fail(error.to_string()))?;
            for chunk_index in first_chunk..=last_chunk {
                if let Some(entry) =
                    self.custody
                        .window_slots
                        .get_mut(&(device, inode, chunk_index))
                {
                    entry.pending_holders.insert(source_id);
                }
            }
            return Ok(Some(source));
        }

        let Some(owned_fd) = source.host_file() else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };
        let Some(budget) = self.custody._vm.admit_window_slots(missing.len()) else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };

        let Some(needed_gpa) = (missing.len() as u64).checked_mul(WINDOW_CHUNK_BYTES) else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };
        let Some(next_gpa) = self
            .custody
            .anonymous_next_gpa
            .raw()
            .checked_add(needed_gpa)
        else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };
        if next_gpa > (1u64 << 52) {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        }

        let Some(inode_lease) = admit_window_inode(owned_fd.as_fd()) else {
            return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
        };

        let start_gpa = self.custody.anonymous_next_gpa.raw();
        let mut prepared = Vec::with_capacity(missing.len());
        let mut staged = Vec::with_capacity(missing.len());
        for (index, &key) in missing.iter().enumerate() {
            let base = FrameGpa::new(start_gpa + index as u64 * WINDOW_CHUNK_BYTES);
            let chunk_start = key.2 * WINDOW_CHUNK_BYTES;
            let Ok(extent) = BackingExtent::host_file_window(
                base,
                owned_fd.as_fd(),
                chunk_start,
                WINDOW_CHUNK_BYTES as usize,
            ) else {
                return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
            };
            let identity = crate::cpl0_boot::backing_identity(&*self.custody.frame_inventory)?;
            prepared.push(PreparedBacking {
                extent: Arc::new(extent),
                identity,
            });
            staged.push((key, base, identity));
        }

        let handles = match self.custody._vm.install_window_slots(budget, &prepared) {
            Ok(handles) => handles,
            Err(error) => {
                if self.custody._vm.is_quarantined() {
                    return Err(fail(error.to_string()));
                }
                return refuse(bytes, carrick_abi::LINUX_ENOSYS.guest_retval());
            }
        };
        self.custody.anonymous_next_gpa = FrameGpa::new(next_gpa);
        for chunk_index in first_chunk..=last_chunk {
            if let Some(entry) = self
                .custody
                .window_slots
                .get_mut(&(device, inode, chunk_index))
            {
                entry.pending_holders.insert(source_id);
            }
        }
        for ((key, base, identity), handle) in staged.into_iter().zip(handles) {
            let mut pending_holders = std::collections::BTreeSet::new();
            pending_holders.insert(source_id);
            self.custody.window_slots.insert(
                key,
                crate::cpl0_boot::WindowSlotEntry {
                    handle,
                    gpa: base,
                    identity,
                    _inode_lease: Arc::clone(&inode_lease),
                    committed: false,
                    pending_holders,
                },
            );
        }
        Ok(Some(source))
    }

    /// Retain the source before making its reply visible in the exact caller MM.
    pub fn complete_host_file(
        &mut self,
        address: carrick_guest_arch::KernelVa,
        bytes: &mut [u8],
        source: Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
        admit_window_inode: impl FnOnce(
            std::os::fd::BorrowedFd<'_>,
        ) -> Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) -> Result<(), TrapError> {
        // Reauthenticate the entire retained output after the host service ran.
        self.custody
            .read_kernel_pod_bytes(self.execution.context, address, bytes.len(), 1)?;
        if let Some(source) = source {
            if replied_map_source_is_window(bytes)? {
                if let Some(source) =
                    self.install_window_mapping(bytes, source, admit_window_inode)?
                {
                    self.custody
                        .sources_mut(self.execution.context)?
                        .inherit_window(source);
                }
            } else {
                self.custody
                    .sources_mut(self.execution.context)?
                    .inherit(source);
            }
        }
        let physical =
            kernel_pod_physical(&self.custody.kernel_pod_storage, address, bytes.len(), 1)
                .ok_or_else(|| fail("host file reply storage"))?;
        self.custody
            ._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))
    }
}

/// Whether the source a map-source record retained is a shared file window
/// ([`carrick_core_abi::host_file::HostFileOp::MapShared`], #1338). The host
/// service has written its reply by now, so the record must read as replied.
/// Any other record is a broken invariant: retaining a window's source as a
/// byte copy would drop every store the guest makes through the mapping.
fn replied_map_source_is_window(bytes: &[u8]) -> Result<bool, TrapError> {
    use carrick_core_abi::host_file::{HostFileOp, replied_parts};
    match replied_parts(bytes) {
        Some((header, _, _)) if header.op == HostFileOp::MapShared => Ok(true),
        Some((header, _, _)) if header.op == HostFileOp::MapPrivate => Ok(false),
        _ => Err(fail("retained map source without a replied map record")),
    }
}

pub(in crate::cpl0_boot) struct FileSupplyRequest {
    execution: GrantExecution,
    window: PortalGrantWindow,
    source: Arc<dyn carrick_hal::fork_stock::HostBackingRetention>,
    /// The source is a shared file window (#1338).
    shared: bool,
}
pub(in crate::cpl0_boot) struct FileSupply {
    execution: GrantExecution,
    window: PortalGrantWindow,
    contents: FileContents,
}
/// What a file fault publishes.
pub(in crate::cpl0_boot) enum FileContents {
    /// A private copy of the file's bytes from the window's start (`None`:
    /// the source could not be read).
    Copied(Option<Vec<u8>>),
    /// A shared file window: the fault maps the file's own pages.
    Window(WindowFile),
}
/// The host file behind a shared file window, read outside carrier custody.
pub(in crate::cpl0_boot) struct WindowFile {
    device: u64,
    inode: u64,
    /// The file's size when the fault was served.
    len: u64,
}
impl FileSupplyRequest {
    pub(in crate::cpl0_boot) fn read(self) -> Result<FileSupply, TrapError> {
        let identity = self
            .window
            .host_backing
            .ok_or_else(|| fail("file source absent"))?;
        if self.shared {
            let metadata = self
                .source
                .host_file_metadata()
                .ok_or_else(|| fail("shared file window source has no host metadata"))?;
            return Ok(FileSupply {
                execution: self.execution,
                window: self.window,
                contents: FileContents::Window(WindowFile {
                    device: metadata.device,
                    inode: metadata.inode,
                    len: metadata.len,
                }),
            });
        }
        let request = carrick_hal::fork_stock::HostBackingRead::new(
            identity,
            self.window.range.len() as usize,
        )
        .ok_or_else(|| fail("file supply read length"))?;
        let bytes = match self.source.read(request) {
            Ok(bytes) => Some(bytes),
            Err(
                carrick_hal::fork_stock::HostBackingReadError::Inaccessible
                | carrick_hal::fork_stock::HostBackingReadError::Unavailable,
            ) => None,
            Err(error) => return Err(fail(format!("file supply read: {error:?}"))),
        };
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() > request.length())
        {
            return Err(fail("file source returned oversized prefix"));
        }
        Ok(FileSupply {
            execution: self.execution,
            window: self.window,
            contents: FileContents::Copied(bytes),
        })
    }
}

impl<I: CarrierCpuIo, M: CarrierMemoryIo> super::ProductionCpuLease<I, M> {
    pub(super) fn read_owner_file(
        &mut self,
        task: Option<carrick_guest_arch::TaskIdentity>,
        native_service: bool,
    ) -> Result<Option<FileSupply>, TrapError> {
        let request = {
            let mut custody = self
                ._custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            if let Some(task) = task {
                let cpu = self
                    .physical_slot()
                    .ok_or_else(|| fail("file supply CPU slot"))?;
                self.cpu.with_stopped_io(task, |io| {
                    custody.file_supply_request(&StoppedCpuLease { cpu, io }, native_service)
                })?
            } else {
                self.cpu.with_idle_peer_io(|io| {
                    custody.file_supply_request(
                        &StoppedCpuLease {
                            cpu: carrick_guest_arch::CpuId::new(1),
                            io,
                        },
                        native_service,
                    )
                })?
            }
        };
        // No carrier custody, CPU-I/O borrow or MM editor survives file I/O.
        request.map(|request| request.read()).transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod custody_tests {
    use super::*;
    use carrick_el1_abi::{
        EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, SnapshotGeneration,
    };

    /// One map-source record as `complete_host_file` sees it: the host
    /// service has replied.
    fn replied_map_record(op: carrick_core_abi::host_file::HostFileOp) -> Vec<u8> {
        map_record(op, true)
    }

    fn map_record(op: carrick_core_abi::host_file::HostFileOp, replied: bool) -> Vec<u8> {
        use carrick_core_abi::host_file::{
            HostFileHeader, HostFileRequestView, MapSourceReply, encode, record_len,
        };
        let mut bytes = vec![0; record_len(0, MapSourceReply::BYTES).unwrap()];
        encode(
            &mut bytes,
            HostFileHeader {
                op,
                table: [1, 2, 3],
                fd: 3,
                flags: 0,
                args: [0, 0x2000, 0, 0],
            },
            &[],
            MapSourceReply::BYTES,
        )
        .unwrap();
        let reply = MapSourceReply {
            handle: NonZeroU64::new(9).unwrap(),
            generation: NonZeroU64::MIN,
        }
        .encode();
        if replied {
            HostFileRequestView::parse(&mut bytes)
                .unwrap()
                .reply(0, &reply)
                .unwrap();
        }
        bytes
    }

    /// #1338: a source the host retained for a `MapShared` record is a
    /// shared file window once its reply is written, so its faults never
    /// copy bytes. Reading the replied record as a pending request answered
    /// "not a window" and retained it as a private copy: every store through
    /// the mapping was lost (KVM witness rows `linker_read_back`,
    /// `shared_child_write_in_pread`).
    #[test]
    fn replied_map_shared_record_retains_a_window_source() {
        use carrick_core_abi::host_file::HostFileOp;
        assert!(replied_map_source_is_window(&replied_map_record(HostFileOp::MapShared)).unwrap());
        assert!(
            !replied_map_source_is_window(&replied_map_record(HostFileOp::MapPrivate)).unwrap()
        );
        // A record with no reply, or of another operation, retains nothing.
        assert!(replied_map_source_is_window(&map_record(HostFileOp::MapShared, false)).is_err());
        assert!(replied_map_source_is_window(&replied_map_record(HostFileOp::Ftruncate)).is_err());
    }

    #[test]
    fn x86_prepare_candidates_continue_after_twelve_root_table_loans() {
        use carrick_hal::fork_stock::{ForkStock, UntaggedRoots};

        let carrier = NonZeroU64::MIN;
        let mm = carrick_el1_abi::ReservationMm::new(301).unwrap();
        let root = RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap();
        // SAFETY: this test owns the admitted initial root and its incarnation.
        let owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(carrier, mm, NonZeroU64::MIN)
        };
        let mut stock = ForkStock::<UntaggedRoots>::new(carrier, None, UntaggedRoots);
        stock
            .install(
                (1..=24)
                    .map(|page| RootGpa::page_aligned(FrameGpa::new(page * 4096)).unwrap())
                    .collect(),
                carrick_hal::fork_stock::TableReserve::EMPTY,
                Vec::new(),
            )
            .unwrap();
        stock.register_root(owner, root).unwrap();
        let mut loans = Vec::new();
        for _ in 0..13 {
            let offered = stock.descriptor_table_candidates();
            assert!(!offered.is_empty());
            loans.push(
                stock
                    .reserve_native_descriptor_tables(&mut NoTableLedger, owner, root, 1)
                    .unwrap(),
            );
        }
        assert_eq!(loans.len(), 13);
        assert_eq!(stock.table_stock().len(), 11);
    }
    /// #3017: the host's reserve is exactly the span the CPL0 editor
    /// licenses: from the occupied end up to the Prepare working suffix.
    #[test]
    fn initial_table_reserve_is_the_span_between_grants_and_working_tables() {
        let extent = carrick_core_abi::X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize;
        let occupied = 0x40_0000;
        let working = prepare_table_suffix(extent, occupied).unwrap();
        let reserve = initial_table_reserve(occupied, working).unwrap();
        let expected = (working.start().raw() - (INITIAL_EXTENT_GPA + occupied as u64)) / 4096;
        assert_eq!(reserve.pages() as u64, expected);
        assert!(
            expected > 100_000,
            "the window, not the image, bounds the tables"
        );
        assert!(initial_table_reserve(occupied + 1, working).is_none());
        let full = working.start().raw() - INITIAL_EXTENT_GPA;
        assert_eq!(
            initial_table_reserve(full as usize, working).map(|reserve| reserve.pages()),
            Some(0)
        );
    }
    #[test]
    fn native_backing_editor_exclusion_busy_once_then_success() {
        let layout = std::alloc::Layout::new::<X86Cpl0Zone>();
        // SAFETY: the atomic-only zone has a valid zero state and typed alignment.
        let zone = unsafe {
            let pointer = std::alloc::alloc_zeroed(layout).cast::<X86Cpl0Zone>();
            assert!(!pointer.is_null());
            Box::from_raw(pointer)
        };
        let index = zone.spaces.publish_closed(77, 0x1000, 0).unwrap();
        let access = SpaceAccess::source_free_with_context(&zone.spaces);
        access.open(index);
        let editor = access.try_begin_edit(index, 77, NonZeroU64::MIN).unwrap();
        assert!(matches!(
            return_settlement::unsettled_pause_for_test(access, 77),
            Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy)
        ));
        assert_eq!(
            zone.spaces.gate(index),
            0,
            "refusal must not close the editor's gate"
        );
        drop(editor);
        let pause = return_settlement::unsettled_pause_for_test(access, 77).unwrap();
        drop(pause);
        assert_eq!(zone.spaces.gate(index), 0);
    }

    /// The carrier's reschedule MSIs, as a host COW release sends them:
    /// recorded, or (`refuse`) refused like a failed `KVM_SIGNAL_MSI`.
    struct MsiLog {
        sent: std::sync::Mutex<Vec<(u32, u32)>>,
        refuse: bool,
    }
    impl CarrierMemoryIo for MsiLog {
        fn carrier_slot_limit(&self) -> Result<u32, carrick_hal::OsError> {
            Ok(0)
        }
        unsafe fn set_user_memory_region(
            &self,
            _: crate::carrier_memory::CarrierMemoryRegion,
        ) -> Result<(), carrick_hal::OsError> {
            Err(carrick_hal::OsError::new(
                "no carrier memory in this witness",
            ))
        }
        fn signal_msi(&self, address_lo: u32, data: u32) -> Result<(), carrick_hal::OsError> {
            if self.refuse {
                return Err(carrick_hal::OsError::new("refused witness MSI"));
            }
            self.sent.lock().unwrap().push((address_lo, data));
            Ok(())
        }
    }

    const UNPLACEABLE_MM: u64 = 302;
    const OWNER_SLOT: SlotId = SlotId::new(1);
    const OWNER_APIC: u8 = 7;

    /// #2925's shape, VM-free: a native member of `UNPLACEABLE_MM` parks on
    /// its MM's gate while two host COW exclusions hold it raised (a
    /// settlement's nested pause). The only driven CPU that may run the
    /// member is in the guest on another MM. The inner exclusion's release
    /// lowers the gate 2 -> 1 and wakes the member, but the gate is still
    /// raised, so no guest slot may take it: the release's
    /// `HostCowWake::deliver` gets it as a handback. Returns what `finish`
    /// reported, the member's claim after the release, and the MSIs sent.
    fn release_gate_over_an_unplaceable_member(
        refuse_msi: bool,
    ) -> (
        Result<(), TrapError>,
        carrick_sched_core::Claim,
        Vec<(u32, u32)>,
    ) {
        use carrick_sched_core::spaces::notification::{SpaceWaitCause, SpaceWakeDelivery};
        let layout = std::alloc::Layout::new::<X86Cpl0Zone>();
        // SAFETY: the atomic-only zone has a valid zero state and typed alignment.
        let zone = unsafe {
            let pointer = std::alloc::alloc_zeroed(layout).cast::<X86Cpl0Zone>();
            assert!(!pointer.is_null());
            Box::from_raw(pointer)
        };
        let routes = PublishedApicIds::new();
        assert!(routes.publish(
            carrick_guest_arch::CpuId::new(u32::from(OWNER_SLOT.raw())),
            PublishedApicId(OWNER_APIC),
        ));
        let wake = HostCowWake {
            routes: &routes,
            vm: Arc::new(MsiLog {
                sent: std::sync::Mutex::new(Vec::new()),
                refuse: refuse_msi,
            }),
            error: std::cell::RefCell::new(None),
        };
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        // A queue's own completions (its publications outside a release).
        let complete = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(&zone, Waker::Host, owned);
        // The member's ring owner: driven, in the guest, running another MM.
        zone.drive(OWNER_SLOT, 1);
        zone.publish_slot(
            OWNER_SLOT,
            UNPLACEABLE_MM + 1,
            Some(u32::from(OWNER_SLOT.raw())),
            0,
        );
        zone.enter_guest(OWNER_SLOT);
        let index = zone
            .spaces
            .publish_closed(UNPLACEABLE_MM, 0x7000, 0x7000)
            .unwrap();
        let entry = zone
            .space_entry(NonZeroU64::new(UNPLACEABLE_MM).unwrap())
            .unwrap();
        entry
            .admit_notifications(
                NonZeroU64::MIN,
                &carrick_sched_core::BoundedSpin(0),
                &complete,
            )
            .unwrap();
        let lease = entry.notifications(NonZeroU64::MIN).unwrap();
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: SpaceWakeDelivery::Captured(&delivery),
        });
        access.open(index);
        let outer = return_settlement::unsettled_pause_for_test(access, UNPLACEABLE_MM).unwrap();
        let pause = return_settlement::unsettled_pause_for_test(access, UNPLACEABLE_MM).unwrap();
        assert_eq!(zone.spaces.gate(index), 2);
        let member = zone
            .alloc_record(carrick_sched_core::ThreadIdentity {
                tid: 77,
                serial: 1,
                mm: UNPLACEABLE_MM,
                file_table: 1,
                generation: 1,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1 << OWNER_SLOT.raw(),
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        assert!(zone.mark_native_owned(member));
        let snapshot = lease.observe(SpaceWaitCause::Gate);
        zone.object_wait_with_completion(
            lease.key(SpaceWaitCause::Gate),
            &carrick_sched_core::BoundedSpin(0),
            &complete,
        )
        .unwrap()
        .park_rechecked(
            snapshot,
            member,
            carrick_sched_core::object_wait::OperationToken::new(77, 1).unwrap(),
            || true,
        )
        .unwrap();
        // The inner host COW release wakes the member under a raised gate.
        drop(pause);
        assert_eq!(zone.spaces.gate(index), 1);
        let finished = wake.finish();
        let claim = zone.record(member).claim();
        drop(outer);
        assert_eq!(zone.spaces.gate(index), 0);
        let sent = std::mem::take(&mut *wake.vm.sent.lock().unwrap());
        (finished, claim, sent)
    }

    /// #2925: a member the host COW release wakes but no guest slot can
    /// take goes back to its ring owner's queue, with that CPU's reschedule
    /// MSI, instead of failing the carrier with "native COW release produced
    /// unsupported host-home completion custody".
    #[test]
    fn host_cow_release_hands_an_unplaceable_member_back_to_its_ring_owner() {
        let (finished, claim, sent) = release_gate_over_an_unplaceable_member(false);
        assert!(finished.is_ok(), "host COW release failed: {finished:?}");
        assert!(
            matches!(claim, carrick_sched_core::Claim::Queued { slot, .. } if slot == OWNER_SLOT),
            "the member is queued on its ring owner: {claim:?}"
        );
        assert_eq!(
            sent,
            [(
                0xfee0_0000 | (u32::from(OWNER_APIC) << 12),
                u32::from(carrick_x86::interrupts::RESCHED_VECTOR),
            )],
            "one reschedule MSI to the owner's published APIC"
        );
    }

    /// A reschedule the carrier cannot deliver fails the release, rather
    /// than leaving the handed-back member behind a CPU nobody woke.
    #[test]
    fn host_cow_release_reports_a_failed_handback_msi() {
        let (finished, claim, sent) = release_gate_over_an_unplaceable_member(true);
        let error = finished.expect_err("a refused reschedule MSI is a carrier error");
        assert!(
            format!("{error:?}").contains("host wake MSI"),
            "the MSI refusal is reported: {error:?}"
        );
        assert!(
            matches!(claim, carrick_sched_core::Claim::Queued { slot, .. } if slot == OWNER_SLOT),
            "the member is still queued on its ring owner: {claim:?}"
        );
        assert!(sent.is_empty());
    }

    fn execution() -> GrantExecution {
        GrantExecution {
            cpu: carrick_guest_arch::CpuId::new(1),
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(42),
                generation: SnapshotGeneration::from_raw(12),
                mm: EntryMmKey::from_raw(302),
                thread_generation: EntryThreadGeneration::from_raw(102),
            },
            context: AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).unwrap(),
                mm: MmGeneration::new(NonZeroU64::new(302).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::new(17).unwrap()),
            },
        }
    }
    #[test]
    fn kernel_pod_transport_authenticates_declared_bootstrap_allocator_aperture() {
        use carrick_guest_arch::KernelVa;
        let storage = retained_kernel_pod_storage(&[]);
        let start = X86_CPL0_BOOTSTRAP_METADATA_BASE;
        assert_eq!(
            kernel_pod_physical(&storage, KernelVa::new(start + 0xff8), 64, 8),
            Some(FrameGpa::new(ALLOCATOR_GPA + 0xff8))
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(start - 8), 64, 8).is_none());
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(start + EL1_BOOTSTRAP_METADATA_SIZE - 32),
                64,
                8
            )
            .is_none()
        );
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_HEAP_OFFSET),
                64,
                8
            )
            .is_none()
        );
    }

    #[test]
    fn kernel_pod_storage_enforces_shared_supervisor_extent() {
        use carrick_mem::elf::{LoadSegment, SegmentPerms};
        let mut segment = LoadSegment {
            file_offset: 0,
            virtual_address: IMAGE_VA + IMAGE_SIZE - 4096,
            file_size: 0,
            memory_size: 4096,
            alignment: 4096,
            perms: SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
        };
        assert!(KernelPodStorage::from_load(&segment).is_some());
        segment.memory_size += 1;
        assert!(KernelPodStorage::from_load(&segment).is_none());
    }

    #[test]
    fn kernel_pod_transport_uses_exact_writable_elf_storage_not_virtual_alias_shape() {
        use carrick_guest_arch::KernelVa;
        use carrick_mem::elf::{LoadSegment, SegmentPerms};
        let segment = LoadSegment {
            file_offset: 0,
            virtual_address: IMAGE_VA + 0x70000,
            file_size: 0,
            memory_size: 0x3000,
            alignment: 4096,
            perms: SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
        };
        let writable = KernelPodStorage::from_load(&segment).unwrap();
        let storage = [writable];
        let address = KernelVa::new(segment.virtual_address + 0xff8);
        assert_eq!(
            kernel_pod_physical(&storage, address, 64, 8),
            Some(FrameGpa::new(IMAGE_GPA + 0x70ff8))
        );
        assert!(
            kernel_pod_physical(&storage, KernelVa::new(segment.virtual_address - 8), 64, 8)
                .is_none()
        );
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(segment.virtual_address + 0x2fe0),
                64,
                8
            )
            .is_none()
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(address.raw() + 1), 64, 8).is_none());
        assert!(
            kernel_pod_physical(&storage, KernelVa::new(DIRECT_VA + 0x900000), 64, 8).is_none()
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(u64::MAX - 7), 64, 8).is_none());
        assert!(
            KernelPodStorage::from_load(&LoadSegment {
                perms: SegmentPerms {
                    read: true,
                    write: true,
                    execute: true
                },
                ..segment
            })
            .is_none()
        );
        assert!(
            KernelPodStorage::from_load(&LoadSegment {
                perms: SegmentPerms {
                    read: true,
                    write: false,
                    execute: false
                },
                ..segment
            })
            .is_none()
        );
    }

    /// The real carrier boot stock, in the worst case the credits are sized for
    /// (the initial MM used its whole worst-case tables and its own COW
    /// branch), still serves the first fork's COW branch after the
    /// maintenance root is taken. Without the dedicated credit this loan
    /// was refused for capacity.
    #[test]
    fn real_boot_stock_serves_the_first_fork_after_the_maintenance_root() {
        use carrick_el1_abi::{
            ForkStockExchange, ForkStockRequest, PortalOperation, ReservationGeneration,
        };
        use carrick_hal::fork_stock::{ForkStock, UntaggedRoots};
        let data_pages = 2;
        let table_grants = super::initial_table_grant_count(data_pages).unwrap();
        let first_fork_branch = carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES;
        let used = table_grants - first_fork_branch - super::MAINTENANCE_ROOT_TABLE_CREDITS;
        let frame_offset = 0x3000;
        let unused: Vec<RootGpa> = (used..table_grants)
            .map(|index| {
                RootGpa::page_aligned(super::initial_grant_gpa(frame_offset, index)).unwrap()
            })
            .collect();
        let boot = boot_fork_stock(unused).unwrap();
        assert_eq!(boot.tables.len(), first_fork_branch);
        let mut metadata = vec![0u64; (META_LEN / 8) as usize];
        // SAFETY: the zeroed vector outlives every use of the window.
        let window = unsafe {
            LifecycleWindow::new(
                core::ptr::NonNull::new(metadata.as_mut_ptr().cast::<u8>()).unwrap(),
                METADATA_VA,
                META_LEN,
            )
        };
        assert!(boot.lifecycles.iter().all(|life| window.is_zero(*life)));
        let carrier = NonZeroU64::new(7).unwrap();
        let mut stock: ForkStock<UntaggedRoots, ()> = ForkStock::new(
            carrier,
            carrick_hal::fork_stock::ForkControlCapacity::unused(KERNEL_REGION_GPA),
            UntaggedRoots,
        );
        stock
            .install(
                boot.tables,
                carrick_hal::fork_stock::TableReserve::EMPTY,
                boot.lifecycles,
            )
            .unwrap();
        let exec = execution();
        let request = ForkStockRequest {
            binding: exec.binding,
            context: exec.context,
            operation: PortalOperation {
                carrier,
                mm: ReservationMm::new(302).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::new(2).unwrap(),
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_mm: ReservationMm::new(303).unwrap(),
            child_bytes: (first_fork_branch as u64 - 1) * 4096,
            parent_bytes: 4096,
        };
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let loan = stock
            .loan(&mut NoTableLedger, exec, &mut exchange, |life| {
                window.is_zero(life)
            })
            .unwrap();
        assert_eq!(exchange.take(request), Some(Ok(loan)));
        assert_eq!(stock.counters().loans, 1);
    }

    #[test]
    fn real_boot_layout_maintenance_root_is_admitted() {
        // The carrier takes the first unused initial table grant, staged in
        // the initial extent after the boot records.
        for (frame_offset, first_unused) in [(0x1000, 1), (0x3000, 4), (0x10_0000, 63)] {
            let root =
                RootGpa::page_aligned(initial_grant_gpa(frame_offset, first_unused)).unwrap();
            assert!(
                maintenance_root_admitted(root),
                "{frame_offset:#x}/{first_unused}"
            );
        }
        let outside = RootGpa::page_aligned(FrameGpa::new(
            carrick_core_abi::X86_CPL0_INITIAL_EXTENT_GPA
                + carrick_core_abi::X86_CPL0_INITIAL_EXTENT_MAX_SIZE,
        ))
        .unwrap();
        assert!(!maintenance_root_admitted(outside));
    }

    #[test]
    fn maintenance_root_copies_only_the_shared_supervisor_entries() {
        let mut initial = vec![0u8; 4096];
        for (index, word) in [
            (0usize, 0x1003u64),
            (255, 0x2003),
            (256, 0x3003),
            (508, 0x4003),
            (511, 0x5003),
        ] {
            initial[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        let root = root_words(&maintenance_root_page(&initial).unwrap()).unwrap();
        // User half and the MM-private COW copy branch stay zero.
        assert_eq!((root[0], root[255], root[508]), (0, 0, 0));
        assert_eq!((root[256], root[511]), (0x3003, 0x5003));
        // A shared entry published after the copy is detected.
        let live = root_words(&initial).unwrap();
        let mut changed = live;
        changed[300] = 0x6003;
        assert!(carrick_mmu_core::x86::owner_mmu::maintenance_root_matches(
            &live, &root
        ));
        assert!(!carrick_mmu_core::x86::owner_mmu::maintenance_root_matches(
            &changed, &root
        ));
        assert!(maintenance_root_page(&initial[..4088]).is_none());
    }

    #[test]
    fn production_physical_ports_do_not_alias_native_or_fixture_doorbells() {
        for (index, port) in CPL0_CARRIER_PORTS.iter().enumerate() {
            assert!(
                !CPL0_CARRIER_PORTS[..index].contains(port),
                "CPL0 carrier port {port:#x} is decoded twice"
            );
        }
        // The bhyve-only FP-stub doorbell shares its number with the
        // initial-boot port, which this carrier decodes exactly once.
        assert_eq!(
            carrick_x86::FP_STUB_DOORBELL_PORT,
            carrick_core_abi::X86_INITIAL_BOOT_PORT
        );
    }

    #[test]
    fn owner_grant_receipt_refuses_recycled_execution_or_root() {
        let admitted = execution();
        assert!(admitted.matches(admitted));
        let mut foreign = admitted;
        foreign.binding.task = EntryTaskKey::from_raw(43);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.generation = SnapshotGeneration::from_raw(13);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.mm = EntryMmKey::from_raw(303);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.thread_generation = EntryThreadGeneration::from_raw(103);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.cpu = carrick_guest_arch::CpuId::new(0);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.root = RootGpa::page_aligned(FrameGpa::new(0x8000)).unwrap();
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.generation = ContextGeneration::new(NonZeroU64::new(18).unwrap());
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.mm = MmGeneration::new(NonZeroU64::new(303).unwrap());
        assert!(!admitted.matches(foreign));
    }
    #[test]
    fn fork_physical_stock_requires_exact_disjoint_contiguous_capacity() {
        use carrick_hal::fork_stock::take_fork_table_stock;
        let page = |address| RootGpa::page_aligned(FrameGpa::new(address)).unwrap();
        let mut holes = vec![page(0x1000), page(0x3000), page(0x5000)];
        let before = holes.clone();
        assert!(take_fork_table_stock(&mut holes, 8192, 4096).is_none());
        assert_eq!(holes, before);
        let mut stock = vec![
            page(0x6000),
            page(0x2000),
            page(0x4000),
            page(0x1000),
            page(0x3000),
            page(0x5000),
        ];
        let (child, parent) = take_fork_table_stock(&mut stock, 12288, 8192).unwrap();
        assert_eq!(child.len(), 3);
        assert_eq!(parent.len(), 2);
        assert_eq!(stock.len(), 1);
        for arena in [&child, &parent] {
            assert!(
                arena
                    .windows(2)
                    .all(|pair| pair[1].address().raw() == pair[0].address().raw() + 4096)
            );
        }
        assert!(
            child
                .iter()
                .all(|frame| !parent.contains(frame) && !stock.contains(frame))
        );
        let mut alias = vec![page(0x1000), page(0x1000), page(0x2000)];
        assert!(take_fork_table_stock(&mut alias, 4096, 4096).is_none());
    }

    #[test]
    fn cow_physical_pause_releases_admitted_gate_through_owned_venue() {
        let layout = std::alloc::Layout::new::<X86Cpl0Zone>();
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        let zone = unsafe { Box::from_raw(pointer.cast::<X86Cpl0Zone>()) };
        let index = zone.spaces.publish_closed(302, 0x7000, 0x7000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(302).unwrap()).unwrap();
        entry
            .admit_notifications(
                NonZeroU64::MIN,
                &carrick_sched_core::BoundedSpin(0),
                &|owned| {
                    let _ = owned.deliver_handbacks(&mut |_| panic!("no enrolled waiters"));
                },
            )
            .unwrap();
        let calls = std::cell::Cell::new(0);
        let delivery = |_: &X86Cpl0Zone,
                        _: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            let _ = owned.deliver_handbacks(&mut |_| panic!("no enrolled waiters"));
            calls.set(calls.get() + 1);
        };
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        });
        access.open(index);
        let before = calls.get();
        let pause = return_settlement::unsettled_pause_for_test(access, 302).unwrap();
        assert_eq!(zone.spaces.gate(index), 1);
        drop(pause);
        assert_eq!(zone.spaces.gate(index), 0);
        assert_eq!(calls.get(), before + 1);
        let editor = access.try_begin_edit(index, 302, NonZeroU64::MIN).unwrap();
        assert!(return_settlement::unsettled_pause_for_test(access, 302).is_err());
        assert_eq!(zone.spaces.gate(index), 0);
        drop(editor);
    }
    #[test]
    fn cow_physical_exclusion_refuses_live_editor_and_reopens_after_settlement() {
        let pointer = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<X86Cpl0Zone>()) };
        assert!(!pointer.is_null());
        let zone = unsafe { Box::from_raw(pointer.cast::<X86Cpl0Zone>()) };
        let spaces = &zone.spaces;
        let delivery = |_: &X86Cpl0Zone,
                        _: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            let _ = owned.deliver_handbacks(&mut |_| panic!("no waiters"));
        };
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        });
        let index = spaces.publish_closed(302, 0x7000, 0x7000).unwrap();
        spaces.open(index);
        let editor = spaces.try_begin_edit(index, 302, NonZeroU64::MIN).unwrap();
        assert!(return_settlement::unsettled_pause_for_test(access, 302).is_err());
        drop(editor);
        let pause = return_settlement::unsettled_pause_for_test(access, 302).unwrap();
        assert_eq!(pause.proof().key(), 302);
        assert!(spaces.try_begin_edit(index, 302, NonZeroU64::MIN).is_none());
        drop(pause);
        assert!(spaces.try_begin_edit(index, 302, NonZeroU64::MIN).is_some());
    }

    #[test]
    fn cow_loan_refuses_source_alias_and_foreign_completion() {
        use carrick_el1_abi::{CowGrant, CowGrantCompletion, CowGrantPurpose};
        let grant = CowGrant {
            slot: 4,
            epoch: 8,
            mm_key: 302,
            physical_ipa: 0x10000,
            backing: BackingIdentity {
                frame_id: NonZeroU64::new(1).unwrap(),
                mapping_id: NonZeroU64::new(2).unwrap(),
                owner_generation: NonZeroU64::new(3).unwrap(),
                inventory_revision: NonZeroU64::new(4).unwrap(),
            },
            tables: Default::default(),
        };
        let source = FrameGpa::new(0x21000);
        let receipt = CowGrantCompletion {
            purpose: CowGrantPurpose::UserWrite,
            grant,
            span_va: 0x401000,
            span_len: 4096,
            old_ipa: source.raw(),
            new_ipa: 0x11000,
            tables_linked: 0,
        };
        assert!(exact_cow_receipt(grant, &receipt));
        let mut wrong = receipt;
        // Another offset in its compound than the replacement's.
        wrong.old_ipa = 0x32000;
        assert!(!exact_cow_receipt(grant, &wrong));
        let mut wrong = receipt;
        wrong.grant.mm_key += 1;
        assert!(!exact_cow_receipt(grant, &wrong));
        let mut wrong = receipt;
        wrong.grant.epoch += 8;
        assert!(!exact_cow_receipt(grant, &wrong));
        let mut wrong = receipt;
        wrong.new_ipa += 4096;
        assert!(!exact_cow_receipt(grant, &wrong));
        // The page is the receipt's own: any one page of the MM.
        let mut other_page = receipt;
        other_page.span_va += 4096;
        assert!(exact_cow_receipt(grant, &other_page));
        let mut wrong = receipt;
        wrong.span_va += 1;
        assert!(!exact_cow_receipt(grant, &wrong));
        let mut wrong = receipt;
        wrong.span_len = 8192;
        assert!(!exact_cow_receipt(grant, &wrong));
        let mut wrong = receipt;
        wrong.purpose = CowGrantPurpose::RetiredBacking;
        assert!(!exact_cow_receipt(grant, &wrong));
        let alias = CowGrant {
            physical_ipa: 0x20000,
            ..grant
        };
        let alias_receipt = CowGrantCompletion {
            grant: alias,
            new_ipa: source.raw(),
            ..receipt
        };
        assert!(!exact_cow_receipt(alias, &alias_receipt));
    }
    /// #2655: a fork near the measured `go` shape (3,081 inherited pages
    /// outside grant windows, 2,006 inside them) needs two rows per outside
    /// page and one per covering window. One segment refuses it.
    #[test]
    fn fork_residency_demand_counts_both_sides_and_admits_at_half_load() {
        let mut storage = Box::<carrick_el1_abi::FrameGrantResidencyTable>::new_uninit();
        // SAFETY: typed allocation supplies the complete table's alignment and size.
        let residency = unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(storage.as_mut_ptr());
            storage.assume_init()
        };
        let parent = 4u64;
        let window = |index: u64| carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: parent,
            semantic_base: 0x4000_0000 + index * 0x20_0000,
            physical_ipa: 0x1_0000_0000 + index * 0x20_0000,
            len: 0x20_0000,
            mapping_id: 100 + index,
            frame_id: 100 + index,
            owner_generation: 1,
            inventory_revision: 1,
        };
        for index in 0..15 {
            residency.publish(window(index)).unwrap();
        }
        // 2,006 pages inside the 15 windows, then 3,081 pages outside any.
        let covered = (0..2006u64).map(|page| 0x4000_0000 + page * 4096);
        let uncovered = (0..3081u64).map(|page| 0x40_0000 + page * 4096);
        let demand = ForkResidencyDemand::count(&residency, parent, covered.chain(uncovered));
        // 2,006 pages span windows 0..=3 only: four child window rows.
        assert_eq!(demand.rows, 2 * 3081 + 4);
        assert!(!demand.admitted(&residency));
        // Another MM's rows never count as this parent's coverage.
        assert_eq!(
            ForkResidencyDemand::count(&residency, parent + 1, [0x4000_0000].into_iter()).rows,
            2
        );
        let empty = ForkResidencyDemand::count(&residency, parent, core::iter::empty());
        assert_eq!(empty.rows, 0);
        assert!(empty.admitted(&residency));
        // Exactly half full admits; one more row does not.
        let half = carrick_el1_abi::FRAME_GRANT_RESIDENCY_SLOTS / 2 - 15;
        assert!(ForkResidencyDemand { rows: half }.admitted(&residency));
        assert!(!ForkResidencyDemand { rows: half + 1 }.admitted(&residency));
    }

    #[test]
    fn refused_fork_retires_only_its_new_parent_residency_rows() {
        let mut storage = Box::<carrick_el1_abi::FrameGrantResidencyTable>::new_uninit();
        // SAFETY: typed allocation supplies the complete table's alignment and size.
        let residency = unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(storage.as_mut_ptr());
            storage.assume_init()
        };
        let existing = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: 301,
            semantic_base: 0x400000,
            physical_ipa: 0x800000,
            len: 4096,
            mapping_id: 1,
            frame_id: 1,
            owner_generation: 1,
            inventory_revision: 1,
        };
        residency.publish(existing).unwrap();
        let added = carrick_el1_abi::FrameGrantResidencyIdentity {
            semantic_base: 0x401000,
            physical_ipa: 0x801000,
            mapping_id: 2,
            frame_id: 2,
            ..existing
        };
        let slot = residency.publish(added).unwrap();
        let page = residency.lookup(added.mm_key, added.semantic_base).unwrap();
        assert!(residency.record_commit(page));
        rollback_fork_parent_residency(&residency, &[(slot, added)]).unwrap();
        assert!(
            residency
                .lookup(added.mm_key, added.semantic_base)
                .is_none()
        );
        assert_eq!(
            residency
                .lookup(existing.mm_key, existing.semantic_base)
                .unwrap()
                .identity,
            existing
        );
        assert!(residency.publish(added).is_some());
    }
}

#[path = "cpl0_native_service.rs"]
pub(super) mod native_service;

#[path = "cpl0_return_settlement.rs"]
mod return_settlement;
use return_settlement::CowPause;
pub use return_settlement::ReturnSettlementCounters;
#[cfg(feature = "test-support")]
pub use return_settlement::{OwedReturnHolderHold, OwedReturnHolderRelease};
