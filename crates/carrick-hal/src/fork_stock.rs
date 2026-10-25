//! Carrier custody of in-kernel fork stock, shared by every guest ISA.
//!
//! A guest kernel forks without a host process: a stopped CPU borrows
//! physical page-table pages and one lifecycle record from this custody
//! through the ISA-neutral fork-stock crossing (`HVC #6` on AArch64, port I/O
//! on x86), settles the loan (commit or abort), and later retires the child's
//! memory with [`NativeChildRetire`]. Retired stock enters QUARANTINE and only
//! returns to the reusable stock once
//!
//! 1. the retiring MM is not the MM of the CPU servicing the reclaim,
//! 2. the carrier proves no zone slot has that MM installed, and
//! 3. its tables and lifecycle record have been cleared and its address tag
//!    (the AArch64 ASID) retired with its TLB invalidation acknowledged.
//!
//! Every ISA and host shares this one state machine. A carrier supplies only
//! its mechanics: the child address tag ([`ChildAddressTags`]), the grant
//! accounting of loaned table pages ([`ForkTableLedger`]), and the physical
//! closures that check, clear and observe guest memory.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use carrick_el1_abi::{
    ChildRetireRefusal, ExecutionBinding, ForkLifecycleLoan, ForkStockExchange, ForkStockLoan,
    ForkStockRefusal, ForkStockSettlement, NativeChildRetire, ReservationMm,
};
use carrick_guest_arch::{AddressContext, Asid, CpuId, RootGpa};

use crate::asid::{AsidAllocator, AsidError, AsidGeneration};

/// Strong custody of an opaque byte source, independent of its original MM.
/// The implementing source owner authenticates the handle and generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostBackingRead {
    identity: carrick_el1_abi::HostBackingIdentity,
    length: usize,
}
impl HostBackingRead {
    pub fn new(identity: carrick_el1_abi::HostBackingIdentity, length: usize) -> Option<Self> {
        (length != 0
            && length as u64 <= carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
            && identity.advance(length as u64).is_some())
        .then_some(Self { identity, length })
    }
    pub fn identity(self) -> carrick_el1_abi::HostBackingIdentity {
        self.identity
    }
    pub fn length(self) -> usize {
        self.length
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostBackingReadError {
    Inaccessible,
    Stale,
    Unavailable,
}

pub trait HostBackingRetention: Send + Sync {
    fn identity(&self) -> carrick_el1_abi::HostBackingIdentity;
    /// Returns a bounded readable prefix; no bytes beyond a backing fault are supplied.
    fn read(&self, request: HostBackingRead) -> Result<Vec<u8>, HostBackingReadError>;
}

/// Sources inherited from an exact, live committed child. Source identities
/// belong to byte custody, never to the resident-frame inventory.
#[derive(Default, Clone)]
pub struct ForkHostBackingCustody {
    sources: BTreeMap<(NonZeroU64, NonZeroU64), std::sync::Arc<dyn HostBackingRetention>>,
}
impl ForkHostBackingCustody {
    pub fn inherit(&mut self, source: std::sync::Arc<dyn HostBackingRetention>) {
        let identity = source.identity();
        self.sources
            .insert((identity.handle(), identity.generation()), source);
    }

    pub fn retain(
        &self,
        identity: carrick_el1_abi::HostBackingIdentity,
        owner: impl FnOnce() -> Option<std::sync::Arc<dyn HostBackingRetention>>,
    ) -> Option<std::sync::Arc<dyn HostBackingRetention>> {
        let matches = |source: &std::sync::Arc<dyn HostBackingRetention>| {
            let retained = source.identity();
            retained.handle() == identity.handle() && retained.generation() == identity.generation()
        };
        self.sources
            .get(&(identity.handle(), identity.generation()))
            .cloned()
            .or_else(|| owner().filter(matches))
    }
}
pub use carrick_observability::compat::{
    ForkAdmissionRefusal, ForkCapacityResource, ForkQuarantineState,
};

#[derive(Debug, Default)]
struct QuarantinedChild {
    released: bool,
    absent: bool,
}

/// Bytes in one loaned page-table page.
const TABLE_PAGE_BYTES: u64 = 4096;
const CONTROL_WINDOW_BYTES: u64 = carrick_el1_abi::AARCH64_KERNEL_CONTROL_SIZE as u64;

/// Physical control capacity is exclusive when the ISA copies a supervisor
/// control window. x86 has no such alias; its nonzero wire base is unused by
/// the shared fork walk and therefore consumes no physical control stock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum ControlKind {
    Exclusive,
    Unused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ForkControlCapacity {
    base: u64,
    kind: ControlKind,
}

impl ForkControlCapacity {
    fn exclusive(base: u64) -> Option<Self> {
        (base != 0
            && base.is_multiple_of(CONTROL_WINDOW_BYTES)
            && base.checked_add(CONTROL_WINDOW_BYTES).is_some())
        .then_some(Self {
            base,
            kind: ControlKind::Exclusive,
        })
    }

    pub fn unused(wire_base: u64) -> Option<Self> {
        (wire_base != 0
            && wire_base.is_multiple_of(CONTROL_WINDOW_BYTES)
            && wire_base.checked_add(CONTROL_WINDOW_BYTES).is_some())
        .then_some(Self {
            base: wire_base,
            kind: ControlKind::Unused,
        })
    }

    pub fn base(self) -> u64 {
        self.base
    }

    fn is_exclusive(self) -> bool {
        self.kind == ControlKind::Exclusive
    }
}

/// Admitted CPU execution context for physical grant authentication.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GrantExecution {
    pub cpu: CpuId,
    pub binding: ExecutionBinding,
    pub context: AddressContext<RootGpa>,
}

impl GrantExecution {
    pub fn new(cpu: CpuId, binding: ExecutionBinding, context: AddressContext<RootGpa>) -> Self {
        Self {
            cpu,
            binding,
            context,
        }
    }

    pub fn matches(self, current: Self) -> bool {
        self.cpu == current.cpu
            && self.binding == current.binding
            && self.context == current.context
    }
}

/// Errors returned by the fork-stock service.
#[derive(Debug, PartialEq, Eq)]
pub enum ForkStockServiceError {
    NoPendingLoan,
    StaleExecution,
    LoanMismatch,
    ExposedDirtyTable,
    InvalidRecord,
    MemoryAccessFailed,
    Asid(AsidError),
    /// Quarantined stock is waiting, but the carrier holds no zone
    /// occupancy authority to prove its MM runs nowhere.
    OccupancyUnavailable,
    /// The exact live child has no reusable authenticated table stock.
    DescriptorTableCapacity,
}

/// Per-child address-space tag. AArch64 tags every forked root with a
/// carrier ASID; x86 CPL0 runs without PCID and needs none.
pub trait ChildAddressTags {
    type Tag: Copy + core::fmt::Debug + Eq;
    /// `None` when every tag is live or awaiting invalidation.
    fn allocate(&mut self) -> Option<Self::Tag>;
    /// The architectural tag the guest installs with the child root.
    fn wire(tag: Self::Tag) -> Option<Asid>;
    /// Return a tag no translation was ever published under.
    fn release_unpublished(&mut self, tag: Self::Tag) -> Result<(), ForkStockServiceError>;
    /// Retire a published tag. `absence` proves no slot still has the MM
    /// installed, which (installers invalidate before publishing absence)
    /// is the TLB-invalidation acknowledgement for its tag.
    fn retire(
        &mut self,
        tag: ChildTag<Self::Tag>,
        absence: SlotAbsence,
    ) -> Result<(), ForkStockServiceError>;
}

/// A child's address tag bound to the MM it was committed for. Only the
/// stock mints one (at commit), so an absence proof for one MM can never
/// retire the tag of another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildTag<T> {
    tag: T,
    mm: ReservationMm,
}

impl<T: Copy> ChildTag<T> {
    pub(crate) fn bind(tag: T, mm: ReservationMm) -> Self {
        Self { tag, mm }
    }

    pub fn tag(&self) -> T {
        self.tag
    }

    pub fn mm(&self) -> ReservationMm {
        self.mm
    }

    /// The tag, when `absence` proves this tag's own MM absent.
    pub fn discharged_by(&self, absence: &SlotAbsence) -> Option<T> {
        (absence.mm() == self.mm).then_some(self.tag)
    }
}

impl ChildAddressTags for AsidAllocator {
    type Tag = AsidGeneration;

    fn allocate(&mut self) -> Option<AsidGeneration> {
        AsidAllocator::allocate(self).ok()
    }

    fn wire(tag: AsidGeneration) -> Option<Asid> {
        Some(tag.asid())
    }

    fn release_unpublished(&mut self, tag: AsidGeneration) -> Result<(), ForkStockServiceError> {
        AsidAllocator::release_unpublished(self, tag).map_err(ForkStockServiceError::Asid)
    }

    fn retire(
        &mut self,
        tag: ChildTag<AsidGeneration>,
        absence: SlotAbsence,
    ) -> Result<(), ForkStockServiceError> {
        self.retire_absent(tag, absence)
            .map_err(ForkStockServiceError::Asid)
    }
}

/// Address-space tags for a carrier whose roots carry none (x86 CPL0
/// without PCID: every CR3 load drains non-global translations).
#[derive(Clone, Copy, Debug, Default)]
pub struct UntaggedRoots;

impl ChildAddressTags for UntaggedRoots {
    type Tag = ();

    fn allocate(&mut self) -> Option<()> {
        Some(())
    }

    fn wire((): ()) -> Option<Asid> {
        None
    }

    fn release_unpublished(&mut self, (): ()) -> Result<(), ForkStockServiceError> {
        Ok(())
    }

    fn retire(
        &mut self,
        tag: ChildTag<()>,
        absence: SlotAbsence,
    ) -> Result<(), ForkStockServiceError> {
        tag.discharged_by(&absence)
            .ok_or(ForkStockServiceError::InvalidRecord)
    }
}

/// Proof, from the carrier's zone occupancy authority, that no execution
/// slot has an MM installed. Guest installers switch to the maintenance root
/// and invalidate before publishing absence, so this is also the TLB
/// acknowledgement a retired address tag needs. Only [`Self::scan`] mints it.
#[derive(Debug, Eq, PartialEq)]
pub struct SlotAbsence {
    mm: ReservationMm,
}

impl SlotAbsence {
    /// `installed` is every slot's installed space; `None` if any names `mm`.
    pub fn scan(mm: ReservationMm, installed: impl IntoIterator<Item = u64>) -> Option<Self> {
        installed
            .into_iter()
            .all(|space| space != mm.raw())
            .then_some(Self { mm })
    }

    pub fn mm(&self) -> ReservationMm {
        self.mm
    }
}

/// Execution venue for a quarantine drain. A maintenance venue has no active
/// guest MM; it is admitted only after the live hardware root matches the
/// carrier's retained maintenance root. All-slot absence is still required.
#[derive(Clone, Copy, Debug)]
pub struct ReclaimExecution {
    active: Option<ReservationMm>,
}
impl From<ReservationMm> for ReclaimExecution {
    fn from(active: ReservationMm) -> Self {
        Self {
            active: Some(active),
        }
    }
}
impl ReclaimExecution {
    pub fn maintenance_root(live: RootGpa, maintenance: RootGpa) -> Option<Self> {
        (maintenance.address().raw() != 0 && live == maintenance).then_some(Self { active: None })
    }
}

/// Grant accounting for loaned table pages, charged to the borrowing MM.
pub trait ForkTableLedger {
    /// False refuses the grant; nothing was charged for `page`.
    fn grant(&mut self, page: RootGpa, mm: ReservationMm) -> bool;
    fn give_back(&mut self, page: RootGpa, mm: ReservationMm);
}

/// A carrier that keeps no separate grant ledger for fork tables.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTableLedger;

impl ForkTableLedger for NoTableLedger {
    fn grant(&mut self, _: RootGpa, _: ReservationMm) -> bool {
        true
    }

    fn give_back(&mut self, _: RootGpa, _: ReservationMm) {}
}

/// Byte stride between lifecycle slots; each slot holds the 4 KiB lifecycle
/// page and, [`LIFECYCLE_CONTROLS_OFFSET`] above it, the thread controls.
pub const LIFECYCLE_SLOT_STRIDE: u64 = 0x4000;
/// Offset of a slot's thread control array from its lifecycle page.
pub const LIFECYCLE_CONTROLS_OFFSET: u64 = 0x1000;

/// `count` lifecycle slots starting at `first_page` inside the metadata
/// aperture at `aperture`. Every carrier uses this one slot shape.
pub fn lifecycle_slots(
    aperture: u64,
    first_page: u64,
    count: u64,
) -> Option<Vec<ForkLifecycleLoan>> {
    (0..count)
        .map(|slot| {
            let page = first_page.checked_add(slot.checked_mul(LIFECYCLE_SLOT_STRIDE)?)?;
            ForkLifecycleLoan::new_for_base(
                aperture,
                carrick_guest_arch::KernelVa::new(page),
                carrick_guest_arch::KernelVa::new(page.checked_add(LIFECYCLE_CONTROLS_OFFSET)?),
            )
        })
        .collect()
}

/// The one lifecycle hygiene policy every carrier implements: an issued
/// record must be proven cold (all zero) and a returned record is cleared
/// before it reenters the stock. A dirty record at loan time is withdrawn.
pub trait LifecycleHygiene {
    fn is_zero(&self, lifecycle: ForkLifecycleLoan) -> bool;
    fn clear(&self, lifecycle: ForkLifecycleLoan) -> bool;
}

impl LifecycleHygiene for LifecycleWindow {
    fn is_zero(&self, lifecycle: ForkLifecycleLoan) -> bool {
        LifecycleWindow::is_zero(*self, lifecycle)
    }
    fn clear(&self, lifecycle: ForkLifecycleLoan) -> bool {
        LifecycleWindow::clear(*self, lifecycle)
    }
}

/// Host view of a guest metadata window that holds lifecycle records, so a
/// carrier can prove an issued record is cold storage and clear a returned
/// one before it reenters the stock.
#[derive(Clone, Copy, Debug)]
pub struct LifecycleWindow {
    host: core::ptr::NonNull<u8>,
    va: u64,
    len: u64,
}

/// Prepared control aliases of one cold lifecycle loan. The carrier retains
/// the underlying metadata mapping through the loan and its eventual reclaim.
#[must_use = "publish aliases only after the matching loan is accepted"]
pub struct PreparedLifecycleAffinity {
    controls: core::ptr::NonNull<carrick_el1_abi::ThreadControlSlot>,
    guest_controls: carrick_guest_arch::GuestVa,
    count: usize,
}
impl PreparedLifecycleAffinity {
    /// Publish only after the owner accepted the matching loan. No fallible
    /// operation remains: preparation checked the entire retained array.
    pub fn publish(self) {
        let stride = core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>();
        for index in 0..self.count {
            // SAFETY: preparation checked the complete aligned control array;
            // the carrier's stock custody retains its mapping through reclaim.
            let control = unsafe { &*self.controls.as_ptr().add(index) };
            let guest = carrick_guest_arch::GuestVa::new(
                self.guest_controls.raw() + (index * stride) as u64,
            );
            // SAFETY: LifecycleWindow licenses these host/guest aliases of the
            // same retained allocation, including the complete authority cell.
            unsafe {
                control.publish_affinity_aliases(guest);
            }
        }
    }
}

impl LifecycleWindow {
    /// # Safety
    /// `host` must remain valid for reads and writes of `len` bytes while
    /// this window or any derived alias-publication token/source is used,
    /// and must back guest kernel VAs `va..va + len`.
    pub unsafe fn new(host: core::ptr::NonNull<u8>, va: u64, len: u64) -> Self {
        Self { host, va, len }
    }

    fn ranges(self, lifecycle: ForkLifecycleLoan) -> Option<[(*mut u8, usize); 2]> {
        let range = |va: u64, len: usize| -> Option<(*mut u8, usize)> {
            let start = va.checked_sub(self.va)?;
            if start.checked_add(u64::try_from(len).ok()?)? > self.len {
                return None;
            }
            // SAFETY: the constructor licensed `len` host bytes at `host`.
            let ptr = unsafe { self.host.as_ptr().add(usize::try_from(start).ok()?) };
            Some((ptr, len))
        };
        let controls = core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>()
            * (carrick_el1_abi::THREAD_POOL_ENTRIES + 1);
        Some([
            range(
                lifecycle.page.raw(),
                core::mem::size_of::<carrick_el1_abi::ThreadLifecyclePage>(),
            )?,
            range(lifecycle.controls.raw(), controls)?,
        ])
    }

    /// Prepare an infallible alias publication from cold retained storage.
    /// Preparation itself writes nothing, so a refused loan remains cold.
    pub fn prepare_affinity_aliases(
        self,
        lifecycle: ForkLifecycleLoan,
    ) -> Option<PreparedLifecycleAffinity> {
        let ranges = self.ranges(lifecycle)?;
        let (controls, len) = ranges[1];
        let stride = core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>();
        if !controls
            .addr()
            .is_multiple_of(core::mem::align_of::<carrick_el1_abi::ThreadControlSlot>())
            || !len.is_multiple_of(stride)
            || lifecycle
                .page
                .raw()
                .checked_add(core::mem::size_of::<carrick_el1_abi::ThreadLifecyclePage>() as u64)?
                > lifecycle.controls.raw()
        {
            return None;
        }
        lifecycle.controls.raw().checked_add(len as u64)?;
        if !self.is_zero(lifecycle) {
            return None;
        }
        Some(PreparedLifecycleAffinity {
            controls: core::ptr::NonNull::new(controls.cast())?,
            guest_controls: carrick_guest_arch::GuestVa::new(lifecycle.controls.raw()),
            count: len / stride,
        })
    }

    /// True when the record's page and controls are all zero.
    pub fn is_zero(self, lifecycle: ForkLifecycleLoan) -> bool {
        self.ranges(lifecycle).is_some_and(|ranges| {
            ranges.iter().all(|(ptr, len)| {
                // SAFETY: in-window bytes; the record is unexposed while
                // its custody is decided by a stopped CPU.
                unsafe { core::slice::from_raw_parts(*ptr, *len) }
                    .iter()
                    .all(|byte| *byte == 0)
            })
        })
    }

    /// Zero the record when none of its thread control slots is still
    /// referenced by the process graph. False when it lies outside the window
    /// or any control slot is still graph-referenced.
    pub fn clear(self, lifecycle: ForkLifecycleLoan) -> bool {
        self.ranges(lifecycle).is_some_and(|ranges| {
            let (controls_ptr, controls_len) = ranges[1];
            let slot_size = core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>();
            if !controls_ptr
                .addr()
                .is_multiple_of(core::mem::align_of::<carrick_el1_abi::ThreadControlSlot>())
                || !controls_len.is_multiple_of(slot_size)
            {
                return false;
            }
            // SAFETY: `ranges` verified the control array lies within the
            // retained metadata window and the pointer is aligned for
            // `ThreadControlSlot`, whose fields are all atomic.
            let controls = unsafe {
                core::slice::from_raw_parts(
                    controls_ptr.cast::<carrick_el1_abi::ThreadControlSlot>(),
                    controls_len / slot_size,
                )
            };
            // Hold every exclusive reservation until the entire record has
            // been scrubbed. Any concurrent retain fails while these guards
            // exist; a failed reservation drops those already acquired.
            let Some(_resets) = controls
                .iter()
                .map(|control| control.reserve_reset_for_reclaim().ok())
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            for (ptr, len) in ranges {
                // SAFETY: in-window bytes of a record no live task or graph
                // entry references.
                unsafe { core::ptr::write_bytes(ptr, 0, len) };
            }
            true
        })
    }
}

/// Release the carrier-wide per-MM state a fork child held once it leaves
/// quarantine: every frame-inventory mapping (frames no other MM maps
/// retire) and every COW residency row keyed by the MM. Root-registry and
/// memslot custody stay with the carrier's own memory owner.
pub fn release_child_mm(
    inventory: &dyn crate::PhysicalFrameInventory,
    residency: &carrick_el1_abi::FrameGrantResidencyTable,
    mm: ReservationMm,
) -> bool {
    let Some(generation) = NonZeroU64::new(mm.raw()).map(carrick_guest_arch::MmGeneration::new)
    else {
        return false;
    };
    inventory.retire_mm(generation).is_ok() && residency.retire_overlapping(mm.raw(), 0, u64::MAX)
}

/// Ordered key of one MM in carrier custody.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MmKey(NonZeroU64);

impl MmKey {
    fn of(mm: ReservationMm) -> Option<Self> {
        NonZeroU64::new(mm.raw()).map(Self)
    }

    fn mm(self) -> Option<ReservationMm> {
        ReservationMm::new(self.0.get())
    }
}

/// Admitted physical custody reserved for a pending fork loan during
/// preparation, before child publication. Consumed infallibly when the
/// child commits, or dropped on abort to release its physical pins.
#[derive(Debug)]
pub struct AdmittedForkCustody<C> {
    loan_id: NonZeroU64,
    child_key: MmKey,
    parent_key: MmKey,
    child_used: usize,
    parent_used: usize,
    completion: carrick_el1_abi::PortalForkCompletion,
    physical: C,
}

impl<C> AdmittedForkCustody<C> {
    pub fn completion(&self) -> carrick_el1_abi::PortalForkCompletion {
        self.completion
    }

    pub fn physical(&self) -> &C {
        &self.physical
    }
}

/// Outstanding physical loan held by one stopped CPU.
#[derive(Debug)]
pub struct PendingForkLoan<T, C = ()> {
    pub loan: ForkStockLoan,
    pub execution: GrantExecution,
    pub child_tables: Vec<RootGpa>,
    pub parent_tables: Vec<RootGpa>,
    pub lifecycle: ForkLifecycleLoan,
    pub control: ForkControlCapacity,
    pub tag: T,
    admitted: Option<AdmittedForkCustody<C>>,
}

impl<T, C> PendingForkLoan<T, C> {
    pub fn admitted_custody(&self) -> Option<&AdmittedForkCustody<C>> {
        self.admitted.as_ref()
    }
}

/// A settled child whose memory is live in the guest owner graph.
#[derive(Debug)]
struct CommittedChild<T, C> {
    owner: carrick_el1_abi::El1MmHandle,
    root: RootGpa,
    lifecycle: ForkLifecycleLoan,
    control: ForkControlCapacity,
    tag: ChildTag<T>,
    /// Carrier authenticated physical allocations inherited by this MM.
    /// They stay pinned through quarantine and drop only after neutral release.
    physical: C,
}

/// Exact predecessor custody retained after an exec owner atomically moves a
/// child to its successor MM.  The old tables, address tag, and physical pins
/// remain unavailable until the execution venue proves that no CPU still has
/// the predecessor installed.
#[derive(Debug)]
struct ExecPredecessor<T, C> {
    predecessor: ReservationMm,
    successor: ReservationMm,
    tag: ChildTag<T>,
    tables: Vec<RootGpa>,
    physical: C,
    released: bool,
}

/// One-shot identity for settling an exec predecessor after the ring has
/// switched translation and invalidated the old address tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecPredecessorReceipt<T> {
    sequence: NonZeroU64,
    predecessor: ReservationMm,
    successor: ReservationMm,
    successor_tag: T,
}

impl<T: Copy> ExecPredecessorReceipt<T> {
    pub const fn predecessor(self) -> ReservationMm {
        self.predecessor
    }

    pub const fn successor(self) -> ReservationMm {
        self.successor
    }

    pub const fn successor_tag(self) -> T {
        self.successor_tag
    }
}

/// Monotonic counters for diagnostics and the counted-`EAGAIN` contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForkStockCounters {
    /// Loans granted.
    pub loans: u64,
    /// Loans refused for capacity (the guest lowers each to `EAGAIN`).
    pub capacity_refusals: u64,
    /// Native backing supplies refused because fewer than one bounded grant
    /// set remained; the carrier stays live and the stock is unchanged.
    pub descriptor_capacity_refusals: u64,
    /// Loans refused because the request named another execution or carrier.
    pub stale_refusals: u64,
    /// Loans refused for a malformed request or loan geometry.
    pub invalid_refusals: u64,
    /// Loans refused because the issued lifecycle record was not cold.
    pub inventory_refusals: u64,
    /// Children retired into quarantine.
    pub quarantined_children: u64,
    /// Child retirements refused with a typed reply (stock stays charged).
    pub retire_refusals: u64,
    /// Lifecycle records found dirty at loan time and withdrawn for good.
    pub withdrawn_lifecycles: u64,
    /// Quarantined children whose stock returned to the reusable pool.
    pub returned_children: u64,
    /// Reclaim attempts that left a child quarantined because its release,
    /// clear or tag retirement failed; the next drain retries it.
    pub reclaim_deferrals: u64,
}

impl ForkStockCounters {
    /// Nonzero counters by stable family name, for run reports: every
    /// refused fork is attributable to its typed reason.
    pub fn families(&self) -> Vec<(&'static str, u64)> {
        [
            ("loan", self.loans),
            ("capacity_refusal", self.capacity_refusals),
            (
                "descriptor_capacity_refusal",
                self.descriptor_capacity_refusals,
            ),
            ("stale_refusal", self.stale_refusals),
            ("invalid_refusal", self.invalid_refusals),
            ("inventory_refusal", self.inventory_refusals),
            ("withdrawn_lifecycle", self.withdrawn_lifecycles),
            ("quarantined_child", self.quarantined_children),
            ("retire_refusal", self.retire_refusals),
            ("returned_child", self.returned_children),
            ("reclaim_deferral", self.reclaim_deferrals),
        ]
        .into_iter()
        .filter(|(_, count)| *count != 0)
        .collect()
    }
}

/// Deterministic table allocator: contiguous 4 KiB runs for child and parent.
pub fn take_fork_table_stock(
    stock: &mut Vec<RootGpa>,
    child_bytes: u64,
    parent_bytes: u64,
) -> Option<(Vec<RootGpa>, Vec<RootGpa>)> {
    if child_bytes == 0
        || parent_bytes == 0
        || !child_bytes.is_multiple_of(TABLE_PAGE_BYTES)
        || !parent_bytes.is_multiple_of(TABLE_PAGE_BYTES)
    {
        return None;
    }
    let child = usize::try_from(child_bytes / TABLE_PAGE_BYTES).ok()?;
    let parent = usize::try_from(parent_bytes / TABLE_PAGE_BYTES).ok()?;
    if stock.len() < child.checked_add(parent)? {
        return None;
    }
    let mut available = stock.clone();
    available.sort_unstable_by_key(|page| page.address().raw());
    if available.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    fn take_run(pages: &mut Vec<RootGpa>, count: usize) -> Option<Vec<RootGpa>> {
        let start = pages.windows(count).position(|run| {
            run.windows(2).all(|pair| {
                pair[0].address().raw().checked_add(TABLE_PAGE_BYTES)
                    == Some(pair[1].address().raw())
            })
        })?;
        Some(pages.drain(start..start + count).collect())
    }
    let (child_tables, parent_tables) = if child >= parent {
        let child_tables = take_run(&mut available, child)?;
        (child_tables, take_run(&mut available, parent)?)
    } else {
        let parent_tables = take_run(&mut available, parent)?;
        (take_run(&mut available, child)?, parent_tables)
    };
    *stock = available;
    Some((child_tables, parent_tables))
}

/// Runtime reservation of root-table arenas from the carrier's existing
/// stage-1 slot allocator. Holding it excludes those arenas from host-created
/// address spaces; the backend retains it for the entire stock lifetime.
pub trait NativeForkTableReservation: core::fmt::Debug + Send + Sync {
    fn arenas(&self) -> &[RootGpa];
}

/// Existing runtime table reservation and physical inventory for one carrier.
/// The backend retains both until all fork stock and quarantined children end.
pub struct NativeForkStockResources {
    pub tables: std::sync::Arc<dyn NativeForkTableReservation>,
    pub inventory: std::sync::Arc<dyn crate::PhysicalFrameInventory>,
}

/// Authenticated table pages removed from reusable fork stock for one live
/// native child. Only [`ForkStock::reserve_native_descriptor_tables`] creates
/// this value, so a descriptor transaction cannot substitute data frames for
/// EL1-reachable page-table frames.
#[must_use = "submit and commit the reservation, or cancel it back to fork stock"]
pub struct NativeDescriptorTableReservation {
    key: MmKey,
    mm: ReservationMm,
    root: RootGpa,
    pages: Vec<RootGpa>,
    descriptor_tables: carrick_mmu_core::aarch64::descriptor_txn::TableGrants,
}

#[derive(Debug)]
struct PendingNativeDescriptorTables {
    mm: ReservationMm,
    root: RootGpa,
    pages: Vec<RootGpa>,
    txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
}

impl NativeDescriptorTableReservation {
    /// The descriptor executor's bounded table-grant record.
    pub fn descriptor_tables(&self) -> carrick_mmu_core::aarch64::descriptor_txn::TableGrants {
        self.descriptor_tables
    }

    pub fn pages(&self) -> &[RootGpa] {
        &self.pages
    }
}
impl NativeForkStockResources {
    /// True when both resource bundles name the same carrier's reserved
    /// fork-table arenas and physical frame inventory.
    pub fn matches(&self, other: &Self) -> bool {
        self.tables.arenas() == other.tables.arenas()
            && std::sync::Arc::ptr_eq(&self.inventory, &other.inventory)
    }
}
impl core::fmt::Debug for NativeForkStockResources {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeForkStockResources")
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

/// The carrier's bounded fork stock, pending loans and child quarantine.
#[derive(Debug)]
pub struct ForkStock<T: ChildAddressTags, C = ()> {
    carrier: NonZeroU64,
    controls: Vec<ForkControlCapacity>,
    unused_control: Option<ForkControlCapacity>,
    tables: Vec<RootGpa>,
    lifecycles: Vec<ForkLifecycleLoan>,
    pending: Vec<Option<PendingForkLoan<T::Tag, C>>>,
    next_loan: NonZeroU64,
    next_exec_predecessor: NonZeroU64,
    children: BTreeMap<MmKey, CommittedChild<T::Tag, C>>,
    exec_predecessors: BTreeMap<NonZeroU64, ExecPredecessor<T::Tag, C>>,
    /// Table pages each live MM consumed, as a child or as a fork parent.
    committed_tables: BTreeMap<MmKey, Vec<RootGpa>>,
    /// Submitted native backing transactions awaiting their exact EL1 receipt.
    /// Unused grants are not terminal child custody and return to stock here.
    pending_descriptor_tables: BTreeMap<(MmKey, u64), PendingNativeDescriptorTables>,
    /// Quarantined children; `true` once their carrier release succeeded,
    /// so a later reclaim never releases the same MM twice.
    quarantine: BTreeMap<MmKey, QuarantinedChild>,
    last_refusal: Option<ForkAdmissionRefusal>,
    tags: T,
    counters: ForkStockCounters,
}

impl<T: ChildAddressTags, C> ForkStock<T, C> {
    pub fn new(carrier: NonZeroU64, control: Option<ForkControlCapacity>, tags: T) -> Self {
        Self {
            carrier,
            controls: control
                .filter(|control| control.is_exclusive())
                .into_iter()
                .collect(),
            unused_control: control.filter(|control| !control.is_exclusive()),
            tables: Vec::new(),
            lifecycles: Vec::new(),
            pending: Vec::new(),
            next_loan: NonZeroU64::MIN,
            next_exec_predecessor: NonZeroU64::MIN,
            children: BTreeMap::new(),
            exec_predecessors: BTreeMap::new(),
            committed_tables: BTreeMap::new(),
            pending_descriptor_tables: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            last_refusal: None,
            tags,
            counters: ForkStockCounters::default(),
        }
    }

    pub fn carrier(&self) -> NonZeroU64 {
        self.carrier
    }

    pub fn set_carrier(&mut self, carrier: NonZeroU64) {
        self.carrier = carrier;
    }

    pub fn tags(&self) -> &T {
        &self.tags
    }

    #[cfg(test)]
    pub(crate) fn tags_mut_for_tests(&mut self) -> &mut T {
        &mut self.tags
    }

    pub fn counters(&self) -> ForkStockCounters {
        self.counters
    }

    /// Reusable table pages (excludes loaned, committed and quarantined).
    pub fn table_stock(&self) -> &[RootGpa] {
        &self.tables
    }

    /// Reusable lifecycle records.
    pub fn lifecycle_stock(&self) -> &[ForkLifecycleLoan] {
        &self.lifecycles
    }

    /// Replace the initial capacity before a guest can borrow stock. The
    /// carrier retains the physical backing of every supplied window.
    #[cfg(test)]
    pub(crate) fn install_control_capacity(
        &mut self,
        controls: Vec<ForkControlCapacity>,
    ) -> Result<(), ForkStockServiceError> {
        let mut unique = controls.clone();
        unique.sort_unstable();
        unique.dedup();
        if controls.is_empty()
            || unique.len() != controls.len()
            || controls.iter().any(|control| !control.is_exclusive())
            || !self.tables.is_empty()
            || !self.lifecycles.is_empty()
            || !self.children.is_empty()
            || !self.exec_predecessors.is_empty()
            || !self.committed_tables.is_empty()
            || !self.pending_descriptor_tables.is_empty()
            || self.pending.iter().any(Option::is_some)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        self.controls = controls;
        self.unused_control = None;
        Ok(())
    }

    /// True when a fork can be admitted a lifecycle record right now.
    pub fn lifecycle_available(&self) -> bool {
        !self.lifecycles.is_empty()
    }

    /// Whether the next loan needs another ISA control window.
    pub fn needs_control_capacity(&self) -> bool {
        self.controls.is_empty() && self.unused_control.is_none()
    }

    pub fn pending(&self, cpu: CpuId) -> Option<&PendingForkLoan<T::Tag, C>> {
        self.pending.get(cpu_index(cpu)?)?.as_ref()
    }

    /// Settled children whose memory is not yet reclaimed.
    pub fn live_children(&self) -> usize {
        self.children.len()
    }

    pub fn child_tag(&self, mm: ReservationMm) -> Option<T::Tag> {
        Some(self.children.get(&MmKey::of(mm)?)?.tag.tag())
    }

    /// Committed physical root, for authenticating a stopped child lane.
    pub fn child_root(&self, mm: ReservationMm) -> Option<RootGpa> {
        Some(self.children.get(&MmKey::of(mm)?)?.root)
    }

    /// Borrow inherited custody only for the exact committed owner and root.
    /// Retired children retain pins for reclamation, but cannot admit births.
    pub fn child_custody(
        &self,
        operation: carrick_el1_abi::PortalOperation,
        root: RootGpa,
    ) -> Option<&C> {
        let key = MmKey::of(operation.mm)?;
        let child = self.children.get(&key)?;
        (child.owner.carrier() == operation.carrier
            && child.owner.incarnation() == operation.incarnation
            && child.root == root
            && !self.quarantine.contains_key(&key))
        .then_some(&child.physical)
    }

    /// Physical access requires the committed root; this grants no new
    /// semantic admission. Terminal settlement may consume an existing receipt.
    pub fn child_physical_mut(&mut self, mm: ReservationMm, root: RootGpa) -> Option<&mut C> {
        let child = self.children.get_mut(&MmKey::of(mm)?)?;
        (child.root == root).then_some(&mut child.physical)
    }
    pub fn child_owner(&self, mm: ReservationMm) -> Option<carrick_el1_abi::El1MmHandle> {
        Some(self.children.get(&MmKey::of(mm)?)?.owner)
    }

    pub fn child_lifecycle(&self, mm: ReservationMm) -> Option<ForkLifecycleLoan> {
        Some(self.children.get(&MmKey::of(mm)?)?.lifecycle)
    }

    /// Preclaim authenticated EL1 table-pool pages for one exact live child.
    /// The caller submits only the typed result, then either commits it to the
    /// child's terminal custody or cancels it before the guest can execute.
    pub fn reserve_native_descriptor_tables(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        owner: carrick_el1_abi::El1MmHandle,
        root: RootGpa,
        count: usize,
    ) -> Result<NativeDescriptorTableReservation, ForkStockServiceError> {
        use carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS;

        let mm = owner.mm();
        let key = MmKey::of(mm).ok_or(ForkStockServiceError::StaleExecution)?;
        if count == 0
            || count > MAX_TABLE_GRANTS
            || self.child_owner(mm) != Some(owner)
            || self.child_root(mm) != Some(root)
            || self.quarantine.contains_key(&key)
        {
            return Err(ForkStockServiceError::StaleExecution);
        }
        if self.tables.len() < count {
            self.counters.descriptor_capacity_refusals =
                self.counters.descriptor_capacity_refusals.saturating_add(1);
            return Err(ForkStockServiceError::DescriptorTableCapacity);
        }
        self.tables
            .sort_unstable_by_key(|page| page.address().raw());
        let pages = self.tables.split_off(self.tables.len() - count);
        for (charged, page) in pages.iter().enumerate() {
            if !ledger.grant(*page, mm) {
                for page in pages.iter().take(charged) {
                    ledger.give_back(*page, mm);
                }
                self.tables.extend(pages);
                self.counters.descriptor_capacity_refusals =
                    self.counters.descriptor_capacity_refusals.saturating_add(1);
                return Err(ForkStockServiceError::DescriptorTableCapacity);
            }
        }
        let raw_pages: Vec<_> = pages
            .iter()
            .map(|page| carrick_mmu_core::aarch64::SubstrateGpa(page.address().raw()))
            .collect();
        let Some(descriptor_tables) =
            carrick_mmu_core::aarch64::descriptor_txn::TableGrants::new(&raw_pages)
        else {
            for page in &pages {
                ledger.give_back(*page, mm);
            }
            self.tables.extend(pages);
            return Err(ForkStockServiceError::InvalidRecord);
        };
        Ok(NativeDescriptorTableReservation {
            key,
            mm,
            root,
            pages,
            descriptor_tables,
        })
    }

    /// Bind a submitted reservation to its exact transaction until EL1
    /// reports which prefix it linked. Invalid or duplicate submissions return
    /// every grant immediately; they never consume shared stock.
    pub fn track_native_descriptor_tables(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        reservation: NativeDescriptorTableReservation,
        txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) -> Result<(), ForkStockServiceError> {
        let key = (reservation.key, txn.id.generation.get());
        if txn.id.mm_key != reservation.key.0
            || txn.tables != reservation.descriptor_tables
            || self.pending_descriptor_tables.contains_key(&key)
        {
            self.cancel_native_descriptor_tables(ledger, reservation);
            return Err(ForkStockServiceError::InvalidRecord);
        }
        self.pending_descriptor_tables.insert(
            key,
            PendingNativeDescriptorTables {
                mm: reservation.mm,
                root: reservation.root,
                pages: reservation.pages,
                txn,
            },
        );
        Ok(())
    }

    /// The exact transaction awaiting settlement for one live child.
    pub fn pending_native_descriptor_transaction(
        &self,
        owner: carrick_el1_abi::El1MmHandle,
        root: RootGpa,
        generation: core::num::NonZeroU64,
    ) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn> {
        let key = MmKey::of(owner.mm())?;
        let pending = self
            .pending_descriptor_tables
            .get(&(key, generation.get()))?;
        (self.child_owner(owner.mm()) == Some(owner) && pending.root == root).then_some(pending.txn)
    }

    /// Settle a submitted reservation from EL1's authenticated receipt. Only
    /// the linked prefix remains charged to child retirement; refused,
    /// rolled-back and unused grants return to the shared stock exactly once.
    pub fn settle_native_descriptor_tables(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        owner: carrick_el1_abi::El1MmHandle,
        root: RootGpa,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<(), ForkStockServiceError> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;

        let key = MmKey::of(owner.mm()).ok_or(ForkStockServiceError::StaleExecution)?;
        let pending_key = (key, receipt.id.generation.get());
        let pending = self
            .pending_descriptor_tables
            .get(&pending_key)
            .ok_or(ForkStockServiceError::StaleExecution)?;
        if self.child_owner(owner.mm()) != Some(owner)
            || pending.root != root
            || receipt.id != pending.txn.id
            || receipt.digest != pending.txn.digest()
        {
            return Err(ForkStockServiceError::StaleExecution);
        }
        let linked = match receipt.outcome {
            DescriptorOutcome::Applied(_) => {
                let verified = pending
                    .txn
                    .verify_receipt(receipt)
                    .map_err(|_| ForkStockServiceError::InvalidRecord)?;
                pending
                    .pages
                    .len()
                    .checked_sub(verified.unused_table_grants().len())
                    .ok_or(ForkStockServiceError::InvalidRecord)?
            }
            DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_) => 0,
            DescriptorOutcome::Indeterminate(_) => {
                return Err(ForkStockServiceError::InvalidRecord);
            }
        };
        let mut pending = self
            .pending_descriptor_tables
            .remove(&pending_key)
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        let unused = pending.pages.split_off(linked);
        if !pending.pages.is_empty() {
            self.committed_tables
                .entry(key)
                .or_default()
                .extend(pending.pages);
        }
        for page in &unused {
            ledger.give_back(*page, pending.mm);
        }
        self.tables.extend(unused);
        Ok(())
    }

    /// Return all grants after the guest withdrew an unclaimed submission.
    pub fn cancel_submitted_native_descriptor_tables(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        owner: carrick_el1_abi::El1MmHandle,
        root: RootGpa,
        generation: core::num::NonZeroU64,
    ) -> Result<(), ForkStockServiceError> {
        let key = MmKey::of(owner.mm()).ok_or(ForkStockServiceError::StaleExecution)?;
        let pending_key = (key, generation.get());
        let pending = self
            .pending_descriptor_tables
            .get(&pending_key)
            .ok_or(ForkStockServiceError::StaleExecution)?;
        if self.child_owner(owner.mm()) != Some(owner) || pending.root != root {
            return Err(ForkStockServiceError::StaleExecution);
        }
        let pending = self
            .pending_descriptor_tables
            .remove(&pending_key)
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        for page in &pending.pages {
            ledger.give_back(*page, pending.mm);
        }
        self.tables.extend(pending.pages);
        Ok(())
    }

    /// Return a reservation whose descriptor transaction was not submitted.
    pub fn cancel_native_descriptor_tables(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        reservation: NativeDescriptorTableReservation,
    ) {
        for page in &reservation.pages {
            ledger.give_back(*page, reservation.mm);
        }
        self.tables.extend(reservation.pages);
    }

    /// An unfinished descriptor supply may already have linked any of its
    /// grants. Transfer all of them to terminal MM custody before withdrawing
    /// the live child identity that authenticated receipt settlement.
    fn take_pending_descriptor_tables(&mut self, key: MmKey) -> Vec<RootGpa> {
        let pending: Vec<_> = self
            .pending_descriptor_tables
            .keys()
            .filter(|(pending, _)| *pending == key)
            .copied()
            .collect();
        let mut pending_pages = Vec::new();
        for pending_key in pending {
            if let Some(pending) = self.pending_descriptor_tables.remove(&pending_key) {
                pending_pages.extend(pending.pages);
            }
        }
        pending_pages
    }

    /// Move one exact live fork child to a prepared exec successor. Every
    /// refusing check precedes mutation. The lifecycle/control allocation is
    /// process custody and therefore follows the successor; predecessor table,
    /// tag, and physical custody move to a one-shot settlement receipt.
    pub fn replace_child_for_exec(
        &mut self,
        execution: GrantExecution,
        successor: carrick_el1_abi::El1MmHandle,
        successor_root: RootGpa,
        successor_physical: C,
    ) -> Result<ExecPredecessorReceipt<T::Tag>, (ForkStockServiceError, C)> {
        let Some(predecessor_mm) = ReservationMm::new(execution.binding.mm.raw()) else {
            return Err((ForkStockServiceError::StaleExecution, successor_physical));
        };
        let Some(predecessor_key) = MmKey::of(predecessor_mm) else {
            return Err((ForkStockServiceError::StaleExecution, successor_physical));
        };
        let successor_mm = successor.mm();
        let Some(successor_key) = MmKey::of(successor_mm) else {
            return Err((ForkStockServiceError::InvalidRecord, successor_physical));
        };
        let exact_predecessor = self.children.get(&predecessor_key).is_some_and(|child| {
            child.owner.carrier() == self.carrier
                && child.owner.mm() == predecessor_mm
                && child.root == execution.context.root
                && child.owner.incarnation() == execution.context.generation.raw()
                && execution.context.mm.raw().get() == predecessor_mm.raw()
        });
        if !exact_predecessor
            || successor.carrier() != self.carrier
            || successor_mm == predecessor_mm
            || self.children.contains_key(&successor_key)
            || self.quarantine.contains_key(&predecessor_key)
            || self.quarantine.contains_key(&successor_key)
            || self
                .exec_predecessors
                .values()
                .any(|pending| pending.predecessor == predecessor_mm)
        {
            return Err((ForkStockServiceError::StaleExecution, successor_physical));
        }
        let Some(successor_tag) = self.tags.allocate() else {
            return Err((
                ForkStockServiceError::Asid(AsidError::Exhausted),
                successor_physical,
            ));
        };
        let sequence = self.next_exec_predecessor;
        let Some(next) = sequence.get().checked_add(1).and_then(NonZeroU64::new) else {
            let _ = self.tags.release_unpublished(successor_tag);
            return Err((ForkStockServiceError::InvalidRecord, successor_physical));
        };

        // All validation and fallible allocation completed. These removals
        // are exact by the checks above and the mutable owner excludes drift.
        let Some(predecessor) = self.children.remove(&predecessor_key) else {
            let _ = self.tags.release_unpublished(successor_tag);
            return Err((ForkStockServiceError::StaleExecution, successor_physical));
        };
        let mut tables = self
            .committed_tables
            .remove(&predecessor_key)
            .unwrap_or_default();
        tables.extend(self.take_pending_descriptor_tables(predecessor_key));
        let successor_child = CommittedChild {
            owner: successor,
            root: successor_root,
            lifecycle: predecessor.lifecycle,
            control: predecessor.control,
            tag: ChildTag::bind(successor_tag, successor_mm),
            physical: successor_physical,
        };
        let replaced = self.children.insert(successor_key, successor_child);
        debug_assert!(replaced.is_none());
        let pending = ExecPredecessor {
            predecessor: predecessor_mm,
            successor: successor_mm,
            tag: predecessor.tag,
            tables,
            physical: predecessor.physical,
            released: false,
        };
        let replaced = self.exec_predecessors.insert(sequence, pending);
        debug_assert!(replaced.is_none());
        self.next_exec_predecessor = next;
        Ok(ExecPredecessorReceipt {
            sequence,
            predecessor: predecessor_mm,
            successor: successor_mm,
            successor_tag,
        })
    }

    /// Consume an exact exec predecessor receipt after translation switch.
    /// Carrier release runs once; table clearing and tag retirement must both
    /// succeed before stock is reusable. A stale or duplicate receipt cannot
    /// act on a later MM that recycled either numeric identity.
    pub fn settle_exec_predecessor(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        receipt: ExecPredecessorReceipt<T::Tag>,
        absence: SlotAbsence,
        mut clear_tables: impl FnMut(&[RootGpa]) -> bool,
        mut release: impl FnMut(&C, &SlotAbsence) -> bool,
    ) -> Result<(), ForkStockServiceError> {
        let Some(mut pending) = self.exec_predecessors.remove(&receipt.sequence) else {
            return Err(ForkStockServiceError::StaleExecution);
        };
        let exact = pending.predecessor == receipt.predecessor
            && pending.successor == receipt.successor
            && absence.mm() == receipt.predecessor
            && self
                .children
                .get(&MmKey::of(receipt.successor).ok_or(ForkStockServiceError::InvalidRecord)?)
                .is_some_and(|child| child.tag.tag() == receipt.successor_tag);
        if !exact {
            self.exec_predecessors.insert(receipt.sequence, pending);
            return Err(ForkStockServiceError::StaleExecution);
        }
        if !pending.released {
            if !release(&pending.physical, &absence) {
                self.exec_predecessors.insert(receipt.sequence, pending);
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            pending.released = true;
        }
        if !clear_tables(&pending.tables) {
            self.exec_predecessors.insert(receipt.sequence, pending);
            return Err(ForkStockServiceError::ExposedDirtyTable);
        }
        if let Err(error) = self.tags.retire(pending.tag, absence) {
            self.exec_predecessors.insert(receipt.sequence, pending);
            return Err(error);
        }
        for page in &pending.tables {
            ledger.give_back(*page, pending.predecessor);
        }
        self.tables.extend(pending.tables);
        drop(pending.physical);
        Ok(())
    }

    /// True when some retired child is waiting for reclaim.
    pub fn has_quarantine(&self) -> bool {
        !self.quarantine.is_empty()
    }

    pub fn is_quarantined(&self, mm: ReservationMm) -> bool {
        MmKey::of(mm).is_some_and(|key| self.quarantine.contains_key(&key))
    }

    /// Pages held by quarantined children (never in the reusable stock).
    pub fn quarantined_tables(&self) -> Vec<RootGpa> {
        self.quarantine
            .keys()
            .filter_map(|key| self.committed_tables.get(key))
            .flatten()
            .copied()
            .collect()
    }

    /// Seed the bounded stock before any guest can request it. Pages and
    /// records must be distinct; nothing may be outstanding.
    pub fn install(
        &mut self,
        tables: Vec<RootGpa>,
        lifecycles: Vec<ForkLifecycleLoan>,
    ) -> Result<(), ForkStockServiceError> {
        let mut unique = tables.clone();
        unique.sort_unstable_by_key(|page| page.address().raw());
        unique.dedup();
        let mut records: Vec<u64> = lifecycles.iter().map(|life| life.page.raw()).collect();
        records.sort_unstable();
        records.dedup();
        if unique.len() != tables.len()
            || records.len() != lifecycles.len()
            || !self.tables.is_empty()
            || !self.lifecycles.is_empty()
            || !self.children.is_empty()
            || !self.committed_tables.is_empty()
            || !self.pending_descriptor_tables.is_empty()
            || self.pending.iter().any(Option::is_some)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        self.tables = tables;
        self.lifecycles = lifecycles;
        Ok(())
    }

    /// Last refusal retained for a carrier's structured run report.
    pub fn admission_refusal(&self) -> Option<ForkAdmissionRefusal> {
        self.last_refusal.clone()
    }

    fn record_capacity(
        &mut self,
        exchange: &ForkStockExchange,
        resource: ForkCapacityResource,
        cpu: CpuId,
    ) {
        if let Some(request) = exchange.request() {
            let record = ForkAdmissionRefusal {
                carrier: request.operation.carrier.get(),
                mm: request.operation.mm.raw(),
                cpu: cpu.raw(),
                resource,
                child_pages: request.child_bytes / TABLE_PAGE_BYTES,
                parent_pages: request.parent_bytes / TABLE_PAGE_BYTES,
                available_pages: self.tables.len(),
                available_lifecycles: self.lifecycles.len(),
                quarantine: self
                    .quarantine
                    .iter()
                    .map(|(mm, state)| ForkQuarantineState {
                        mm: mm.0.get(),
                        absent: state.absent,
                        carrier_released: state.released,
                    })
                    .collect(),
            };
            carrick_observability::probes::fork_admission_identity(&record);
            carrick_observability::probes::fork_admission_refusal(&record);
            for child in &record.quarantine {
                carrick_observability::probes::fork_quarantine_state(&record, child);
            }
            self.last_refusal = Some(record);
        }
    }

    fn refuse_capacity(
        &mut self,
        exchange: &mut ForkStockExchange,
        resource: ForkCapacityResource,
        cpu: CpuId,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        self.record_capacity(exchange, resource, cpu);
        self.refuse(exchange, ForkStockRefusal::Capacity)
    }

    fn refuse(
        &mut self,
        exchange: &mut ForkStockExchange,
        refusal: ForkStockRefusal,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        let counter = match refusal {
            ForkStockRefusal::Capacity => &mut self.counters.capacity_refusals,
            ForkStockRefusal::Stale => &mut self.counters.stale_refusals,
            ForkStockRefusal::Invalid => &mut self.counters.invalid_refusals,
            ForkStockRefusal::Inventory => &mut self.counters.inventory_refusals,
        };
        *counter = counter.saturating_add(1);
        exchange.refuse(refusal);
        Err(refusal)
    }

    fn refuse_settlement(
        &mut self,
        settlement: &mut ForkStockSettlement,
        refusal: ForkStockRefusal,
    ) -> ForkStockRefusal {
        let counter = match refusal {
            ForkStockRefusal::Capacity => &mut self.counters.capacity_refusals,
            ForkStockRefusal::Stale => &mut self.counters.stale_refusals,
            ForkStockRefusal::Invalid => &mut self.counters.invalid_refusals,
            ForkStockRefusal::Inventory => &mut self.counters.inventory_refusals,
        };
        *counter = counter.saturating_add(1);
        settlement.refuse(refusal);
        refusal
    }

    /// Service a stopped-CPU loan request. `lifecycle_fresh` lets the host
    /// prove the issued record is cleared storage before the guest owns it;
    /// a stale record refuses with [`ForkStockRefusal::Inventory`].
    pub fn loan(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        execution: GrantExecution,
        exchange: &mut ForkStockExchange,
        lifecycle_fresh: impl FnOnce(ForkLifecycleLoan) -> bool,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        let Some(request) = exchange.request() else {
            return self.refuse(exchange, ForkStockRefusal::Invalid);
        };
        if request.binding != execution.binding
            || request.context != execution.context
            || request.operation.carrier != self.carrier
        {
            return self.refuse(exchange, ForkStockRefusal::Stale);
        }
        let Some(index) = cpu_index(execution.cpu) else {
            return self.refuse(exchange, ForkStockRefusal::Invalid);
        };
        if index >= self.pending.len() {
            self.pending.resize_with(index + 1, || None);
        }
        if self.pending[index].is_some() {
            return self.refuse_capacity(
                exchange,
                ForkCapacityResource::PendingLoan,
                execution.cpu,
            );
        }
        if self.lifecycles.is_empty() {
            return self.refuse_capacity(exchange, ForkCapacityResource::Lifecycle, execution.cpu);
        }
        if self.controls.is_empty() && self.unused_control.is_none() {
            return self.refuse_capacity(exchange, ForkCapacityResource::Control, execution.cpu);
        }
        let Some((child_tables, parent_tables)) =
            take_fork_table_stock(&mut self.tables, request.child_bytes, request.parent_bytes)
        else {
            return self.refuse_capacity(exchange, ForkCapacityResource::Tables, execution.cpu);
        };
        let Some(next) = self.next_loan.checked_add(1) else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            return self.refuse_capacity(
                exchange,
                ForkCapacityResource::LoanIdentity,
                execution.cpu,
            );
        };
        let Some(tag) = self.tags.allocate() else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            return self.refuse_capacity(exchange, ForkCapacityResource::AddressTag, execution.cpu);
        };
        let Some(lifecycle) = self.lifecycles.pop() else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            // A failed tag release still answers the guest with a refusal.
            let released = self.tags.release_unpublished(tag);
            let refused =
                self.refuse_capacity(exchange, ForkCapacityResource::Lifecycle, execution.cpu);
            return released.map_err(|_| ForkStockRefusal::Invalid).and(refused);
        };
        let Some(control) = self.unused_control.or_else(|| self.controls.pop()) else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            self.lifecycles.push(lifecycle);
            let released = self.tags.release_unpublished(tag);
            let refused =
                self.refuse_capacity(exchange, ForkCapacityResource::Control, execution.cpu);
            return released.map_err(|_| ForkStockRefusal::Invalid).and(refused);
        };
        let id = self.next_loan;
        let child_base = child_tables[0].address().raw();
        let parent_base = parent_tables[0].address().raw();
        let reserved = ReservedLoan {
            child_mm: request.child_mm,
            parent_mm: request.operation.mm,
            child_tables,
            parent_tables,
            lifecycle,
            control,
            tag,
        };
        let fresh = lifecycle_fresh(lifecycle);
        let admitted = request
            .admit_loan(
                child_base,
                parent_base,
                control.base(),
                id,
                lifecycle,
                T::wire(tag),
            )
            .filter(|_| fresh);
        let Some(loan) = admitted else {
            if fresh {
                return self.restore_and_refuse(
                    ledger,
                    exchange,
                    reserved,
                    0,
                    ForkStockRefusal::Invalid,
                );
            }
            // One hygiene policy for every carrier: a dirty lifecycle record
            // is a custody fault in that record, not in the carrier. It is
            // withdrawn (never reissued) and the loan refused as Inventory.
            let result =
                self.restore_and_refuse(ledger, exchange, reserved, 0, ForkStockRefusal::Inventory);
            self.lifecycles.retain(|record| *record != lifecycle);
            self.counters.withdrawn_lifecycles =
                self.counters.withdrawn_lifecycles.saturating_add(1);
            return result;
        };
        let charges: Vec<_> = reserved.charges().collect();
        let mut charged = 0;
        for (page, mm) in charges {
            if !ledger.grant(page, mm) {
                self.record_capacity(exchange, ForkCapacityResource::Ledger, execution.cpu);
                return self.restore_and_refuse(
                    ledger,
                    exchange,
                    reserved,
                    charged,
                    ForkStockRefusal::Capacity,
                );
            }
            charged += 1;
        }
        if !exchange.grant(
            child_base,
            parent_base,
            control.base(),
            id,
            lifecycle,
            T::wire(tag),
        ) {
            return self.restore_and_refuse(
                ledger,
                exchange,
                reserved,
                charged,
                ForkStockRefusal::Invalid,
            );
        }
        let ReservedLoan {
            child_tables,
            parent_tables,
            ..
        } = reserved;
        self.next_loan = next;
        self.counters.loans = self.counters.loans.saturating_add(1);
        self.pending[index] = Some(PendingForkLoan {
            loan,
            execution,
            child_tables,
            parent_tables,
            lifecycle,
            control,
            tag,
            admitted: None,
        });
        Ok(loan)
    }

    /// Undo a reservation and always answer the exchange with a refusal; a
    /// failed restore reports `Invalid` after the guest has its refusal.
    fn restore_and_refuse(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        exchange: &mut ForkStockExchange,
        reserved: ReservedLoan<T::Tag>,
        charged: usize,
        refusal: ForkStockRefusal,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        let restored = self.restore(ledger, reserved, charged);
        let refused = self.refuse(exchange, refusal);
        restored.and(refused)
    }

    /// Undo a reservation whose first `charged` ledger grants were made.
    fn restore(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        reserved: ReservedLoan<T::Tag>,
        charged: usize,
    ) -> Result<(), ForkStockRefusal> {
        for (page, mm) in reserved.charges().take(charged) {
            ledger.give_back(page, mm);
        }
        self.tables.extend(reserved.child_tables);
        self.tables.extend(reserved.parent_tables);
        self.lifecycles.push(reserved.lifecycle);
        if reserved.control.is_exclusive() {
            self.controls.push(reserved.control);
        }
        self.tags
            .release_unpublished(reserved.tag)
            .map_err(|_| ForkStockRefusal::Invalid)
    }

    /// The outstanding loan of an authenticated stopped CPU.
    pub fn settlement_loan(
        &self,
        execution: GrantExecution,
    ) -> Result<ForkStockLoan, ForkStockServiceError> {
        let pending = self
            .pending(execution.cpu)
            .ok_or(ForkStockServiceError::NoPendingLoan)?;
        if !pending.execution.matches(execution) {
            return Err(ForkStockServiceError::StaleExecution);
        }
        Ok(pending.loan)
    }

    fn validate_completion(
        &self,
        execution: GrantExecution,
        completion: carrick_el1_abi::PortalForkCompletion,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
    ) -> Result<(MmKey, MmKey, usize, usize), ForkStockServiceError> {
        let loan = self.settlement_loan(execution)?;
        let pending = self
            .pending(execution.cpu)
            .ok_or(ForkStockServiceError::NoPendingLoan)?;
        if !is_resolvable(&pending.child_tables) || !is_resolvable(&pending.parent_tables) {
            return Err(ForkStockServiceError::MemoryAccessFailed);
        }
        let child_used = usize::try_from(completion.child_tables_used / TABLE_PAGE_BYTES)
            .map_err(|_| ForkStockServiceError::InvalidRecord)?;
        let parent_used = usize::try_from(completion.parent_tables_used / TABLE_PAGE_BYTES)
            .map_err(|_| ForkStockServiceError::InvalidRecord)?;
        if child_used == 0
            || child_used > pending.child_tables.len()
            || parent_used > pending.parent_tables.len()
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        if !is_clean(&pending.child_tables[child_used..])
            || !is_clean(&pending.parent_tables[parent_used..])
        {
            return Err(ForkStockServiceError::ExposedDirtyTable);
        }
        let child_key =
            MmKey::of(loan.request.child_mm).ok_or(ForkStockServiceError::InvalidRecord)?;
        let parent_key =
            MmKey::of(loan.request.operation.mm).ok_or(ForkStockServiceError::InvalidRecord)?;
        if self.children.contains_key(&child_key) || self.committed_tables.contains_key(&child_key)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        Ok((child_key, parent_key, child_used, parent_used))
    }

    /// Validate a prepared child's table completion and retain its inherited
    /// physical custody into an [`AdmittedForkCustody`] token on the pending
    /// loan before child publication. Any refusal leaves the loan pending so
    /// the guest can scrub and abort it into a counted fork failure.
    pub fn reserve_custody(
        &mut self,
        execution: GrantExecution,
        settlement: &mut ForkStockSettlement,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
        retain_physical: impl FnOnce(
            carrick_el1_abi::PortalForkRequest,
            carrick_guest_arch::KernelVa,
            u64,
        ) -> Result<C, ForkStockRefusal>,
    ) -> Result<&AdmittedForkCustody<C>, ForkStockRefusal> {
        let loan = match self.settlement_loan(execution) {
            Ok(loan) => loan,
            Err(ForkStockServiceError::StaleExecution) => {
                return Err(self.refuse_settlement(settlement, ForkStockRefusal::Stale));
            }
            Err(_) => {
                return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
            }
        };
        let Some(index) = cpu_index(execution.cpu) else {
            return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
        };
        if self
            .pending
            .get(index)
            .and_then(Option::as_ref)
            .is_none_or(|pending| pending.admitted.is_some())
        {
            return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
        }
        let Some((completion, custody_va, count)) = settlement.reservation(loan) else {
            return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
        };
        let (child_key, parent_key, child_used, parent_used) =
            match self.validate_completion(execution, completion, is_resolvable, is_clean) {
                Ok(validated) => validated,
                Err(ForkStockServiceError::MemoryAccessFailed) => {
                    return Err(self.refuse_settlement(settlement, ForkStockRefusal::Inventory));
                }
                Err(ForkStockServiceError::StaleExecution) => {
                    return Err(self.refuse_settlement(settlement, ForkStockRefusal::Stale));
                }
                Err(_) => {
                    return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
                }
            };
        let physical = match retain_physical(loan.request, custody_va, count) {
            Ok(physical) => physical,
            Err(refusal) => return Err(self.refuse_settlement(settlement, refusal)),
        };
        if !settlement.accept(loan) {
            return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
        }
        if self.pending[index].is_none() {
            return Err(self.refuse_settlement(settlement, ForkStockRefusal::Invalid));
        }
        let Some(pending) = self.pending[index].as_mut() else {
            return Err(ForkStockRefusal::Invalid);
        };
        Ok(pending.admitted.insert(AdmittedForkCustody {
            loan_id: loan.id,
            child_key,
            parent_key,
            child_used,
            parent_used,
            completion,
            physical,
        }))
    }

    fn consume_admitted(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        mut pending: PendingForkLoan<T::Tag, C>,
        admitted: AdmittedForkCustody<C>,
    ) {
        let loan = pending.loan;
        let unused_child: Vec<_> = pending.child_tables.drain(admitted.child_used..).collect();
        let unused_parent: Vec<_> = pending
            .parent_tables
            .drain(admitted.parent_used..)
            .collect();
        self.children.insert(
            admitted.child_key,
            CommittedChild {
                owner: admitted.completion.child,
                root: pending.child_tables[0],
                lifecycle: pending.lifecycle,
                control: pending.control,
                tag: ChildTag::bind(pending.tag, loan.request.child_mm),
                physical: admitted.physical,
            },
        );
        self.committed_tables
            .entry(admitted.child_key)
            .or_default()
            .extend(pending.child_tables);
        if !pending.parent_tables.is_empty() {
            self.committed_tables
                .entry(admitted.parent_key)
                .or_default()
                .extend(pending.parent_tables);
        }
        for page in &unused_child {
            ledger.give_back(*page, loan.request.child_mm);
        }
        for page in &unused_parent {
            ledger.give_back(*page, loan.request.operation.mm);
        }
        self.tables.extend(unused_child);
        self.tables.extend(unused_parent);
    }

    /// Consume the [`AdmittedForkCustody`] token reserved during preparation
    /// and commit the child into carrier custody.
    pub fn commit_admitted(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        execution: GrantExecution,
        settlement: &mut ForkStockSettlement,
    ) -> Result<(), ForkStockServiceError> {
        let loan = self.settlement_loan(execution)?;
        let index = cpu_index(execution.cpu).ok_or(ForkStockServiceError::NoPendingLoan)?;
        let (completion, _, count) = settlement
            .request(loan)
            .ok_or(ForkStockServiceError::LoanMismatch)?;
        if count != 0 {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let admitted_matches = self.pending[index]
            .as_ref()
            .and_then(|pending| pending.admitted.as_ref())
            .is_some_and(|admitted| {
                admitted.loan_id == loan.id && admitted.completion == completion
            });
        if !admitted_matches || !settlement.accept(loan) {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let Some(mut pending) = self.pending[index].take() else {
            return Err(ForkStockServiceError::InvalidRecord);
        };
        let Some(admitted) = pending.admitted.take() else {
            self.pending[index] = Some(pending);
            return Err(ForkStockServiceError::InvalidRecord);
        };
        self.consume_admitted(ledger, pending, admitted);
        Ok(())
    }

    /// Settle an outstanding loan: an exact abort returns every untouched
    /// page and the lifecycle record; a commit consumes the admitted custody
    /// token reserved during preparation and returns the unused suffixes.
    ///
    /// `is_resolvable` proves the host can reach each loaned page,
    /// `is_clean` that pages returning to stock are zero, and
    /// `clear_lifecycle` clears an aborted lifecycle record the guest may
    /// already have initialized.
    pub fn settle(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        execution: GrantExecution,
        settlement: &mut ForkStockSettlement,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
        clear_lifecycle: impl FnOnce(ForkLifecycleLoan) -> bool,
    ) -> Result<(), ForkStockServiceError> {
        let loan = self.settlement_loan(execution)?;
        let index = cpu_index(execution.cpu).ok_or(ForkStockServiceError::NoPendingLoan)?;
        let pending = self.pending[index]
            .as_ref()
            .ok_or(ForkStockServiceError::NoPendingLoan)?;
        if !is_resolvable(&pending.child_tables) || !is_resolvable(&pending.parent_tables) {
            return Err(ForkStockServiceError::MemoryAccessFailed);
        }
        if settlement.abort_matches(loan) {
            if !is_clean(&pending.child_tables) || !is_clean(&pending.parent_tables) {
                return Err(ForkStockServiceError::ExposedDirtyTable);
            }
            if !clear_lifecycle(pending.lifecycle) {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            self.tags.release_unpublished(pending.tag)?;
            let pending = self.pending[index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;
            drop(pending.admitted);
            for page in &pending.child_tables {
                ledger.give_back(*page, loan.request.child_mm);
            }
            for page in &pending.parent_tables {
                ledger.give_back(*page, loan.request.operation.mm);
            }
            self.tables.extend(pending.child_tables);
            self.tables.extend(pending.parent_tables);
            self.lifecycles.push(pending.lifecycle);
            if pending.control.is_exclusive() {
                self.controls.push(pending.control);
            }
            if !settlement.accept(loan) {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            Ok(())
        } else {
            self.commit_admitted(ledger, execution, settlement)
        }
    }

    /// The executing child has left the shared owner graph: quarantine its
    /// stock. The record must name the executing binding and its exact root.
    /// Submitted descriptor grants without a final receipt may already be
    /// linked, so retirement absorbs every one into the child's committed
    /// table custody. Reclaim clears them before reuse. The typed reply is
    /// written into the record either way.
    pub fn retire_child(
        &mut self,
        execution: GrantExecution,
        retire: &mut NativeChildRetire,
    ) -> Result<(), ForkStockServiceError> {
        let key = ReservationMm::new(execution.binding.mm.raw()).and_then(MmKey::of);
        let admitted = key.filter(|key| {
            retire.request_matches(execution.binding, execution.context)
                && self
                    .children
                    .get(key)
                    .is_some_and(|child| child.root == execution.context.root)
                && !self.quarantine.contains_key(key)
        });
        let Some(key) = admitted else {
            retire.refuse(ChildRetireRefusal::Stale);
            self.counters.retire_refusals = self.counters.retire_refusals.saturating_add(1);
            return Err(ForkStockServiceError::StaleExecution);
        };
        if !retire.accept() {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let pending_pages = self.take_pending_descriptor_tables(key);
        if !pending_pages.is_empty() {
            self.committed_tables
                .entry(key)
                .or_default()
                .extend(pending_pages);
        }
        self.quarantine.insert(key, QuarantinedChild::default());
        self.counters.quarantined_children = self.counters.quarantined_children.saturating_add(1);
        Ok(())
    }

    /// Drain quarantine. A child MM is reclaimed only when it is not
    /// active in the authenticated execution venue and `occupancy` proves no zone slot has it installed.
    /// Its tables and lifecycle record are cleared and its tag retired
    /// before anything reenters the reusable stock. A child whose release,
    /// clear or tag retirement fails is deferred (counted, still
    /// quarantined, retried at the next drain); only a broken custody
    /// invariant (a quarantined MM with neither a committed child nor
    /// borrowed parent tables) is an error.
    pub fn reclaim(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        execution: impl Into<ReclaimExecution>,
        occupancy: impl Fn(ReservationMm) -> Option<SlotAbsence>,
        mut clear_tables: impl FnMut(&[RootGpa]) -> bool,
        mut clear_lifecycle: impl FnMut(ForkLifecycleLoan) -> bool,
        mut release: impl FnMut(&SlotAbsence) -> bool,
    ) -> Result<usize, ForkStockServiceError> {
        let active = execution.into().active.and_then(MmKey::of);
        let candidates: Vec<(MmKey, SlotAbsence)> = self
            .quarantine
            .iter_mut()
            .filter_map(|(key, state)| {
                let absence = (Some(*key) != active)
                    .then(|| key.mm().and_then(&occupancy))
                    .flatten()
                    .filter(|absence| absence.mm().raw() == key.0.get());
                state.absent = absence.is_some();
                absence.map(|absence| (*key, absence))
            })
            .collect();
        let mut reclaimed = 0;
        for (key, absence) in candidates {
            let mm = key.mm().ok_or(ForkStockServiceError::InvalidRecord)?;
            let child = self
                .children
                .get(&key)
                .map(|child| (child.lifecycle, child.tag));
            if child.is_none() && !self.committed_tables.contains_key(&key) {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            let pages = self
                .committed_tables
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            // Carrier per-MM state (root registry, inventory, residency) is
            // released before any of the child's stock can be reissued. Each
            // step is idempotent on retry (release runs once, tracked by the
            // quarantine flag; clears and tag retirement are restartable), so
            // a failed step defers only this child: it stays quarantined, its
            // stock stays held, the deferral is counted, and the next drain
            // retries it. Guest behaviour never turns into a carrier fault.
            let deferred = if let Some((lifecycle, tag)) = child {
                if self
                    .quarantine
                    .get(&key)
                    .is_some_and(|state| !state.released)
                    && !release(&absence)
                {
                    true
                } else {
                    self.quarantine
                        .get_mut(&key)
                        .ok_or(ForkStockServiceError::InvalidRecord)?
                        .released = true;
                    !clear_tables(pages)
                        || !clear_lifecycle(lifecycle)
                        || self.tags.retire(tag, absence).is_err()
                }
            } else {
                self.quarantine
                    .get_mut(&key)
                    .ok_or(ForkStockServiceError::InvalidRecord)?
                    .released = true;
                !clear_tables(pages)
            };
            if deferred {
                self.counters.reclaim_deferrals = self.counters.reclaim_deferrals.saturating_add(1);
                continue;
            }
            let child = self.children.remove(&key);
            if let Some(pages) = self.committed_tables.remove(&key) {
                for page in &pages {
                    ledger.give_back(*page, mm);
                }
                self.tables.extend(pages);
            }
            if let Some(child) = child {
                self.lifecycles.push(child.lifecycle);
                if child.control.is_exclusive() {
                    self.controls.push(child.control);
                }
                self.counters.returned_children = self.counters.returned_children.saturating_add(1);
            }
            self.quarantine.remove(&key);
            reclaimed += 1;
        }
        Ok(reclaimed)
    }

    /// The container root exited: retire any child entry and quarantine any
    /// borrowed parent fork tables so the next drain clears and returns them
    /// once the root leaves its execution slot. Its tag is owned by the host
    /// root MM rather than the fork stock.
    pub fn retire_exited_root(&mut self, mm: ReservationMm) {
        if let Some(key) = MmKey::of(mm) {
            self.children.remove(&key);
            if self
                .committed_tables
                .get(&key)
                .is_some_and(|pages| !pages.is_empty())
            {
                self.quarantine.entry(key).or_default();
            } else {
                self.quarantine.remove(&key);
            }
        }
    }
}

impl<C> ForkStock<AsidAllocator, C> {
    /// Admit one newly mapped AArch64 control window before the next loan.
    /// The constructor is ISA-bound: `ForkStock<UntaggedRoots>` has no such
    /// method and cannot manufacture an exclusive capacity through `new`.
    pub fn provide_arm_control_capacity(&mut self, base: u64) -> Result<(), ForkStockServiceError> {
        let control =
            ForkControlCapacity::exclusive(base).ok_or(ForkStockServiceError::InvalidRecord)?;
        if self.controls.contains(&control)
            || self
                .pending
                .iter()
                .flatten()
                .any(|loan| loan.control == control)
            || self.children.values().any(|child| child.control == control)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        self.controls.push(control);
        Ok(())
    }
}

fn cpu_index(cpu: CpuId) -> Option<usize> {
    usize::try_from(cpu.raw()).ok()
}

/// Stock taken for one loan before it is granted.
struct ReservedLoan<T> {
    child_mm: ReservationMm,
    parent_mm: ReservationMm,
    child_tables: Vec<RootGpa>,
    parent_tables: Vec<RootGpa>,
    lifecycle: ForkLifecycleLoan,
    control: ForkControlCapacity,
    tag: T,
}

impl<T> ReservedLoan<T> {
    /// Each loaned page with the MM its grant is charged to, child first.
    fn charges(&self) -> impl Iterator<Item = (RootGpa, ReservationMm)> + '_ {
        let child = self.child_tables.iter().map(|page| (*page, self.child_mm));
        let parent = self
            .parent_tables
            .iter()
            .map(|page| (*page, self.parent_mm));
        child.chain(parent)
    }
}

#[cfg(test)]
mod tests;
