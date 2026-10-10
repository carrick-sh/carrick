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

/// Bytes in one loaned page-table page.
const TABLE_PAGE_BYTES: u64 = 4096;

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
    /// The carrier could not release the retired MM's per-MM state.
    ReleaseRefused,
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

impl LifecycleWindow {
    /// # Safety
    /// `host` must be valid for reads and writes of `len` bytes for as long
    /// as the window is used, and must back guest kernel VAs `va..va + len`.
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

    /// Zero the record. False when it lies outside the window.
    pub fn clear(self, lifecycle: ForkLifecycleLoan) -> bool {
        self.ranges(lifecycle).is_some_and(|ranges| {
            for (ptr, len) in ranges {
                // SAFETY: in-window bytes of a record no live task owns.
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

/// Outstanding physical loan held by one stopped CPU.
#[derive(Clone, Debug)]
pub struct PendingForkLoan<T> {
    pub loan: ForkStockLoan,
    pub execution: GrantExecution,
    pub child_tables: Vec<RootGpa>,
    pub parent_tables: Vec<RootGpa>,
    pub lifecycle: ForkLifecycleLoan,
    pub tag: T,
}

/// A settled child whose memory is live in the guest owner graph.
#[derive(Clone, Copy, Debug)]
struct CommittedChild<T> {
    root: RootGpa,
    lifecycle: ForkLifecycleLoan,
    tag: ChildTag<T>,
}

/// Monotonic counters for diagnostics and the counted-`EAGAIN` contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForkStockCounters {
    /// Loans granted.
    pub loans: u64,
    /// Loans refused for capacity (the guest lowers each to `EAGAIN`).
    pub capacity_refusals: u64,
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
}

impl ForkStockCounters {
    /// Nonzero counters by stable family name, for run reports: every
    /// refused fork is attributable to its typed reason.
    pub fn families(&self) -> Vec<(&'static str, u64)> {
        [
            ("loan", self.loans),
            ("capacity_refusal", self.capacity_refusals),
            ("stale_refusal", self.stale_refusals),
            ("invalid_refusal", self.invalid_refusals),
            ("inventory_refusal", self.inventory_refusals),
            ("withdrawn_lifecycle", self.withdrawn_lifecycles),
            ("quarantined_child", self.quarantined_children),
            ("retire_refusal", self.retire_refusals),
            ("returned_child", self.returned_children),
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

/// The carrier's bounded fork stock, pending loans and child quarantine.
#[derive(Debug)]
pub struct ForkStock<T: ChildAddressTags> {
    carrier: NonZeroU64,
    kernel_control_ipa: u64,
    tables: Vec<RootGpa>,
    lifecycles: Vec<ForkLifecycleLoan>,
    pending: Vec<Option<PendingForkLoan<T::Tag>>>,
    next_loan: NonZeroU64,
    children: BTreeMap<MmKey, CommittedChild<T::Tag>>,
    /// Table pages each live MM consumed, as a child or as a fork parent.
    committed_tables: BTreeMap<MmKey, Vec<RootGpa>>,
    /// Quarantined children; `true` once their carrier release succeeded,
    /// so a later reclaim never releases the same MM twice.
    quarantine: BTreeMap<MmKey, bool>,
    tags: T,
    counters: ForkStockCounters,
}

impl<T: ChildAddressTags> ForkStock<T> {
    pub fn new(carrier: NonZeroU64, kernel_control_ipa: u64, tags: T) -> Self {
        Self {
            carrier,
            kernel_control_ipa,
            tables: Vec::new(),
            lifecycles: Vec::new(),
            pending: Vec::new(),
            next_loan: NonZeroU64::MIN,
            children: BTreeMap::new(),
            committed_tables: BTreeMap::new(),
            quarantine: BTreeMap::new(),
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

    /// True when a fork can be admitted a lifecycle record right now.
    pub fn lifecycle_available(&self) -> bool {
        !self.lifecycles.is_empty()
    }

    pub fn pending(&self, cpu: CpuId) -> Option<&PendingForkLoan<T::Tag>> {
        self.pending.get(cpu_index(cpu)?)?.as_ref()
    }

    /// Settled children whose memory is not yet reclaimed.
    pub fn live_children(&self) -> usize {
        self.children.len()
    }

    pub fn child_tag(&self, mm: ReservationMm) -> Option<T::Tag> {
        Some(self.children.get(&MmKey::of(mm)?)?.tag.tag())
    }

    pub fn child_lifecycle(&self, mm: ReservationMm) -> Option<ForkLifecycleLoan> {
        Some(self.children.get(&MmKey::of(mm)?)?.lifecycle)
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
            || self.pending.iter().any(Option::is_some)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        self.tables = tables;
        self.lifecycles = lifecycles;
        Ok(())
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
            self.pending.resize(index + 1, None);
        }
        if self.pending[index].is_some() || self.lifecycles.is_empty() {
            return self.refuse(exchange, ForkStockRefusal::Capacity);
        }
        let Some((child_tables, parent_tables)) =
            take_fork_table_stock(&mut self.tables, request.child_bytes, request.parent_bytes)
        else {
            return self.refuse(exchange, ForkStockRefusal::Capacity);
        };
        let Some(next) = self.next_loan.checked_add(1) else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            return self.refuse(exchange, ForkStockRefusal::Capacity);
        };
        let Some(tag) = self.tags.allocate() else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            return self.refuse(exchange, ForkStockRefusal::Capacity);
        };
        let Some(lifecycle) = self.lifecycles.pop() else {
            self.tables.extend(child_tables);
            self.tables.extend(parent_tables);
            // A failed tag release still answers the guest with a refusal.
            let released = self.tags.release_unpublished(tag);
            let refused = self.refuse(exchange, ForkStockRefusal::Capacity);
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
            tag,
        };
        let fresh = lifecycle_fresh(lifecycle);
        let admitted = request
            .admit_loan(
                child_base,
                parent_base,
                self.kernel_control_ipa,
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
            self.kernel_control_ipa,
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
            tag,
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

    /// Every check a commit settlement must pass, without consuming the
    /// loan. A carrier that publishes its own state for the child (KVM
    /// inherited frames) calls this first so nothing is published for a
    /// commit the stock would refuse; `settle` runs the same checks.
    pub fn validate_commit(
        &self,
        execution: GrantExecution,
        settlement: &ForkStockSettlement,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
    ) -> Result<carrick_el1_abi::PortalForkCompletion, ForkStockServiceError> {
        let loan = self.settlement_loan(execution)?;
        let pending = self
            .pending(execution.cpu)
            .ok_or(ForkStockServiceError::NoPendingLoan)?;
        if !is_resolvable(&pending.child_tables) || !is_resolvable(&pending.parent_tables) {
            return Err(ForkStockServiceError::MemoryAccessFailed);
        }
        let (completion, _custody, _count) = settlement
            .request(loan)
            .ok_or(ForkStockServiceError::LoanMismatch)?;
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
        if self.children.contains_key(&child_key) || self.committed_tables.contains_key(&child_key)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        Ok(completion)
    }

    /// Settle an outstanding loan: an exact abort returns every untouched
    /// page and the lifecycle record; a commit charges used pages to the
    /// child and parent and returns the unused suffixes.
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
            let pending = self.pending[index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;
            for page in &pending.child_tables {
                ledger.give_back(*page, loan.request.child_mm);
            }
            for page in &pending.parent_tables {
                ledger.give_back(*page, loan.request.operation.mm);
            }
            self.tables.extend(pending.child_tables);
            self.tables.extend(pending.parent_tables);
            self.lifecycles.push(pending.lifecycle);
            self.tags.release_unpublished(pending.tag)?;
        } else {
            let completion =
                self.validate_commit(execution, settlement, &is_resolvable, &is_clean)?;
            let child_used = usize::try_from(completion.child_tables_used / TABLE_PAGE_BYTES)
                .map_err(|_| ForkStockServiceError::InvalidRecord)?;
            let parent_used = usize::try_from(completion.parent_tables_used / TABLE_PAGE_BYTES)
                .map_err(|_| ForkStockServiceError::InvalidRecord)?;
            let child_key =
                MmKey::of(loan.request.child_mm).ok_or(ForkStockServiceError::InvalidRecord)?;
            let parent_key =
                MmKey::of(loan.request.operation.mm).ok_or(ForkStockServiceError::InvalidRecord)?;
            let mut pending = self.pending[index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;
            let unused_child: Vec<_> = pending.child_tables.drain(child_used..).collect();
            let unused_parent: Vec<_> = pending.parent_tables.drain(parent_used..).collect();
            self.children.insert(
                child_key,
                CommittedChild {
                    root: pending.child_tables[0],
                    lifecycle: pending.lifecycle,
                    tag: ChildTag::bind(pending.tag, loan.request.child_mm),
                },
            );
            self.committed_tables
                .entry(child_key)
                .or_default()
                .extend(pending.child_tables);
            self.committed_tables
                .entry(parent_key)
                .or_default()
                .extend(pending.parent_tables);
            for page in &unused_child {
                ledger.give_back(*page, loan.request.child_mm);
            }
            for page in &unused_parent {
                ledger.give_back(*page, loan.request.operation.mm);
            }
            self.tables.extend(unused_child);
            self.tables.extend(unused_parent);
        }
        if !settlement.accept(loan) {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        Ok(())
    }

    /// The executing child has left the shared owner graph: quarantine its
    /// stock. The record must name the executing binding and its exact root.
    /// The typed reply is written into the record either way.
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
        self.quarantine.insert(key, false);
        self.counters.quarantined_children = self.counters.quarantined_children.saturating_add(1);
        Ok(())
    }

    /// Drain quarantine. A child MM is reclaimed only when it is not
    /// `active` and `occupancy` proves no zone slot has it installed.
    /// Its tables and lifecycle record are cleared and its tag retired
    /// before anything reenters the reusable stock.
    pub fn reclaim(
        &mut self,
        ledger: &mut impl ForkTableLedger,
        active: ReservationMm,
        occupancy: impl Fn(ReservationMm) -> Option<SlotAbsence>,
        mut clear_tables: impl FnMut(&[RootGpa]) -> bool,
        mut clear_lifecycle: impl FnMut(ForkLifecycleLoan) -> bool,
        mut release: impl FnMut(&SlotAbsence) -> bool,
    ) -> Result<usize, ForkStockServiceError> {
        let active = MmKey::of(active);
        let candidates: Vec<(MmKey, SlotAbsence)> = self
            .quarantine
            .keys()
            .copied()
            .filter(|key| Some(*key) != active)
            .filter_map(|key| {
                let absence = occupancy(key.mm()?)?;
                (absence.mm().raw() == key.0.get()).then_some((key, absence))
            })
            .collect();
        let mut reclaimed = 0;
        for (key, absence) in candidates {
            let mm = key.mm().ok_or(ForkStockServiceError::InvalidRecord)?;
            let child = *self
                .children
                .get(&key)
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            let pages = self
                .committed_tables
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            // Carrier per-MM state (root registry, inventory, residency) is
            // released before any of the child's stock can be reissued.
            if self.quarantine.get(&key) == Some(&false) {
                if !release(&absence) {
                    return Err(ForkStockServiceError::ReleaseRefused);
                }
                self.quarantine.insert(key, true);
            }
            if !clear_tables(pages) || !clear_lifecycle(child.lifecycle) {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            self.tags.retire(child.tag, absence)?;
            self.children.remove(&key);
            if let Some(pages) = self.committed_tables.remove(&key) {
                for page in &pages {
                    ledger.give_back(*page, mm);
                }
                self.tables.extend(pages);
            }
            self.lifecycles.push(child.lifecycle);
            self.quarantine.remove(&key);
            reclaimed += 1;
            self.counters.returned_children = self.counters.returned_children.saturating_add(1);
        }
        Ok(reclaimed)
    }

    /// The container root exited and the VM ends with it: forget its custody.
    /// Its tag is never reissued, so no absence proof (impossible while the
    /// root is still installed on the exiting CPU) is needed.
    pub fn retire_exited_root(&mut self, mm: ReservationMm) {
        if let Some(key) = MmKey::of(mm) {
            self.children.remove(&key);
            self.quarantine.remove(&key);
        }
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
