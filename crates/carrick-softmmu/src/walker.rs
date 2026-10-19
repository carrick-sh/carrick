//! Stage-1 page-table walker binding over [`translate_leaf_hardware`], [`LiveDescriptorWords`],
//! [`LinearPlacement`], [`ExtentTable`], and [`SoftTlb`].

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use carrick_mmu_core::x86::descriptor_txn::{
    DEFAULT_MAX_PHY_ADDR, DescriptorRefusal, HardwareFaultClass, HardwareWalkConfig,
    LiveDescriptorWords, MAX_MAX_PHY_ADDR, MIN_MAX_PHY_ADDR, translate_leaf_hardware,
};

use crate::domains::{
    Access, AuthenticatedGpa, CpuAccessMode, FrameGpa, GuestVa, OwnerGeneration, PAGE_BASE_MASK_4K,
    PAGE_OFFSET_MASK_4K, PAGE_SIZE_4K, PageFaultClass, PageFaultInfo, RootGpa, SoftCpuException,
    SoftTranslationError, Stage1Gpa, TranslatedLeaf, X86Page4K,
};
use crate::placement::{HostVa, LinearPlacement, PlacementError, X86HostPage4K};
use crate::retirement::{
    CommitRefused, PendingRetirement, SoftDomainHandle, SoftRequester, SoftSeatError, SoftVcpuSeat,
    commit_domain,
};
use crate::tlb::SoftTlb;
use carrick_core::mm::retirement::invalidation::{
    DomainCompletion, GenerationExhausted, InvalidationKind, ReclaimQueue,
};

/// Committed physical extent record used to authenticate `(Stage1Gpa, len, OwnerGeneration) -> AuthenticatedGpa`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentRecord {
    /// Starting 4 KiB-aligned frame GPA of the extent.
    pub base: FrameGpa,
    /// Byte length of the extent (multiple of 4 KiB).
    pub len_bytes: u64,
    /// Active owner generation for this extent.
    pub generation: OwnerGeneration,
}

impl ExtentRecord {
    /// Construct a new 4 KiB-aligned extent record.
    pub const fn new(base: FrameGpa, len_bytes: u64, generation: OwnerGeneration) -> Self {
        Self {
            base,
            len_bytes,
            generation,
        }
    }

    /// Exclusive end GPA of the extent.
    pub const fn end_gpa(self) -> u64 {
        self.base.raw().saturating_add(self.len_bytes)
    }

    /// Return `true` if `[gpa, gpa + len_bytes)` lies wholly inside this extent.
    pub const fn contains_span(self, gpa: u64, len_bytes: u64) -> bool {
        let Some(span_end) = gpa.checked_add(len_bytes) else {
            return false;
        };
        gpa >= self.base.raw() && span_end <= self.end_gpa()
    }
}

/// One identity a retirement took out of use. It stays refused for reuse
/// until the retirement's [`DomainCompletion`] releases it through
/// [`ExtentTable::reclaim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetiredIdentity {
    ExtentBase(FrameGpa),
    ExtentGeneration(OwnerGeneration),
    Root(RootGpa),
    RootGeneration(OwnerGeneration),
}

/// Why an [`ExtentTable`] edit was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentEditError {
    /// Nothing changed: the record is malformed or overlaps, a retired
    /// identity it names is still pending, or the table is terminal.
    Refused,
    /// Nothing changed: the requester is a member of another inventory.
    ForeignRequester,
    /// The edit is in place but its invalidation could not be requested: the
    /// domain's generation counter is exhausted. The table is now terminal
    /// and refuses every later edit; the caller must stop its CPUs.
    Exhausted,
}

/// A retired value and the invalidation every soft vCPU owes for it.
#[derive(Debug)]
pub struct Retirement<T> {
    pub retired: T,
    pub pending: PendingRetirement,
}

/// Physical extent inventory and frame-keyed code-page tracker
/// authenticating `(Stage1Gpa, len, OwnerGeneration) -> AuthenticatedGpa`.
///
/// It owns the invalidation domain of every soft vCPU translating through
/// it: extent and root-generation retirement is a domain-wide request
/// (`crate::retirement`), and the retired identities wait in a
/// [`ReclaimQueue`] until the request completes.
#[derive(Debug)]
pub struct ExtentTable {
    by_base: BTreeMap<u64, ExtentRecord>,
    root_generations: BTreeMap<u64, OwnerGeneration>,
    code_pages: BTreeMap<u64, (bool, u64)>,
    extents_visited: AtomicU64,
    domain: SoftDomainHandle,
    reclaim: ReclaimQueue<RetiredIdentity>,
    terminal: bool,
}

/// Why [`ExtentTable::try_clone`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentCloneError {
    /// A retirement is still pending: a copy would forget which identities
    /// must stay refused until its completion.
    Pending,
    /// The table is terminal.
    Terminal,
    /// No fresh invalidation domain could be issued.
    Exhausted,
}

impl ExtentTable {
    /// Create an empty extent table with no registered roots and a fresh
    /// invalidation domain.
    pub fn new() -> Result<Self, GenerationExhausted> {
        Ok(Self {
            by_base: BTreeMap::new(),
            root_generations: BTreeMap::new(),
            code_pages: BTreeMap::new(),
            extents_visited: AtomicU64::new(0),
            domain: SoftDomainHandle::new()?,
            reclaim: ReclaimQueue::new(),
            terminal: false,
        })
    }

    /// An independent copy of the records in a fresh invalidation domain
    /// with no members. There is no `Clone`: a copy that shared this
    /// domain but not its reclaim queue could reuse an identity whose
    /// retirement is still in flight. Refused while any retirement is
    /// pending; soft vCPUs seated here are not members of the copy, so
    /// they refuse to translate through it.
    pub fn try_clone(&self) -> Result<Self, ExtentCloneError> {
        if self.terminal {
            return Err(ExtentCloneError::Terminal);
        }
        if !self.reclaim.is_empty() {
            return Err(ExtentCloneError::Pending);
        }
        Ok(Self {
            by_base: self.by_base.clone(),
            root_generations: self.root_generations.clone(),
            code_pages: self.code_pages.clone(),
            extents_visited: AtomicU64::new(self.extents_visited.load(Ordering::Relaxed)),
            domain: SoftDomainHandle::new()
                .map_err(|GenerationExhausted| ExtentCloneError::Exhausted)?,
            reclaim: ReclaimQueue::new(),
            terminal: false,
        })
    }

    /// Seat a soft vCPU whose translation cache is `tlb` in this
    /// inventory's domain. The claim flushes `tlb` before adopting the
    /// member, and the CPU starts parked.
    pub fn register_vcpu(&self, tlb: &mut SoftTlb) -> Result<SoftVcpuSeat, SoftSeatError> {
        SoftVcpuSeat::claim(&self.domain, tlb)
    }

    /// Whether `seat` is a member of this inventory's domain.
    pub fn is_member(&self, seat: &SoftVcpuSeat) -> bool {
        seat.belongs_to(&self.domain)
    }

    /// Kicks issued by this domain's retirements so far.
    pub fn retirement_kicks(&self) -> u64 {
        self.domain.kicks()
    }

    /// Retired identities still waiting for their completion.
    pub fn pending_identities(&self) -> usize {
        self.reclaim.len()
    }

    /// Release the identities a completed retirement took out of use.
    /// Returns how many became reusable.
    pub fn reclaim(&mut self, completion: &DomainCompletion) -> usize {
        self.reclaim.drain_ready(completion).len()
    }

    fn is_pending(&self, identity: RetiredIdentity) -> bool {
        self.reclaim.iter().any(|pending| *pending == identity)
    }

    fn admit_edit(&self, requester: Option<&SoftRequester<'_>>) -> Result<(), ExtentEditError> {
        if self.terminal {
            return Err(ExtentEditError::Refused);
        }
        if requester.is_some_and(|requester| !requester.seat.belongs_to(&self.domain)) {
            return Err(ExtentEditError::ForeignRequester);
        }
        Ok(())
    }

    /// Publish the domain-wide invalidation for an edit already in place and
    /// queue its retired identities.
    fn retire(
        &mut self,
        identities: [RetiredIdentity; 2],
        requester: Option<SoftRequester<'_>>,
    ) -> Result<PendingRetirement, ExtentEditError> {
        match commit_domain(&self.domain, InvalidationKind::Unmap, requester) {
            Ok(pending) => {
                for identity in identities {
                    self.reclaim.push(pending.reclaim_tag(), identity);
                }
                Ok(pending)
            }
            // The edit is in place and cannot be invalidated: terminal.
            Err(CommitRefused::Exhausted | CommitRefused::ForeignRequester) => {
                self.terminal = true;
                Err(ExtentEditError::Exhausted)
            }
        }
    }

    /// Register the expected [`OwnerGeneration`] for walks under an
    /// unregistered `root` (`false` if already registered, or if the root or
    /// generation is still pending retirement).
    pub fn set_root_generation(&mut self, root: RootGpa, generation: OwnerGeneration) -> bool {
        if self.terminal
            || self.root_generations.contains_key(&root.address().raw())
            || self.is_pending(RetiredIdentity::Root(root))
            || self.is_pending(RetiredIdentity::RootGeneration(generation))
        {
            return false;
        }
        self.root_generations
            .insert(root.address().raw(), generation);
        true
    }
    /// Replace (or set) `root`'s [`OwnerGeneration`]. Replacing a live
    /// generation retires it: every soft vCPU owes the returned invalidation.
    pub fn replace_root_generation(
        &mut self,
        root: RootGpa,
        generation: OwnerGeneration,
        requester: Option<SoftRequester<'_>>,
    ) -> Result<Option<Retirement<OwnerGeneration>>, ExtentEditError> {
        self.admit_edit(requester.as_ref())?;
        if self.is_pending(RetiredIdentity::Root(root))
            || self.is_pending(RetiredIdentity::RootGeneration(generation))
        {
            return Err(ExtentEditError::Refused);
        }
        let Some(previous) = self
            .root_generations
            .insert(root.address().raw(), generation)
        else {
            return Ok(None);
        };
        let pending = self.retire(
            [
                RetiredIdentity::Root(root),
                RetiredIdentity::RootGeneration(previous),
            ],
            requester,
        )?;
        Ok(Some(Retirement {
            retired: previous,
            pending,
        }))
    }
    /// Remove `root`'s generation registration, retiring it.
    pub fn remove_root_generation(
        &mut self,
        root: RootGpa,
        requester: Option<SoftRequester<'_>>,
    ) -> Result<Option<Retirement<OwnerGeneration>>, ExtentEditError> {
        self.admit_edit(requester.as_ref())?;
        let Some(removed) = self.root_generations.remove(&root.address().raw()) else {
            return Ok(None);
        };
        let pending = self.retire(
            [
                RetiredIdentity::Root(root),
                RetiredIdentity::RootGeneration(removed),
            ],
            requester,
        )?;
        Ok(Some(Retirement {
            retired: removed,
            pending,
        }))
    }
    /// Return the registered [`OwnerGeneration`] for `root` (`None` if `root` is unregistered).
    pub fn expected_generation(&self, root: RootGpa) -> Option<OwnerGeneration> {
        self.root_generations.get(&root.address().raw()).copied()
    }
    pub fn extents_visited(&self) -> u64 {
        self.extents_visited.load(Ordering::Relaxed)
    }
    pub fn reset_extents_visited(&self) {
        self.extents_visited.store(0, Ordering::Relaxed);
    }

    fn validate_non_overlapping(&self, record: ExtentRecord, allow_replace_base: bool) -> bool {
        let base = record.base.raw();
        if record.len_bytes == 0
            || (base & PAGE_OFFSET_MASK_4K) != 0
            || (record.len_bytes & PAGE_OFFSET_MASK_4K) != 0
        {
            return false;
        }
        let Some(end) = base.checked_add(record.len_bytes) else {
            return false;
        };
        if let Some((_, prev)) = self.by_base.range(..=base).next_back() {
            if prev.base.raw() == base {
                if !allow_replace_base {
                    return false;
                }
            } else if prev.end_gpa() > base {
                return false;
            }
        }
        if let Some((&next_base, _)) = self.by_base.range(base..).find(|&(&k, _)| k != base)
            && next_base < end
        {
            return false;
        }
        true
    }

    fn clear_code_pages_in_span(&mut self, base: u64, end: u64) {
        let keys: alloc::vec::Vec<u64> =
            self.code_pages.range(base..end).map(|(&k, _)| k).collect();
        for k in keys {
            if let Some(entry) = self.code_pages.get_mut(&k) {
                entry.0 = false;
            }
        }
    }

    fn extent_pending(&self, record: ExtentRecord) -> bool {
        self.is_pending(RetiredIdentity::ExtentBase(record.base))
            || self.is_pending(RetiredIdentity::ExtentGeneration(record.generation))
    }

    /// Install a new, non-overlapping extent (`false` if unaligned, empty,
    /// overlapping any existing extent, or naming a base or generation that
    /// is still pending retirement).
    pub fn install(&mut self, record: ExtentRecord) -> bool {
        if self.terminal
            || !self.validate_non_overlapping(record, false)
            || self.extent_pending(record)
        {
            return false;
        }
        self.by_base.insert(record.base.raw(), record);
        true
    }
    /// Replace (or install) an extent at `record.base`. Replacing a live
    /// extent retires it: every soft vCPU owes the returned invalidation.
    pub fn replace(
        &mut self,
        record: ExtentRecord,
        requester: Option<SoftRequester<'_>>,
    ) -> Result<Option<Retirement<ExtentRecord>>, ExtentEditError> {
        self.admit_edit(requester.as_ref())?;
        if !self.validate_non_overlapping(record, true) || self.extent_pending(record) {
            return Err(ExtentEditError::Refused);
        }
        let Some(old) = self.by_base.insert(record.base.raw(), record) else {
            return Ok(None);
        };
        self.clear_code_pages_in_span(old.base.raw(), old.end_gpa());
        let pending = self.retire(
            [
                RetiredIdentity::ExtentBase(old.base),
                RetiredIdentity::ExtentGeneration(old.generation),
            ],
            requester,
        )?;
        Ok(Some(Retirement {
            retired: old,
            pending,
        }))
    }
    /// Retire the extent starting at `base`: every soft vCPU owes the
    /// returned invalidation before its base or generation is reusable.
    pub fn remove(
        &mut self,
        base: FrameGpa,
        requester: Option<SoftRequester<'_>>,
    ) -> Result<Option<Retirement<ExtentRecord>>, ExtentEditError> {
        self.admit_edit(requester.as_ref())?;
        let Some(old) = self.by_base.remove(&base.raw()) else {
            return Ok(None);
        };
        self.clear_code_pages_in_span(old.base.raw(), old.end_gpa());
        let pending = self.retire(
            [
                RetiredIdentity::ExtentBase(old.base),
                RetiredIdentity::ExtentGeneration(old.generation),
            ],
            requester,
        )?;
        Ok(Some(Retirement {
            retired: old,
            pending,
        }))
    }
    /// Look up the single predecessor extent covering `[gpa, gpa + len_bytes)`.
    pub fn lookup_span(&self, gpa: u64, len_bytes: u64) -> Option<ExtentRecord> {
        self.extents_visited.fetch_add(1, Ordering::Relaxed);
        let (_, record) = self.by_base.range(..=gpa).next_back()?;
        record.contains_span(gpa, len_bytes).then_some(*record)
    }

    pub(crate) fn authenticate(
        &self,
        stage1_gpa: Stage1Gpa,
        len_bytes: u64,
        expected_generation: OwnerGeneration,
    ) -> Option<AuthenticatedGpa> {
        let page_gpa = stage1_gpa.raw() & PAGE_BASE_MASK_4K;
        let record = self.lookup_span(page_gpa, len_bytes)?;
        (record.generation == expected_generation)
            .then_some(AuthenticatedGpa::from_authenticated_raw(page_gpa))
    }

    pub(crate) fn authenticate_table_frame(
        &self,
        table: Stage1Gpa,
        expected_generation: OwnerGeneration,
    ) -> Option<AuthenticatedGpa> {
        self.authenticate(table, PAGE_SIZE_4K, expected_generation)
    }

    pub(crate) fn authenticate_leaf(
        &self,
        root: RootGpa,
        leaf: &TranslatedLeaf,
    ) -> Result<AuthenticatedGpa, Option<OwnerGeneration>> {
        let expected = self.expected_generation(root).ok_or(None)?;
        let leaf_size = if leaf.size >= PAGE_SIZE_4K && leaf.size.is_power_of_two() {
            leaf.size
        } else {
            PAGE_SIZE_4K
        };
        let leaf_base = Stage1Gpa::from_leaf_base(leaf);
        let record = self
            .lookup_span(leaf_base.raw(), leaf_size)
            .ok_or(Some(expected))?;
        if record.generation != expected {
            return Err(Some(expected));
        }
        Ok(AuthenticatedGpa::from_authenticated_raw(
            leaf.output.raw() & PAGE_BASE_MASK_4K,
        ))
    }

    /// Mark `frame_gpa` as holding cached translated blocks and flush the `write` plane across `tlbs`.
    pub fn mark_code_page(
        &mut self,
        frame_gpa: AuthenticatedGpa,
        tlbs: &mut [&mut SoftTlb],
    ) -> u64 {
        let entry = self.code_pages.entry(frame_gpa.raw()).or_insert((false, 0));
        entry.0 = true;
        if entry.1 == 0 {
            entry.1 = 1;
        }
        let code_gen = entry.1;
        for tlb in tlbs {
            tlb.flush_write_plane();
        }
        code_gen
    }
    pub fn clear_code_page(&mut self, frame_gpa: AuthenticatedGpa) {
        if let Some(entry) = self.code_pages.get_mut(&frame_gpa.raw()) {
            entry.0 = false;
        }
    }
    pub fn is_code_page(&self, frame_gpa: AuthenticatedGpa) -> bool {
        self.code_pages
            .get(&frame_gpa.raw())
            .is_some_and(|&(active, _)| active)
    }
    pub fn code_generation(&self, frame_gpa: AuthenticatedGpa) -> u64 {
        self.code_pages
            .get(&frame_gpa.raw())
            .map_or(0, |&(_, generation)| generation)
    }
    /// Bump `frame_gpa`'s code generation on guest write and flush `write`
    /// planes across `peer_tlbs`. `None` once the frame's generation is
    /// exhausted: the bump is refused (never saturated, which would let a
    /// stale translated block match a rewritten page) and nothing changes.
    pub fn on_code_page_write(
        &mut self,
        frame_gpa: AuthenticatedGpa,
        peer_tlbs: &mut [&mut SoftTlb],
    ) -> Option<u64> {
        let current = self
            .code_pages
            .get(&frame_gpa.raw())
            .map_or(0, |&(_, generation)| generation);
        let code_gen = current.checked_add(1)?;
        self.code_pages.insert(frame_gpa.raw(), (true, code_gen));
        for tlb in peer_tlbs {
            tlb.flush_write_plane();
        }
        Some(code_gen)
    }
}

/// Trait representing the guest-physical memory and extent inventory seen by [`SoftWalker`].
///
/// # Safety
///
/// Implementors must uphold [`LinearPlacement::new`]'s host-memory contract for
/// every host range admitted by placement bounds and extent authentication;
/// extent metadata may describe ranges that placement rejects. Admitted
/// page-table words must support aligned `AtomicU64` accesses. Backing storage
/// must remain initialized, readable, writable and at a stable address while
/// borrowed for walks and native/JIT accesses, including callbacks. Consumers
/// of cached host addresses must retain the originating memory for every access
/// and discard stale translations before using a different placement. Shared
/// access must not introduce conflicting Rust references or data races; in
/// particular, page-table atomics must not race with non-atomic guest accesses.
/// A borrowed placement alone does not keep its backing alive.
pub unsafe trait SoftMmuMemory {
    fn placement(&self) -> &LinearPlacement;
    fn extents(&self) -> &ExtentTable;
    fn extents_mut(&mut self) -> &mut ExtentTable;
    fn on_descriptor_load(&self) {}
    fn before_descriptor_cas(&self, _pa: u64, _slot: &AtomicU64, _current: u64, _new: u64) {}
    fn mark_code_page(&mut self, frame_gpa: AuthenticatedGpa, tlbs: &mut [&mut SoftTlb]) -> u64 {
        self.extents_mut().mark_code_page(frame_gpa, tlbs)
    }
    fn is_code_page(&self, frame_gpa: AuthenticatedGpa) -> bool {
        self.extents().is_code_page(frame_gpa)
    }
    fn code_generation(&self, frame_gpa: AuthenticatedGpa) -> u64 {
        self.extents().code_generation(frame_gpa)
    }
}

/// Crate-owned [`LiveDescriptorWords`] adapter that authenticates every page-table frame load
/// and `ACCESSED`/`DIRTY` CAS against `root`'s registered [`OwnerGeneration`] and accesses the
/// authenticated [`AtomicU64`] at `placement.host(table_frame) + (pa & 0xfff)`.
pub struct AuthenticatedDescriptorWords<'a, M: SoftMmuMemory + ?Sized> {
    memory: &'a M,
    root: RootGpa,
}

impl<'a, M: SoftMmuMemory + ?Sized> AuthenticatedDescriptorWords<'a, M> {
    pub const fn new(memory: &'a M, root: RootGpa) -> Self {
        Self { memory, root }
    }
    fn word_slot(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        if (pa & 0x7) != 0 {
            return Err(DescriptorRefusal::BadRange);
        }
        let expected_gen = self
            .memory
            .extents()
            .expected_generation(self.root)
            .ok_or(DescriptorRefusal::MissingTable)?;
        let table_frame = self
            .memory
            .extents()
            .authenticate_table_frame(Stage1Gpa::new(pa & PAGE_BASE_MASK_4K), expected_gen)
            .ok_or(DescriptorRefusal::MissingTable)?;
        let host_page = self
            .memory
            .placement()
            .host(table_frame)
            .map_err(|_| DescriptorRefusal::MissingTable)?;
        let word_addr = host_page.page_base() + ((pa & PAGE_OFFSET_MASK_4K) as usize);
        // SAFETY: SoftMmuMemory guarantees live, initialized backing and atomic
        // access compatibility. Authentication and placement bounds cover this
        // table page, and the checked 8-byte offset keeps the word aligned and in-page.
        Ok(unsafe { &*(word_addr as *const AtomicU64) })
    }
}

impl<M: SoftMmuMemory + ?Sized> LiveDescriptorWords for AuthenticatedDescriptorWords<'_, M> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let slot = self.word_slot(pa)?;
        self.memory.on_descriptor_load();
        Ok(slot.load(Ordering::Acquire))
    }
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        let slot = self.word_slot(pa)?;
        self.memory.before_descriptor_cas(pa, slot, current, new);
        Ok(slot
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.word_slot(pa)?.store(value, Ordering::Release);
        Ok(())
    }
    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    fn invalidate_range(&self, _va: u64, _len: u64) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// Successful single-page RAM translation returned by [`SoftWalker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedAccess {
    pub host_addr: usize,
    pub host_page: HostVa,
    pub frame_gpa: AuthenticatedGpa,
    pub leaf: TranslatedLeaf,
    pub is_user_page: bool,
    pub code_generation: u64,
    pub invalidated_code_page: bool,
}

/// Non-fault outcome of resolving a single-page guest memory access via [`SoftWalker::walk_and_fill`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    Ram(ResolvedAccess),
    Mmio { gpa: u64, leaf: TranslatedLeaf },
}

/// Non-fault outcome of [`SoftWalker::probe_or_walk_outcome`] for a single-page access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessOutcome {
    Ram(usize),
    Mmio { gpa: u64, leaf: TranslatedLeaf },
}

/// Non-fault outcome of [`SoftWalker::resolve_span`] for an operand of length `1..=4096`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedSpan {
    SinglePage {
        host_addr: usize,
        len: usize,
    },
    Straddling {
        first_host_addr: usize,
        first_len: usize,
        second_host_addr: usize,
        second_len: usize,
    },
    Mmio {
        va: GuestVa,
        gpa: u64,
        len: usize,
        leaf: TranslatedLeaf,
    },
}

/// Deterministic structural counters for [`SoftWalker`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftWalkerStats {
    pub walks: u64,
    pub tlb_fills: u64,
    pub page_faults: u64,
    pub cpu_exceptions: u64,
    pub descriptor_load_errors: u64,
    pub ad_cas_retries_exhausted: u64,
    pub mmio_exits: u64,
    pub code_page_invalidations: u64,
    pub page_crossing_accesses: u64,
}

/// Stage-1 page-table walker binding that enforces x86 hardware permission rules in a single walk
/// via [`translate_leaf_hardware`] and populates [`SoftTlb`].
#[derive(Clone, Copy, Debug)]
pub struct SoftWalker {
    max_phy_addr: u8,
    nxe: bool,
    stats: SoftWalkerStats,
}

impl Default for SoftWalker {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftWalker {
    pub const fn new() -> Self {
        Self::with_paging_config(DEFAULT_MAX_PHY_ADDR, true)
    }
    pub const fn with_max_phy_addr(max_phy_addr: u8) -> Self {
        Self::with_paging_config(max_phy_addr, true)
    }
    pub const fn with_paging_config(max_phy_addr: u8, nxe: bool) -> Self {
        let clamped = if max_phy_addr < MIN_MAX_PHY_ADDR {
            MIN_MAX_PHY_ADDR
        } else if max_phy_addr > MAX_MAX_PHY_ADDR {
            MAX_MAX_PHY_ADDR
        } else {
            max_phy_addr
        };
        Self {
            max_phy_addr: clamped,
            nxe,
            stats: SoftWalkerStats {
                walks: 0,
                tlb_fills: 0,
                page_faults: 0,
                cpu_exceptions: 0,
                descriptor_load_errors: 0,
                ad_cas_retries_exhausted: 0,
                mmio_exits: 0,
                code_page_invalidations: 0,
                page_crossing_accesses: 0,
            },
        }
    }
    pub const fn max_phy_addr(&self) -> u8 {
        self.max_phy_addr
    }
    pub fn set_max_phy_addr(&mut self, max_phy_addr: u8) {
        self.max_phy_addr = max_phy_addr.clamp(MIN_MAX_PHY_ADDR, MAX_MAX_PHY_ADDR);
    }
    pub const fn nxe(&self) -> bool {
        self.nxe
    }
    pub fn set_nxe(&mut self, nxe: bool) {
        self.nxe = nxe;
    }
    pub const fn stats(&self) -> SoftWalkerStats {
        self.stats
    }
    pub fn reset_stats(&mut self) {
        self.stats = SoftWalkerStats::default();
    }

    fn non_canonical_exception(
        &mut self,
        va: GuestVa,
        access: Access,
        mode: CpuAccessMode,
    ) -> SoftTranslationError {
        self.stats.cpu_exceptions += 1;
        let exc = if mode.stack_access {
            SoftCpuException::StackSegment0 { va, access }
        } else {
            SoftCpuException::GeneralProtection0 { va, access }
        };
        SoftTranslationError::CpuException(exc)
    }

    /// Perform a single slow-path stage-1 hardware walk via [`translate_leaf_hardware`] and populate `tlb`.
    pub fn walk_and_fill<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<WalkOutcome, SoftTranslationError> {
        self.stats.walks += 1;
        let effective_nxe = self.nxe && mode.efer_nxe;
        let effective_mode = mode.with_efer_nxe(effective_nxe);
        let hw_config = HardwareWalkConfig {
            max_phy_addr: self.max_phy_addr,
            nxe: effective_nxe,
            cr0_wp: effective_mode.cr0_wp,
            cr4_smep: effective_mode.cr4_smep,
            cr4_smap: effective_mode.cr4_smap,
            rflags_ac: effective_mode.ac,
            update_ad: true,
        };

        let walk_res = {
            let checked = AuthenticatedDescriptorWords::new(memory, root);
            let dva = va.to_descriptor_va();
            translate_leaf_hardware(
                &checked,
                root,
                dva,
                access,
                effective_mode.cpl.is_user(),
                &hw_config,
            )
        };
        let leaf = match walk_res {
            Ok(leaf) => leaf,
            Err(HardwareFaultClass::NonCanonical) => {
                return Err(self.non_canonical_exception(va, access, effective_mode));
            }
            Err(HardwareFaultClass::DescriptorLoad(refusal)) => {
                self.stats.descriptor_load_errors += 1;
                return Err(SoftTranslationError::DescriptorLoad { va, refusal });
            }
            Err(HardwareFaultClass::AdCasRetryExhausted { retries }) => {
                self.stats.ad_cas_retries_exhausted += 1;
                return Err(SoftTranslationError::AdCasRetryExhausted { va, retries });
            }
            Err(hw_fault) => {
                let pf_class = match hw_fault {
                    HardwareFaultClass::NotPresent => PageFaultClass::NotPresent,
                    HardwareFaultClass::Reserved => PageFaultClass::ReservedBit,
                    HardwareFaultClass::Protection => PageFaultClass::Protection,
                    HardwareFaultClass::CowWrite => PageFaultClass::CowWrite,
                    HardwareFaultClass::Nx => PageFaultClass::NxProtection,
                    HardwareFaultClass::Smep => PageFaultClass::SmepProtection,
                    HardwareFaultClass::Smap => PageFaultClass::SmapProtection,
                    _ => unreachable!(),
                };
                self.stats.page_faults += 1;
                self.stats.cpu_exceptions += 1;
                let pf = PageFaultInfo::new(va, access, effective_mode, pf_class, None);
                return Err(SoftTranslationError::CpuException(
                    SoftCpuException::PageFault(pf),
                ));
            }
        };

        let page_stage1 = Stage1Gpa::from_leaf_page(&leaf);
        let byte_gpa = leaf.output.raw();
        if memory.placement().is_mmio_hole(page_stage1.raw())
            || memory.placement().is_mmio_hole(byte_gpa)
        {
            self.stats.mmio_exits += 1;
            return Ok(WalkOutcome::Mmio {
                gpa: byte_gpa,
                leaf,
            });
        }

        let frame_gpa =
            memory
                .extents()
                .authenticate_leaf(root, &leaf)
                .map_err(
                    |expected_generation| SoftTranslationError::UnauthenticatedExtent {
                        va,
                        stage1_gpa: Stage1Gpa::from_leaf_base(&leaf),
                        expected_generation,
                        leaf,
                    },
                )?;

        let host_page = match memory.placement().host(frame_gpa) {
            Ok(host_va) => host_va,
            Err(PlacementError::MmioHole { gpa }) => {
                self.stats.mmio_exits += 1;
                return Ok(WalkOutcome::Mmio {
                    gpa: gpa | (va.page_offset() as u64),
                    leaf,
                });
            }
            Err(error) => {
                return Err(SoftTranslationError::Placement {
                    va,
                    frame_gpa,
                    error,
                });
            }
        };

        let was_code_page = memory.is_code_page(frame_gpa);
        let mut invalidated_code_page = false;
        let fill = |tlb: &mut SoftTlb, plane: Access| {
            tlb.fill_plane_with_leaf_size(plane, va, effective_mode, host_page, leaf.size);
        };
        match access {
            Access::Read => {
                fill(tlb, Access::Read);
                self.stats.tlb_fills += 1;
            }
            Access::Write => {
                fill(tlb, Access::Read);
                self.stats.tlb_fills += 1;
                if was_code_page {
                    tlb.flush_write_plane();
                    memory
                        .extents_mut()
                        .on_code_page_write(frame_gpa, &mut [])
                        .ok_or(SoftTranslationError::CodeGenerationExhausted { va, frame_gpa })?;
                    invalidated_code_page = true;
                    self.stats.code_page_invalidations += 1;
                } else {
                    fill(tlb, Access::Write);
                    self.stats.tlb_fills += 1;
                }
            }
            Access::Execute => {
                if was_code_page {
                    let _ = tlb.evict_write_va(va);
                }
                fill(tlb, Access::Execute);
                self.stats.tlb_fills += 1;
            }
        }

        Ok(WalkOutcome::Ram(ResolvedAccess {
            host_addr: host_page.page_base() + va.page_offset(),
            host_page,
            frame_gpa,
            leaf,
            is_user_page: leaf.effective_user,
            code_generation: memory.code_generation(frame_gpa),
            invalidated_code_page,
        }))
    }

    /// Fast-path TLB probe followed by slow-path [`Self::walk_and_fill`] for a single-page access.
    #[allow(clippy::too_many_arguments)]
    pub fn probe_or_walk_outcome<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<AccessOutcome, SoftTranslationError> {
        let effective_mode = mode.with_efer_nxe(self.nxe && mode.efer_nxe);
        if let Some(host_addr) = tlb.probe(va, len, access, effective_mode) {
            return Ok(AccessOutcome::Ram(host_addr));
        }
        match self.walk_and_fill(memory, tlb, root, va, access, effective_mode)? {
            WalkOutcome::Ram(resolved) => Ok(AccessOutcome::Ram(resolved.host_addr)),
            WalkOutcome::Mmio { gpa, leaf } => Ok(AccessOutcome::Mmio { gpa, leaf }),
        }
    }

    /// Resolve a potentially page-crossing guest memory operand of length `1..=4096` bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_span<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<ResolvedSpan, SoftTranslationError> {
        let effective_mode = mode.with_efer_nxe(self.nxe && mode.efer_nxe);
        if !va.crosses_page(len) {
            return match self.probe_or_walk_outcome(
                memory,
                tlb,
                root,
                va,
                len,
                access,
                effective_mode,
            )? {
                AccessOutcome::Ram(host_addr) => Ok(ResolvedSpan::SinglePage { host_addr, len }),
                AccessOutcome::Mmio { gpa, leaf } => Ok(ResolvedSpan::Mmio { va, gpa, len, leaf }),
            };
        }

        let _ = tlb.probe(va, len, access, effective_mode);
        self.stats.page_crossing_accesses += 1;
        if !va.is_canonical_48bit() {
            return Err(self.non_canonical_exception(va, access, effective_mode));
        }

        let first_len = (PAGE_SIZE_4K as usize) - va.page_offset();
        let second_len = len.saturating_sub(first_len);
        let second_va = match va.checked_add(first_len as u64) {
            Some(next) if next.is_canonical_48bit() => next,
            Some(non_canon) => {
                return Err(self.non_canonical_exception(non_canon, access, effective_mode));
            }
            None => return Err(self.non_canonical_exception(va, access, effective_mode)),
        };

        let first_host_addr =
            match self.walk_and_fill(memory, tlb, root, va, access, effective_mode)? {
                WalkOutcome::Ram(r) => r.host_addr,
                WalkOutcome::Mmio { gpa, leaf } => {
                    return Ok(ResolvedSpan::Mmio {
                        va,
                        gpa,
                        len: first_len,
                        leaf,
                    });
                }
            };
        let second_host_addr =
            match self.walk_and_fill(memory, tlb, root, second_va, access, effective_mode)? {
                WalkOutcome::Ram(r) => r.host_addr,
                WalkOutcome::Mmio { gpa, leaf } => {
                    return Ok(ResolvedSpan::Mmio {
                        va: second_va,
                        gpa,
                        len: second_len,
                        leaf,
                    });
                }
            };
        Ok(ResolvedSpan::Straddling {
            first_host_addr,
            first_len,
            second_host_addr,
            second_len,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn code_generation_refuses_exhaustion_instead_of_saturating() {
        let mut table = ExtentTable::new().expect("fresh domain");
        let frame = AuthenticatedGpa::from_authenticated_raw(0x5000);
        assert_eq!(table.mark_code_page(frame, &mut []), 1);
        assert_eq!(table.on_code_page_write(frame, &mut []), Some(2));
        table.code_pages.insert(frame.raw(), (true, u64::MAX));
        assert_eq!(table.on_code_page_write(frame, &mut []), None);
        assert_eq!(table.code_generation(frame), u64::MAX, "nothing changed");
    }
}
