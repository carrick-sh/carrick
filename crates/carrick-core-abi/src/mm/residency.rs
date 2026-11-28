//! Exact live residency and retained grant-window custody for either ISA.
use crate::{
    ExtentGrantReceipt, MetadataExtent, MetadataExtentResolver, MetadataResolutionError,
    PinnedMetadataExtent, ReservationMetadataAllocator,
};
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod interleaving_tests;
mod pause;
mod transfer;
use pause::Point;
pub use transfer::{
    FrameGrantResidencyTransfer, ResidencyTransferRefusal, TransferRange, TransferReceipt,
};

pub const FRAME_GRANT_RESIDENCY_SLOTS: usize = 4096;
const MAX_RESIDENCY_EXTENSIONS: usize = 256;
/// Requested bulk extent: 512 Linux pages, clamped by the supplying adapter
/// at the exact VMA or alignment edge.
pub const EL1_FRAME_GRANT_TARGET_SIZE: u64 = 2 * 1024 * 1024;

const GRANT_EMPTY: u64 = 0;
const GRANT_RETIRED: u64 = 1;
const GRANT_WRITING: u64 = 2;
const GRANT_LIVE: u64 = 3;
const GRANT_STATE_MASK: u64 = 3;
pub const GRANT_PAGE_SIZE: u64 = 4096;
const GRANT_PROBES: usize = 64;
pub const TRANSFER_PIN_RETIRED: u64 = 1 << 63;
const TRANSFER_PIN_RETIRING: u64 = TRANSFER_PIN_RETIRED | 1;

/// Exact frame ownership carried beside the residency bits. A slot cannot
/// authorize a reused mapping or frame with the same VA and IPA but a new
/// owner generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameGrantResidencyIdentity {
    pub mm_key: u64,
    pub semantic_base: u64,
    pub physical_ipa: u64,
    pub len: u64,
    pub mapping_id: u64,
    pub frame_id: u64,
    pub owner_generation: u64,
    pub inventory_revision: u64,
}

impl FrameGrantResidencyIdentity {
    fn valid(self) -> bool {
        let Some(end) = self.semantic_base.checked_add(self.len) else {
            return false;
        };
        self.mm_key != 0
            && self.mapping_id != 0
            && self.frame_id != 0
            && self.owner_generation != 0
            && self.inventory_revision != 0
            && self.len != 0
            && self.len <= EL1_FRAME_GRANT_TARGET_SIZE
            && self.semantic_base.is_multiple_of(GRANT_PAGE_SIZE)
            && self.physical_ipa.is_multiple_of(GRANT_PAGE_SIZE)
            && self.len.is_multiple_of(GRANT_PAGE_SIZE)
            && self.physical_ipa.checked_add(self.len).is_some()
            && (self.semantic_base / EL1_FRAME_GRANT_TARGET_SIZE)
                == ((end - 1) / EL1_FRAME_GRANT_TARGET_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameGrantResidencyPage {
    pub slot: usize,
    pub identity: FrameGrantResidencyIdentity,
    pub expected_ipa: u64,
    epoch: u64,
    bit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameGrantResidencyRefusal {
    InvalidIdentity,
    Overlap,
    Capacity,
}

/// One grant's identity and 512 per-page residency bits. `GRANT_LIVE` is
/// published last; retirement removes it first. All callers changing leaves
/// or bits hold the exact-MM editor, including the host mutation pause.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyRecord {
    state: AtomicU64,
    mm_key: AtomicU64,
    semantic_base: AtomicU64,
    physical_ipa: AtomicU64,
    len: AtomicU64,
    mapping_id: AtomicU64,
    frame_id: AtomicU64,
    owner_generation: AtomicU64,
    inventory_revision: AtomicU64,
    committed: [AtomicU64; 8],
    transfer_pins: AtomicU64,
    // Keep the existing 192-byte wire record fully initialized. This occupies
    // the former tail padding without moving any published field.
    _reserved: [u64; 6],
}

impl FrameGrantResidencyRecord {
    pub const COMMITTED_OFFSET: usize = core::mem::offset_of!(Self, committed);
    pub const TRANSFER_PINS_OFFSET: usize = core::mem::offset_of!(Self, transfer_pins);
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(GRANT_EMPTY),
            mm_key: AtomicU64::new(0),
            semantic_base: AtomicU64::new(0),
            physical_ipa: AtomicU64::new(0),
            len: AtomicU64::new(0),
            mapping_id: AtomicU64::new(0),
            frame_id: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            inventory_revision: AtomicU64::new(0),
            committed: [const { AtomicU64::new(0) }; 8],
            transfer_pins: AtomicU64::new(TRANSFER_PIN_RETIRED),
            _reserved: [0; 6],
        }
    }

    fn identity(&self) -> FrameGrantResidencyIdentity {
        FrameGrantResidencyIdentity {
            mm_key: self.mm_key.load(Ordering::Relaxed),
            semantic_base: self.semantic_base.load(Ordering::Relaxed),
            physical_ipa: self.physical_ipa.load(Ordering::Relaxed),
            len: self.len.load(Ordering::Relaxed),
            mapping_id: self.mapping_id.load(Ordering::Relaxed),
            frame_id: self.frame_id.load(Ordering::Relaxed),
            owner_generation: self.owner_generation.load(Ordering::Relaxed),
            inventory_revision: self.inventory_revision.load(Ordering::Relaxed),
        }
    }

    /// Write `identity` into a slot its writer owns (a reservation, or a
    /// closed row being re-keyed in place by a seeded mutant). No state or
    /// pin changes.
    fn write_identity(&self, identity: FrameGrantResidencyIdentity) {
        self.mm_key.store(identity.mm_key, Ordering::Relaxed);
        self.semantic_base
            .store(identity.semantic_base, Ordering::Relaxed);
        self.physical_ipa
            .store(identity.physical_ipa, Ordering::Relaxed);
        self.len.store(identity.len, Ordering::Relaxed);
        self.mapping_id
            .store(identity.mapping_id, Ordering::Relaxed);
        self.frame_id.store(identity.frame_id, Ordering::Relaxed);
        self.owner_generation
            .store(identity.owner_generation, Ordering::Relaxed);
        self.inventory_revision
            .store(identity.inventory_revision, Ordering::Relaxed);
    }
}

/// One claimed slot: its index and the exact `GRANT_WRITING` state the
/// claim wrote, whose generation no other claim of the slot ever repeats.
/// Only [`FrameGrantResidencyTable::reserve_slot`] makes one, and it is
/// neither `Copy` nor `Clone`: it is spent once, by value, by
/// [`FrameGrantResidencyTable::publish_reservation`] or
/// [`FrameGrantResidencyTable::release_reservation`], and each checks the
/// slot still holds this exact claim before it changes anything. A stale or
/// replayed spend therefore cannot touch another owner's reservation. Every
/// holder (a replacement, a retirement, a transfer) releases the ones it
/// still holds when it is dropped.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a reservation is published into or released"]
pub(crate) struct Reservation {
    slot: usize,
    claimed_state: u64,
}

impl Default for FrameGrantResidencyRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// An exact-generation grant-window residency lease. Retirement is refused
/// until every lease drops. This guards grant-window publication only; it
/// does not retain physical frames. Physical custody belongs to the host
/// CarrierVmCustody stage-2 pin and retirement protocol.
/// The shared table must outlive every lease, including canceled operations.
pub struct FrameGrantTransferPin<'a> {
    record: &'a FrameGrantResidencyRecord,
    releases: &'a AtomicU64,
}
impl Drop for FrameGrantTransferPin<'_> {
    fn drop(&mut self) {
        self.record.transfer_pins.fetch_sub(1, Ordering::AcqRel);
        // The release event a refused edit enrols on (see
        // [`FrameGrantResidencyTable::lease_released`]).
        self.releases.fetch_add(1, Ordering::Release);
    }
}

/// What a `Leased` refusal observed: the table's lease-release count before
/// it tried to close the rows. The refused caller enrols on the lease's
/// release, probes [`FrameGrantResidencyTable::lease_released`] once, and
/// reruns: contention is "not now", never an errno or a poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRelease {
    observed: u64,
}

/// Exact-MM reservation of every residency row overlapping one descriptor
/// retirement. The caller either commits after the descriptor transaction or
/// drops this token to reopen transfer admission without changing residency.
pub struct FrameGrantResidencyRetirement<'a> {
    table: FrameGrantResidencyTable<ResidencyRows<'a>>,
    preclaim: Option<ResidencyRetirementPreclaim>,
}
impl FrameGrantResidencyRetirement<'_> {
    /// Retire the preclaimed rows after their stage-1 leaves are unreachable.
    /// Exact-MM exclusion makes a failed commit an invariant violation.
    #[must_use]
    pub fn commit(mut self) -> bool {
        self.preclaim
            .take()
            .is_some_and(|preclaim| self.table.commit_retirement(preclaim))
    }

    /// Transfer the active preclaim to an owned host guard that retains the
    /// same resolved residency view until [`FrameGrantResidencyTable::commit_preclaimed_retirement`]
    /// or [`FrameGrantResidencyTable::cancel_preclaimed_retirement`] spends it.
    /// `None` never happens: a token holds its preclaim until it is spent.
    #[must_use]
    pub fn into_preclaim(mut self) -> Option<ResidencyRetirementPreclaim> {
        self.preclaim.take()
    }
}
impl Drop for FrameGrantResidencyRetirement<'_> {
    fn drop(&mut self) {
        if let Some(preclaim) = self.preclaim.take() {
            self.table.cancel_retirement(preclaim);
        }
    }
}

/// One admitted retirement: its range, and the slots reserved for the parts
/// of the rows it splits. Only [`FrameGrantResidencyTable::begin_retire_overlapping`]
/// makes one. It is neither `Copy` nor `Clone`: it is spent once, by value,
/// on the same resolved view, by a commit or a cancel, and its reservations
/// are owned by their generation.
#[derive(Debug)]
#[must_use = "a preclaim is committed or cancelled"]
pub struct ResidencyRetirementPreclaim {
    mm_key: u64,
    start: u64,
    end: u64,
    /// The slot for the part below the range of the row that crosses its
    /// start, and for the part above the range of the row that crosses its
    /// end. Rows of one MM never overlap, so there is at most one of each.
    lower: Option<Reservation>,
    upper: Option<Reservation>,
}

/// What a retirement owes the parts of a split row that lie outside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitRowCustody {
    /// The row is its pages' custody record (an MM whose owner serves its
    /// faults from this table). Each outside part has its slot reserved
    /// before anything changes, or the retirement is refused with
    /// [`ResidencyRetirementRefusal::Capacity`] and the caller grows the
    /// table and reruns (#2813).
    Reserved,
    /// The venue keeps its own ledger and cannot grow the table (the host
    /// venue): the row only accelerates. A part with no slot is declined, as
    /// an initial publication at capacity is.
    Declinable,
}

/// Why [`FrameGrantResidencyTable::begin_retire_overlapping`] changed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyRetirementRefusal {
    InvalidRange,
    /// A grant-window lease holds a row the retirement would retire.
    Leased(LeaseRelease),
    /// No slot for a part of a split row that lies outside the retired
    /// range. The table needs a segment.
    Capacity,
}

/// Why [`FrameGrantResidencyTable::begin_replacement`] changed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyReplacementRefusal {
    InvalidIdentity,
    /// A grant-window lease holds a row the replacement would retire.
    Leased(LeaseRelease),
    /// No slot for the replacement row, or for the part of a retired row
    /// that lies outside the replaced span. The table needs a segment.
    Capacity,
}

/// One copy-on-write's whole residency change, admitted before any leaf
/// changes: transfer admission is closed on every row the replacement
/// overlaps, and a slot is reserved for the replacement row and for each
/// part of those rows outside the replaced span. [`commit`](Self::commit)
/// therefore cannot run out of slots, and dropping the token restores the
/// table exactly (#2813). The caller holds the exact-MM editor throughout.
pub struct FrameGrantResidencyReplacement<'a> {
    table: FrameGrantResidencyTable<ResidencyRows<'a>>,
    replacement: FrameGrantResidencyIdentity,
    /// The replacement row's slot and the outside parts' slots, spent by
    /// the commit or released by the drop.
    reserved: Option<ReplacementSlots>,
}
#[derive(Debug)]
struct ReplacementSlots {
    replacement: Reservation,
    lower: Option<Reservation>,
    upper: Option<Reservation>,
}
impl FrameGrantResidencyReplacement<'_> {
    /// Publish the replacement row with every page committed and the
    /// overlapped rows' outside parts with their committed bits, then retire
    /// the overlapped rows. Call it once the replacement leaves are live.
    /// Exact-MM exclusion makes a failed commit an invariant violation.
    #[must_use]
    pub fn commit(mut self) -> bool {
        self.reserved
            .take()
            .is_some_and(|reserved| self.table.commit_replacement(self.replacement, reserved))
    }
}
impl Drop for FrameGrantResidencyReplacement<'_> {
    fn drop(&mut self) {
        if let Some(reserved) = self.reserved.take() {
            for reservation in [Some(reserved.replacement), reserved.lower, reserved.upper]
                .into_iter()
                .flatten()
            {
                self.table.release_reservation(reservation);
            }
            self.table.reopen_replaced_rows(
                self.replacement.mm_key,
                self.replacement.semantic_base,
                self.replacement.semantic_base + self.replacement.len,
            );
        }
    }
}

/// A shared open-addressed segment. Grants hash by their smallest power-of-two
/// page-count bucket. A page in a grant lies in its base bucket or the next
/// bucket, so lookups check those two buckets for each size class. Disjoint
/// short grants in one 2 MiB window no longer consume one 64-slot chain.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ResidencySegment {
    slots: [FrameGrantResidencyRecord; FRAME_GRANT_RESIDENCY_SLOTS],
    dirty: [AtomicU64; FRAME_GRANT_RESIDENCY_SLOTS / 64],
}

impl ResidencySegment {
    const fn initial_slot() -> FrameGrantResidencyRecord {
        FrameGrantResidencyRecord::new()
    }

    const fn initial_dirty() -> AtomicU64 {
        AtomicU64::new(0)
    }

    const fn new() -> Self {
        Self {
            slots: [const { Self::initial_slot() }; FRAME_GRANT_RESIDENCY_SLOTS],
            dirty: [const { Self::initial_dirty() }; FRAME_GRANT_RESIDENCY_SLOTS / 64],
        }
    }

    /// Initialize in place without materializing a large stack temporary.
    ///
    /// # Safety
    /// `ptr` must be valid for writes, non-null, aligned to `align_of::<Self>()`,
    /// and point to storage of at least `size_of::<Self>()` bytes.
    unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: caller guarantees aligned, writable storage for the table.
        // Each record constructor initializes its complete wire image; no
        // reference to partially initialized storage is formed.
        unsafe {
            let slots = core::ptr::addr_of_mut!((*ptr).slots).cast::<FrameGrantResidencyRecord>();
            for index in 0..FRAME_GRANT_RESIDENCY_SLOTS {
                slots.add(index).write(Self::initial_slot());
            }
            let dirty = core::ptr::addr_of_mut!((*ptr).dirty).cast::<AtomicU64>();
            for index in 0..FRAME_GRANT_RESIDENCY_SLOTS / 64 {
                dirty.add(index).write(Self::initial_dirty());
            }
        }
    }
}

/// The allocator's exact enclosing extent and the segment's address within it.
/// Both are guest addresses. Host venues must resolve their own retained alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidencySegmentLocation {
    pub guest_base: u64,
    pub extent: ExtentGrantReceipt,
}

#[derive(Debug)]
#[repr(C)]
struct SegmentLocationWire {
    guest_base: AtomicU64,
    extent_base: AtomicU64,
    extent_size: AtomicU64,
    extent_token: AtomicU64,
}

impl SegmentLocationWire {
    const fn new() -> Self {
        Self {
            guest_base: AtomicU64::new(0),
            extent_base: AtomicU64::new(0),
            extent_size: AtomicU64::new(0),
            extent_token: AtomicU64::new(0),
        }
    }

    fn write(&self, location: ResidencySegmentLocation) {
        self.guest_base
            .store(location.guest_base, Ordering::Relaxed);
        self.extent_base
            .store(location.extent.base_va, Ordering::Relaxed);
        self.extent_size
            .store(location.extent.size as u64, Ordering::Relaxed);
        self.extent_token
            .store(location.extent.token, Ordering::Relaxed);
    }

    fn read(&self) -> ResidencySegmentLocation {
        ResidencySegmentLocation {
            guest_base: self.guest_base.load(Ordering::Relaxed),
            extent: ExtentGrantReceipt {
                base_va: self.extent_base.load(Ordering::Relaxed),
                size: self.extent_size.load(Ordering::Relaxed) as usize,
                token: self.extent_token.load(Ordering::Relaxed),
            },
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct ResidencyDirectory {
    publishing: AtomicU64,
    count: AtomicU64,
    entries: [SegmentLocationWire; MAX_RESIDENCY_EXTENSIONS],
    retirement_epoch: AtomicU64,
    /// The last transfer id handed out: every transfer tags its
    /// reservations with an id no other transfer ever uses.
    transfer_ids: AtomicU64,
    /// Grant-window lease releases, the event a `Leased` refusal enrols on.
    lease_releases: AtomicU64,
    reserved: [u64; 3],
}

impl ResidencyDirectory {
    const fn new() -> Self {
        Self {
            publishing: AtomicU64::new(0),
            count: AtomicU64::new(0),
            entries: [const { SegmentLocationWire::new() }; MAX_RESIDENCY_EXTENSIONS],
            retirement_epoch: AtomicU64::new(0),
            transfer_ids: AtomicU64::new(0),
            lease_releases: AtomicU64::new(0),
            reserved: [0; 3],
        }
    }

    unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: caller owns the uninitialized directory. Use field writes
        // to avoid putting the directory on the supervisor stack.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).publishing).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).count).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).retirement_epoch).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).transfer_ids).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).lease_releases).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).reserved).write([0; 3]);
            let entries = core::ptr::addr_of_mut!((*ptr).entries).cast::<SegmentLocationWire>();
            for index in 0..MAX_RESIDENCY_EXTENSIONS {
                entries.add(index).write(SegmentLocationWire::new());
            }
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ResidencyStorage {
    bootstrap: ResidencySegment,
    directory: ResidencyDirectory,
}

/// The operation must release its MM editor before asking the carrier
/// allocator to grow. Allocation pressure and a racing publisher are
/// distinct from a permanently full directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyGrowthRefusal {
    MetadataRequired,
    Publishing,
    Full,
    InvalidExtent,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct FrameGrantResidencyTable<S = ResidencyStorage> {
    storage: S,
}

impl FrameGrantResidencyTable {
    pub const fn new() -> Self {
        // Evaluate the empty table at compile time so debug callers copy one
        // value into their return slot instead of materializing separate
        // `ResidencySegment` and `ResidencyStorage` temporaries on the stack.
        const {
            FrameGrantResidencyTable {
                storage: ResidencyStorage {
                    bootstrap: ResidencySegment::new(),
                    directory: ResidencyDirectory::new(),
                },
            }
        }
    }

    /// Initialize in place without materializing a large stack temporary.
    ///
    /// # Safety
    /// `ptr` must be valid for writes, non-null, aligned to `align_of::<Self>()`,
    /// and point to storage of at least `size_of::<Self>()` bytes.
    pub unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: the caller owns the table storage, including the bootstrap
        // segment and directory. No reference to uninitialized storage is formed.
        unsafe {
            ResidencySegment::init_in_place(core::ptr::addr_of_mut!((*ptr).storage.bootstrap));
            ResidencyDirectory::init_in_place(core::ptr::addr_of_mut!((*ptr).storage.directory));
        }
    }

    pub fn extension_count(&self) -> usize {
        self.storage.directory.count.load(Ordering::Acquire) as usize
    }

    pub fn extension_location(&self, index: usize) -> Option<ResidencySegmentLocation> {
        if index >= self.extension_count() {
            return None;
        }
        Some(self.storage.directory.entries.get(index)?.read())
    }

    /// Publish one segment through the carrier's metadata allocator after
    /// releasing the MM editor. Once published, the allocation belongs to the
    /// table for the carrier lifetime and each venue uses its own alias.
    ///
    /// Callers must refresh their residency view after this succeeds, even
    /// when another owner published the requested segment first.
    pub fn grow(
        &self,
        allocator: &impl ReservationMetadataAllocator,
        observed_extensions: usize,
    ) -> Result<(), ResidencyGrowthRefusal> {
        let current = self.extension_count();
        if current > observed_extensions {
            return Ok(());
        }
        if current == MAX_RESIDENCY_EXTENSIONS {
            return Err(ResidencyGrowthRefusal::Full);
        }
        if current != observed_extensions {
            return Err(ResidencyGrowthRefusal::InvalidExtent);
        }

        let layout = Layout::new::<ResidencySegment>();
        let (ptr, extent) = allocator
            .allocate_with_extent(layout)
            .ok_or(ResidencyGrowthRefusal::MetadataRequired)?;
        let location = ResidencySegmentLocation {
            guest_base: ptr as u64,
            extent,
        };
        let result = self.append_segment(location, layout, observed_extensions);
        if !matches!(result, Ok(true)) {
            allocator.deallocate(ptr, layout);
        }
        result.map(|_| ())
    }

    fn append_segment(
        &self,
        location: ResidencySegmentLocation,
        layout: Layout,
        expected: usize,
    ) -> Result<bool, ResidencyGrowthRefusal> {
        let address = location.guest_base;
        let extent = location.extent;
        if address == 0
            || !address.is_multiple_of(layout.align() as u64)
            || address < extent.base_va
            || !address
                .checked_add(layout.size() as u64)
                .is_some_and(|end| {
                    extent
                        .base_va
                        .checked_add(extent.size as u64)
                        .is_some_and(|limit| end <= limit)
                })
        {
            return Err(ResidencyGrowthRefusal::InvalidExtent);
        }

        // SAFETY: the allocator returned a fresh allocation with this layout.
        // Initialization happens before publication and outside the append lock.
        unsafe { ResidencySegment::init_in_place(address as *mut ResidencySegment) };
        let directory = &self.storage.directory;
        directory
            .publishing
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ResidencyGrowthRefusal::Publishing)?;
        let installed = directory.count.load(Ordering::Relaxed) as usize == expected;
        if installed {
            directory.entries[expected].write(location);
            directory
                .count
                .store((expected + 1) as u64, Ordering::Release);
        }
        directory.publishing.store(0, Ordering::Release);
        Ok(installed)
    }

    /// Resolve published extensions in the allocator's own guest venue. A
    /// borrowed view sees a fixed prefix, so a caller that drops its editor
    /// and waits must open a fresh view upon re-entry.
    ///
    /// # Safety
    /// The caller must own the allocator venue that published the addresses.
    /// Every published allocation must be mapped at its named guest address
    /// for the entire borrow. Host callers must resolve pinned aliases instead.
    pub unsafe fn guest_view(&self) -> FrameGrantResidencyTable<ResidencyRows<'_>> {
        ResidencyRows {
            bootstrap: &self.storage.bootstrap,
            directory: &self.storage.directory,
            extensions: ResidencyExtensions::Guest(&self.storage.directory, self.extension_count()),
        }
        .as_table()
    }

    /// Resolve a dynamic extension through a pin on its exact retained
    /// extent. The alias may be unrelated to the guest address.
    ///
    /// # Safety
    /// The pin must come from this table's carrier and VM generation. Extent
    /// tokens identify allocations only within that carrier.
    pub unsafe fn resolve_extension<'a>(
        &'a self,
        index: usize,
        pin: &'a impl PinnedMetadataExtent,
    ) -> Option<ResolvedResidencySegment<'a>> {
        let location = self.extension_location(index)?;
        let extent = MetadataExtent::new(
            location.extent.base_va,
            location.extent.size as u64,
            location.extent.token,
        )?;
        if extent != pin.extent() {
            return None;
        }
        // SAFETY: pin retains this carrier allocator extent, and the directory
        // published the exact segment base after initialization.
        unsafe { self.resolve_alias(index, location, pin.host_base()) }
    }

    /// Resolve an extension inside the carrier's retained bootstrap extent.
    ///
    /// # Safety
    /// `host_base` must map the exact bootstrap extent of this table's carrier
    /// for the whole borrow.
    pub unsafe fn resolve_bootstrap_extension(
        &self,
        index: usize,
        guest_base: u64,
        extent_size: usize,
        host_base: core::ptr::NonNull<u8>,
    ) -> Option<ResolvedResidencySegment<'_>> {
        let location = self.extension_location(index)?;
        if location.extent
            != (ExtentGrantReceipt {
                base_va: guest_base,
                size: extent_size,
                token: 0,
            })
        {
            return None;
        }
        // SAFETY: caller retains this exact carrier's bootstrap backing.
        unsafe { self.resolve_alias(index, location, host_base) }
    }

    unsafe fn resolve_alias(
        &self,
        index: usize,
        location: ResidencySegmentLocation,
        host_base: core::ptr::NonNull<u8>,
    ) -> Option<ResolvedResidencySegment<'_>> {
        let layout = Layout::new::<ResidencySegment>();
        let offset = location.guest_base.checked_sub(location.extent.base_va)? as usize;
        if offset.checked_add(layout.size())? > location.extent.size {
            return None;
        }
        // SAFETY: caller retains the whole enclosing extent, and the preceding
        // bounds check covers the complete initialized segment.
        let alias = unsafe { host_base.as_ptr().add(offset).cast::<ResidencySegment>() };
        if !alias.is_aligned() {
            return None;
        }
        Some(ResolvedResidencySegment {
            table: self,
            index,
            // SAFETY: the published exact location is initialized and the
            // caller retains the matching aligned alias for this borrow.
            segment: unsafe { &*alias },
        })
    }

    /// Create a view from the complete, ordered prefix of retained aliases.
    /// Reject cross-carrier or out-of-order entries before looking at rows.
    pub fn resolved_view<'a>(
        &'a self,
        extensions: &'a [ResolvedResidencySegment<'a>],
    ) -> Option<FrameGrantResidencyTable<ResidencyRows<'a>>> {
        if extensions.len() != self.extension_count()
            || extensions
                .iter()
                .enumerate()
                .any(|(index, alias)| alias.index != index || !core::ptr::eq(alias.table, self))
        {
            return None;
        }
        Some(
            ResidencyRows {
                bootstrap: &self.storage.bootstrap,
                directory: &self.storage.directory,
                extensions: ResidencyExtensions::Aliases(extensions),
            }
            .as_table(),
        )
    }
}

pub struct ResolvedResidencySegment<'a> {
    table: &'a FrameGrantResidencyTable,
    index: usize,
    segment: &'a ResidencySegment,
}

/// Uninhabited pin for bootstrap-only host venues that have no dynamic
/// metadata extent resolver.
pub enum NoDynamicResidencyPin {}

// SAFETY: uninhabited; cannot be instantiated.
unsafe impl PinnedMetadataExtent for NoDynamicResidencyPin {
    fn extent(&self) -> MetadataExtent {
        match *self {}
    }

    fn host_base(&self) -> core::ptr::NonNull<u8> {
        match *self {}
    }
}

/// Resolver for bootstrap-only host venues: rejects dynamic (`token != 0`)
/// extensions fail-closed while allowing bootstrap (`token == 0`) aliases.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDynamicResidencyResolver;

impl MetadataExtentResolver for NoDynamicResidencyResolver {
    type Pin = NoDynamicResidencyPin;

    fn pin(&self, _extent: MetadataExtent) -> Result<Self::Pin, MetadataResolutionError> {
        Err(MetadataResolutionError::InvalidExtent)
    }
}

/// Host-owned retained aliases for every published residency extension.
/// Mirrors `ResolvedReservationNodes`: refresh before host retirement,
/// reconciliation, or census; an unchanged extension count does zero
/// resolution or allocation work. Construct on the host heap, never on an
/// EL1/CPL0 supervisor stack.
pub struct ResolvedResidencyTable<P: PinnedMetadataExtent> {
    table: *const FrameGrantResidencyTable,
    count: usize,
    segments: [*const ResidencySegment; MAX_RESIDENCY_EXTENSIONS],
    pins: [Option<P>; MAX_RESIDENCY_EXTENSIONS],
}

// SAFETY: once published in the carrier directory, each segment pointer is
// immutable and retained by either the carrier bootstrap region or `pins[i]`.
// Access to records uses atomics only; no `&mut` is ever exposed.
unsafe impl<P: PinnedMetadataExtent + Send> Send for ResolvedResidencyTable<P> {}
unsafe impl<P: PinnedMetadataExtent + Sync> Sync for ResolvedResidencyTable<P> {}

impl<P: PinnedMetadataExtent> Default for ResolvedResidencyTable<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PinnedMetadataExtent> ResolvedResidencyTable<P> {
    pub fn new() -> Self {
        Self {
            table: core::ptr::null(),
            count: 0,
            segments: [core::ptr::null(); MAX_RESIDENCY_EXTENSIONS],
            pins: core::array::from_fn(|_| None),
        }
    }

    pub fn extension_count(&self) -> usize {
        self.count
    }

    pub fn table_ptr(&self) -> *const FrameGrantResidencyTable {
        self.table
    }

    /// Resolve any extensions published after the cached prefix. Bootstrap
    /// extensions (`token == 0`) resolve against `bootstrap` (`(guest_base,
    /// extent_size, host_base)`); dynamic extensions (`token != 0`) are pinned
    /// through `resolver`.
    ///
    /// # Safety
    /// `table` and (when provided) `bootstrap` must belong to the same live
    /// carrier as `resolver` and remain mapped for every borrow of `self`.
    pub unsafe fn refresh<R: MetadataExtentResolver<Pin = P>>(
        &mut self,
        table: &FrameGrantResidencyTable,
        resolver: &R,
        bootstrap: Option<(u64, usize, core::ptr::NonNull<u8>)>,
    ) -> Result<(), MetadataResolutionError> {
        if !self.table.is_null() && !core::ptr::eq(self.table, table) {
            return Err(MetadataResolutionError::StaleOwner);
        }
        let count = table.extension_count();
        if count > MAX_RESIDENCY_EXTENSIONS || self.count > count {
            return Err(MetadataResolutionError::StaleOwner);
        }
        while self.count < count {
            let index = self.count;
            let location = table
                .extension_location(index)
                .ok_or(MetadataResolutionError::StaleOwner)?;
            let (segment_ptr, pin) = if location.extent.token == 0 {
                let Some((guest_base, extent_size, host_base)) = bootstrap else {
                    return Err(MetadataResolutionError::InvalidExtent);
                };
                // SAFETY: caller retains the exact carrier bootstrap mapping.
                let resolved = unsafe {
                    table.resolve_bootstrap_extension(index, guest_base, extent_size, host_base)
                }
                .ok_or(MetadataResolutionError::InvalidExtent)?;
                (resolved.segment as *const ResidencySegment, None)
            } else {
                let extent = MetadataExtent::new(
                    location.extent.base_va,
                    location.extent.size as u64,
                    location.extent.token,
                )
                .ok_or(MetadataResolutionError::InvalidExtent)?;
                let pin = resolver.pin(extent)?;
                // SAFETY: `pin` retains the exact dynamic extent for `table`'s carrier.
                let resolved = unsafe { table.resolve_extension(index, &pin) }
                    .ok_or(MetadataResolutionError::InvalidExtent)?;
                (resolved.segment as *const ResidencySegment, Some(pin))
            };
            self.table = table;
            self.segments[index] = segment_ptr;
            self.pins[index] = pin;
            self.count += 1;
        }
        self.table = table;
        Ok(())
    }

    /// Borrow a view covering the bootstrap segment and every resolved
    /// extension prefix. Returns `None` before the first `refresh`.
    pub fn view(&self) -> Option<FrameGrantResidencyTable<ResidencyRows<'_>>> {
        if self.table.is_null() {
            return None;
        }
        // SAFETY: `refresh` verified `self.table` and every non-null segment
        // alias in `self.segments[..self.count]`, and caller/pins retain them
        // for the entire lifetime of `&self`.
        let table = unsafe { &*self.table };
        Some(
            ResidencyRows {
                bootstrap: &table.storage.bootstrap,
                directory: &table.storage.directory,
                extensions: ResidencyExtensions::Resolved(&self.segments[..self.count]),
            }
            .as_table(),
        )
    }

    /// Borrow a view covering every resolved extension prefix, falling back to
    /// `fallback`'s bootstrap storage only if `refresh` has never run.
    pub fn view_or_bootstrap<'a>(
        &'a self,
        fallback: &'a FrameGrantResidencyTable,
    ) -> FrameGrantResidencyTable<ResidencyRows<'a>> {
        self.view().unwrap_or_else(|| {
            ResidencyRows {
                bootstrap: &fallback.storage.bootstrap,
                directory: &fallback.storage.directory,
                extensions: ResidencyExtensions::Resolved(&[]),
            }
            .as_table()
        })
    }
}

/// Venue-local access to the bootstrap and extension storage.
#[derive(Clone, Copy)]
pub struct ResidencyRows<'a> {
    bootstrap: &'a ResidencySegment,
    directory: &'a ResidencyDirectory,
    extensions: ResidencyExtensions<'a>,
}

#[derive(Clone, Copy)]
enum ResidencyExtensions<'a> {
    Aliases(&'a [ResolvedResidencySegment<'a>]),
    Resolved(&'a [*const ResidencySegment]),
    Guest(&'a ResidencyDirectory, usize),
}

mod sealed {
    pub trait ResidencyStorage {
        fn rows(&self) -> super::ResidencyRows<'_>;
    }
}

/// Storage accepted by the shared descriptor and retirement owner. The
/// bootstrap wire record and each retained venue view use the same methods.
pub trait FrameGrantResidencyAccess: sealed::ResidencyStorage {}
impl<S: sealed::ResidencyStorage> FrameGrantResidencyAccess for S {}

impl sealed::ResidencyStorage for ResidencyStorage {
    fn rows(&self) -> ResidencyRows<'_> {
        #[cfg(target_os = "none")]
        {
            ResidencyRows {
                bootstrap: &self.bootstrap,
                directory: &self.directory,
                extensions: ResidencyExtensions::Guest(
                    &self.directory,
                    self.directory.count.load(Ordering::Acquire) as usize,
                ),
            }
        }
        #[cfg(not(target_os = "none"))]
        {
            ResidencyRows {
                bootstrap: &self.bootstrap,
                directory: &self.directory,
                extensions: ResidencyExtensions::Aliases(&[]),
            }
        }
    }
}

impl sealed::ResidencyStorage for ResidencyRows<'_> {
    fn rows(&self) -> ResidencyRows<'_> {
        *self
    }
}

impl<'a> ResidencyRows<'a> {
    fn segments(self) -> impl Iterator<Item = &'a ResidencySegment> {
        let count = match self.extensions {
            ResidencyExtensions::Aliases(entries) => entries.len(),
            ResidencyExtensions::Resolved(entries) => entries.len(),
            ResidencyExtensions::Guest(_, count) => count,
        };
        (0..=count).map_while(move |index| self.segment(index))
    }

    fn segment(self, index: usize) -> Option<&'a ResidencySegment> {
        let Some(index) = index.checked_sub(1) else {
            return Some(self.bootstrap);
        };
        match self.extensions {
            ResidencyExtensions::Aliases(entries) => entries.get(index).map(|alias| alias.segment),
            ResidencyExtensions::Resolved(entries) => entries.get(index).map(|&ptr| {
                // SAFETY: `ResolvedResidencyTable::refresh` validated each
                // non-null, aligned segment alias and pins retain it for `'a`.
                unsafe { &*ptr }
            }),
            ResidencyExtensions::Guest(directory, count) if index < count => {
                let location = directory.entries.get(index)?.read();
                // SAFETY: guest_view requires published allocations to remain
                // mapped in the allocator venue for the entire borrowed view.
                Some(unsafe { &*(location.guest_base as *const ResidencySegment) })
            }
            ResidencyExtensions::Guest(_, _) => None,
        }
    }

    fn as_table(self) -> FrameGrantResidencyTable<Self> {
        FrameGrantResidencyTable { storage: self }
    }
}

impl<S: sealed::ResidencyStorage> FrameGrantResidencyTable<S> {
    fn segments(&self) -> impl Iterator<Item = &ResidencySegment> {
        self.storage.rows().segments()
    }

    fn slots(&self) -> impl Iterator<Item = &FrameGrantResidencyRecord> {
        self.segments().flat_map(|segment| segment.slots.iter())
    }

    fn slot(&self, index: usize) -> Option<&FrameGrantResidencyRecord> {
        self.slot_entry(index).map(|(record, _)| record)
    }

    fn slot_entry(&self, index: usize) -> Option<(&FrameGrantResidencyRecord, &AtomicU64)> {
        let segment = self
            .storage
            .rows()
            .segment(index / FRAME_GRANT_RESIDENCY_SLOTS)?;
        let offset = index % FRAME_GRANT_RESIDENCY_SLOTS;
        Some((&segment.slots[offset], &segment.dirty[offset / 64]))
    }

    fn first_slot(mm_key: u64, bucket: u64, class: u32) -> usize {
        let mixed = mm_key.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ bucket.wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ u64::from(class).wrapping_mul(0x94d0_49bb_1331_11eb);
        (mixed as usize) & (FRAME_GRANT_RESIDENCY_SLOTS - 1)
    }

    fn probe(mm_key: u64, bucket: u64, class: u32, offset: usize) -> usize {
        (Self::first_slot(mm_key, bucket, class) + offset) & (FRAME_GRANT_RESIDENCY_SLOTS - 1)
    }

    /// Host: publish an authenticated grant while the exact-MM mutation guard
    /// excludes a guest editor. Failure leaves ordinary host first touch live.
    pub fn publish(&self, identity: FrameGrantResidencyIdentity) -> Option<usize> {
        self.try_publish(identity).ok()
    }

    /// Publish without collapsing invalid identity, overlap and probe capacity
    /// into the same refusal. The caller holds this MM's editor.
    pub fn try_publish(
        &self,
        identity: FrameGrantResidencyIdentity,
    ) -> Result<usize, FrameGrantResidencyRefusal> {
        if !identity.valid() {
            return Err(FrameGrantResidencyRefusal::InvalidIdentity);
        }
        // All size classes share one table. Check every covered page before
        // admission so unlike classes cannot publish overlapping grants.
        // Exact-MM editors serialize publications for this MM.
        for page in (identity.semantic_base..identity.semantic_base + identity.len)
            .step_by(GRANT_PAGE_SIZE as usize)
        {
            if self.lookup(identity.mm_key, page).is_some() {
                return Err(FrameGrantResidencyRefusal::Overlap);
            }
        }
        let reservation = self
            .reserve_slot(identity.mm_key, identity.semantic_base, identity.len)
            .ok_or(FrameGrantResidencyRefusal::Capacity)?;
        let slot = reservation.slot;
        if !self.publish_reservation(reservation, identity, [0; 8]) {
            return Err(FrameGrantResidencyRefusal::Capacity);
        }
        Ok(slot)
    }

    /// Claim a reusable slot on the probe chain of a row at `semantic_base`
    /// of `len` bytes. The slot reads as an in-flight publication, which no
    /// lookup sees and no other claim takes, until the returned reservation
    /// is published into or released.
    fn reserve_slot(&self, mm_key: u64, semantic_base: u64, len: u64) -> Option<Reservation> {
        let class = (len / GRANT_PAGE_SIZE).next_power_of_two().trailing_zeros();
        let bucket = semantic_base / (GRANT_PAGE_SIZE << class);
        for (segment_index, segment) in self.segments().enumerate() {
            for probe in 0..GRANT_PROBES {
                let slot = Self::probe(mm_key, bucket, class, probe);
                let record = &segment.slots[slot];
                let state = record.state.load(Ordering::Acquire);
                if !matches!(state & GRANT_STATE_MASK, GRANT_EMPTY | GRANT_RETIRED) {
                    continue;
                }
                // Claim the exact reusable epoch we observed, with a fresh
                // generation. Another MM can take this slot even while this
                // MM's editor is held.
                let claimed_state = (state & !GRANT_STATE_MASK).wrapping_add(4) | GRANT_WRITING;
                if record
                    .state
                    .compare_exchange(state, claimed_state, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Some(Reservation {
                        slot: segment_index * FRAME_GRANT_RESIDENCY_SLOTS + slot,
                        claimed_state,
                    });
                }
            }
        }
        None
    }

    /// Return a reservation nothing was published into. The slot stays a
    /// tombstone so no probe chain through it is cut. False, changing
    /// nothing, if the slot no longer holds this exact claim.
    fn release_reservation(&self, reservation: Reservation) -> bool {
        let Some(record) = self.slot(reservation.slot) else {
            return false;
        };
        // A transfer's tag on the slot goes before the slot is reusable, so
        // its next claimant never carries it.
        if record.transfer_pins.load(Ordering::Acquire) >= TRANSFER_PIN_RETIRED {
            record
                .transfer_pins
                .store(TRANSFER_PIN_RETIRED, Ordering::Release);
        }
        let released = record
            .state
            .compare_exchange(
                reservation.claimed_state,
                (reservation.claimed_state & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if released {
            // A released reservation is a reusable slot that was not one
            // while it was held: real capacity progress for a waiter that
            // refused for capacity.
            self.storage
                .rows()
                .directory
                .retirement_epoch
                .fetch_add(1, Ordering::Release);
        }
        released
    }

    /// Publish `identity` with `committed` into the slot `reservation`
    /// claimed: identity and bits first, then the pin word, then `GRANT_LIVE`
    /// by a CAS from the exact claim, so no reader sees the row live with a
    /// field or a commit missing. A row with a committed page is marked
    /// dirty for the host's walk. False, changing nothing, if the slot no
    /// longer holds this exact claim.
    fn publish_reservation(
        &self,
        reservation: Reservation,
        identity: FrameGrantResidencyIdentity,
        committed: [u64; 8],
    ) -> bool {
        let Some((record, dirty)) = self.slot_entry(reservation.slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) != reservation.claimed_state {
            return false;
        }
        record.write_identity(identity);
        for (word, value) in record.committed.iter().zip(committed) {
            word.store(value, Ordering::Relaxed);
        }
        record.transfer_pins.store(0, Ordering::Release);
        if record
            .state
            .compare_exchange(
                reservation.claimed_state,
                (reservation.claimed_state & !GRANT_STATE_MASK) | GRANT_LIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if committed.iter().any(|word| *word != 0) {
            dirty.fetch_or(1 << (reservation.slot % 64), Ordering::Release);
        }
        pause::at(Point::Published {
            slot: reservation.slot,
        });
        true
    }

    /// Retire the live row in `slot`, whose state reads `state`, and return
    /// its committed bits. The one retire step every path shares. The caller
    /// has closed the row's transfer admission and published every row that
    /// keeps custody of any of its pages, so a lock-free reader finds each
    /// kept page in one row or the other at every step. The row's dirty bit
    /// is cleared while the row is still live and closed: nobody else can
    /// claim the slot yet, so the bit is still this row's, and the slot's
    /// next owner's bit can never be erased. `None`, changing nothing, if
    /// the row is no longer that generation.
    fn retire_row(&self, slot: usize, state: u64) -> Option<[u64; 8]> {
        let (record, dirty) = self.slot_entry(slot)?;
        let bits = core::array::from_fn(|index| record.committed[index].load(Ordering::Acquire));
        let bit = 1 << (slot % 64);
        let was_dirty = dirty.fetch_and(!bit, Ordering::AcqRel) & bit != 0;
        if record
            .state
            .compare_exchange(
                state,
                (state & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            if was_dirty {
                dirty.fetch_or(bit, Ordering::Release);
            }
            return None;
        }
        pause::at(Point::Retired { slot });
        self.storage
            .rows()
            .directory
            .retirement_epoch
            .fetch_add(1, Ordering::Release);
        Some(bits)
    }

    /// The lease-release count a `Leased` refusal reports.
    fn lease_release_point(&self) -> LeaseRelease {
        LeaseRelease {
            observed: self
                .storage
                .rows()
                .directory
                .lease_releases
                .load(Ordering::Acquire),
        }
    }

    /// The one probe after enrolling on a `Leased` refusal's release: true
    /// once any grant-window lease has dropped since the refusal observed
    /// the count, so the rerun can be admitted.
    pub fn lease_released(&self, refusal: LeaseRelease) -> bool {
        self.storage
            .rows()
            .directory
            .lease_releases
            .load(Ordering::Acquire)
            != refusal.observed
    }

    /// Admit one copy-on-write's residency change before any leaf changes:
    /// see [`FrameGrantResidencyReplacement`]. A refusal changes nothing.
    pub fn begin_replacement(
        &self,
        replacement: FrameGrantResidencyIdentity,
    ) -> Result<FrameGrantResidencyReplacement<'_>, ResidencyReplacementRefusal> {
        if !replacement.valid() {
            return Err(ResidencyReplacementRefusal::InvalidIdentity);
        }
        let mm_key = replacement.mm_key;
        let start = replacement.semantic_base;
        let end = start + replacement.len;
        let leases = self.lease_release_point();
        if !self.close_replaced_rows(mm_key, start, end) {
            return Err(ResidencyReplacementRefusal::Leased(leases));
        }
        // Rows of one MM never overlap: only the row holding the span's
        // first page can reach below it, and only the row holding its last
        // page can reach above it.
        let below = self.lookup(mm_key, start).and_then(|row| {
            let base = row.identity.semantic_base;
            (base < start).then(|| (base, start - base))
        });
        let above = self.lookup(mm_key, end - GRANT_PAGE_SIZE).and_then(|row| {
            let row_end = row.identity.semantic_base + row.identity.len;
            (row_end > end).then(|| (end, row_end - end))
        });
        let refuse = |held: [Option<Reservation>; 3]| {
            for reservation in held.into_iter().flatten() {
                self.release_reservation(reservation);
            }
            self.reopen_replaced_rows(mm_key, start, end);
            Err(ResidencyReplacementRefusal::Capacity)
        };
        let Some(replacement_slot) = self.reserve_slot(mm_key, start, replacement.len) else {
            return refuse([None, None, None]);
        };
        let mut parts = [None, None];
        for (index, span) in [below, above].into_iter().enumerate() {
            let Some((base, len)) = span else {
                continue;
            };
            match self.reserve_slot(mm_key, base, len) {
                Some(reservation) => parts[index] = Some(reservation),
                None => {
                    let [lower, upper] = parts;
                    return refuse([Some(replacement_slot), lower, upper]);
                }
            }
        }
        let [lower, upper] = parts;
        Ok(FrameGrantResidencyReplacement {
            table: self.storage.rows().as_table(),
            replacement,
            reserved: Some(ReplacementSlots {
                replacement: replacement_slot,
                lower,
                upper,
            }),
        })
    }

    /// Close transfer admission on every row overlapping `[start, end)`,
    /// found by bounded lookups. False, with nothing closed, when a
    /// grant-window lease holds one.
    fn close_replaced_rows(&self, mm_key: u64, start: u64, end: u64) -> bool {
        for page in (start..end).step_by(GRANT_PAGE_SIZE as usize) {
            let Some(row) = self.lookup(mm_key, page) else {
                continue;
            };
            // A row that began on an earlier page of the span is closed.
            if page > start && row.identity.semantic_base < page {
                continue;
            }
            let closed = self.slot(row.slot).is_some_and(|record| {
                record
                    .transfer_pins
                    .compare_exchange(
                        0,
                        TRANSFER_PIN_RETIRING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            });
            if !closed {
                self.reopen_replaced_rows(mm_key, start, page);
                return false;
            }
        }
        true
    }

    fn reopen_replaced_rows(&self, mm_key: u64, start: u64, end: u64) {
        for page in (start..end).step_by(GRANT_PAGE_SIZE as usize) {
            if let Some(record) = self
                .lookup(mm_key, page)
                .and_then(|row| self.slot(row.slot))
            {
                let _ = record.transfer_pins.compare_exchange(
                    TRANSFER_PIN_RETIRING,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }

    /// Publish the replacement and every outside part first, then retire
    /// the closed rows: each page of the span and of the outside parts is
    /// found in a live row at every step.
    fn commit_replacement(
        &self,
        replacement: FrameGrantResidencyIdentity,
        reserved: ReplacementSlots,
    ) -> bool {
        let mm_key = replacement.mm_key;
        let start = replacement.semantic_base;
        let end = start + replacement.len;
        let ReplacementSlots {
            replacement: replacement_slot,
            mut lower,
            mut upper,
        } = reserved;
        let mut all = [0u64; 8];
        for bit in 0..(replacement.len / GRANT_PAGE_SIZE) as usize {
            all[bit / 64] |= 1 << (bit % 64);
        }
        let mut committed = self.publish_reservation(replacement_slot, replacement, all);
        for page in (start..end).step_by(GRANT_PAGE_SIZE as usize) {
            if !committed {
                break;
            }
            // Only a row this replacement closed: the replacement row, live
            // over the same pages, is open. A row retired on an earlier page
            // is no longer found.
            let Some(row) = self.find_row(mm_key, page, |record| {
                record.transfer_pins.load(Ordering::Acquire) == TRANSFER_PIN_RETIRING
            }) else {
                continue;
            };
            let bits = self
                .slot(row.slot)
                .map(|record| core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire)))
                .unwrap_or([0; 8]);
            let base = row.identity.semantic_base;
            let row_end = base + row.identity.len;
            for (keep, from, to) in [
                (&mut lower, base, start.min(row_end)),
                (&mut upper, end.max(base), row_end),
            ] {
                if from >= to {
                    continue;
                }
                committed &= keep.take().is_some_and(|reservation| {
                    self.publish_part(reservation, row.identity, bits, from, to)
                });
            }
            committed &= self.retire_row(row.slot, row.epoch).is_some();
        }
        for reservation in [lower, upper].into_iter().flatten() {
            self.release_reservation(reservation);
        }
        committed
    }

    /// Publish `[from, to)` of the row `identity` into `reservation`,
    /// carrying the row's committed bits for those pages.
    fn publish_part(
        &self,
        reservation: Reservation,
        identity: FrameGrantResidencyIdentity,
        bits: [u64; 8],
        from: u64,
        to: u64,
    ) -> bool {
        let base = identity.semantic_base;
        self.publish_reservation(
            reservation,
            FrameGrantResidencyIdentity {
                semantic_base: from,
                physical_ipa: identity.physical_ipa + (from - base),
                len: to - from,
                ..identity
            },
            shifted_bits(
                bits,
                ((from - base) / GRANT_PAGE_SIZE) as usize,
                ((to - from) / GRANT_PAGE_SIZE) as usize,
            ),
        )
    }

    /// Number of addressable records in this venue's resolved view.
    pub fn slot_capacity(&self) -> usize {
        self.segments().count() * FRAME_GRANT_RESIDENCY_SLOTS
    }

    /// Monotonic count of committed row retirements across every segment.
    /// Callers sample this before a refused growth or probe and check it once
    /// after enrolling on progress.
    pub fn retirement_epoch(&self) -> u64 {
        self.storage
            .rows()
            .directory
            .retirement_epoch
            .load(Ordering::Acquire)
    }

    /// True while another owner is installing a new extension segment.
    pub fn is_publishing(&self) -> bool {
        self.storage
            .rows()
            .directory
            .publishing
            .load(Ordering::Acquire)
            != 0
    }

    /// Number of extension segments published in the directory.
    pub fn published_extensions(&self) -> usize {
        self.storage.rows().directory.count.load(Ordering::Acquire) as usize
    }

    /// Diagnostic sample of occupied slots, including in-flight publishers.
    /// Other MMs can change the table during the scan.
    pub fn observed_slots_used(&self) -> usize {
        self.slots()
            .filter(|record| {
                matches!(
                    record.state.load(Ordering::Relaxed) & GRANT_STATE_MASK,
                    GRANT_WRITING | GRANT_LIVE
                )
            })
            .count()
    }

    /// Diagnose every observed occupied slot. A writing row or a row whose
    /// epoch changed during classification yields None. Diagnostic results
    /// must not be used to authorize descriptor or inventory mutations.
    pub fn inspect_occupied<T>(
        &self,
        mut classify: impl FnMut(FrameGrantResidencyIdentity, bool) -> T,
        mut observe: impl FnMut(Option<T>),
    ) {
        for record in self.slots() {
            let epoch = record.state.load(Ordering::Acquire);
            match epoch & GRANT_STATE_MASK {
                GRANT_WRITING => observe(None),
                GRANT_LIVE => {
                    let identity = record.identity();
                    let committed = record
                        .committed
                        .iter()
                        .any(|word| word.load(Ordering::Acquire) != 0);
                    if record.state.load(Ordering::Acquire) != epoch {
                        observe(None);
                        continue;
                    }
                    let class = classify(identity, committed);
                    observe((record.state.load(Ordering::Acquire) == epoch).then_some(class));
                }
                _ => {}
            }
        }
    }

    /// Guest: find the exact live grant covering a prepared leaf.
    ///
    /// A lookup holds no lock. Every edit that re-splits, replaces or moves
    /// rows publishes each row that keeps custody of a page before it
    /// retires the row it replaces, so this finds a page whose custody an
    /// edit keeps at every step of that edit: in the old row, or in the new
    /// one. A reader outside the exact-MM editor can therefore see a page in
    /// two rows of one MM for an instant (both name the same frame, or the
    /// old and new frames of a replacement), never in none.
    pub fn lookup(&self, mm_key: u64, va: u64) -> Option<FrameGrantResidencyPage> {
        self.find_row(mm_key, va, |_| true)
    }

    /// [`Self::lookup`], limited to rows `accept` takes.
    fn find_row(
        &self,
        mm_key: u64,
        va: u64,
        accept: impl Fn(&FrameGrantResidencyRecord) -> bool,
    ) -> Option<FrameGrantResidencyPage> {
        let page = va & !(GRANT_PAGE_SIZE - 1);
        for (segment_index, segment) in self.segments().enumerate() {
            for class in 0..=EL1_FRAME_GRANT_TARGET_SIZE
                .div_ceil(GRANT_PAGE_SIZE)
                .trailing_zeros()
            {
                let bucket = page / (GRANT_PAGE_SIZE << class);
                for candidate in [Some(bucket), (class > 0 && bucket > 0).then(|| bucket - 1)]
                    .into_iter()
                    .flatten()
                {
                    for probe in 0..GRANT_PROBES {
                        let slot = Self::probe(mm_key, candidate, class, probe);
                        let record = &segment.slots[slot];
                        let epoch = record.state.load(Ordering::Acquire);
                        match epoch & GRANT_STATE_MASK {
                            GRANT_EMPTY => break,
                            GRANT_LIVE => {
                                let identity = record.identity();
                                if identity.mm_key == mm_key
                                    && page >= identity.semantic_base
                                    && page - identity.semantic_base < identity.len
                                    && accept(record)
                                    && record.state.load(Ordering::Acquire) == epoch
                                {
                                    let bit = ((page - identity.semantic_base) / GRANT_PAGE_SIZE)
                                        as usize;
                                    return Some(FrameGrantResidencyPage {
                                        slot: segment_index * FRAME_GRANT_RESIDENCY_SLOTS + slot,
                                        identity,
                                        expected_ipa: identity.physical_ipa
                                            + bit as u64 * GRANT_PAGE_SIZE,
                                        epoch,
                                        bit,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        None
    }

    /// Retain an exact live residency generation independently of the MM
    /// editor. A racing retirement either closes admission first or observes
    /// this pin and refuses; stale page tokens cannot pin a successor.
    pub fn pin_transfer(&self, page: FrameGrantResidencyPage) -> Option<FrameGrantTransferPin<'_>> {
        let record = self.slot(page.slot)?;
        if record.state.load(Ordering::Acquire) != page.epoch || record.identity() != page.identity
        {
            return None;
        }
        record
            .transfer_pins
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pins| {
                (pins < TRANSFER_PIN_RETIRED - 1).then_some(pins + 1)
            })
            .ok()?;
        let pin = FrameGrantTransferPin {
            record,
            releases: &self.storage.rows().directory.lease_releases,
        };
        if record.state.load(Ordering::Acquire) != page.epoch || record.identity() != page.identity
        {
            drop(pin);
            return None;
        }
        Some(pin)
    }

    /// Guest: record a committed VALID leaf before releasing the MM editor.
    pub fn record_commit(&self, page: FrameGrantResidencyPage) -> bool {
        let Some((record, dirty)) = self.slot_entry(page.slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) != page.epoch
            || record.identity() != page.identity
            || page.bit >= (page.identity.len / GRANT_PAGE_SIZE) as usize
            || page.expected_ipa != page.identity.physical_ipa + page.bit as u64 * GRANT_PAGE_SIZE
        {
            return false;
        }
        record.committed[page.bit / 64].fetch_or(1 << (page.bit % 64), Ordering::Release);
        dirty.fetch_or(1 << (page.slot % 64), Ordering::Release);
        true
    }

    /// Host mincore view. The slot must still be live for this exact MM and
    /// grant; retirement removes visibility before backing can be reused.
    pub fn is_guest_committed(&self, mm_key: u64, va: u64) -> bool {
        let Some(page) = self.lookup(mm_key, va) else {
            return false;
        };
        let Some(record) = self.slot(page.slot) else {
            return false;
        };
        record.state.load(Ordering::Acquire) == page.epoch
            && record.identity() == page.identity
            && record.committed[page.bit / 64].load(Ordering::Acquire) & (1 << (page.bit % 64)) != 0
            && record.state.load(Ordering::Acquire) == page.epoch
    }

    /// Host: visit only records changed since their last reconciliation. The
    /// callback must validate the live leaf and update host residency before
    /// `ack_dirty` is called; exact-MM exclusion prevents same-MM new bits.
    pub fn for_each_dirty_mm<B>(
        &self,
        mm_key: u64,
        mut visit: impl FnMut(usize, FrameGrantResidencyIdentity, [u64; 8]) -> core::ops::ControlFlow<B>,
    ) -> core::ops::ControlFlow<B> {
        for (segment_index, segment) in self.segments().enumerate() {
            for (word_index, word) in segment.dirty.iter().enumerate() {
                let mut pending = word.load(Ordering::Acquire);
                while pending != 0 {
                    let bit = pending.trailing_zeros() as usize;
                    pending &= pending - 1;
                    let slot = word_index * 64 + bit;
                    let record = &segment.slots[slot];
                    let epoch = record.state.load(Ordering::Acquire);
                    if epoch & GRANT_STATE_MASK == GRANT_LIVE {
                        let identity = record.identity();
                        if identity.mm_key == mm_key
                            && record.state.load(Ordering::Acquire) == epoch
                        {
                            let bits = core::array::from_fn(|i| {
                                record.committed[i].load(Ordering::Acquire)
                            });
                            if record.state.load(Ordering::Acquire) == epoch {
                                visit(
                                    segment_index * FRAME_GRANT_RESIDENCY_SLOTS + slot,
                                    identity,
                                    bits,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    }

    pub fn ack_dirty(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some((record, dirty)) = self.slot_entry(slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE
            || record.identity() != identity
        {
            return false;
        }
        dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
        true
    }

    /// Host: snapshot the guest commits while holding the exact-MM guard.
    pub fn committed_words(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<[u64; 8]> {
        let record = self.slot(slot)?;
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return None;
        }
        let bits = core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire));
        (record.state.load(Ordering::Acquire) == epoch).then_some(bits)
    }

    /// Host: retire this exact grant before unmapping or reusing its owner.
    pub fn retire(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some(record) = self.slot(slot) else {
            return false;
        };
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return false;
        }
        if record
            .transfer_pins
            .compare_exchange(0, TRANSFER_PIN_RETIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if self.retire_row(slot, epoch).is_none() {
            record.transfer_pins.store(0, Ordering::Release);
            return false;
        }
        true
    }

    /// Host: visit `[base, end)` of every live grant of `mm_key` that
    /// overlaps `[start, start + len)`: backing already prepared for this
    /// exact MM, which no second grant may cover. One pass over the table.
    pub fn live_spans_overlapping(
        &self,
        mm_key: u64,
        start: u64,
        len: u64,
        mut visit: impl FnMut(u64, u64),
    ) {
        let end = start.saturating_add(len);
        for record in self.slots() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            let grant_end = identity.semantic_base.saturating_add(identity.len);
            if identity.mm_key == mm_key
                && identity.semantic_base < end
                && start < grant_end
                && record.state.load(Ordering::Acquire) == state
            {
                visit(identity.semantic_base, grant_end);
            }
        }
    }

    /// Revoke only replaced pages. Preserve the exact owner and committed
    /// bits of each outside fragment, under the caller's exact-MM editor.
    /// Republished fragments have fresh epochs: no captured pre-edit page
    /// token can authorize a replaced or recycled page. Index saturation
    /// declines fragment acceleration, as it does initial publication.
    /// Returns false if a grant-window lease prevents revocation. Earlier
    /// revocations remain valid; callers must not replace leaves on refusal.
    pub fn retire_overlapping(&self, mm_key: u64, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        if start >= end {
            return true;
        }
        for (slot, record) in self.slots().enumerate() {
            if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            if identity.mm_key == mm_key
                && identity.semantic_base < end
                && start < identity.semantic_base.saturating_add(identity.len)
                && !self.retire_fragment(slot, identity, start, end)
            {
                return false;
            }
        }
        true
    }

    /// Close transfer admission for every live row the descriptor retirement
    /// will replace. No row or committed bit changes until [`commit`](FrameGrantResidencyRetirement::commit),
    /// and dropping the token restores the exact preclaim state.
    ///
    /// A row the range splits keeps its parts outside the range: `custody`
    /// says whether their slots are reserved here, so that the commit cannot
    /// lose one, or whether a part without a slot is declined.
    pub fn begin_retire_overlapping(
        &self,
        mm_key: u64,
        start: u64,
        len: u64,
        custody: SplitRowCustody,
    ) -> Result<FrameGrantResidencyRetirement<'_>, ResidencyRetirementRefusal> {
        let Some(end) = start.checked_add(len) else {
            return Err(ResidencyRetirementRefusal::InvalidRange);
        };
        if mm_key == 0 || start >= end {
            return Err(ResidencyRetirementRefusal::InvalidRange);
        }
        let leases = self.lease_release_point();
        let mut preclaim = ResidencyRetirementPreclaim {
            mm_key,
            start,
            end,
            lower: None,
            upper: None,
        };
        let (cut_start, cut_end) = Self::retirement_cut(start, end);
        let (mut below, mut above) = (None, None);
        for record in self.slots() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            if identity.mm_key != mm_key
                || identity.semantic_base >= end
                || start >= identity.semantic_base.saturating_add(identity.len)
                || record.state.load(Ordering::Acquire) != state
            {
                continue;
            }
            if record
                .transfer_pins
                .compare_exchange(
                    0,
                    TRANSFER_PIN_RETIRING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                self.cancel_retirement(preclaim);
                return Err(ResidencyRetirementRefusal::Leased(leases));
            }
            if record.state.load(Ordering::Acquire) != state || record.identity() != identity {
                record.transfer_pins.store(0, Ordering::Release);
                self.cancel_retirement(preclaim);
                return Err(ResidencyRetirementRefusal::Leased(leases));
            }
            let base = identity.semantic_base;
            let grant_end = base + identity.len;
            if base < cut_start.min(grant_end) {
                below = Some((base, cut_start.min(grant_end) - base));
            }
            if cut_end.max(base) < grant_end {
                above = Some((cut_end.max(base), grant_end - cut_end.max(base)));
            }
        }
        for (upper, part) in [(false, below), (true, above)] {
            let Some((base, len)) = part else {
                continue;
            };
            let reserved = self.reserve_slot(mm_key, base, len);
            if reserved.is_none() && custody == SplitRowCustody::Reserved {
                self.cancel_retirement(preclaim);
                return Err(ResidencyRetirementRefusal::Capacity);
            }
            if upper {
                preclaim.upper = reserved;
            } else {
                preclaim.lower = reserved;
            }
        }
        Ok(FrameGrantResidencyRetirement {
            table: self.storage.rows().as_table(),
            preclaim: Some(preclaim),
        })
    }

    /// The page-aligned range a retirement of `[start, end)` removes.
    fn retirement_cut(start: u64, end: u64) -> (u64, u64) {
        (
            start & !(GRANT_PAGE_SIZE - 1),
            end.saturating_add(GRANT_PAGE_SIZE - 1) & !(GRANT_PAGE_SIZE - 1),
        )
    }

    fn cancel_retirement(&self, preclaim: ResidencyRetirementPreclaim) {
        let ResidencyRetirementPreclaim {
            mm_key,
            start,
            end,
            lower,
            upper,
        } = preclaim;
        for reservation in [lower, upper].into_iter().flatten() {
            self.release_reservation(reservation);
        }
        for record in self.slots() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            if identity.mm_key == mm_key
                && identity.semantic_base < end
                && start < identity.semantic_base.saturating_add(identity.len)
                && record.state.load(Ordering::Acquire) == state
            {
                let _ = record.transfer_pins.compare_exchange(
                    TRANSFER_PIN_RETIRING,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }

    /// Commit a preclaim transferred via [`FrameGrantResidencyRetirement::into_preclaim`]
    /// on the same resolved view.
    #[must_use]
    pub fn commit_preclaimed_retirement(&self, preclaim: ResidencyRetirementPreclaim) -> bool {
        self.commit_retirement(preclaim)
    }

    /// Cancel a preclaim transferred via [`FrameGrantResidencyRetirement::into_preclaim`]
    /// on the same resolved view.
    pub fn cancel_preclaimed_retirement(&self, preclaim: ResidencyRetirementPreclaim) {
        self.cancel_retirement(preclaim);
    }

    fn commit_retirement(&self, preclaim: ResidencyRetirementPreclaim) -> bool {
        let ResidencyRetirementPreclaim {
            mm_key,
            start,
            end,
            mut lower,
            mut upper,
        } = preclaim;
        let mut committed = true;
        for (slot, record) in self.slots().enumerate() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            // A part this commit published lies outside the range, so the
            // scan never revisits one.
            if identity.mm_key == mm_key
                && identity.semantic_base < end
                && start < identity.semantic_base.saturating_add(identity.len)
                && !self.retire_claimed_fragment(
                    slot, state, identity, start, end, &mut lower, &mut upper,
                )
            {
                committed = false;
                break;
            }
        }
        for reservation in [lower, upper].into_iter().flatten() {
            self.release_reservation(reservation);
        }
        committed
    }

    /// Revoke a small page-aligned span using bounded grant lookups instead
    /// of scanning the carrier's index. Intended for one COW compound.
    /// The exact-MM editor excludes concurrent leaf/publication changes.
    pub fn retire_small_span(&self, mm_key: u64, start: u64, len: u64) -> bool {
        if !start.is_multiple_of(GRANT_PAGE_SIZE)
            || !len.is_multiple_of(GRANT_PAGE_SIZE)
            || len > crate::COW_GRANT_SIZE
        {
            return false;
        }
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        for page in (start..end).step_by(GRANT_PAGE_SIZE as usize) {
            if let Some(found) = self.lookup(mm_key, page)
                && !self.retire_fragment(found.slot, found.identity, start, end)
            {
                return false;
            }
        }
        true
    }

    /// Retire one unclaimed row overlapping `[start, end)`: close it, then
    /// as [`Self::retire_claimed_fragment`]. False, changing nothing, when a
    /// lease holds it or it is no longer `identity`.
    fn retire_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
    ) -> bool {
        let Some(record) = self.slot(slot) else {
            return false;
        };
        let state = record.state.load(Ordering::Acquire);
        if state & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return false;
        }
        if record
            .transfer_pins
            .compare_exchange(
                0,
                TRANSFER_PIN_RETIRING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if record.state.load(Ordering::Acquire) != state || record.identity() != identity {
            let _ = record.transfer_pins.compare_exchange(
                TRANSFER_PIN_RETIRING,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return false;
        }
        self.retire_claimed_fragment(slot, state, identity, start, end, &mut None, &mut None)
    }

    /// Retire the closed row `identity` in `slot` (state `state`): publish
    /// its parts outside `[start, end)` with their committed bits, each into
    /// the slot its admission reserved, then retire the row. A part with no
    /// reserved slot (a [`SplitRowCustody::Declinable`] admission, or a
    /// retirement that took none) takes one now, or is declined.
    #[allow(clippy::too_many_arguments)]
    fn retire_claimed_fragment(
        &self,
        slot: usize,
        state: u64,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
        lower: &mut Option<Reservation>,
        upper: &mut Option<Reservation>,
    ) -> bool {
        let Some(record) = self.slot(slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) != state
            || record.identity() != identity
            || record.transfer_pins.load(Ordering::Acquire) != TRANSFER_PIN_RETIRING
        {
            return false;
        }
        let bits = core::array::from_fn(|index| record.committed[index].load(Ordering::Acquire));
        let base = identity.semantic_base;
        let grant_end = base + identity.len;
        let (cut_start, cut_end) = Self::retirement_cut(start, end);
        for (from, to, reserved) in [
            (base, cut_start.min(grant_end), lower),
            (cut_end.max(base), grant_end, upper),
        ] {
            if from >= to {
                continue;
            }
            if let Some(reservation) = reserved
                .take()
                .or_else(|| self.reserve_slot(identity.mm_key, from, to - from))
                && !self.publish_part(reservation, identity, bits, from, to)
            {
                return false;
            }
        }
        self.retire_row(slot, state).is_some()
    }
}

/// `count` of `bits` from bit `shift` on, moved down to bit 0.
fn shifted_bits(bits: [u64; 8], shift: usize, count: usize) -> [u64; 8] {
    let mut words = [0u64; 8];
    for bit in 0..count {
        let old = shift + bit;
        if bits[old / 64] & (1 << (old % 64)) != 0 {
            words[bit / 64] |= 1 << (bit % 64);
        }
    }
    words
}

impl Default for FrameGrantResidencyTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn table() -> std::boxed::Box<FrameGrantResidencyTable> {
        let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
        // SAFETY: allocation uses the table layout and is initialized before
        // the owning Box is constructed.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<FrameGrantResidencyTable>();
            assert!(!ptr.is_null());
            FrameGrantResidencyTable::init_in_place(ptr);
            std::boxed::Box::from_raw(ptr)
        }
    }

    fn identity() -> FrameGrantResidencyIdentity {
        FrameGrantResidencyIdentity {
            mm_key: 7,
            semantic_base: 0x10_0000,
            physical_ipa: 0x20_0000,
            len: 16 * GRANT_PAGE_SIZE,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        }
    }

    #[test]
    fn full_residency_preserves_live_rows_and_reuses_retired_slots() {
        let table = table();
        let first = FrameGrantResidencyIdentity {
            semantic_base: 0x1000_0000,
            len: GRANT_PAGE_SIZE,
            ..identity()
        };
        let at = |index: usize| FrameGrantResidencyIdentity {
            semantic_base: first.semantic_base + index as u64 * GRANT_PAGE_SIZE,
            physical_ipa: first.physical_ipa + index as u64 * GRANT_PAGE_SIZE,
            ..first
        };
        for index in 0..FRAME_GRANT_RESIDENCY_SLOTS {
            let identity = at(index);
            table.try_publish(identity).unwrap();
            assert!(
                table.record_commit(
                    table
                        .lookup(identity.mm_key, identity.semantic_base)
                        .unwrap()
                )
            );
        }
        let wider = FrameGrantResidencyIdentity {
            len: 2 * GRANT_PAGE_SIZE,
            ..first
        };
        assert_eq!(
            table.try_publish(wider),
            Err(FrameGrantResidencyRefusal::Overlap)
        );
        let next = at(FRAME_GRANT_RESIDENCY_SLOTS);
        assert_eq!(
            table.try_publish(next),
            Err(FrameGrantResidencyRefusal::Capacity)
        );

        // These addresses hash to the same probe chain. Retiring the first
        // exact row makes its slot available to the next request.
        let stale = table.lookup(first.mm_key, first.semantic_base).unwrap();
        let retirement = table
            .begin_retire_overlapping(
                first.mm_key,
                first.semantic_base,
                first.len,
                SplitRowCustody::Reserved,
            )
            .unwrap();
        assert!(retirement.commit());
        assert_eq!(table.try_publish(next), Ok(stale.slot));
        assert!(!table.record_commit(stale));
        assert!(table.is_guest_committed(first.mm_key, first.semantic_base + GRANT_PAGE_SIZE));
        assert!(!table.is_guest_committed(next.mm_key, next.semantic_base));
    }

    /// #2813: a retirement that splits a row never loses the parts outside
    /// the retired range. A hole in the middle of a 16-page row needs two
    /// slots (the old row keeps its own until the commit) and the table has
    /// none: the admission refuses with `Capacity` and changes nothing. With
    /// room, the same retirement publishes both parts with their committed
    /// bits, and a dropped admission returns its reserved slots.
    #[test]
    fn retirement_reserves_a_split_rows_parts_or_changes_nothing() {
        let table = table();
        let row = identity();
        let pages = row.len / GRANT_PAGE_SIZE;
        table.publish(row).unwrap();
        for page in 0..pages {
            let page = table
                .lookup(row.mm_key, row.semantic_base + page * GRANT_PAGE_SIZE)
                .unwrap();
            assert!(table.record_commit(page));
        }
        // Every other slot holds a one-page row of the same MM.
        const FILLER_BASE: u64 = 0x1_0000_0000;
        for index in 0..64 * table.slot_capacity() as u64 {
            if table.observed_slots_used() == table.slot_capacity() {
                break;
            }
            let _ = table.publish(FrameGrantResidencyIdentity {
                semantic_base: FILLER_BASE + index * GRANT_PAGE_SIZE,
                physical_ipa: 0x00a0_0000_0000 + index * GRANT_PAGE_SIZE,
                len: GRANT_PAGE_SIZE,
                ..row
            });
        }
        assert_eq!(table.observed_slots_used(), table.slot_capacity());

        let hole = row.semantic_base + 4 * GRANT_PAGE_SIZE;
        let hole_len = 4 * GRANT_PAGE_SIZE;
        assert_eq!(
            table
                .begin_retire_overlapping(row.mm_key, hole, hole_len, SplitRowCustody::Reserved)
                .err(),
            Some(ResidencyRetirementRefusal::Capacity)
        );
        for page in 0..pages {
            assert!(
                table.is_guest_committed(row.mm_key, row.semantic_base + page * GRANT_PAGE_SIZE),
                "page {page} lost its row to a refused retirement"
            );
        }
        let whole = table.lookup(row.mm_key, row.semantic_base).unwrap();
        assert_eq!(whole.identity, row);
        assert!(table.pin_transfer(whole).is_some(), "admission reopened");
        assert_eq!(table.observed_slots_used(), table.slot_capacity());

        // Room: every filler retires. An admission that is dropped changes
        // nothing and keeps no slot.
        assert!(table.retire_overlapping(row.mm_key, FILLER_BASE, 1 << 40));
        let used = table.observed_slots_used();
        drop(
            table
                .begin_retire_overlapping(row.mm_key, hole, hole_len, SplitRowCustody::Reserved)
                .unwrap(),
        );
        assert_eq!(table.observed_slots_used(), used);
        assert_eq!(table.lookup(row.mm_key, hole).unwrap().identity, row);

        let retirement = table
            .begin_retire_overlapping(row.mm_key, hole, hole_len, SplitRowCustody::Reserved)
            .unwrap();
        assert!(retirement.commit());
        for page in 0..pages {
            let va = row.semantic_base + page * GRANT_PAGE_SIZE;
            if (4..8).contains(&page) {
                assert!(
                    table.lookup(row.mm_key, va).is_none(),
                    "page {page} retired"
                );
                continue;
            }
            let part = table.lookup(row.mm_key, va).unwrap();
            assert_eq!(part.expected_ipa, row.physical_ipa + page * GRANT_PAGE_SIZE);
            assert!(table.is_guest_committed(row.mm_key, va), "page {page}");
        }
        assert_eq!(table.observed_slots_used(), used + 1, "one row became two");
    }

    #[test]
    fn retirement_preclaim_refuses_pins_and_rolls_back_or_commits_whole() {
        let table = table();
        let identity = identity();
        assert!(table.publish(identity).is_some());
        let page = table
            .lookup(
                identity.mm_key,
                identity.semantic_base + 2 * GRANT_PAGE_SIZE,
            )
            .unwrap();
        let pin = table.pin_transfer(page).unwrap();
        assert!(
            table
                .begin_retire_overlapping(
                    identity.mm_key,
                    identity.semantic_base + GRANT_PAGE_SIZE,
                    2 * GRANT_PAGE_SIZE,
                    SplitRowCustody::Reserved,
                )
                .err()
                .is_some_and(|refusal| matches!(refusal, ResidencyRetirementRefusal::Leased(_))),
            "a live transfer must refuse before descriptor retirement"
        );
        drop(pin);

        let retirement = table
            .begin_retire_overlapping(
                identity.mm_key,
                identity.semantic_base + GRANT_PAGE_SIZE,
                2 * GRANT_PAGE_SIZE,
                SplitRowCustody::Reserved,
            )
            .unwrap();
        assert!(
            table.pin_transfer(page).is_none(),
            "preclaim closes admission"
        );
        drop(retirement);
        assert!(
            table.pin_transfer(page).is_some(),
            "dropping an uncommitted claim restores the row"
        );

        let retirement = table
            .begin_retire_overlapping(
                identity.mm_key,
                identity.semantic_base + GRANT_PAGE_SIZE,
                2 * GRANT_PAGE_SIZE,
                SplitRowCustody::Reserved,
            )
            .unwrap();
        assert!(retirement.commit());
        assert!(
            table
                .lookup(identity.mm_key, identity.semantic_base)
                .is_some(),
            "prefix survives"
        );
        assert!(
            table
                .lookup(identity.mm_key, identity.semantic_base + GRANT_PAGE_SIZE)
                .is_none(),
            "replaced pages are revoked"
        );
        assert!(
            table
                .lookup(
                    identity.mm_key,
                    identity.semantic_base + 3 * GRANT_PAGE_SIZE
                )
                .is_some(),
            "suffix survives"
        );
    }

    #[test]
    fn extension_slots_share_lookup_dirty_ack_and_retirement() {
        let bootstrap = table();
        let extension = table();
        let aliases = [ResolvedResidencySegment {
            table: &bootstrap,
            index: 0,
            segment: &extension.storage.bootstrap,
        }];
        let view = ResidencyRows {
            bootstrap: &bootstrap.storage.bootstrap,
            directory: &bootstrap.storage.directory,
            extensions: ResidencyExtensions::Aliases(&aliases),
        }
        .as_table();
        let first = identity();
        for page in 0..=FRAME_GRANT_RESIDENCY_SLOTS {
            let offset = page as u64 * GRANT_PAGE_SIZE;
            let row = FrameGrantResidencyIdentity {
                semantic_base: first.semantic_base + offset,
                physical_ipa: first.physical_ipa + offset,
                len: GRANT_PAGE_SIZE,
                ..first
            };
            let slot = view.try_publish(row).expect("space in either segment");
            let selected = view
                .lookup(row.mm_key, row.semantic_base)
                .expect("published");
            assert_eq!(selected.slot, slot);
            assert_eq!(
                slot >= FRAME_GRANT_RESIDENCY_SLOTS,
                page == FRAME_GRANT_RESIDENCY_SLOTS
            );
            assert!(view.record_commit(selected));
        }
        let mut count = 0;
        let _: core::ops::ControlFlow<()> =
            view.for_each_dirty_mm(first.mm_key, |slot, row, bits| {
                count += 1;
                assert_eq!(bits[0], 1);
                assert!(view.ack_dirty(slot, row));
                core::ops::ControlFlow::Continue(())
            });
        assert_eq!(count, FRAME_GRANT_RESIDENCY_SLOTS + 1);
        let last_va = first.semantic_base + FRAME_GRANT_RESIDENCY_SLOTS as u64 * GRANT_PAGE_SIZE;
        let last = view.lookup(first.mm_key, last_va).expect("extension row");
        let pin = view.pin_transfer(last).expect("exact extension pin");
        let len = (FRAME_GRANT_RESIDENCY_SLOTS + 1) as u64 * GRANT_PAGE_SIZE;
        assert!(
            view.begin_retire_overlapping(
                first.mm_key,
                first.semantic_base,
                len,
                SplitRowCustody::Reserved
            )
            .is_err()
        );
        drop(pin);
        assert!(
            view.begin_retire_overlapping(
                first.mm_key,
                first.semantic_base,
                len,
                SplitRowCustody::Reserved
            )
            .expect("pins released across both segments")
            .commit()
        );
        assert_eq!(view.observed_slots_used(), 0);
        assert!(view.pin_transfer(last).is_none());
    }

    #[test]
    fn allocator_refusal_preserves_rows_and_the_same_growth_can_succeed() {
        use core::cell::{Cell, RefCell};

        struct TestAllocator {
            refuse: Cell<bool>,
            allocations: RefCell<std::vec::Vec<(*mut u8, Layout)>>,
        }
        impl Drop for TestAllocator {
            fn drop(&mut self) {
                for (address, layout) in self.allocations.get_mut().drain(..) {
                    // SAFETY: all table views have been dropped. The test
                    // allocator owns each exact address and allocation layout.
                    unsafe { std::alloc::dealloc(address, layout) };
                }
            }
        }
        // SAFETY: each allocation is retained through test teardown and has
        // an exact enclosing extent receipt.
        unsafe impl ReservationMetadataAllocator for TestAllocator {
            fn allocate_with_extent(
                &self,
                layout: Layout,
            ) -> Option<(*mut u8, ExtentGrantReceipt)> {
                if self.refuse.replace(false) {
                    return None;
                }
                // SAFETY: layout is for a nonempty, aligned residency segment.
                let ptr = unsafe { std::alloc::alloc(layout) };
                if ptr.is_null() {
                    return None;
                }
                self.allocations.borrow_mut().push((ptr, layout));
                Some((
                    ptr,
                    ExtentGrantReceipt {
                        base_va: ptr as u64,
                        size: layout.size(),
                        token: 1,
                    },
                ))
            }

            fn deallocate(&self, ptr: *mut u8, layout: Layout) {
                let mut allocations = self.allocations.borrow_mut();
                let index = allocations
                    .iter()
                    .position(|entry| *entry == (ptr, layout))
                    .unwrap();
                allocations.swap_remove(index);
                // SAFETY: the directory declined the allocation, and the
                // stored entry proves this allocator retained the same layout.
                unsafe { std::alloc::dealloc(ptr, layout) };
            }
        }

        let allocator = TestAllocator {
            refuse: Cell::new(true),
            allocations: RefCell::new(std::vec::Vec::new()),
        };
        let table = table();
        let first = identity();
        for page in 0..FRAME_GRANT_RESIDENCY_SLOTS {
            let offset = page as u64 * GRANT_PAGE_SIZE;
            let row = FrameGrantResidencyIdentity {
                semantic_base: first.semantic_base + offset,
                physical_ipa: first.physical_ipa + offset,
                len: GRANT_PAGE_SIZE,
                ..first
            };
            assert!(table.publish(row).is_some());
        }
        let offset = FRAME_GRANT_RESIDENCY_SLOTS as u64 * GRANT_PAGE_SIZE;
        let pending = FrameGrantResidencyIdentity {
            semantic_base: first.semantic_base + offset,
            physical_ipa: first.physical_ipa + offset,
            len: GRANT_PAGE_SIZE,
            ..first
        };
        assert_eq!(
            table.try_publish(pending),
            Err(FrameGrantResidencyRefusal::Capacity)
        );
        let observed = table.extension_count();
        assert_eq!(
            table.grow(&allocator, observed),
            Err(ResidencyGrowthRefusal::MetadataRequired)
        );
        assert_eq!(table.extension_count(), observed);
        assert_eq!(table.observed_slots_used(), FRAME_GRANT_RESIDENCY_SLOTS);

        assert_eq!(table.grow(&allocator, observed), Ok(()));
        assert_eq!(table.grow(&allocator, observed), Ok(()));
        assert_eq!(table.extension_count(), observed + 1);
        assert_eq!(allocator.allocations.borrow().len(), 1);
        // SAFETY: the test allocator returned the same address used by the
        // guest view and retains its allocations through the last borrow.
        let view = unsafe { table.guest_view() };
        let slot = view
            .try_publish(pending)
            .expect("pending row fits the new segment");
        assert!(slot >= FRAME_GRANT_RESIDENCY_SLOTS);
        assert_eq!(
            view.lookup(pending.mm_key, pending.semantic_base)
                .unwrap()
                .slot,
            slot
        );

        // The host identifies the same allocator grant and must supply its
        // retained pin before it can acknowledge or retire this row.
        struct Pin(MetadataExtent);
        // SAFETY: TestAllocator retains the published extent throughout the
        // local pin and view. This fixture's two venues use the same mapping.
        unsafe impl PinnedMetadataExtent for Pin {
            fn extent(&self) -> MetadataExtent {
                self.0
            }
            fn host_base(&self) -> core::ptr::NonNull<u8> {
                core::ptr::NonNull::new(self.0.base() as *mut u8).unwrap()
            }
        }
        let location = table.extension_location(0).unwrap();
        let extent = location.extent;
        let pin =
            Pin(MetadataExtent::new(extent.base_va, extent.size as u64, extent.token).unwrap());
        let stale =
            Pin(MetadataExtent::new(extent.base_va, extent.size as u64, extent.token + 1).unwrap());
        // SAFETY: both pins use the exact test carrier's allocator venue.
        assert!(unsafe { table.resolve_extension(0, &stale) }.is_none());
        assert!(table.resolved_view(&[]).is_none());
        // SAFETY: pin uses the exact test carrier's allocator venue.
        let aliases = [unsafe { table.resolve_extension(0, &pin) }.unwrap()];
        let host = table.resolved_view(&aliases).unwrap();
        let epoch_before = table.retirement_epoch();
        assert!(host.retire(slot, pending));
        assert_eq!(table.retirement_epoch(), epoch_before + 1);
        assert!(view.lookup(pending.mm_key, pending.semantic_base).is_none());

        // ResolvedResidencyTable caches dynamic pins across refreshes and
        // retires rows across both bootstrap and dynamic segments.
        struct Resolver {
            expected: MetadataExtent,
            pin_calls: Cell<usize>,
        }
        impl MetadataExtentResolver for Resolver {
            type Pin = Pin;
            fn pin(&self, extent: MetadataExtent) -> Result<Pin, MetadataResolutionError> {
                self.pin_calls.set(self.pin_calls.get() + 1);
                if extent != self.expected {
                    return Err(MetadataResolutionError::InvalidExtent);
                }
                Ok(Pin(extent))
            }
        }
        let resolver = Resolver {
            expected: MetadataExtent::new(extent.base_va, extent.size as u64, extent.token)
                .unwrap(),
            pin_calls: Cell::new(0),
        };
        let mut resolved = std::boxed::Box::new(ResolvedResidencyTable::new());
        // SAFETY: table and resolver belong to this fixture for the whole test.
        unsafe { resolved.refresh(&table, &resolver, None).unwrap() };
        assert_eq!(resolved.extension_count(), 1);
        assert_eq!(resolver.pin_calls.get(), 1);
        // Unchanged generation performs zero re-pinning.
        unsafe { resolved.refresh(&table, &resolver, None).unwrap() };
        assert_eq!(resolver.pin_calls.get(), 1);
        let host_view = resolved.view().unwrap();
        let second_slot = view.try_publish(pending).expect("re-publish in extension");
        assert!(second_slot >= FRAME_GRANT_RESIDENCY_SLOTS);
        assert_eq!(
            host_view.observed_slots_used(),
            FRAME_GRANT_RESIDENCY_SLOTS + 1
        );
        let total_len = (FRAME_GRANT_RESIDENCY_SLOTS + 1) as u64 * GRANT_PAGE_SIZE;
        let epoch_before_bulk = host_view.retirement_epoch();
        assert!(
            host_view
                .begin_retire_overlapping(
                    first.mm_key,
                    first.semantic_base,
                    total_len,
                    SplitRowCustody::Reserved
                )
                .expect("retire across bootstrap and dynamic segments")
                .commit()
        );
        assert_eq!(host_view.observed_slots_used(), 0);
        assert_eq!(
            host_view.retirement_epoch(),
            epoch_before_bulk + (FRAME_GRANT_RESIDENCY_SLOTS + 1) as u64
        );
    }

    #[test]
    fn constructors_have_identical_wire_bytes_and_frozen_arm_layout() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(compare_constructors)
            .expect("spawn layout test")
            .join()
            .expect("compare constructors");
    }

    fn compare_constructors() {
        assert_eq!(core::mem::size_of::<FrameGrantResidencyRecord>(), 192);
        assert_eq!(core::mem::align_of::<FrameGrantResidencyRecord>(), 64);
        assert_eq!(FrameGrantResidencyRecord::COMMITTED_OFFSET, 72);
        assert_eq!(FrameGrantResidencyRecord::TRANSFER_PINS_OFFSET, 136);
        assert_eq!(core::mem::size_of::<FrameGrantResidencyTable>(), 795_200);
        assert_eq!(core::mem::align_of::<FrameGrantResidencyTable>(), 64);

        let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
        // SAFETY: both allocations use the table layout, are checked for null,
        // initialized before reading, and deallocated using that same layout.
        unsafe {
            let ordinary = std::alloc::alloc(layout).cast::<FrameGrantResidencyTable>();
            let inplace = std::alloc::alloc(layout).cast::<FrameGrantResidencyTable>();
            assert!(!ordinary.is_null() && !inplace.is_null());
            ordinary.write(FrameGrantResidencyTable::new());
            FrameGrantResidencyTable::init_in_place(inplace);
            let ordinary_bytes = core::slice::from_raw_parts(ordinary.cast::<u8>(), layout.size());
            let inplace_bytes = core::slice::from_raw_parts(inplace.cast::<u8>(), layout.size());
            assert_eq!(ordinary_bytes, inplace_bytes);
            std::alloc::dealloc(ordinary.cast(), layout);
            std::alloc::dealloc(inplace.cast(), layout);
        }
    }
}
