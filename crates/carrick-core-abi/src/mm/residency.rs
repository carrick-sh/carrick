//! Exact live residency and retained grant-window custody for either ISA.
use crate::{ExtentGrantReceipt, ReservationMetadataAllocator};
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
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

    fn publish(&self, identity: FrameGrantResidencyIdentity) {
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
        for word in &self.committed {
            word.store(0, Ordering::Relaxed);
        }
        self.transfer_pins.store(0, Ordering::Release);
        let writing = self.state.load(Ordering::Relaxed);
        self.state.store(
            (writing & !GRANT_STATE_MASK) | GRANT_LIVE,
            Ordering::Release,
        );
    }
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
}
impl Drop for FrameGrantTransferPin<'_> {
    fn drop(&mut self) {
        self.record.transfer_pins.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Exact-MM reservation of every residency row overlapping one descriptor
/// retirement. The caller either commits after the descriptor transaction or
/// drops this token to reopen transfer admission without changing residency.
pub struct FrameGrantResidencyRetirement<'a> {
    table: FrameGrantResidencyTable<ResidencyRows<'a>>,
    mm_key: u64,
    start: u64,
    end: u64,
    active: bool,
}
impl FrameGrantResidencyRetirement<'_> {
    /// Retire the preclaimed rows after their stage-1 leaves are unreachable.
    /// Exact-MM exclusion makes a failed commit an invariant violation.
    #[must_use]
    pub fn commit(mut self) -> bool {
        let committed = self
            .table
            .commit_retirement(self.mm_key, self.start, self.end);
        self.active = false;
        committed
    }
}
impl Drop for FrameGrantResidencyRetirement<'_> {
    fn drop(&mut self) {
        if self.active {
            self.table
                .cancel_retirement(self.mm_key, self.start, self.end);
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
    reserved: [u64; 6],
}

impl ResidencyDirectory {
    const fn new() -> Self {
        Self {
            publishing: AtomicU64::new(0),
            count: AtomicU64::new(0),
            entries: [const { SegmentLocationWire::new() }; MAX_RESIDENCY_EXTENSIONS],
            reserved: [0; 6],
        }
    }

    unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: caller owns the uninitialized directory. Use field writes
        // to avoid putting the directory on the supervisor stack.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).publishing).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).count).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).reserved).write([0; 6]);
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
        Self {
            storage: ResidencyStorage {
                bootstrap: ResidencySegment::new(),
                directory: ResidencyDirectory::new(),
            },
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
        self.storage
            .directory
            .entries
            .get(index)
            .map(SegmentLocationWire::read)
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
            extensions: ResidencyExtensions::Guest(&self.storage.directory, self.extension_count()),
        }
        .as_table()
    }

    /// Create a view using already resolved and retained aliases.
    ///
    /// # Safety
    /// Each alias at index `i` must refer to this table's published
    /// `extension_location(i)`, with the pin held for the whole borrow.
    pub unsafe fn resolved_view<'a>(
        &'a self,
        extensions: &'a [&'a ResidencySegment],
    ) -> Option<FrameGrantResidencyTable<ResidencyRows<'a>>> {
        (extensions.len() == self.extension_count()).then(|| {
            ResidencyRows {
                bootstrap: &self.storage.bootstrap,
                extensions: ResidencyExtensions::Aliases(extensions),
            }
            .as_table()
        })
    }
}

/// Venue-local access to the bootstrap and extension storage.
#[derive(Clone, Copy)]
pub struct ResidencyRows<'a> {
    bootstrap: &'a ResidencySegment,
    extensions: ResidencyExtensions<'a>,
}

#[derive(Clone, Copy)]
enum ResidencyExtensions<'a> {
    Aliases(&'a [&'a ResidencySegment]),
    Guest(&'a ResidencyDirectory, usize),
}

mod sealed {
    pub trait ResidencyStorage {
        fn rows(&self) -> super::ResidencyRows<'_>;
    }
}

impl sealed::ResidencyStorage for ResidencyStorage {
    fn rows(&self) -> ResidencyRows<'_> {
        ResidencyRows {
            bootstrap: &self.bootstrap,
            extensions: ResidencyExtensions::Aliases(&[]),
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
            ResidencyExtensions::Guest(_, count) => count,
        };
        (0..=count).map_while(move |index| self.segment(index))
    }

    fn segment(self, index: usize) -> Option<&'a ResidencySegment> {
        let Some(index) = index.checked_sub(1) else {
            return Some(self.bootstrap);
        };
        match self.extensions {
            ResidencyExtensions::Aliases(entries) => entries.get(index).copied(),
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
        let class = (identity.len / GRANT_PAGE_SIZE)
            .next_power_of_two()
            .trailing_zeros();
        let bucket = identity.semantic_base / (GRANT_PAGE_SIZE << class);
        for (segment_index, segment) in self.segments().enumerate() {
            for probe in 0..GRANT_PROBES {
                let slot = Self::probe(identity.mm_key, bucket, class, probe);
                let record = &segment.slots[slot];
                let state = record.state.load(Ordering::Acquire);
                if !matches!(state & GRANT_STATE_MASK, GRANT_EMPTY | GRANT_RETIRED) {
                    continue;
                }
                // Claim the exact reusable epoch we observed. Another MM can
                // take this slot even while this MM's editor is held.
                if record
                    .state
                    .compare_exchange(
                        state,
                        (state & !GRANT_STATE_MASK).wrapping_add(4) | GRANT_WRITING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    record.publish(identity);
                    return Ok(segment_index * FRAME_GRANT_RESIDENCY_SLOTS + slot);
                }
            }
        }
        Err(FrameGrantResidencyRefusal::Capacity)
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
    pub fn lookup(&self, mm_key: u64, va: u64) -> Option<FrameGrantResidencyPage> {
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
        let pin = FrameGrantTransferPin { record };
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
        let Some((record, dirty)) = self.slot_entry(slot) else {
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
        if record
            .state
            .compare_exchange(
                epoch,
                (epoch & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            record.transfer_pins.store(0, Ordering::Release);
            return false;
        }
        dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
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
    pub fn begin_retire_overlapping(
        &self,
        mm_key: u64,
        start: u64,
        len: u64,
    ) -> Option<FrameGrantResidencyRetirement<'_>> {
        let end = start.checked_add(len)?;
        if mm_key == 0 || start >= end {
            return None;
        }
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
                self.cancel_retirement(mm_key, start, end);
                return None;
            }
            if record.state.load(Ordering::Acquire) != state || record.identity() != identity {
                record.transfer_pins.store(0, Ordering::Release);
                self.cancel_retirement(mm_key, start, end);
                return None;
            }
        }
        Some(FrameGrantResidencyRetirement {
            table: self.storage.rows().as_table(),
            mm_key,
            start,
            end,
            active: true,
        })
    }

    fn cancel_retirement(&self, mm_key: u64, start: u64, end: u64) {
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

    fn commit_retirement(&self, mm_key: u64, start: u64, end: u64) -> bool {
        for (slot, record) in self.slots().enumerate() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            if identity.mm_key == mm_key
                && identity.semantic_base < end
                && start < identity.semantic_base.saturating_add(identity.len)
                && !self.retire_claimed_fragment(slot, identity, start, end)
            {
                return false;
            }
        }
        true
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

    fn retire_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
    ) -> bool {
        let Some(bits) = self.committed_words(slot, identity) else {
            return false;
        };
        if !self.retire(slot, identity) {
            return false;
        }
        self.publish_retirement_fragments(identity, bits, start, end);
        true
    }

    fn retire_claimed_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
    ) -> bool {
        let Some((record, dirty)) = self.slot_entry(slot) else {
            return false;
        };
        let state = record.state.load(Ordering::Acquire);
        if state & GRANT_STATE_MASK != GRANT_LIVE
            || record.identity() != identity
            || record.transfer_pins.load(Ordering::Acquire) != TRANSFER_PIN_RETIRING
        {
            return false;
        }
        let bits = core::array::from_fn(|index| record.committed[index].load(Ordering::Acquire));
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
            return false;
        }
        dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
        self.publish_retirement_fragments(identity, bits, start, end);
        true
    }

    fn publish_retirement_fragments(
        &self,
        identity: FrameGrantResidencyIdentity,
        bits: [u64; 8],
        start: u64,
        end: u64,
    ) {
        let base = identity.semantic_base;
        let grant_end = base + identity.len;
        let cut_start = start & !(GRANT_PAGE_SIZE - 1);
        let cut_end = end.saturating_add(GRANT_PAGE_SIZE - 1) & !(GRANT_PAGE_SIZE - 1);
        for (fragment_start, fragment_end) in [
            (base, cut_start.min(grant_end)),
            (cut_end.max(base), grant_end),
        ] {
            if fragment_start >= fragment_end {
                continue;
            }
            let fragment = FrameGrantResidencyIdentity {
                semantic_base: fragment_start,
                physical_ipa: identity.physical_ipa + fragment_start - base,
                len: fragment_end - fragment_start,
                ..identity
            };
            if let Some(fragment_slot) = self.publish(fragment)
                && let Some((record, dirty)) = self.slot_entry(fragment_slot)
            {
                let shift = ((fragment_start - base) / GRANT_PAGE_SIZE) as usize;
                let count = (fragment.len / GRANT_PAGE_SIZE) as usize;
                for bit in 0..count {
                    let old_bit = shift + bit;
                    if bits[old_bit / 64] & (1 << (old_bit % 64)) != 0 {
                        record.committed[bit / 64].fetch_or(1 << (bit % 64), Ordering::Release);
                        dirty.fetch_or(1 << (fragment_slot % 64), Ordering::Release);
                    }
                }
            }
        }
    }
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
            .begin_retire_overlapping(first.mm_key, first.semantic_base, first.len)
            .unwrap();
        assert!(retirement.commit());
        assert_eq!(table.try_publish(next), Ok(stale.slot));
        assert!(!table.record_commit(stale));
        assert!(table.is_guest_committed(first.mm_key, first.semantic_base + GRANT_PAGE_SIZE));
        assert!(!table.is_guest_committed(next.mm_key, next.semantic_base));
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
                )
                .is_none(),
            "a live transfer must refuse before descriptor retirement"
        );
        drop(pin);

        let retirement = table
            .begin_retire_overlapping(
                identity.mm_key,
                identity.semantic_base + GRANT_PAGE_SIZE,
                2 * GRANT_PAGE_SIZE,
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
        let aliases = [&extension.storage.bootstrap];
        let view = ResidencyRows {
            bootstrap: &bootstrap.storage.bootstrap,
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
            view.begin_retire_overlapping(first.mm_key, first.semantic_base, len)
                .is_none()
        );
        drop(pin);
        assert!(
            view.begin_retire_overlapping(first.mm_key, first.semantic_base, len)
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
