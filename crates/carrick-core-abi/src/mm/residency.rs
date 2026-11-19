//! Exact live residency and retained grant-window custody for either ISA.
use core::sync::atomic::{AtomicU64, Ordering};
pub const FRAME_GRANT_RESIDENCY_SLOTS: usize = 4096;
// Each new segment doubles total capacity while preserving all existing slot
// numbers and their transfer pins.
const RESIDENCY_SEGMENTS: usize = 5;
const EXTENSION_SLOTS: usize = FRAME_GRANT_RESIDENCY_SLOTS * ((1 << (RESIDENCY_SEGMENTS - 1)) - 1);
pub const FRAME_GRANT_RESIDENCY_EXTENSION_BYTES: usize =
    core::mem::size_of::<FrameGrantResidencyExtensions>();
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
            transfer_pins: AtomicU64::new(0),
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
    table: &'a FrameGrantResidencyTable,
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

// All-zero is a valid, inactive extension. The region allocation supplies
// zero-filled pages, and publication touches records only as they are probed.
#[repr(C, align(64))]
struct FrameGrantResidencyExtensions {
    slots: [FrameGrantResidencyRecord; EXTENSION_SLOTS],
    dirty: [AtomicU64; EXTENSION_SLOTS / 64],
}

struct ResidencySegment<'a> {
    first: usize,
    slots: &'a [FrameGrantResidencyRecord],
    dirty: &'a [AtomicU64],
}

impl ResidencySegment<'_> {
    fn probe(&self, hash: usize, offset: usize) -> usize {
        hash.wrapping_add(offset) & (self.slots.len() - 1)
    }
}

/// Shared open-addressed index with address-stable, demand-activated segments. Grants hash by their smallest power-of-two
/// page-count bucket. A page in a grant lies in its base bucket or the next
/// bucket, so lookups check those two buckets for each size class. Disjoint
/// short grants in one 2 MiB window no longer consume one 64-slot chain.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyTable {
    slots: [FrameGrantResidencyRecord; FRAME_GRANT_RESIDENCY_SLOTS],
    dirty: [AtomicU64; FRAME_GRANT_RESIDENCY_SLOTS / 64],
    extension_offset: AtomicU64,
    active_extensions: AtomicU64,
    _reserved: [u64; 6],
}

impl FrameGrantResidencyTable {
    const fn initial_slot() -> FrameGrantResidencyRecord {
        FrameGrantResidencyRecord::new()
    }

    const fn initial_dirty() -> AtomicU64 {
        AtomicU64::new(0)
    }

    pub const fn new() -> Self {
        Self {
            slots: [const { Self::initial_slot() }; FRAME_GRANT_RESIDENCY_SLOTS],
            dirty: [const { Self::initial_dirty() }; FRAME_GRANT_RESIDENCY_SLOTS / 64],
            extension_offset: AtomicU64::new(0),
            active_extensions: AtomicU64::new(0),
            _reserved: [0; 6],
        }
    }

    /// Initialize in place without materializing a large stack temporary.
    ///
    /// # Safety
    /// `ptr` must be valid for writes, non-null, aligned to `align_of::<Self>()`,
    /// and point to storage of at least `size_of::<Self>()` bytes.
    pub unsafe fn init_in_place(ptr: *mut Self) {
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
            core::ptr::addr_of_mut!((*ptr).extension_offset).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).active_extensions).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr)._reserved).write([0; 6]);
        }
    }

    /// Attach the reserved tail of the shared, zero-filled ABI mapping before
    /// either venue can publish a grant. A displacement maps to the same
    /// bytes in the host and guest even when their virtual addresses differ.
    ///
    /// # Safety
    /// Both offsets must name aligned, disjoint storage of the corresponding
    /// size inside one retained allocation. The extension follows the table,
    /// starts zeroed and stays at its displacement for every table borrow,
    /// including borrows in the guest alias. Call once at exclusive boot.
    pub unsafe fn attach_extensions(base: *mut u8, table: usize, extension: usize) {
        debug_assert!(extension > table);
        // Expose provenance of the whole mapping; the table reference alone
        // covers only its inline segment, not the separate tail reservation.
        base.expose_provenance();
        // SAFETY: exclusive publication into the initialized shared head.
        let table_ref = unsafe { &*base.add(table).cast::<Self>() };
        table_ref
            .extension_offset
            .store((extension - table) as u64, Ordering::Release);
    }

    fn segment(&self, index: usize) -> ResidencySegment<'_> {
        if index == 0 {
            return ResidencySegment {
                first: 0,
                slots: &self.slots,
                dirty: &self.dirty,
            };
        }
        let offset = self.extension_offset.load(Ordering::Acquire) as usize;
        debug_assert!(offset != 0 && index < RESIDENCY_SEGMENTS);
        let address = core::ptr::from_ref(self).addr() + offset;
        // SAFETY: attach_extensions tied this displacement to the same
        // retained allocation and initialized it before publishing the offset.
        let extensions = unsafe {
            &*core::ptr::with_exposed_provenance::<FrameGrantResidencyExtensions>(address)
        };
        let first = FRAME_GRANT_RESIDENCY_SLOTS << (index - 1);
        let local = first - FRAME_GRANT_RESIDENCY_SLOTS;
        ResidencySegment {
            first,
            slots: &extensions.slots[local..local + first],
            dirty: &extensions.dirty[local / 64..(local + first) / 64],
        }
    }

    fn active_segment_count(&self) -> usize {
        1 + self.active_extensions.load(Ordering::Acquire) as usize
    }

    pub fn active_slots(&self) -> usize {
        FRAME_GRANT_RESIDENCY_SLOTS << (self.active_segment_count() - 1)
    }

    fn records(&self) -> impl Iterator<Item = (usize, &FrameGrantResidencyRecord)> {
        (0..self.active_segment_count()).flat_map(|index| {
            let segment = self.segment(index);
            (segment.first..).zip(segment.slots)
        })
    }

    fn record(&self, slot: usize) -> Option<(&FrameGrantResidencyRecord, &AtomicU64)> {
        if slot >= self.active_slots() {
            return None;
        }
        // Segment zero and one each have 4,096 slots. Subsequent segment
        // starts are the previous capacity, doubling at every step.
        let index = if slot < FRAME_GRANT_RESIDENCY_SLOTS {
            0
        } else {
            (slot / FRAME_GRANT_RESIDENCY_SLOTS).ilog2() + 1
        };
        let segment = self.segment(index as usize);
        let local = slot - segment.first;
        Some((&segment.slots[local], &segment.dirty[local / 64]))
    }

    fn hash(mm_key: u64, bucket: u64, class: u32) -> usize {
        let mixed = mm_key.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ bucket.wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ u64::from(class).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed as usize
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
        let hash = Self::hash(identity.mm_key, bucket, class);
        let active = self.active_segment_count();
        for index in 0..active {
            if let Some(slot) = Self::publish_in_segment(self.segment(index), hash, identity) {
                return Ok(slot);
            }
        }
        if active < RESIDENCY_SEGMENTS && self.extension_offset.load(Ordering::Acquire) != 0 {
            // The next segment already has zeroed shared backing. If a peer
            // published it, use that same segment instead of growing twice.
            let _ = self.active_extensions.compare_exchange(
                (active - 1) as u64,
                active as u64,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Some(slot) = Self::publish_in_segment(self.segment(active), hash, identity) {
                return Ok(slot);
            }
        }
        Err(FrameGrantResidencyRefusal::Capacity)
    }

    fn publish_in_segment(
        segment: ResidencySegment<'_>,
        hash: usize,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<usize> {
        for probe in 0..GRANT_PROBES {
            let slot = segment.probe(hash, probe);
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
                return Some(segment.first + slot);
            }
        }
        None
    }

    /// Diagnostic sample of occupied slots, including in-flight publishers.
    /// Other MMs can change the table during the scan.
    pub fn observed_slots_used(&self) -> usize {
        self.records()
            .filter(|(_, record)| {
                matches!(
                    record.state.load(Ordering::Relaxed) & GRANT_STATE_MASK,
                    GRANT_WRITING | GRANT_LIVE
                )
            })
            .count()
    }

    /// Guest: find the exact live grant covering a prepared leaf.
    pub fn lookup(&self, mm_key: u64, va: u64) -> Option<FrameGrantResidencyPage> {
        let page = va & !(GRANT_PAGE_SIZE - 1);
        for index in 0..self.active_segment_count() {
            let segment = self.segment(index);
            for class in 0..=EL1_FRAME_GRANT_TARGET_SIZE
                .div_ceil(GRANT_PAGE_SIZE)
                .trailing_zeros()
            {
                let bucket = page / (GRANT_PAGE_SIZE << class);
                for candidate in [Some(bucket), (class > 0 && bucket > 0).then(|| bucket - 1)]
                    .into_iter()
                    .flatten()
                {
                    let hash = Self::hash(mm_key, candidate, class);
                    for probe in 0..GRANT_PROBES {
                        let slot = segment.probe(hash, probe);
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
                                        slot: segment.first + slot,
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
        let (record, _) = self.record(page.slot)?;
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
        let Some((record, dirty)) = self.record(page.slot) else {
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
        let Some((record, _)) = self.record(page.slot) else {
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
        for index in 0..self.active_segment_count() {
            let segment = self.segment(index);
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
                                visit(segment.first + slot, identity, bits)?;
                            }
                        }
                    }
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    }

    pub fn ack_dirty(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some((record, dirty)) = self.record(slot) else {
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
        let (record, _) = self.record(slot)?;
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return None;
        }
        let bits = core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire));
        (record.state.load(Ordering::Acquire) == epoch).then_some(bits)
    }

    /// Host: retire this exact grant before unmapping or reusing its owner.
    pub fn retire(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some((record, dirty)) = self.record(slot) else {
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
        dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
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
        for (_, record) in self.records() {
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
        for (slot, record) in self.records() {
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
        for (_, record) in self.records() {
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
            table: self,
            mm_key,
            start,
            end,
            active: true,
        })
    }

    fn cancel_retirement(&self, mm_key: u64, start: u64, end: u64) {
        for (_, record) in self.records() {
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
        for (slot, record) in self.records() {
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
        let Some((record, dirty)) = self.record(slot) else {
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
        dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
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
                && let Some((record, dirty)) = self.record(fragment_slot)
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

        let hash =
            FrameGrantResidencyTable::hash(next.mm_key, next.semantic_base / GRANT_PAGE_SIZE, 0);
        let first_slot = table.segment(0).probe(hash, 0);
        let retired = table.slots[first_slot].identity();
        let stale = table.lookup(retired.mm_key, retired.semantic_base).unwrap();
        let retirement = table
            .begin_retire_overlapping(retired.mm_key, retired.semantic_base, retired.len)
            .unwrap();
        assert!(retirement.commit());
        assert_eq!(table.try_publish(next), Ok(stale.slot));
        assert!(!table.record_commit(stale));
        let survivor = if retired == first { at(1) } else { first };
        assert!(table.is_guest_committed(survivor.mm_key, survivor.semantic_base));
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
        assert_eq!(core::mem::size_of::<FrameGrantResidencyTable>(), 787_008);
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
