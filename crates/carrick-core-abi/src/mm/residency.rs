//! Exact live residency and retained grant-window custody for either ISA.
use core::sync::atomic::{AtomicU64, Ordering};
pub const FRAME_GRANT_RESIDENCY_SLOTS: usize = 4096;
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

/// Fixed shared open-addressed index. Grants hash by their smallest power-of-two
/// page-count bucket. A page in a grant lies in its base bucket or the next
/// bucket, so lookups check those two buckets for each size class. Disjoint
/// short grants in one 2 MiB window no longer consume one 64-slot chain.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyTable {
    slots: [FrameGrantResidencyRecord; FRAME_GRANT_RESIDENCY_SLOTS],
    dirty: [AtomicU64; FRAME_GRANT_RESIDENCY_SLOTS / 64],
}

impl FrameGrantResidencyTable {
    pub const fn new() -> Self {
        Self {
            slots: [const { FrameGrantResidencyRecord::new() }; FRAME_GRANT_RESIDENCY_SLOTS],
            dirty: [const { AtomicU64::new(0) }; FRAME_GRANT_RESIDENCY_SLOTS / 64],
        }
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
        if !identity.valid() {
            return None;
        }
        // All size classes share one table. Check every covered page before
        // admission so unlike classes cannot publish overlapping grants.
        // Exact-MM editors serialize publications for this MM.
        for page in (identity.semantic_base..identity.semantic_base + identity.len)
            .step_by(GRANT_PAGE_SIZE as usize)
        {
            if self.lookup(identity.mm_key, page).is_some() {
                return None;
            }
        }
        let class = (identity.len / GRANT_PAGE_SIZE)
            .next_power_of_two()
            .trailing_zeros();
        let bucket = identity.semantic_base / (GRANT_PAGE_SIZE << class);
        let mut available = None;
        for probe in 0..GRANT_PROBES {
            let slot = Self::probe(identity.mm_key, bucket, class, probe);
            let record = &self.slots[slot];
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK == GRANT_LIVE {
                let prior = record.identity();
                if prior.mm_key == identity.mm_key
                    && prior.semantic_base < identity.semantic_base + identity.len
                    && identity.semantic_base < prior.semantic_base + prior.len
                {
                    return None;
                }
            } else if state == GRANT_EMPTY {
                available.get_or_insert(slot);
                break;
            } else if state & GRANT_STATE_MASK == GRANT_RETIRED {
                available.get_or_insert(slot);
            }
        }
        let slot = available?;
        let record = &self.slots[slot];
        let state = record.state.load(Ordering::Acquire);
        record
            .state
            .compare_exchange(
                state,
                (state & !GRANT_STATE_MASK).wrapping_add(4) | GRANT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        record.publish(identity);
        Some(slot)
    }

    /// Guest: find the exact live grant covering a prepared leaf.
    pub fn lookup(&self, mm_key: u64, va: u64) -> Option<FrameGrantResidencyPage> {
        let page = va & !(GRANT_PAGE_SIZE - 1);
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
                    let record = &self.slots[slot];
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
                                let bit =
                                    ((page - identity.semantic_base) / GRANT_PAGE_SIZE) as usize;
                                return Some(FrameGrantResidencyPage {
                                    slot,
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
        None
    }

    /// Retain an exact live residency generation independently of the MM
    /// editor. A racing retirement either closes admission first or observes
    /// this pin and refuses; stale page tokens cannot pin a successor.
    pub fn pin_transfer(&self, page: FrameGrantResidencyPage) -> Option<FrameGrantTransferPin<'_>> {
        let record = self.slots.get(page.slot)?;
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
        let Some(record) = self.slots.get(page.slot) else {
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
        self.dirty[page.slot / 64].fetch_or(1 << (page.slot % 64), Ordering::Release);
        true
    }

    /// Host mincore view. The slot must still be live for this exact MM and
    /// grant; retirement removes visibility before backing can be reused.
    pub fn is_guest_committed(&self, mm_key: u64, va: u64) -> bool {
        let Some(page) = self.lookup(mm_key, va) else {
            return false;
        };
        let record = &self.slots[page.slot];
        record.state.load(Ordering::Acquire) == page.epoch
            && record.identity() == page.identity
            && record.committed[page.bit / 64].load(Ordering::Acquire) & (1 << (page.bit % 64)) != 0
            && record.state.load(Ordering::Acquire) == page.epoch
    }

    /// Host: visit only records changed since their last reconciliation. The
    /// callback must validate the live leaf and update host residency before
    /// `ack_dirty` is called; exact-MM exclusion prevents same-MM new bits.
    pub fn for_each_dirty_mm(
        &self,
        mm_key: u64,
        mut visit: impl FnMut(usize, FrameGrantResidencyIdentity, [u64; 8]),
    ) {
        for (word_index, word) in self.dirty.iter().enumerate() {
            let mut pending = word.load(Ordering::Acquire);
            while pending != 0 {
                let bit = pending.trailing_zeros() as usize;
                pending &= pending - 1;
                let slot = word_index * 64 + bit;
                let record = &self.slots[slot];
                let epoch = record.state.load(Ordering::Acquire);
                if epoch & GRANT_STATE_MASK == GRANT_LIVE {
                    let identity = record.identity();
                    if identity.mm_key == mm_key && record.state.load(Ordering::Acquire) == epoch {
                        let bits =
                            core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire));
                        if record.state.load(Ordering::Acquire) == epoch {
                            visit(slot, identity, bits);
                        }
                    }
                }
            }
        }
    }

    pub fn ack_dirty(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some(record) = self.slots.get(slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE
            || record.identity() != identity
        {
            return false;
        }
        self.dirty[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
        true
    }

    /// Host: snapshot the guest commits while holding the exact-MM guard.
    pub fn committed_words(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<[u64; 8]> {
        let record = self.slots.get(slot)?;
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return None;
        }
        let bits = core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire));
        (record.state.load(Ordering::Acquire) == epoch).then_some(bits)
    }

    /// Host: retire this exact grant before unmapping or reusing its owner.
    pub fn retire(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some(record) = self.slots.get(slot) else {
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
        self.dirty[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
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
        for record in &self.slots {
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
        for (slot, record) in self.slots.iter().enumerate() {
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
        let base = identity.semantic_base;
        let grant_end = base + identity.len;
        // A byte-level overlap revokes its entire Linux page.
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
            if let Some(fragment_slot) = self.publish(fragment) {
                let shift = ((fragment_start - base) / GRANT_PAGE_SIZE) as usize;
                let count = (fragment.len / GRANT_PAGE_SIZE) as usize;
                for bit in 0..count {
                    let old_bit = shift + bit;
                    if bits[old_bit / 64] & (1 << (old_bit % 64)) != 0 {
                        self.slots[fragment_slot].committed[bit / 64]
                            .fetch_or(1 << (bit % 64), Ordering::Release);
                        self.dirty[fragment_slot / 64]
                            .fetch_or(1 << (fragment_slot % 64), Ordering::Release);
                    }
                }
            }
        }
        true
    }
}

impl Default for FrameGrantResidencyTable {
    fn default() -> Self {
        Self::new()
    }
}
