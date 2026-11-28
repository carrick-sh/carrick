//! A custody transfer of one MM's residency rows: the residency half of a
//! populated `mremap(MREMAP_MAYMOVE)` move (#2611).
//!
//! In HVPatch a resident frame's IPA does not change when the guest moves
//! the virtual range; only the records keyed by the guest address do. The
//! residency rows are keyed by `(mm, semantic_base)`, so a move re-keys them
//! from `src + k` to `dst + k` and keeps everything else: the same frames,
//! the same mapping, frame, owner-generation and inventory identity, and the
//! same committed bits. Nothing is copied, granted or returned, and the API
//! has no way to do any of those.
//!
//! The shape is the same two-phase one as a copy-on-write replacement
//! ([`super::FrameGrantResidencyReplacement`]), under the exact-MM editor
//! the ring server already holds for the move:
//! - [`FrameGrantResidencyTable::begin_transfer`] refuses a `dst` that holds
//!   any row of the MM, closes transfer admission on every row overlapping
//!   `src` (a held grant-window lease is "not now"), and reserves every slot
//!   the commit needs: each moved part at `dst` (split where `dst` crosses a
//!   2 MiB window, since a row lives in one window) and each part of a row
//!   straddling an edge of `src` that stays behind. Nothing is visible at
//!   `dst` yet. A refusal changes nothing.
//! - [`FrameGrantResidencyTransfer::commit`], once the `dst` leaves are
//!   written and the `src` leaves are cleared and drained, retires each
//!   source row and publishes its parts in their reserved slots, carrying the
//!   committed bits, and returns a [`TransferReceipt`].
//! - Dropping the token instead restores the table exactly: the reserved
//!   slots are released and the source rows reopen.
//!
//! The invariants T1 to T9 of #2611 are checked by the explorer in
//! `transfer/explore.rs`, which also kills one seeded mutant per invariant.

use core::sync::atomic::Ordering;

use super::{
    EL1_FRAME_GRANT_TARGET_SIZE, FRAME_GRANT_RESIDENCY_SLOTS, FrameGrantResidencyIdentity,
    FrameGrantResidencyTable, GRANT_LIVE, GRANT_PAGE_SIZE, GRANT_PROBES, GRANT_RETIRED,
    GRANT_STATE_MASK, GRANT_WRITING, ResidencyRows, TRANSFER_PIN_RETIRING, sealed,
};

#[cfg(test)]
mod explore;

/// One equal-length move of one MM's pages: `[src, src + len)` to
/// `[dst, dst + len)`. Only [`Self::new`] makes one, so every transfer is
/// non-empty, page-aligned, overflow-free and has disjoint ranges (T4's
/// shape). A destination longer than the moved pages (an `mremap` growth)
/// is the reservation root's lazy hole, never part of the transfer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransferRange {
    mm_key: u64,
    src: u64,
    dst: u64,
    len: u64,
}

impl TransferRange {
    /// `None` for the null MM, an empty or unaligned range, one whose end
    /// overflows, or overlapping ranges (Linux refuses an overlapping move).
    pub fn new(mm_key: u64, src: u64, dst: u64, len: u64) -> Option<Self> {
        let aligned = |value: u64| value.is_multiple_of(GRANT_PAGE_SIZE);
        let src_end = src.checked_add(len)?;
        let dst_end = dst.checked_add(len)?;
        let disjoint = src_end <= dst || dst_end <= src;
        let admits_overlap = mutant::active() == mutant::Mutant::AdmitsOverlap;
        (mm_key != 0
            && len != 0
            && aligned(src)
            && aligned(dst)
            && aligned(len)
            && (disjoint || admits_overlap))
            .then_some(Self {
                mm_key,
                src,
                dst,
                len,
            })
    }
    pub const fn mm_key(self) -> u64 {
        self.mm_key
    }
    pub const fn src(self) -> u64 {
        self.src
    }
    pub const fn dst(self) -> u64 {
        self.dst
    }
    pub const fn len(self) -> u64 {
        self.len
    }
    /// Never true: [`Self::new`] refuses an empty transfer.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
    const fn src_end(self) -> u64 {
        self.src + self.len
    }
    const fn dst_end(self) -> u64 {
        self.dst + self.len
    }
    /// Where the page at `va` in `src` lands.
    const fn moved(self, va: u64) -> u64 {
        va - self.src + self.dst
    }
}

/// What a committed transfer did. A transfer grants, copies and returns no
/// frame by construction, so the only counts are of re-keyed custody.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[must_use]
pub struct TransferReceipt {
    /// Source rows retired and re-published at `dst`.
    pub rows_rekeyed: u64,
    /// Resident pages (frames) whose custody moved to a `dst` address.
    pub frames_relinked: u64,
    /// Of those, pages whose guest commit bit moved with them.
    pub committed_relinked: u64,
    /// Parts of source rows straddling an edge of `src`, kept in place.
    pub outside_parts: u64,
}

/// Why [`FrameGrantResidencyTable::begin_transfer`] changed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyTransferRefusal {
    /// `dst` holds a row of this MM: the move's destination is not a hole.
    /// A broken caller (first fit only offers holes), never "not now".
    Occupied,
    /// A grant-window lease holds a source row: "not now", rerun after the
    /// lease drops.
    Leased,
    /// No slot for a part the commit must publish. The table needs a
    /// segment; grow it and rerun (#2813).
    Capacity,
}

/// One admitted transfer, owed a commit after the leaf edit, or a drop that
/// restores the table. The caller holds the exact-MM editor throughout.
#[must_use = "a transfer must be committed after its leaf edit, or dropped to cancel it"]
pub struct FrameGrantResidencyTransfer<'a> {
    table: FrameGrantResidencyTable<ResidencyRows<'a>>,
    range: TransferRange,
    active: bool,
}

impl FrameGrantResidencyTransfer<'_> {
    pub fn range(&self) -> TransferRange {
        self.range
    }

    /// Retire every source row and publish its parts, with their committed
    /// bits, in the slots reserved for them. Call it once the `dst` leaves
    /// are written and the `src` leaves are unreachable. `None` only if the
    /// exact-MM exclusion was broken, an invariant violation.
    #[must_use]
    pub fn commit(mut self) -> Option<TransferReceipt> {
        self.active = false;
        self.table.commit_transfer(self.range)
    }
}

impl Drop for FrameGrantResidencyTransfer<'_> {
    fn drop(&mut self) {
        if self.active {
            self.table.cancel_transfer(self.range);
        }
    }
}

/// One part of a source row that the commit publishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Part {
    identity: FrameGrantResidencyIdentity,
    /// The source row's bit for this part's first page.
    shift: usize,
}

/// Every part of one source row: what stays below and above `src`, and the
/// moved part at `dst`, split where it crosses a 2 MiB window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parts {
    lower: Option<Part>,
    upper: Option<Part>,
    moved: [Option<Part>; 2],
}

impl Parts {
    fn of(range: TransferRange, row: FrameGrantResidencyIdentity) -> Self {
        let base = row.semantic_base;
        let end = base + row.len;
        let part = |semantic_base: u64, from: u64, to: u64| Part {
            identity: FrameGrantResidencyIdentity {
                semantic_base,
                physical_ipa: row.physical_ipa + (from - base),
                len: to - from,
                ..row
            },
            shift: ((from - base) / GRANT_PAGE_SIZE) as usize,
        };
        let lower = (base < range.src()).then(|| part(base, base, range.src()));
        let upper = (end > range.src_end()).then(|| part(range.src_end(), range.src_end(), end));
        let (from, to) = (base.max(range.src()), end.min(range.src_end()));
        let moved_base = range.moved(from);
        let moved_end = moved_base + (to - from);
        let window = (moved_base / EL1_FRAME_GRANT_TARGET_SIZE + 1) * EL1_FRAME_GRANT_TARGET_SIZE;
        let mut moved = [Some(part(moved_base, from, to)), None];
        if window < moved_end {
            let cut = from + (window - moved_base);
            moved = [
                Some(part(moved_base, from, cut)),
                Some(part(window, cut, to)),
            ];
        }
        if mutant::active() == mutant::Mutant::TransferCopies {
            // A fresh frame at `dst`: the copy the transfer exists to avoid.
            for part in moved.iter_mut().flatten() {
                part.identity.frame_id = part.identity.frame_id.wrapping_add(1 << 32);
                part.identity.physical_ipa += 1 << 40;
            }
        }
        Self {
            lower,
            upper,
            moved,
        }
    }

    fn all(self) -> impl Iterator<Item = Part> {
        [self.lower, self.upper, self.moved[0], self.moved[1]]
            .into_iter()
            .flatten()
    }
}

impl<S: sealed::ResidencyStorage> FrameGrantResidencyTable<S> {
    /// Admit one transfer before any leaf changes: see
    /// [`FrameGrantResidencyTransfer`]. A refusal changes nothing.
    pub fn begin_transfer(
        &self,
        range: TransferRange,
    ) -> Result<FrameGrantResidencyTransfer<'_>, ResidencyTransferRefusal> {
        // T4: the transferred part of `dst` holds no row of this MM.
        let prefix_only = mutant::active() == mutant::Mutant::AdmitsPopulatedTail;
        let checked_end = if prefix_only {
            range.dst() + GRANT_PAGE_SIZE
        } else {
            range.dst_end()
        };
        let occupied = self.slots().any(|record| {
            let state = record.state.load(Ordering::Acquire);
            let identity = record.identity();
            state & GRANT_STATE_MASK == GRANT_LIVE
                && identity.mm_key == range.mm_key()
                && identity.semantic_base < checked_end
                && range.dst() < identity.semantic_base + identity.len
                && record.state.load(Ordering::Acquire) == state
        });
        if occupied && mutant::active() != mutant::Mutant::AdmitsPopulatedDst {
            return Err(ResidencyTransferRefusal::Occupied);
        }
        // T3: close every source row; a held lease is "not now".
        self.close_transfer_rows(range)?;
        // T7: reserve every slot the commit publishes into.
        let mut short = false;
        self.for_each_transfer_row(range, |_, row| {
            for part in Parts::of(range, row).all() {
                match self.reserve_slot(
                    part.identity.mm_key,
                    part.identity.semantic_base,
                    part.identity.len,
                ) {
                    Some(slot) => self.mark_reserved(slot, part.identity),
                    None => short = true,
                }
            }
        });
        if short {
            self.cancel_transfer(range);
            return Err(ResidencyTransferRefusal::Capacity);
        }
        if mutant::active() == mutant::Mutant::ExposesEarly {
            self.for_each_transfer_row(range, |_, row| {
                for part in Parts::of(range, row).moved.into_iter().flatten() {
                    if let Some(slot) = self.find_reserved(part.identity)
                        && let Some(record) = self.slot(slot)
                    {
                        record.publish(part.identity);
                    }
                }
            });
        }
        Ok(FrameGrantResidencyTransfer {
            table: self.storage.rows().as_table(),
            range,
            active: true,
        })
    }

    /// A live row of the transfer's MM overlapping `src`.
    fn overlaps_src(range: TransferRange, identity: FrameGrantResidencyIdentity) -> bool {
        let peer = mutant::active() == mutant::Mutant::MovesPeerRecord;
        (identity.mm_key == range.mm_key() || (peer && identity.mm_key != 0))
            && identity.semantic_base < range.src_end()
            && range.src() < identity.semantic_base + identity.len
    }

    /// Visit every source row this transfer closed, with its slot.
    fn for_each_transfer_row(
        &self,
        range: TransferRange,
        mut visit: impl FnMut(usize, FrameGrantResidencyIdentity),
    ) {
        for (slot, record) in self.slots().enumerate() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE {
                continue;
            }
            let identity = record.identity();
            let closed = record.transfer_pins.load(Ordering::Acquire) == TRANSFER_PIN_RETIRING
                || mutant::active() == mutant::Mutant::IgnoresLease;
            if closed
                && Self::overlaps_src(range, identity)
                && record.state.load(Ordering::Acquire) == state
            {
                visit(slot, identity);
            }
        }
    }

    /// Close transfer admission on every source row. On a held lease, the
    /// rows this call closed reopen and nothing else changes.
    fn close_transfer_rows(&self, range: TransferRange) -> Result<(), ResidencyTransferRefusal> {
        let mut failed = None;
        for (slot, record) in self.slots().enumerate() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE
                || !Self::overlaps_src(range, record.identity())
            {
                continue;
            }
            let closed = record
                .transfer_pins
                .compare_exchange(
                    0,
                    TRANSFER_PIN_RETIRING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
            if !closed && mutant::active() != mutant::Mutant::IgnoresLease {
                failed = Some(slot);
                break;
            }
        }
        let Some(failed) = failed else {
            return Ok(());
        };
        for record in self.slots().take(failed) {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK == GRANT_LIVE
                && Self::overlaps_src(range, record.identity())
            {
                let _ = record.transfer_pins.compare_exchange(
                    TRANSFER_PIN_RETIRING,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
        Err(ResidencyTransferRefusal::Leased)
    }

    /// Name a reserved slot by the row it will hold. It stays `WRITING`, so
    /// no lookup sees it, and no other MM's reservation can take it.
    fn mark_reserved(&self, slot: usize, identity: FrameGrantResidencyIdentity) {
        let Some(record) = self.slot(slot) else {
            return;
        };
        record.mm_key.store(identity.mm_key, Ordering::Relaxed);
        record
            .semantic_base
            .store(identity.semantic_base, Ordering::Relaxed);
        record
            .physical_ipa
            .store(identity.physical_ipa, Ordering::Relaxed);
        record.len.store(identity.len, Ordering::Relaxed);
        record
            .mapping_id
            .store(identity.mapping_id, Ordering::Relaxed);
        record.frame_id.store(identity.frame_id, Ordering::Relaxed);
        record
            .owner_generation
            .store(identity.owner_generation, Ordering::Relaxed);
        record
            .inventory_revision
            .store(identity.inventory_revision, Ordering::Relaxed);
    }

    /// The slot [`Self::mark_reserved`] named for `identity`, on the probe
    /// chain [`Self::reserve_slot`] took it from. Under the exact-MM editor
    /// no other reservation of this MM names the same row.
    fn find_reserved(&self, identity: FrameGrantResidencyIdentity) -> Option<usize> {
        let class = (identity.len / GRANT_PAGE_SIZE)
            .next_power_of_two()
            .trailing_zeros();
        let bucket = identity.semantic_base / (GRANT_PAGE_SIZE << class);
        for (segment_index, segment) in self.segments().enumerate() {
            for probe in 0..GRANT_PROBES {
                let slot = Self::probe(identity.mm_key, bucket, class, probe);
                let record = &segment.slots[slot];
                if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK == GRANT_WRITING
                    && record.identity() == identity
                {
                    return Some(segment_index * FRAME_GRANT_RESIDENCY_SLOTS + slot);
                }
            }
        }
        None
    }

    fn commit_transfer(&self, range: TransferRange) -> Option<TransferReceipt> {
        let mut receipt = TransferReceipt::default();
        let mut broken = false;
        // The parts this scan publishes never overlap `src` (the ranges are
        // disjoint), so the scan never revisits one.
        self.for_each_transfer_row(range, |slot, row| {
            if broken {
                return;
            }
            if !self.move_row(range, slot, row, &mut receipt) {
                broken = true;
            }
        });
        (!broken).then_some(receipt)
    }

    /// Retire one source row and publish its parts.
    fn move_row(
        &self,
        range: TransferRange,
        slot: usize,
        row: FrameGrantResidencyIdentity,
        receipt: &mut TransferReceipt,
    ) -> bool {
        let parts = Parts::of(range, row);
        let mut slots = [None; 4];
        for (index, part) in [parts.lower, parts.upper, parts.moved[0], parts.moved[1]]
            .into_iter()
            .enumerate()
        {
            if let Some(part) = part {
                let Some(reserved) = self.find_reserved(part.identity) else {
                    return false;
                };
                slots[index] = Some((reserved, part));
            }
        }
        let Some((record, dirty)) = self.slot_entry(slot) else {
            return false;
        };
        let epoch = record.state.load(Ordering::Acquire);
        let bits: [u64; 8] =
            core::array::from_fn(|index| record.committed[index].load(Ordering::Acquire));
        if mutant::active() == mutant::Mutant::ReusesEpoch
            && parts.lower.is_none()
            && parts.upper.is_none()
            && parts.moved[1].is_none()
            && let Some((reserved, part)) = slots[2]
        {
            // Re-key the source record in place: its slot and epoch survive
            // at `dst`, so a source token's generation names the moved row.
            self.release_reserved_slot(reserved);
            self.mark_live_in_place(slot, part.identity);
            receipt.rows_rekeyed += 1;
            receipt.frames_relinked += part.identity.len / GRANT_PAGE_SIZE;
            receipt.committed_relinked += bits
                .iter()
                .map(|word| u64::from(word.count_ones()))
                .sum::<u64>();
            return true;
        }
        if mutant::active() != mutant::Mutant::KeepsSource {
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
                return false;
            }
            dirty.fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
            self.storage
                .rows()
                .directory
                .retirement_epoch
                .fetch_add(1, Ordering::Release);
        }
        receipt.rows_rekeyed += 1;
        for (index, entry) in slots.into_iter().enumerate() {
            let Some((reserved, part)) = entry else {
                continue;
            };
            let outside = index < 2;
            if outside && mutant::active() == mutant::Mutant::SplitDropsOutside {
                self.release_reserved_slot(reserved);
                continue;
            }
            let carried = if !outside && mutant::active() == mutant::Mutant::DropsBits {
                [0; 8]
            } else {
                bits
            };
            let committed = self.publish_part(reserved, part, carried);
            if outside {
                receipt.outside_parts += 1;
            } else {
                receipt.frames_relinked += part.identity.len / GRANT_PAGE_SIZE;
                receipt.committed_relinked += committed;
            }
        }
        true
    }

    /// Publish `part` into its reserved slot with the source row's bits from
    /// `part.shift` on. Returns how many committed bits it carried.
    fn publish_part(&self, slot: usize, part: Part, bits: [u64; 8]) -> u64 {
        let Some((record, dirty)) = self.slot_entry(slot) else {
            return 0;
        };
        record.publish(part.identity);
        let mut carried = 0;
        for bit in 0..(part.identity.len / GRANT_PAGE_SIZE) as usize {
            let old = part.shift + bit;
            if bits[old / 64] & (1 << (old % 64)) != 0 {
                record.committed[bit / 64].fetch_or(1 << (bit % 64), Ordering::Release);
                carried += 1;
            }
        }
        // The host's walk sees the new row, committed or not.
        dirty.fetch_or(1 << (slot % 64), Ordering::Release);
        carried
    }

    /// The `ReusesEpoch` mutant's in-place re-key.
    fn mark_live_in_place(&self, slot: usize, identity: FrameGrantResidencyIdentity) {
        self.mark_reserved(slot, identity);
        if let Some(record) = self.slot(slot) {
            record.transfer_pins.store(0, Ordering::Release);
        }
    }

    fn cancel_transfer(&self, range: TransferRange) {
        self.for_each_transfer_row(range, |_, row| {
            for part in Parts::of(range, row).all() {
                if let Some(slot) = self.find_reserved(part.identity) {
                    self.release_reserved_slot(slot);
                }
            }
        });
        let drops_source = mutant::active() == mutant::Mutant::FailDropsSource;
        for (slot, record) in self.slots().enumerate() {
            let state = record.state.load(Ordering::Acquire);
            if state & GRANT_STATE_MASK != GRANT_LIVE
                || !Self::overlaps_src(range, record.identity())
            {
                continue;
            }
            let _ = record.transfer_pins.compare_exchange(
                TRANSFER_PIN_RETIRING,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if drops_source {
                let _ = self.retire(slot, record.identity());
            }
        }
    }
}

/// Seeded mutants for the explorer: each breaks one of T1 to T9, and the
/// explorer must find it. Outside tests no mutant is ever active, so every
/// mutant branch folds away.
pub(super) mod mutant {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in super::super) enum Mutant {
        None,
        /// T1: the moved part names a fresh frame.
        TransferCopies,
        /// T2: the source row stays live after the commit.
        KeepsSource,
        /// T3: a leased source row is moved anyway.
        IgnoresLease,
        /// T4: overlapping ranges are admitted.
        AdmitsOverlap,
        /// T4: a populated `dst` is admitted.
        AdmitsPopulatedDst,
        /// T4: only `dst`'s first page is checked, so a populated tail of
        /// the transferred part is admitted.
        AdmitsPopulatedTail,
        /// T5: the part of a straddling row outside `src` is lost.
        SplitDropsOutside,
        /// T1/T5: the moved part loses its committed bits.
        DropsBits,
        /// T6: the source record is re-keyed in place, keeping its epoch.
        ReusesEpoch,
        /// T7: a cancel retires the source rows.
        FailDropsSource,
        /// T8: another MM's rows at the same addresses move too.
        MovesPeerRecord,
        /// T9: `dst` is visible before the commit.
        ExposesEarly,
    }

    #[cfg(test)]
    extern crate std;

    #[cfg(test)]
    std::thread_local! {
        static ACTIVE: core::cell::Cell<Mutant> = const { core::cell::Cell::new(Mutant::None) };
    }

    #[cfg(test)]
    pub(in super::super) fn active() -> Mutant {
        ACTIVE.with(|active| active.get())
    }

    #[cfg(not(test))]
    pub(in super::super) const fn active() -> Mutant {
        Mutant::None
    }

    /// Run `body` with `which` active on this thread.
    #[cfg(test)]
    pub(in super::super) fn with<T>(which: Mutant, body: impl FnOnce() -> T) -> T {
        ACTIVE.with(|active| active.set(which));
        let result = body();
        ACTIVE.with(|active| active.set(Mutant::None));
        result
    }
}
