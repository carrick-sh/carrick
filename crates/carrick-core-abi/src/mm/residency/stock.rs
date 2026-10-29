//! Concrete probe-slot custody and masked residency in the shared table.
use super::*;
use alloc::vec::Vec;
use carrick_guest_arch::{ContextGeneration, MmGeneration, UserVa};

pub const STOCK_CHUNKS_PER_REFILL: usize = 64;
pub const STOCK_CHUNKS_PER_MM: usize = 1024;
pub const STOCK_CHUNKS_PER_CARRIER: u64 = 2048;

/// Same exact address-context generations as the physical grant owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockResidencyOwner {
    pub mm: MmGeneration,
    pub root: ContextGeneration,
}

/// Four Linux pages in one independently releasable 16 KiB chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockPageMask(u8);
impl StockPageMask {
    pub const ALL: Self = Self(15);
    pub const fn new(bits: u8) -> Option<Self> {
        if bits & !15 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, page: usize) -> bool {
        page < 4 && self.0 & (1 << page) != 0
    }
}

/// Virtual occupancy only: claimed before allocation or inventory staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockChunkReservation {
    pub base: UserVa,
    pub retained: StockPageMask,
}

/// Observation of an exact live chunk. No physical capability or adoption
/// rights are conferred by a residency observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockResidencyRecord {
    pub owner: StockResidencyOwner,
    pub identity: FrameGrantResidencyIdentity,
    pub retained: StockPageMask,
}

/// One actual row in the normal probe set. Cancellation keeps an index
/// tombstone: restoring EMPTY could hide a peer inserted behind this claim.
/// The live preimage is unchanged, and the slot is immediately reusable.
#[must_use = "keep concrete capacity through physical settlement"]
pub struct FrameGrantResidencyLease<'a> {
    table: &'a FrameGrantResidencyTable,
    slot: usize,
    epoch: u64,
    mm_key: u64,
    base: u64,
    len: u64,
    stock: bool,
    active: bool,
}
impl FrameGrantResidencyLease<'_> {
    fn accepts(&self, identity: FrameGrantResidencyIdentity) -> bool {
        identity.valid()
            && identity.mm_key == self.mm_key
            && identity.semantic_base == self.base
            && identity.len == self.len
            && (!self.stock || identity.physical_ipa.is_multiple_of(crate::COW_GRANT_SIZE))
            && self.table.slots[self.slot].state.load(Ordering::Acquire) == self.epoch
    }
    pub(super) fn publish(self, identity: FrameGrantResidencyIdentity) -> Option<usize> {
        self.accepts(identity)
            .then(|| self.publish_validated(identity))
    }
    fn publish_validated(mut self, identity: FrameGrantResidencyIdentity) -> usize {
        self.table.slots[self.slot].publish(identity);
        self.active = false;
        self.slot
    }
}
impl Drop for FrameGrantResidencyLease<'_> {
    fn drop(&mut self) {
        if self.active {
            // No live physical publication has been authorized by this token.
            // Exclusive ownership of RESERVED prevents a new writer/retirer.
            self.table.slots[self.slot].state.store(
                (self.epoch & !GRANT_STATE_MASK) | GRANT_WRITING,
                Ordering::Release,
            );
            if self.stock {
                self.table.stock_records.fetch_sub(1, Ordering::AcqRel);
            }
            self.table.slots[self.slot].state.store(
                (self.epoch & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::Release,
            );
        }
    }
}

/// A bounded batch of actual slots, charged while reserved as well as live.
/// The caller holds the exact-MM editor for reserve and publish. Physical,
/// table and descriptor journals remain the encompassing transaction's duty.
#[must_use = "retain claims on indeterminate physical rollback"]
pub struct StockCapacityLease<'a> {
    owner: StockResidencyOwner,
    rows: Vec<FrameGrantResidencyLease<'a>>,
}
impl core::fmt::Debug for StockCapacityLease<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StockCapacityLease")
            .field("owner", &self.owner)
            .field("rows", &self.rows.len())
            .finish()
    }
}
impl StockCapacityLease<'_> {
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Validate the complete batch before publishing anything. There are no
    /// fallible stores after validation; all rows are exclusively claimed.
    /// No allocation or inventory capability is inferred from these IDs.
    /// Refusal returns the owned claims: the physical transaction must keep
    /// them until rollback is verified, including indeterminate settlement.
    pub fn publish(
        self,
        owner: StockResidencyOwner,
        identities: &[FrameGrantResidencyIdentity],
    ) -> Result<Vec<usize>, Self> {
        if owner != self.owner
            || identities.len() != self.rows.len()
            || !self
                .rows
                .iter()
                .zip(identities)
                .all(|(row, identity)| row.accepts(*identity))
        {
            return Err(self);
        }
        let mut slots = Vec::new();
        if slots.try_reserve_exact(self.rows.len()).is_err() {
            return Err(self);
        }
        for (row, identity) in self.rows.into_iter().zip(identities) {
            slots.push(row.publish_validated(*identity));
        }
        Ok(slots)
    }
}

impl FrameGrantResidencyTable {
    pub fn stock_record_count(&self) -> u64 {
        self.stock_records.load(Ordering::Acquire)
    }

    /// Preclaim actual 64-probe rows, with no physical identities required.
    /// Full batches either succeed or cancel every row. Call under the same
    /// exact-MM exclusion used by ordinary residency publication.
    pub fn reserve_stock(
        &self,
        owner: StockResidencyOwner,
        chunks: &[StockChunkReservation],
    ) -> Option<StockCapacityLease<'_>> {
        if chunks.is_empty() || chunks.len() > STOCK_CHUNKS_PER_REFILL {
            return None;
        }
        let mut count = 0;
        for record in &self.slots {
            let state = record.state.load(Ordering::Acquire) & GRANT_STATE_MASK;
            if (state == GRANT_LIVE || state == GRANT_RESERVED)
                && record.mm_key.load(Ordering::Relaxed) == owner.mm.raw().get()
                && record.stock_root.load(Ordering::Relaxed) != 0
            {
                if record.stock_root.load(Ordering::Relaxed) != owner.root.raw().get() {
                    return None;
                }
                count += 1;
            }
        }
        if count + chunks.len() > STOCK_CHUNKS_PER_MM {
            return None;
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(chunks.len()).ok()?;
        for chunk in chunks {
            if chunk.retained.bits() == 0 || !chunk.base.raw().is_multiple_of(crate::COW_GRANT_SIZE)
            {
                return None;
            }
            rows.push(self.reserve_record(
                owner.mm.raw().get(),
                chunk.base.raw(),
                crate::COW_GRANT_SIZE,
                Some((owner, chunk.retained)),
            )?);
        }
        Some(StockCapacityLease { owner, rows })
    }

    pub fn stock_record(
        &self,
        owner: StockResidencyOwner,
        address: UserVa,
    ) -> Option<StockResidencyRecord> {
        let page = self.lookup(owner.mm.raw().get(), address.raw())?;
        let record = &self.slots[page.slot];
        if record.stock_root.load(Ordering::Relaxed) != owner.root.raw().get() {
            return None;
        }
        Some(StockResidencyRecord {
            owner,
            identity: page.identity,
            retained: page.retained?,
        })
    }

    pub(super) fn reserve_record(
        &self,
        mm_key: u64,
        base: u64,
        len: u64,
        stock: Option<(StockResidencyOwner, StockPageMask)>,
    ) -> Option<FrameGrantResidencyLease<'_>> {
        let shape = FrameGrantResidencyIdentity {
            mm_key,
            semantic_base: base,
            physical_ipa: 0,
            len,
            mapping_id: 1,
            frame_id: 1,
            owner_generation: 1,
            inventory_revision: 1,
        };
        if !shape.valid() {
            return None;
        }
        let retained = stock.map(|(_, mask)| mask);
        for (bit, page) in (base..base + len)
            .step_by(GRANT_PAGE_SIZE as usize)
            .enumerate()
        {
            if retained.is_none_or(|mask| mask.contains(bit))
                && self.lookup_inner(mm_key, page, true).is_some()
            {
                return None;
            }
        }
        let class = (len / GRANT_PAGE_SIZE).next_power_of_two().trailing_zeros();
        let bucket = base / (GRANT_PAGE_SIZE << class);
        let mut available = None;
        for offset in 0..GRANT_PROBES {
            let slot = Self::probe(mm_key, bucket, class, offset);
            let state = self.slots[slot].state.load(Ordering::Acquire);
            if state == GRANT_EMPTY {
                available.get_or_insert((slot, state));
                break;
            }
            if state & GRANT_STATE_MASK == GRANT_RETIRED {
                available.get_or_insert((slot, state));
            }
        }
        let (slot, state) = available?;
        let epoch = (state & !GRANT_STATE_MASK).checked_add(8)? | GRANT_RESERVED;
        if stock.is_some() {
            self.stock_records
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < STOCK_CHUNKS_PER_CARRIER).then_some(count + 1)
                })
                .ok()?;
        }
        let record = &self.slots[slot];
        if record
            .state
            .compare_exchange(
                state,
                (epoch & !GRANT_STATE_MASK) | GRANT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            if stock.is_some() {
                self.stock_records.fetch_sub(1, Ordering::AcqRel);
            }
            return None;
        }
        record.store_identity(shape);
        record.stock_root.store(
            stock.map_or(0, |(owner, _)| owner.root.raw().get()),
            Ordering::Relaxed,
        );
        record.stock_retained.store(
            retained.map_or(0, |mask| u64::from(mask.bits())),
            Ordering::Relaxed,
        );
        record.state.store(epoch, Ordering::Release);
        Some(FrameGrantResidencyLease {
            table: self,
            slot,
            epoch,
            mm_key,
            base,
            len,
            stock: stock.is_some(),
            active: true,
        })
    }

    pub(super) fn retire_stock_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
        claimed: bool,
    ) -> bool {
        let record = &self.slots[slot];
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return false;
        }
        if claimed {
            if record.transfer_pins.load(Ordering::Acquire) != TRANSFER_PIN_RETIRING {
                return false;
            }
        } else if record
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
        let mut mask = record.stock_retained.load(Ordering::Acquire);
        for bit in 0..4 {
            let va = identity.semantic_base + bit * GRANT_PAGE_SIZE;
            if va < end && start < va + GRANT_PAGE_SIZE {
                mask &= !(1 << bit);
            }
        }
        record.stock_retained.store(mask, Ordering::Release);
        record.committed[0].fetch_and(mask, Ordering::AcqRel);
        if mask == 0 {
            record.state.store(
                (epoch & !GRANT_STATE_MASK) | GRANT_WRITING,
                Ordering::Release,
            );
            record
                .transfer_pins
                .store(TRANSFER_PIN_RETIRED, Ordering::Release);
            self.dirty[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
            self.stock_records.fetch_sub(1, Ordering::AcqRel);
            record.state.store(
                (epoch & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::Release,
            );
        } else {
            self.dirty[slot / 64].fetch_or(1 << (slot % 64), Ordering::Release);
            record.transfer_pins.store(0, Ordering::Release);
        }
        true
    }
}
