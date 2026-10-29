//! Preallocated per-page adoption overlay in the existing residency owner.
//! This is a transaction participant, not physical or descriptor authority.
use super::{
    FrameGrantResidencyIdentity, FrameGrantResidencyRecord, FrameGrantResidencyTable, GRANT_LIVE,
    GRANT_STATE_MASK, Ordering, StockPageMask, StockResidencyOwner, TRANSFER_PIN_RETIRED,
};
use crate::{ReservationIncarnation, ReservationProtection};

// Low four bits retain S4's page mask; bits 4 through 7 remain reserved.
// Each page has three access bits, independent of its nonzero incarnation.
const PERMISSION_SHIFT: usize = 8;
pub(super) const STOCK_QUARANTINED: u64 = 1 << 63;
const ADOPTING: u64 = TRANSFER_PIN_RETIRED | 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockPageAdoption {
    pub mapping: ReservationIncarnation,
    pub protection: ReservationProtection,
}

/// Stable owner observation for batched inventory reconciliation. NONE is
/// an adoption with no access; an unadopted page has no mapping incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockAdoptionSnapshot {
    pub owner: StockResidencyOwner,
    pub identity: FrameGrantResidencyIdentity,
    pub retained: StockPageMask,
    pub committed: StockPageMask,
    pub pages: [Option<StockPageAdoption>; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockAdoptionRefusal {
    AlreadySettled,
    PreimageChanged,
}

/// The caller retains the exact-MM editor and the encompassing physical,
/// descriptor and root journals through settlement. Staging cannot allocate.
/// Commit only after all participants apply; rollback only after their undo
/// is verified. Unknown undo retains this token and physical custody. Drop
/// quarantines the row rather than inferring that external undo completed.
#[must_use = "settle with the encompassing adoption transaction or retain custody"]
pub struct StockAdoptionTransaction<'a> {
    table: &'a FrameGrantResidencyTable,
    slot: usize,
    epoch: u64,
    owner: StockResidencyOwner,
    identity: FrameGrantResidencyIdentity,
    before_word: u64,
    before_mappings: [u64; 4],
    staged_word: u64,
    staged_mappings: [u64; 4],
    committed: [u64; 8],
    active: bool,
}
impl core::fmt::Debug for StockAdoptionTransaction<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StockAdoptionTransaction")
            .field("owner", &self.owner)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl StockAdoptionTransaction<'_> {
    fn quarantine(&self) {
        self.table.slots[self.slot]
            .stock_retained
            .fetch_or(STOCK_QUARANTINED, Ordering::AcqRel);
    }
    fn matches(&self) -> bool {
        let record = &self.table.slots[self.slot];
        record.state.load(Ordering::Acquire) == self.epoch
            && record.identity() == self.identity
            && record.stock_root.load(Ordering::Acquire) == self.owner.root.raw().get()
            && record.transfer_pins.load(Ordering::Acquire) == ADOPTING
            && record.stock_retained.load(Ordering::Acquire) == self.staged_word
            && core::array::from_fn::<_, 4, _>(|i| record.stock_mappings[i].load(Ordering::Acquire))
                == self.staged_mappings
            && core::array::from_fn::<_, 8, _>(|i| record.committed[i].load(Ordering::Acquire))
                == self.committed
    }
    pub fn commit(&mut self) -> Result<StockAdoptionSnapshot, StockAdoptionRefusal> {
        if !self.active {
            return Err(StockAdoptionRefusal::AlreadySettled);
        }
        if !self.matches() {
            self.quarantine();
            return Err(StockAdoptionRefusal::PreimageChanged);
        }
        let Some(snapshot) = snapshot(
            self.owner,
            self.identity,
            self.staged_word,
            self.staged_mappings,
            self.committed[0],
        ) else {
            self.quarantine();
            return Err(StockAdoptionRefusal::PreimageChanged);
        };
        self.table.dirty[self.slot / 64].fetch_or(1 << (self.slot % 64), Ordering::Release);
        self.table.slots[self.slot]
            .transfer_pins
            .store(0, Ordering::Release);
        self.active = false;
        Ok(snapshot)
    }
    pub fn rollback(&mut self) -> Result<(), StockAdoptionRefusal> {
        if !self.active {
            return Err(StockAdoptionRefusal::AlreadySettled);
        }
        if !self.matches() {
            self.quarantine();
            return Err(StockAdoptionRefusal::PreimageChanged);
        }
        let record = &self.table.slots[self.slot];
        for (word, value) in record.stock_mappings.iter().zip(self.before_mappings) {
            word.store(value, Ordering::Relaxed);
        }
        record
            .stock_retained
            .store(self.before_word, Ordering::Release);
        record.transfer_pins.store(0, Ordering::Release);
        self.active = false;
        Ok(())
    }
}
impl Drop for StockAdoptionTransaction<'_> {
    fn drop(&mut self) {
        if self.active {
            // The exact-MM editor excludes legitimate record replacement.
            // Never clear a mismatched claim or authorize physical release.
            self.quarantine();
        }
    }
}

fn mappings(record: &FrameGrantResidencyRecord) -> [u64; 4] {
    core::array::from_fn(|i| record.stock_mappings[i].load(Ordering::Acquire))
}
fn snapshot(
    owner: StockResidencyOwner,
    identity: FrameGrantResidencyIdentity,
    word: u64,
    mappings: [u64; 4],
    committed: u64,
) -> Option<StockAdoptionSnapshot> {
    if word & STOCK_QUARANTINED != 0 {
        return None;
    }
    let retained = StockPageMask::new((word & 15) as u8)?;
    let mut pages = [None; 4];
    for (i, mapping) in mappings.into_iter().enumerate() {
        let access = (word >> (PERMISSION_SHIFT + 3 * i)) & 7;
        if mapping == 0 {
            if access != 0 {
                return None;
            }
        } else {
            if !retained.contains(i) {
                return None;
            }
            pages[i] = Some(StockPageAdoption {
                mapping: ReservationIncarnation::new(mapping)?,
                protection: ReservationProtection::from_bits(access)?,
            });
        }
    }
    Some(StockAdoptionSnapshot {
        owner,
        identity,
        retained,
        committed: StockPageMask::new((committed & u64::from(retained.bits())) as u8)?,
        pages,
    })
}

impl FrameGrantResidencyTable {
    fn adoption_record(
        &self,
        owner: StockResidencyOwner,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<(usize, u64, &FrameGrantResidencyRecord)> {
        if identity.mm_key != owner.mm.raw().get() || identity.len != crate::COW_GRANT_SIZE {
            return None;
        }
        // A chunk's first page may be retired, so use its actual probe set,
        // not a lookup that requires the base page to remain retained.
        let class = 2;
        let bucket = identity.semantic_base / crate::COW_GRANT_SIZE;
        for offset in 0..super::GRANT_PROBES {
            let slot = Self::probe(identity.mm_key, bucket, class, offset);
            let record = &self.slots[slot];
            let epoch = record.state.load(Ordering::Acquire);
            if epoch == super::GRANT_EMPTY {
                break;
            }
            if epoch & GRANT_STATE_MASK == GRANT_LIVE
                && record.identity() == identity
                && record.stock_root.load(Ordering::Acquire) == owner.root.raw().get()
                && record.state.load(Ordering::Acquire) == epoch
            {
                return Some((slot, epoch, record));
            }
        }
        None
    }

    /// Exact identity observation under the same MM exclusion as dirty ACK.
    /// Pending/quarantined overlays are never exportable as stable access.
    pub fn stock_adoptions(
        &self,
        owner: StockResidencyOwner,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<StockAdoptionSnapshot> {
        let (_, epoch, record) = self.adoption_record(owner, identity)?;
        if record.transfer_pins.load(Ordering::Acquire) >= TRANSFER_PIN_RETIRED {
            return None;
        }
        let value = snapshot(
            owner,
            identity,
            record.stock_retained.load(Ordering::Acquire),
            mappings(record),
            record.committed[0].load(Ordering::Acquire),
        )?;
        (record.state.load(Ordering::Acquire) == epoch
            && record.transfer_pins.load(Ordering::Acquire) < TRANSFER_PIN_RETIRED)
            .then_some(value)
    }
    pub fn stock_adoption_quarantined(
        &self,
        owner: StockResidencyOwner,
        identity: FrameGrantResidencyIdentity,
    ) -> bool {
        self.adoption_record(owner, identity)
            .is_some_and(|(_, _, record)| {
                record.stock_retained.load(Ordering::Acquire) & STOCK_QUARANTINED != 0
            })
    }

    /// Stage only overlay metadata. No physical capability, live-node
    /// authentication, executable cache maintenance or descriptor mutation is
    /// inferred here. The encompassing owner must supply all those proofs.
    pub fn begin_stock_adoption(
        &self,
        owner: StockResidencyOwner,
        identity: FrameGrantResidencyIdentity,
        changes: [Option<StockPageAdoption>; 4],
    ) -> Option<StockAdoptionTransaction<'_>> {
        let (slot, epoch, record) = self.adoption_record(owner, identity)?;
        let before_word = record.stock_retained.load(Ordering::Acquire);
        let before_mappings = mappings(record);
        let before = snapshot(
            owner,
            identity,
            before_word,
            before_mappings,
            record.committed[0].load(Ordering::Acquire),
        )?;
        let mut staged_word = before_word;
        let mut staged_mappings = before_mappings;
        let mut changed = false;
        for (i, change) in changes.into_iter().enumerate() {
            let Some(change) = change else {
                continue;
            };
            if !before.retained.contains(i)
                || before.pages[i].is_some_and(|page| page.mapping != change.mapping)
            {
                return None;
            }
            changed = true;
            staged_mappings[i] = change.mapping.raw();
            let shift = PERMISSION_SHIFT + 3 * i;
            staged_word = (staged_word & !(7 << shift)) | (change.protection.bits() << shift);
        }
        if !changed {
            return None;
        }
        record
            .transfer_pins
            .compare_exchange(0, ADOPTING, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        let transaction = StockAdoptionTransaction {
            table: self,
            slot,
            epoch,
            owner,
            identity,
            before_word,
            before_mappings,
            staged_word,
            staged_mappings,
            committed: core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire)),
            active: true,
        };
        // The editor excludes a same-MM writer. The claim excludes transfer
        // pins/retirement; all validation precedes these infallible stores.
        for (word, value) in record.stock_mappings.iter().zip(staged_mappings) {
            word.store(value, Ordering::Relaxed);
        }
        record.stock_retained.store(staged_word, Ordering::Release);
        Some(transaction)
    }
}

pub(super) fn clear_page(record: &FrameGrantResidencyRecord, word: u64, bit: usize) -> u64 {
    record.stock_mappings[bit].store(0, Ordering::Relaxed);
    word & !(1 << bit) & !(7 << (PERMISSION_SHIFT + 3 * bit))
}
