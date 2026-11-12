//! The neutral owed-return settlement record (#1369 slice 2).
//!
//! A root's journal ([`ReturnJournal`]) holds the resident extents EL1
//! retired at stage-1 whose stage-2 and frame-inventory return is still
//! owed. Each extent sits in one table slot. A slot's epoch advances every
//! time the slot is freed, so a (slot, epoch) pair names exactly one owed
//! extent for its whole life and never its successor.
//!
//! Settlement observes the journal as a [`ReturnSettlementRequest`], retires
//! the extents' backing outside the root guard, and only then acknowledges
//! each slot with [`ReturnJournal::acknowledge_chunk`]: a compare-and-swap
//! of the slot's `start` from the exact value the settlement walked, with
//! (slot, epoch) unchanged. The slot's `start` is the settlement cursor:
//! acknowledging `[start, new_start)` shrinks the extent from the front, and
//! `new_start == end` frees the slot. A front merge moves `start` back over
//! pages that really are unsettled, so an acknowledgement that raced it is
//! stale and has no effect.

use super::{Refusal, ReservationMm, ReservationRange, ReservationSequence};

/// Owed extents one root can hold at once (its share of the shared table).
pub const OWED_RETURNS_PER_MM: usize = 8;

/// Index of one slot in the shared owed-return table.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct OwedSlot(u16);
impl OwedSlot {
    pub const fn new(index: usize) -> Option<Self> {
        if index <= u16::MAX as usize {
            Some(Self(index as u16))
        } else {
            None
        }
    }
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One lifetime of an [`OwedSlot`]: advanced each time the slot is freed.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct OwedSlotEpoch(u64);
impl OwedSlotEpoch {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A resident extent EL1 retired at stage-1 (its terminals keep their output
/// as `SW_RETIRED`) whose stage-2 and frame-inventory return is still owed.
/// The frames stay unreusable, and no `Prepare` may hand the range out again,
/// until settlement acknowledges it ([`ReturnJournal::acknowledge_chunk`]).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct DeferredReturn {
    pub range: ReservationRange,
    /// The newest completed request whose retirement this extent covers.
    pub sequence: ReservationSequence,
    pub slot: OwedSlot,
    pub epoch: OwedSlotEpoch,
}

/// Every extent one root owed when settlement observed its journal. Built
/// under the root guard; acknowledged, extent by extent, under a later one.
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct ReturnSettlementRequest {
    mm: ReservationMm,
    owed: [Option<DeferredReturn>; OWED_RETURNS_PER_MM],
}
impl ReturnSettlementRequest {
    pub const fn new(mm: ReservationMm) -> Self {
        Self {
            mm,
            owed: [None; OWED_RETURNS_PER_MM],
        }
    }
    /// The root whose journal this request observed.
    pub const fn mm(&self) -> ReservationMm {
        self.mm
    }
    /// Add one observed extent. `Invalid`: more than one root's share.
    pub fn push(&mut self, owed: DeferredReturn) -> Result<(), Refusal> {
        let free = self
            .owed
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Refusal::Invalid)?;
        *free = Some(owed);
        Ok(())
    }
    pub fn iter(&self) -> impl Iterator<Item = &DeferredReturn> + '_ {
        self.owed.iter().flatten()
    }
    pub fn len(&self) -> usize {
        self.iter().count()
    }
    pub fn is_empty(&self) -> bool {
        self.owed.iter().all(Option::is_none)
    }
}

/// What one [`ReturnJournal::acknowledge_chunk`] did.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ChunkAcknowledgement {
    /// The chunk reached the extent's end: the slot is free, its epoch
    /// advanced.
    Freed,
    /// The extent's front moved to `new_start`; the rest stays owed.
    Advanced,
    /// The slot's (epoch, start) no longer match: no effect.
    Stale,
}

/// Why owed-return settlement left an MM's returns owed. Never fatal and
/// never an errno: nothing is acknowledged, and a later exclusion retries.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum SkipReason {
    /// A fork loan naming the MM is still pending: its child may still be
    /// arming from the parent's leaves.
    ForkLoanPending,
}

/// The result of one owed-return settlement.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum SettlementOutcome<R> {
    /// Every fallible step succeeded, the batch applied and the observed
    /// slots were acknowledged.
    Settled(R),
    /// The request no longer names the excluded MM's live journal: no
    /// effect, and nothing is quarantined.
    Stale,
    /// Settlement was not attempted; the returns stay owed.
    Skipped(SkipReason),
}

/// One root's owed-return journal, borrowed under its root guard.
pub trait ReturnJournal {
    /// Every extent the root owes now.
    fn owed_returns(&self) -> Result<ReturnSettlementRequest, Refusal>;
    /// Acknowledge `[expected_start, new_start)` of the extent in `slot`.
    /// Effective only while the slot still holds `epoch` and starts at
    /// `expected_start`, and `new_start` lies in `(expected_start, end]`;
    /// `new_start == end` frees the slot and advances its epoch.
    /// `Err(Stale)`: the root is no longer admitted.
    fn acknowledge_chunk(
        &mut self,
        slot: OwedSlot,
        epoch: OwedSlotEpoch,
        expected_start: u64,
        new_start: u64,
    ) -> Result<ChunkAcknowledgement, Refusal>;
}
