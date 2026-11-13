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
//!
//! Freeing a slot takes settlement authority, never a bare (slot, epoch):
//! - an acknowledgement consumes a [`SettledChunk`], which only
//!   [`ReturnSettlementRequest::retire_and_apply`] mints, under an exclusion
//!   of the request's MM and after the venue's fallible steps and its one
//!   infallible apply;
//! - a retired MM's slots are freed only by an [`MmReleaseReceipt`], which
//!   only [`MmReleaseReceipt::released`] mints, once the MM's address space
//!   is excluded and its carrier-wide memory release succeeded.

use super::{Refusal, ReservationMm, ReservationRange, ReservationSequence};
use carrick_sched_core::ExcludedEditor;

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

/// A venue's physical retirement of owed extents.
pub trait OwedReturnRetirement {
    /// What the fallible steps staged for the infallible apply.
    type Prepared;
    type Error;
    /// The fallible steps for every extent of `request`: retire its stage-1
    /// retired leaves, stage-2 and frame-inventory backing. Idempotent over
    /// an extent already retired. On `Err` nothing may be left for
    /// [`Self::apply`]: the venue undoes or keeps retryable its own work.
    fn prepare(&mut self, request: &ReturnSettlementRequest)
    -> Result<Self::Prepared, Self::Error>;
    /// The one infallible apply of a prepared batch.
    fn apply(&mut self, prepared: Self::Prepared);
}

impl ReturnSettlementRequest {
    /// The settlement step that mints acknowledgement authority: under an
    /// exclusion of exactly this request's MM, run the venue's fallible
    /// steps, then its one infallible apply, and only then hand back one
    /// [`SettledChunk`] per observed extent. `Ok(None)`: the exclusion names
    /// another MM, so nothing ran (stale). `Err`: a fallible step failed;
    /// nothing applied and nothing may be acknowledged.
    pub fn retire_and_apply<B: OwedReturnRetirement + ?Sized>(
        self,
        excluded: &ExcludedEditor<'_>,
        backend: &mut B,
    ) -> Result<Option<SettledReturns>, B::Error> {
        if self.mm.raw() != excluded.key() {
            return Ok(None);
        }
        let prepared = backend.prepare(&self)?;
        backend.apply(prepared);
        Ok(Some(SettledReturns {
            mm: self.mm,
            chunks: self.owed.map(|owed| {
                owed.map(|owed| SettledChunk {
                    slot: owed.slot,
                    epoch: owed.epoch,
                    expected_start: owed.range.start(),
                    new_start: owed.range.end(),
                })
            }),
        }))
    }
}

/// Authority to acknowledge `[expected_start, new_start)` of the owed extent
/// in `slot` during lifetime `epoch`: that part was retired and its batch
/// applied. Only [`ReturnSettlementRequest::retire_and_apply`] mints one, so
/// no root holder can free an owed slot without the settlement's exclusion,
/// retirement and apply. Neither `Clone` nor `Copy`: one acknowledgement.
#[must_use = "an unacknowledged settled chunk leaves its extent owed"]
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct SettledChunk {
    slot: OwedSlot,
    epoch: OwedSlotEpoch,
    expected_start: u64,
    new_start: u64,
}
impl SettledChunk {
    pub const fn slot(&self) -> OwedSlot {
        self.slot
    }
    pub const fn epoch(&self) -> OwedSlotEpoch {
        self.epoch
    }
    /// The slot's `start` the settlement walked from.
    pub const fn expected_start(&self) -> u64 {
        self.expected_start
    }
    /// The slot's `start` once this chunk is acknowledged.
    pub const fn new_start(&self) -> u64 {
        self.new_start
    }
}

/// Every extent of one observed request, retired and applied: one
/// [`SettledChunk`] each.
#[must_use = "an unacknowledged settlement leaves its extents owed"]
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct SettledReturns {
    mm: ReservationMm,
    chunks: [Option<SettledChunk>; OWED_RETURNS_PER_MM],
}
impl SettledReturns {
    /// The root whose journal the settled request observed.
    pub const fn mm(&self) -> ReservationMm {
        self.mm
    }
    pub fn is_empty(&self) -> bool {
        self.chunks.iter().all(Option::is_none)
    }
    pub fn into_chunks(self) -> impl Iterator<Item = SettledChunk> {
        self.chunks.into_iter().flatten()
    }
}

/// Evidence that one MM's carrier-wide memory was released for good: its
/// address space is excluded (for a retired MM, no published entry names
/// it) and the venue's whole-MM release (frame-inventory rows, COW
/// residency) succeeded. Only [`Self::released`] mints one; it frees the
/// retired MM's owed slots ([`RetiredReturns::settle_whole_mm`]), whose
/// frames that release returned. Neither `Clone` nor `Copy`.
#[must_use = "an unspent release receipt leaves the MM's returns owed"]
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct MmReleaseReceipt {
    mm: ReservationMm,
}
impl MmReleaseReceipt {
    /// Run the venue's whole-MM `release` for the MM whose editor `absent`
    /// proves excluded, and mint its receipt only if the release succeeded.
    /// `None`: no MM is named, or the release failed; the MM's returns stay
    /// owed and the venue retries its (idempotent) release.
    pub fn released(
        absent: &ExcludedEditor<'_>,
        release: impl FnOnce(ReservationMm) -> bool,
    ) -> Option<Self> {
        let mm = ReservationMm::new(absent.key())?;
        release(mm).then_some(Self { mm })
    }
    /// The released MM.
    pub const fn mm(&self) -> ReservationMm {
        self.mm
    }
}

/// The shared owed-return table, for MMs whose root has retired.
pub trait RetiredReturns {
    /// Free every slot the released MM still owes; returns how many. The
    /// receipt is spent either way. `Busy`: a root still publishes the MM
    /// and owes returns, so nothing is freed and the venue reruns its
    /// release after that root retires.
    fn settle_whole_mm(&self, receipt: MmReleaseReceipt) -> Result<usize, Refusal>;
}

/// One root's owed-return journal, borrowed under its root guard.
pub trait ReturnJournal {
    /// Every extent the root owes now.
    fn owed_returns(&self) -> Result<ReturnSettlementRequest, Refusal>;
    /// Acknowledge the settled chunk of one owed extent. Effective only
    /// while the slot still holds the chunk's epoch and starts at its
    /// `expected_start`, and its `new_start` lies in `(expected_start, end]`;
    /// `new_start == end` frees the slot and advances its epoch.
    /// `Err(Stale)`: the root is no longer admitted.
    ///
    /// Acknowledgement takes settlement authority: a bare (slot, epoch,
    /// start) frees nothing (witness: `carrick-core`'s
    /// `Reservations::acknowledge_chunk` doctests).
    fn acknowledge_chunk(&mut self, chunk: SettledChunk) -> Result<ChunkAcknowledgement, Refusal>;
}

/// One ring thread's claim to drive its MM's owed-return settlement doorbell
/// (#1369 slice 3): the single flight. The shared table keeps one claim word
/// per claimant vCPU slot, naming the root it holds and an epoch that every
/// claim and every release of that word advances by one, so an odd epoch is
/// held. A claim is taken under the root guard (two claimants of one MM
/// serialize there) and released only by the carrier's exit epilogue for that
/// doorbell, by a compare-and-swap from the exact word: a stale epilogue can
/// never release a newer claim, and there is no takeover.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct SettlementClaim {
    slot: u32,
    word: u64,
}
impl SettlementClaim {
    const EPOCH: u64 = (1 << 48) - 1;
    /// The claim a free word `current` of `slot` takes for root `index`.
    /// `None`: the word is still held (its epilogue never ran), or `index`
    /// does not fit.
    pub const fn claim(slot: u32, current: u64, index: usize) -> Option<Self> {
        if current & 1 == 1 || index >= u16::MAX as usize {
            return None;
        }
        let epoch = (current + 1) & Self::EPOCH;
        Some(Self {
            slot,
            word: ((index as u64 + 1) << 48) | epoch,
        })
    }
    /// The word a release of held `word` stores: same root, next epoch.
    pub const fn released(word: u64) -> u64 {
        (word & !Self::EPOCH) | ((word + 1) & Self::EPOCH)
    }
    /// Whether `word` holds a claim for root `index`.
    pub const fn held_for(word: u64, index: usize) -> bool {
        word & 1 == 1 && word >> 48 == index as u64 + 1
    }
    /// A held claim as a doorbell record carries it. `None` for a word that
    /// names no held claim.
    pub const fn from_wire(slot: u32, word: u64) -> Option<Self> {
        if word & 1 == 1 && word >> 48 != 0 {
            Some(Self { slot, word })
        } else {
            None
        }
    }
    /// The claimant's vCPU slot (the claim word it holds).
    pub const fn slot(self) -> u32 {
        self.slot
    }
    pub const fn word(self) -> u64 {
        self.word
    }
}

/// What the carrier answered one settlement doorbell. The ring enrolled on
/// every cause before it rang, so a `Contended` answer parks at the revision
/// it observed before the carrier decided: a release in between wakes it.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
#[repr(u64)]
pub enum SettlementDoorbellReply {
    /// The MM's owed returns settled (or none were owed): rerun the call.
    Settled = 1,
    /// A ring editor of the MM is active: wait for its `Editor` release.
    Editor = 2,
    /// Another holder has the MM's root: wait for its `Reservations` release.
    Reservations = 3,
    /// A fork loan naming the MM is pending: wait for the `PendingEdit`
    /// release the carrier publishes when the loan settles.
    ForkLoanPending = 4,
    /// The record no longer names the caller's live MM or claim: no effect.
    Stale = 5,
}
impl SettlementDoorbellReply {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        Some(match raw {
            1 => Self::Settled,
            2 => Self::Editor,
            3 => Self::Reservations,
            4 => Self::ForkLoanPending,
            5 => Self::Stale,
            _ => return None,
        })
    }
    /// The release a refused doorbell waits for; `None` for a final answer.
    pub const fn wait_cause(
        self,
    ) -> Option<carrick_sched_core::spaces::notification::SpaceWaitCause> {
        use carrick_sched_core::spaces::notification::SpaceWaitCause;
        match self {
            Self::Editor => Some(SpaceWaitCause::Editor),
            Self::Reservations => Some(SpaceWaitCause::Reservations),
            Self::ForkLoanPending => Some(SpaceWaitCause::PendingEdit),
            Self::Settled | Self::Stale => None,
        }
    }
}

/// The physical-service record a ring thread hands its carrier when it rings
/// the owed-return settlement doorbell (HVF: an HVC #6 grant op; x86 CPL0:
/// an op on the owner-grant port). One neutral record for both ISAs: the
/// carrier authenticates the stopped execution's MM against `mm`, settles at
/// an exclusion of that MM, releases `claim` in its epilogue and writes the
/// reply. It is a physical-service doorbell, never a syscall crossing.
#[repr(C)]
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct ReturnSettlementDoorbell {
    pub words: [u64; 6],
}
impl ReturnSettlementDoorbell {
    pub const MAGIC: u64 = 0x4f57_4544_5345_5431; // "OWEDSET1"
    pub const fn request(mm: ReservationMm, claim: SettlementClaim, task: u64) -> Self {
        Self {
            words: [
                Self::MAGIC,
                mm.raw(),
                claim.word(),
                claim.slot() as u64,
                task,
                0,
            ],
        }
    }
    /// The request's MM and claim, if the record is well formed.
    pub fn decode(&self) -> Option<(ReservationMm, SettlementClaim)> {
        if self.words[0] != Self::MAGIC {
            return None;
        }
        Some((
            ReservationMm::new(self.words[1])?,
            SettlementClaim::from_wire(u32::try_from(self.words[3]).ok()?, self.words[2])?,
        ))
    }
    /// The claimant's task key, recorded for diagnostics only.
    pub const fn task(&self) -> u64 {
        self.words[4]
    }
    pub fn answer(&mut self, reply: SettlementDoorbellReply) {
        self.words[5] = reply as u64;
    }
    /// The carrier's answer; an unanswered record is `Stale`.
    pub fn reply(&self) -> SettlementDoorbellReply {
        SettlementDoorbellReply::from_raw(self.words[5]).unwrap_or(SettlementDoorbellReply::Stale)
    }
}
