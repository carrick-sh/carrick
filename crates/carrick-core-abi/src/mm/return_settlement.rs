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
//! The cursor is also what bounds an exclusion (#1482): a ring-owned
//! settlement covers at most [`SETTLEMENT_CHUNK_PAGES`] owed pages under one
//! exclusion of the MM's editor ([`SettlementBound::Chunk`]), acknowledges
//! exactly that chunk, and the next exclusion observes the journal again and
//! continues from the advanced `start`: never a restart from the extent's
//! original front.
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

/// The most owed pages one settlement covers while it holds one exclusion of
/// the MM's editor (#1482): the span of one last-level table (2 MiB). A
/// larger owed extent settles over several exclusions; its slot's `start`,
/// the settlement cursor, carries the progress from one to the next.
pub const SETTLEMENT_CHUNK_PAGES: u64 = 512;
const SETTLEMENT_CHUNK_BYTES: u64 = SETTLEMENT_CHUNK_PAGES * 4096;

/// How much of an observed request one exclusion settles.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum SettlementBound {
    /// At most [`SETTLEMENT_CHUNK_PAGES`] owed pages, from the front of
    /// the observed extents in slot order: every ring-owned settlement. An
    /// extent cut short ends on a chunk-aligned (2 MiB) address, so no
    /// block terminal straddles the cut, and the first extent always
    /// advances.
    Chunk,
    /// Every observed extent in one transaction: only the host venue's
    /// boundary reconciliation, whose callers (fork planning) need the
    /// whole journal settled at once, and which #1393 deletes.
    WholeRequest,
}

impl ReturnSettlementRequest {
    /// The part of this request one exclusion settles under `bound`, and
    /// whether any observed owed page was left out of it (it stays owed in
    /// its slot, from the cursor this chunk's acknowledgement leaves).
    pub fn bounded(self, bound: SettlementBound) -> (Self, bool) {
        if bound == SettlementBound::WholeRequest {
            return (self, false);
        }
        let mut chunk = Self::new(self.mm);
        let mut budget = SETTLEMENT_CHUNK_BYTES;
        let mut rest_owed = false;
        for (entry, observed) in chunk.owed.iter_mut().zip(self.owed) {
            let Some(observed) = observed else { continue };
            let (start, end) = (observed.range.start(), observed.range.end());
            let cut = if end - start <= budget {
                end
            } else {
                // `start + budget < end`: no overflow.
                (start + budget) & !(SETTLEMENT_CHUNK_BYTES - 1)
            };
            rest_owed |= cut < end;
            // `None`: no aligned piece of this extent fits what is left.
            if let Some(range) = ReservationRange::new(start, cut) {
                budget -= cut - start;
                *entry = Some(DeferredReturn { range, ..observed });
            }
        }
        (chunk, rest_owed)
    }

    /// The settlement step that mints acknowledgement authority: under an
    /// exclusion of exactly this request's MM, take the part `bound`
    /// allows ([`Self::bounded`]), run the venue's fallible steps over it,
    /// then its one infallible apply, and only then hand back one
    /// [`SettledChunk`] per extent it covered, each acknowledging exactly
    /// the pages settled. `Ok(None)`: the exclusion names another MM, so
    /// nothing ran (stale). `Err`: a fallible step failed; nothing applied
    /// and nothing may be acknowledged.
    pub fn retire_and_apply<B: OwedReturnRetirement + ?Sized>(
        self,
        excluded: &ExcludedEditor<'_>,
        bound: SettlementBound,
        backend: &mut B,
    ) -> Result<Option<SettledReturns>, B::Error> {
        if self.mm.raw() != excluded.key() {
            return Ok(None);
        }
        let (chunk, rest_owed) = self.bounded(bound);
        let prepared = backend.prepare(&chunk)?;
        backend.apply(prepared);
        Ok(Some(SettledReturns {
            mm: chunk.mm,
            chunks: chunk.owed.map(|owed| {
                owed.map(|owed| SettledChunk {
                    slot: owed.slot,
                    epoch: owed.epoch,
                    expected_start: owed.range.start(),
                    new_start: owed.range.end(),
                })
            }),
            rest_owed,
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
    rest_owed: bool,
}
impl SettledReturns {
    /// The root whose journal the settled request observed.
    pub const fn mm(&self) -> ReservationMm {
        self.mm
    }
    /// Whether the settlement's bound left observed owed pages for a later
    /// exclusion.
    pub const fn rest_owed(&self) -> bool {
        self.rest_owed
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

/// Why a foreign holder of the shared owed-return table refused the full
/// table's drain (#1482 P0-1): the holder-side refusals a waiter can enrol
/// on. Each names the release the holder's own source publishes.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum HolderRefusal {
    /// A ring editor of the holder is active: its `Editor` release.
    Editor,
    /// Another holder has the holder's root: its `Reservations` release.
    Reservations,
    /// A fork loan naming the holder is pending: the `PendingEdit` release
    /// the carrier publishes when the loan settles.
    ForkLoanPending,
}
impl HolderRefusal {
    /// The holder-side refusal one settlement answer names; `None` for a
    /// final answer (`Settled`, `Stale`).
    pub const fn from_reply(reply: SettlementDoorbellReply) -> Option<Self> {
        match reply {
            SettlementDoorbellReply::Editor => Some(Self::Editor),
            SettlementDoorbellReply::Reservations => Some(Self::Reservations),
            SettlementDoorbellReply::ForkLoanPending => Some(Self::ForkLoanPending),
            SettlementDoorbellReply::Settled | SettlementDoorbellReply::Stale => None,
        }
    }
    pub const fn reply(self) -> SettlementDoorbellReply {
        match self {
            Self::Editor => SettlementDoorbellReply::Editor,
            Self::Reservations => SettlementDoorbellReply::Reservations,
            Self::ForkLoanPending => SettlementDoorbellReply::ForkLoanPending,
        }
    }
    /// The holder's release this refusal waits for.
    pub const fn cause(self) -> carrick_sched_core::spaces::notification::SpaceWaitCause {
        use carrick_sched_core::spaces::notification::SpaceWaitCause;
        match self {
            Self::Editor => SpaceWaitCause::Editor,
            Self::Reservations => SpaceWaitCause::Reservations,
            Self::ForkLoanPending => SpaceWaitCause::PendingEdit,
        }
    }
}

/// A foreign holder's wait authority (#1482 P0-1). A full owed-return
/// table's drain freed no slot: `mm`, the oldest holder that refused it,
/// keeps the slots until its `refusal` releases. `revision` is the revision
/// of that release on `mm`'s live notification source, read before the
/// carrier's refused attempt, so a release that followed the refusal is a
/// changed revision to the waiter, never a lost wake.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct HolderWait {
    mm: ReservationMm,
    refusal: HolderRefusal,
    revision: u64,
}
impl HolderWait {
    pub const fn new(mm: ReservationMm, refusal: HolderRefusal, revision: u64) -> Self {
        Self {
            mm,
            refusal,
            revision,
        }
    }
    /// The holder whose live notification source names the wait.
    pub const fn mm(&self) -> ReservationMm {
        self.mm
    }
    pub const fn refusal(&self) -> HolderRefusal {
        self.refusal
    }
    /// The holder's release the waiter enrols on.
    pub const fn cause(&self) -> carrick_sched_core::spaces::notification::SpaceWaitCause {
        self.refusal.cause()
    }
    /// The release's revision before the carrier's refused attempt.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// The carrier's whole answer to one settlement doorbell.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum SettlementDoorbellAnswer {
    /// The caller's own MM: settled (rerun), refused at a cause the caller
    /// observed before it rang, or stale.
    Own(SettlementDoorbellReply),
    /// The caller's MM settled, but the shared table is full of other MMs'
    /// slots and no holder could free one: wait on that holder's release.
    Holder(HolderWait),
}
impl From<SettlementDoorbellReply> for SettlementDoorbellAnswer {
    fn from(reply: SettlementDoorbellReply) -> Self {
        Self::Own(reply)
    }
}
impl SettlementDoorbellAnswer {
    /// Set in the answer word of a [`Self::Holder`] answer, above the
    /// holder's [`HolderRefusal`] reply.
    const HOLDER: u64 = 1 << 8;

    /// The three reply words a carrier writes (the record's tail; HVC x1 to
    /// x3): the answer word, then a holder's MM and revision.
    pub const fn to_words(self) -> [u64; 3] {
        match self {
            Self::Own(reply) => [reply as u64, 0, 0],
            Self::Holder(wait) => [
                Self::HOLDER | wait.refusal.reply() as u64,
                wait.mm.raw(),
                wait.revision,
            ],
        }
    }

    /// Decode three reply words; `None` for words no carrier writes.
    pub const fn from_words(words: [u64; 3]) -> Option<Self> {
        if words[0] & Self::HOLDER == 0 {
            return match SettlementDoorbellReply::from_raw(words[0]) {
                Some(reply) => Some(Self::Own(reply)),
                None => None,
            };
        }
        let Some(reply) = SettlementDoorbellReply::from_raw(words[0] & !Self::HOLDER) else {
            return None;
        };
        let Some(refusal) = HolderRefusal::from_reply(reply) else {
            return None;
        };
        let Some(mm) = ReservationMm::new(words[1]) else {
            return None;
        };
        Some(Self::Holder(HolderWait::new(mm, refusal, words[2])))
    }
}

/// The physical-service record a ring thread hands its carrier when it rings
/// the owed-return settlement doorbell (HVF: an HVC #6 grant op; x86 CPL0:
/// an op on the owner-grant port). One neutral record for both ISAs: the
/// carrier authenticates the stopped execution's MM against `mm`, settles at
/// an exclusion of that MM, releases `claim` in its epilogue and writes the
/// answer ([`SettlementDoorbellAnswer`]) into the last three words.
#[repr(C)]
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct ReturnSettlementDoorbell {
    pub words: [u64; 8],
}
impl ReturnSettlementDoorbell {
    pub const MAGIC: u64 = 0x4f57_4544_5345_5432; // "OWEDSET2"
    const ANSWER: usize = 5;
    pub const fn request(mm: ReservationMm, claim: SettlementClaim, task: u64) -> Self {
        Self {
            words: [
                Self::MAGIC,
                mm.raw(),
                claim.word(),
                claim.slot() as u64,
                task,
                0,
                0,
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
    /// Write the carrier's answer into the record's reply words.
    pub fn answer(&mut self, answer: impl Into<SettlementDoorbellAnswer>) {
        self.set_reply_words(answer.into().to_words());
    }
    /// Store reply words a transport carried (HVC x1 to x3).
    pub fn set_reply_words(&mut self, words: [u64; 3]) {
        self.words[Self::ANSWER..].copy_from_slice(&words);
    }
    /// The carrier's answer; an unanswered or malformed record is `Stale`.
    pub fn outcome(&self) -> SettlementDoorbellAnswer {
        let [answer, mm, revision] = [
            self.words[Self::ANSWER],
            self.words[Self::ANSWER + 1],
            self.words[Self::ANSWER + 2],
        ];
        SettlementDoorbellAnswer::from_words([answer, mm, revision]).unwrap_or(
            SettlementDoorbellAnswer::Own(SettlementDoorbellReply::Stale),
        )
    }
}

#[cfg(test)]
mod answer_tests {
    use super::*;

    /// #1482 P0-1: a holder's wait authority survives the reply words both
    /// transports carry, and an own answer stays an own answer.
    #[test]
    fn holder_and_own_answers_round_trip_the_reply_words() {
        let claim = SettlementClaim::claim(1, 0, 3).unwrap();
        let mut record =
            ReturnSettlementDoorbell::request(ReservationMm::new(7).unwrap(), claim, 9);
        assert_eq!(
            record.outcome(),
            SettlementDoorbellAnswer::Own(SettlementDoorbellReply::Stale),
            "an unanswered record is stale"
        );
        for reply in [
            SettlementDoorbellReply::Settled,
            SettlementDoorbellReply::Editor,
            SettlementDoorbellReply::Stale,
        ] {
            record.answer(reply);
            assert_eq!(record.outcome(), SettlementDoorbellAnswer::Own(reply));
        }
        for refusal in [
            HolderRefusal::Editor,
            HolderRefusal::Reservations,
            HolderRefusal::ForkLoanPending,
        ] {
            let wait = HolderWait::new(ReservationMm::new(42).unwrap(), refusal, 0x55);
            record.answer(SettlementDoorbellAnswer::Holder(wait));
            assert_eq!(record.outcome(), SettlementDoorbellAnswer::Holder(wait));
            let mut carried =
                ReturnSettlementDoorbell::request(ReservationMm::new(7).unwrap(), claim, 9);
            carried.set_reply_words(SettlementDoorbellAnswer::Holder(wait).to_words());
            assert_eq!(carried.outcome(), SettlementDoorbellAnswer::Holder(wait));
        }
        // A holder answer naming no MM, or a final reply, is malformed.
        assert_eq!(
            SettlementDoorbellAnswer::from_words([(1 << 8) | 2, 0, 1]),
            None
        );
        assert_eq!(
            SettlementDoorbellAnswer::from_words([(1 << 8) | 1, 4, 1]),
            None
        );
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    const MIB2: u64 = SETTLEMENT_CHUNK_BYTES;

    fn request(extents: &[(u64, u64)]) -> ReturnSettlementRequest {
        let mut request = ReturnSettlementRequest::new(ReservationMm::new(9).unwrap());
        for (slot, &(start, end)) in extents.iter().enumerate() {
            request
                .push(DeferredReturn {
                    range: ReservationRange::new(start, end).unwrap(),
                    sequence: ReservationSequence::new(1).unwrap(),
                    slot: OwedSlot::new(slot).unwrap(),
                    epoch: OwedSlotEpoch::new(3),
                })
                .unwrap();
        }
        request
    }

    fn ranges(request: &ReturnSettlementRequest) -> alloc::vec::Vec<(u64, u64)> {
        request
            .iter()
            .map(|owed| (owed.range.start(), owed.range.end()))
            .collect()
    }

    fn pages(request: &ReturnSettlementRequest) -> u64 {
        request.iter().map(|owed| owed.range.len() / 4096).sum()
    }

    /// #1482 P0-2: a GiB extent's chunk is its first 2 MiB, and the rest
    /// stays owed.
    #[test]
    fn a_gib_extent_bounds_to_its_first_chunk() {
        let base = 0x1_4000_0000;
        let (chunk, rest) = request(&[(base, base + (1 << 30))]).bounded(SettlementBound::Chunk);
        assert_eq!(ranges(&chunk), [(base, base + MIB2)]);
        assert_eq!(pages(&chunk), SETTLEMENT_CHUNK_PAGES);
        assert!(rest);
    }

    /// An unaligned front cuts on the 2 MiB grid, so the chunk is shorter
    /// than the budget but never cuts a block terminal, and still advances.
    #[test]
    fn an_unaligned_front_cuts_on_the_chunk_grid() {
        let start = 0x40_0000 + 0x3000;
        let (chunk, rest) = request(&[(start, start + 8 * MIB2)]).bounded(SettlementBound::Chunk);
        assert_eq!(ranges(&chunk), [(start, 0x60_0000)]);
        assert!(rest);
    }

    /// The budget is shared by every extent of the request: small extents
    /// settle whole, the extent that overruns is cut, later ones wait.
    #[test]
    fn the_budget_spans_every_extent_of_one_exclusion() {
        let (chunk, rest) = request(&[
            (0x10_0000, 0x10_4000),
            (0x40_0000, 0x40_0000 + 3 * MIB2),
            (0x200_0000, 0x200_1000),
        ])
        .bounded(SettlementBound::Chunk);
        // 4 pages leave 508: the second extent's aligned cut falls on its
        // own start, so it waits for the next exclusion's full budget.
        assert_eq!(
            ranges(&chunk),
            [(0x10_0000, 0x10_4000), (0x200_0000, 0x200_1000)]
        );
        assert!(pages(&chunk) <= SETTLEMENT_CHUNK_PAGES);
        assert!(rest);
        let (all, rest) = request(&[(0x10_0000, 0x10_4000), (0x200_0000, 0x200_1000)])
            .bounded(SettlementBound::Chunk);
        assert_eq!(
            ranges(&all),
            [(0x10_0000, 0x10_4000), (0x200_0000, 0x200_1000)]
        );
        assert!(!rest, "everything owed fits one chunk");
    }

    /// The host venue's whole-request bound is the observed request.
    #[test]
    fn the_whole_request_bound_keeps_every_extent() {
        let observed = request(&[(0x1_0000_0000, 0x1_4000_0000)]);
        let (whole, rest) = observed.clone().bounded(SettlementBound::WholeRequest);
        assert_eq!(whole, observed);
        assert!(!rest);
    }
}
