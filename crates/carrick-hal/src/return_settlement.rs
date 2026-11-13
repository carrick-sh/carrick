//! The one neutral owed-return settlement transaction (#1369 slice 2).
//!
//! EL1 serves a resident private-anonymous `munmap` (or a `Prepare` that
//! replaces resident memory) by retiring its stage-1 terminals in place and
//! journaling the range in its root as an owed return
//! ([`carrick_core_abi::DeferredReturn`]). The frames and the VA stay
//! unreusable until a settlement retires the extent's backing and
//! acknowledges its slot. [`settle_owed_returns`] is that settlement, for
//! every venue: it composes the venue's own authorities and adds no
//! mechanism. Its commit order:
//!
//! 1. authenticate: the observed journal names the excluded MM;
//! 2. fallible steps, through [`OwedReturnRetirement::prepare`]: retire every
//!    owed extent's backing, idempotently (an extent already retired is a
//!    no-op), undoing its own partial work on failure;
//! 3. one infallible apply ([`OwedReturnRetirement::apply`]);
//! 4. acknowledge each slot by (slot, epoch, start)
//!    ([`carrick_core_abi::ReturnJournal::acknowledge_chunk`]).
//!
//! Steps 1 to 3 are [`ReturnSettlementRequest::retire_and_apply`], the only
//! mint of the [`carrick_core_abi::SettledChunk`]s step 4 consumes: no
//! journal holder can acknowledge an extent outside this transaction.
//!
//! A ring-owned settlement is bounded (#1482): one transaction covers at
//! most one [`SettlementBound::Chunk`] of the observed extents, under one
//! exclusion, and acknowledges exactly that chunk. A doorbell drives the
//! rest through [`settle_in_bounded_pauses`], lowering and re-raising the
//! exclusion between chunks within its one crossing.
//!
//! A failure in step 2 applies and acknowledges nothing: the extents stay
//! owed and the next settlement retries them, re-retiring the ones that
//! already succeeded as no-ops. A journal that no longer names the MM is
//! [`SettlementOutcome::Stale`]: no effect, and nothing is quarantined.
//!
//! Lock order: the MM's EL1 editor exclusion, then its [`SettlementLock`],
//! then the fork-stock lock, then the root guard. The root guard is held only
//! inside the journal steps, never across backend service.

use carrick_core_abi::{
    ChunkAcknowledgement, HolderRefusal, HolderWait, OwedReturnRetirement, Refusal, ReservationMm,
    ReturnJournal, ReturnSettlementRequest, SettlementBound, SettlementDoorbellReply,
    SettlementOutcome, SkipReason,
};

/// One MM's settlement lock: serializes every settlement of the MM's owed
/// returns, since two host exclusions of one MM may overlap (a pause and a
/// mutation guard) and two concurrent retirements of the same frames are
/// not idempotent.
#[derive(Debug, Default)]
pub struct SettlementLock(parking_lot::Mutex<()>);

impl SettlementLock {
    pub const fn new() -> Self {
        Self(parking_lot::const_mutex(()))
    }

    /// Take the lock for the MM whose EL1 editor `excluded` proves
    /// excluded. The exclusion is taken first and outlives the guard.
    pub fn lock<'a>(
        &'a self,
        excluded: &'a carrick_sched_core::ExcludedEditor<'_>,
    ) -> SettlementGuard<'a> {
        SettlementGuard {
            mm: excluded.key(),
            _held: self.0.lock(),
        }
    }
}

/// Proof that the settlement lock of MM [`Self::mm`] is held, inside an
/// exclusion of that MM's EL1 editor.
#[must_use]
#[derive(Debug)]
pub struct SettlementGuard<'a> {
    mm: u64,
    _held: parking_lot::MutexGuard<'a, ()>,
}

impl SettlementGuard<'_> {
    /// The MM whose owed returns this guard serializes.
    pub fn mm(&self) -> u64 {
        self.mm
    }
}

/// A venue's access to one MM's journal: each call takes and drops the root
/// guard around `step`, so no backend service ever runs under it.
pub trait ReturnJournalAccess {
    type Error;
    fn with_journal<R>(
        &self,
        step: impl FnOnce(&mut dyn ReturnJournal) -> Result<R, Refusal>,
    ) -> Result<R, Self::Error>;
}

/// What a settled transaction acknowledged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReturnSettlementReceipt {
    /// Slots freed: their extents' frames and VAs are reusable.
    pub freed: usize,
    /// Slots whose front advanced; the rest stays owed.
    pub advanced: usize,
    /// Acknowledgements that matched no live (slot, epoch, start).
    pub stale: usize,
    /// The chunk bound left observed owed pages for a later exclusion, and
    /// every chunk acknowledgement took effect, so that exclusion continues
    /// from the cursors this one advanced.
    pub owed_remains: bool,
}

/// Why a settlement acknowledged nothing. The extents stay owed.
#[derive(Debug, Eq, PartialEq)]
pub enum ReturnSettlementError<J, B> {
    /// The journal could not be observed or acknowledged.
    Journal(J),
    /// A fallible retirement step failed.
    Backend(B),
}

/// Settle what `bound` allows of the returns the excluded MM's journal
/// owes, as one transaction (see the module docs for the commit order).
/// Ring-owned venues settle one [`SettlementBound::Chunk`] per exclusion
/// ([`settle_ring_owned_returns`]); only the host venue's boundary
/// reconciliation takes [`SettlementBound::WholeRequest`].
pub fn settle_owed_returns<J: ReturnJournalAccess, B: OwedReturnRetirement>(
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
    guard: &SettlementGuard<'_>,
    bound: SettlementBound,
    journal: &J,
    backend: &mut B,
) -> Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<J::Error, B::Error>> {
    if guard.mm() != excluded.key() {
        return Ok(SettlementOutcome::Stale);
    }
    let request: ReturnSettlementRequest = journal
        .with_journal(|journal| journal.owed_returns())
        .map_err(ReturnSettlementError::Journal)?;
    let Some(settled) = request
        .retire_and_apply(excluded, bound, backend)
        .map_err(ReturnSettlementError::Backend)?
    else {
        return Ok(SettlementOutcome::Stale);
    };
    if settled.is_empty() {
        return Ok(SettlementOutcome::Settled(ReturnSettlementReceipt {
            owed_remains: settled.rest_owed(),
            ..ReturnSettlementReceipt::default()
        }));
    }
    let rest_owed = settled.rest_owed();
    journal
        .with_journal(|journal| {
            let mut receipt = ReturnSettlementReceipt::default();
            for chunk in settled.into_chunks() {
                match journal.acknowledge_chunk(chunk)? {
                    ChunkAcknowledgement::Freed => receipt.freed += 1,
                    ChunkAcknowledgement::Advanced => receipt.advanced += 1,
                    ChunkAcknowledgement::Stale => receipt.stale += 1,
                }
            }
            receipt.owed_remains = rest_owed && receipt.stale == 0;
            Ok(receipt)
        })
        .map(SettlementOutcome::Settled)
        .map_err(ReturnSettlementError::Journal)
}

/// The settlement every exclusion of a ring-owned MM runs (#1369 slice 3),
/// under that exclusion and the MM's settlement lock: at most one
/// [`SettlementBound::Chunk`] (#1482), so no exclusion walks more than
/// [`carrick_core_abi::SETTLEMENT_CHUNK_PAGES`] owed pages. A fork loan
/// naming the MM (`loan_pending`, read under the fork-stock lock, which
/// follows the settlement lock) skips it: nothing is acknowledged and the
/// returns stay owed for a later exclusion. Otherwise it is
/// [`settle_owed_returns`].
pub fn settle_ring_owned_returns<J: ReturnJournalAccess, B: OwedReturnRetirement>(
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
    guard: &SettlementGuard<'_>,
    loan_pending: bool,
    journal: &J,
    backend: &mut B,
) -> Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<J::Error, B::Error>> {
    if guard.mm() != excluded.key() {
        return Ok(SettlementOutcome::Stale);
    }
    if loan_pending {
        return Ok(SettlementOutcome::Skipped(SkipReason::ForkLoanPending));
    }
    settle_owed_returns(excluded, guard, SettlementBound::Chunk, journal, backend)
}

/// What one exclusion's ring-owned settlement answered, and whether its
/// chunk bound left owed pages for the next exclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PauseSettlement {
    pub reply: SettlementDoorbellReply,
    pub owed_remains: bool,
}

impl PauseSettlement {
    /// A final answer with no settlement behind it (a refused exclusion).
    pub const fn answer(reply: SettlementDoorbellReply) -> Self {
        Self {
            reply,
            owed_remains: false,
        }
    }
}

/// [`doorbell_reply`] for one exclusion, with whether owed pages remain.
pub fn pause_settlement<B>(
    outcome: &Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<Refusal, B>>,
) -> Option<PauseSettlement> {
    Some(PauseSettlement {
        reply: doorbell_reply(outcome)?,
        owed_remains: matches!(
            outcome,
            Ok(SettlementOutcome::Settled(receipt)) if receipt.owed_remains
        ),
    })
}

/// A settlement doorbell's drive (#1482): settle one MM's owed returns over
/// as many bounded exclusions as the chunk bound needs, inside the one
/// crossing. Each `pause` raises one exclusion of the MM's editor, settles
/// one chunk under it ([`settle_ring_owned_returns`]) and lowers it before
/// it returns, so no exclusion is held across chunks. Progress lives in the
/// journal: each chunk's acknowledgement advanced its slot's `start`, and
/// the next pause observes only what is still owed. A pause that answers
/// anything but `Settled` with owed pages left (a refused re-raise, a
/// pending fork loan, a busy root, a stale acknowledgement) ends the drive
/// with that answer; the chunks already settled stay settled, and the
/// ring's rerun continues from their cursors.
pub fn settle_in_bounded_pauses<E>(
    mut pause: impl FnMut() -> Result<PauseSettlement, E>,
) -> Result<SettlementDoorbellReply, E> {
    loop {
        let settled = pause()?;
        if settled.reply != SettlementDoorbellReply::Settled || !settled.owed_remains {
            return Ok(settled.reply);
        }
    }
}

/// A settlement doorbell's answer for one ring-owned settlement. `Busy` from
/// the journal means another holder had the MM's root: the ring waits for
/// its `Reservations` release. `None`: a backend step failed, which the
/// carrier treats as its own fault (quarantine), never a guest answer.
pub fn doorbell_reply<B>(
    outcome: &Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<Refusal, B>>,
) -> Option<SettlementDoorbellReply> {
    Some(match outcome {
        Ok(SettlementOutcome::Settled(_)) => SettlementDoorbellReply::Settled,
        Ok(SettlementOutcome::Skipped(SkipReason::ForkLoanPending)) => {
            SettlementDoorbellReply::ForkLoanPending
        }
        Ok(SettlementOutcome::Stale) => SettlementDoorbellReply::Stale,
        Err(ReturnSettlementError::Journal(Refusal::Busy)) => SettlementDoorbellReply::Reservations,
        Err(ReturnSettlementError::Journal(_)) => SettlementDoorbellReply::Stale,
        Err(ReturnSettlementError::Backend(_)) => return None,
    })
}

/// One holder's release revisions on its live notification source, read
/// before the drain's attempt on it (#1482 P0-1): whichever release the
/// attempt is refused at, the waiter enrols at the revision that preceded
/// the refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HolderRevisions {
    pub editor: u64,
    pub reservations: u64,
    pub pending_edit: u64,
}

impl HolderRevisions {
    /// The revision of the release `refusal` waits for.
    pub const fn of(self, refusal: HolderRefusal) -> u64 {
        match refusal {
            HolderRefusal::Editor => self.editor,
            HolderRefusal::Reservations => self.reservations,
            HolderRefusal::ForkLoanPending => self.pending_edit,
        }
    }
}

/// What a full owed-return table's drain left the caller (#1482 P0-1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    /// The table has a free slot (it had one, or the drain freed one), or a
    /// holder settled: the caller reruns.
    Room,
    /// No holder could free a slot. The oldest holder that refused names
    /// the release to wait for; the caller enrols on it, probes its fence
    /// once and parks, releasing its execution capacity.
    Wait(HolderWait),
    /// Every holder left has no live source: retiring MMs, whose slots only
    /// their release receipts free.
    Retiring,
}

/// A carrier's venue for the one neutral drain ([`drain_owed_return_table`]):
/// the shared table's state, each holder's source and the carrier's own
/// bounded doorbell drive for one MM.
pub trait OwedReturnDrain {
    type Error;
    /// Whether every slot of the shared owed-return table is taken.
    fn table_full(&self) -> bool;
    /// The holder's release revisions; `None`: it has no live source.
    fn observe(&mut self, holder: ReservationMm) -> Option<HolderRevisions>;
    /// Settle `holder` over bounded exclusions ([`settle_in_bounded_pauses`]),
    /// one exclusion at a time, and answer what stopped it.
    fn settle(&mut self, holder: ReservationMm) -> Result<SettlementDoorbellReply, Self::Error>;
}

/// The shared owed-return table is full of other MMs' slots, so the caller's
/// settled journal still cannot take a retirement (#1369 slice 3, #1482
/// P0-1). Settle the other `holders`, oldest slot first, one MM's exclusions
/// at a time (never one MM's while raising another's), until a slot is free.
/// A holder's refusal is not progress: its release revisions are read before
/// the attempt, and when no slot could be freed the oldest refusing holder's
/// wait authority is the answer, so the caller waits on the holder that
/// prevents progress instead of ringing again. Never fatal and never an
/// errno: a refusal is "not now".
pub fn drain_owed_return_table<D: OwedReturnDrain>(
    drain: &mut D,
    holders: &[ReservationMm],
) -> Result<DrainOutcome, D::Error> {
    if !drain.table_full() {
        return Ok(DrainOutcome::Room);
    }
    let mut wait = None;
    let mut live = false;
    for &holder in holders {
        let revisions = drain.observe(holder);
        let reply = drain.settle(holder)?;
        if !drain.table_full() {
            return Ok(DrainOutcome::Room);
        }
        match (HolderRefusal::from_reply(reply), revisions) {
            (Some(refusal), Some(revisions)) => {
                live = true;
                wait.get_or_insert(HolderWait::new(holder, refusal, revisions.of(refusal)));
            }
            // Settled, yet the table is full again: other MMs journaled into
            // the freed slots, which is their progress; the rerun drains anew.
            (None, Some(_)) if reply == SettlementDoorbellReply::Settled => live = true,
            // No live source, or a stale holder: it is retiring.
            _ => {}
        }
    }
    Ok(match wait {
        Some(wait) => DrainOutcome::Wait(wait),
        None if live => DrainOutcome::Room,
        None => DrainOutcome::Retiring,
    })
}

#[cfg(test)]
#[path = "return_settlement/tests.rs"]
mod tests;
