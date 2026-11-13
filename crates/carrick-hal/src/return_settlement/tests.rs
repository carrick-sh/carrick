//! VM-free witnesses for the neutral owed-return transaction: a recording
//! journal with real slot epochs and a recording backend.

use super::*;
use carrick_core_abi::{
    DeferredReturn, OwedSlot, OwedSlotEpoch, ReservationMm, ReservationRange, ReservationSequence,
};
use std::cell::RefCell;

const MM: u64 = 1480;

#[derive(Clone, Copy, Debug)]
struct Slot {
    owner: u64,
    start: u64,
    end: u64,
    epoch: u64,
}

/// One table of owed-return slots, shared by every root, as the core
/// journal keeps it.
struct Journal {
    mm: u64,
    slots: RefCell<Vec<Slot>>,
    log: RefCell<Vec<&'static str>>,
}

impl Journal {
    fn owing(mm: u64, extents: &[(u64, u64)]) -> Self {
        Self {
            mm,
            slots: RefCell::new(
                extents
                    .iter()
                    .map(|&(start, end)| Slot {
                        owner: mm,
                        start,
                        end,
                        epoch: 7,
                    })
                    .collect(),
            ),
            log: RefCell::new(Vec::new()),
        }
    }
    fn owed(&self) -> Vec<(u64, u64)> {
        self.slots
            .borrow()
            .iter()
            .filter(|slot| slot.owner == self.mm)
            .map(|slot| (slot.start, slot.end))
            .collect()
    }
}

struct Guarded<'a>(&'a Journal);

impl ReturnJournal for Guarded<'_> {
    fn owed_returns(&self) -> Result<ReturnSettlementRequest, Refusal> {
        let mut request = ReturnSettlementRequest::new(ReservationMm::new(self.0.mm).unwrap());
        for (index, slot) in self.0.slots.borrow().iter().enumerate() {
            if slot.owner == self.0.mm {
                request.push(DeferredReturn {
                    range: ReservationRange::new(slot.start, slot.end).unwrap(),
                    sequence: ReservationSequence::new(1).unwrap(),
                    slot: OwedSlot::new(index).unwrap(),
                    epoch: OwedSlotEpoch::new(slot.epoch),
                })?;
            }
        }
        Ok(request)
    }
    fn acknowledge_chunk(
        &mut self,
        chunk: carrick_core_abi::SettledChunk,
    ) -> Result<ChunkAcknowledgement, Refusal> {
        self.0.log.borrow_mut().push("acknowledge");
        let (expected_start, new_start) = (chunk.expected_start(), chunk.new_start());
        let mut slots = self.0.slots.borrow_mut();
        let entry = &mut slots[chunk.slot().index()];
        if entry.owner != self.0.mm
            || entry.epoch != chunk.epoch().raw()
            || entry.start != expected_start
            || new_start <= expected_start
            || new_start > entry.end
        {
            return Ok(ChunkAcknowledgement::Stale);
        }
        if new_start == entry.end {
            *entry = Slot {
                owner: 0,
                start: 0,
                end: 0,
                epoch: entry.epoch + 1,
            };
            return Ok(ChunkAcknowledgement::Freed);
        }
        entry.start = new_start;
        Ok(ChunkAcknowledgement::Advanced)
    }
}

impl ReturnJournalAccess for Journal {
    type Error = Refusal;
    fn with_journal<R>(
        &self,
        step: impl FnOnce(&mut dyn ReturnJournal) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        step(&mut Guarded(self))
    }
}

/// Retires extents idempotently; fails the first retirement of `fail_at`.
#[derive(Default)]
struct Backend {
    fail_at: Option<u64>,
    retired: Vec<u64>,
    retirements: Vec<u64>,
    applied: Vec<u64>,
}

impl OwedReturnRetirement for Backend {
    type Prepared = Vec<u64>;
    type Error = u64;
    fn prepare(&mut self, request: &ReturnSettlementRequest) -> Result<Vec<u64>, u64> {
        let mut batch = Vec::new();
        for owed in request.iter() {
            let start = owed.range.start();
            if self.fail_at.take_if(|at| *at == start).is_some() {
                return Err(start);
            }
            if !self.retired.contains(&start) {
                self.retirements.push(start);
                self.retired.push(start);
            }
            batch.push(start);
        }
        Ok(batch)
    }
    fn apply(&mut self, prepared: Vec<u64>) {
        self.applied.extend(prepared);
    }
}

fn settle(
    spaces: &carrick_sched_core::AddressSpaces,
    lock: &SettlementLock,
    mm: u64,
    journal: &Journal,
    backend: &mut Backend,
) -> Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<Refusal, u64>> {
    let excluded = spaces.unpublished(mm).unwrap();
    let guard = lock.lock(&excluded);
    settle_owed_returns(&excluded, &guard, journal, backend)
}

const EXTENTS: [(u64, u64); 3] = [(0x10000, 0x12000), (0x20000, 0x21000), (0x30000, 0x34000)];

/// Fail extent 2 of 3: nothing applies and nothing is acknowledged, so all
/// three stay owed. The retry settles every extent; extent 1, already
/// retired, is a no-op, so no frame retires twice.
#[test]
fn a_failed_extent_acknowledges_nothing_and_the_retry_is_idempotent() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS);
    let mut backend = Backend {
        fail_at: Some(EXTENTS[1].0),
        ..Backend::default()
    };
    assert_eq!(
        settle(&spaces, &lock, MM, &journal, &mut backend),
        Err(ReturnSettlementError::Backend(EXTENTS[1].0))
    );
    assert!(
        backend.applied.is_empty(),
        "no apply before every step held"
    );
    assert!(journal.log.borrow().is_empty(), "nothing acknowledged");
    assert_eq!(journal.owed(), EXTENTS.to_vec());

    assert_eq!(
        settle(&spaces, &lock, MM, &journal, &mut backend),
        Ok(SettlementOutcome::Settled(ReturnSettlementReceipt {
            freed: 3,
            advanced: 0,
            stale: 0,
        }))
    );
    assert_eq!(
        backend.retirements,
        EXTENTS.map(|(start, _)| start).to_vec(),
        "each extent retired exactly once across both attempts"
    );
    assert_eq!(backend.applied, EXTENTS.map(|(start, _)| start).to_vec());
    assert!(journal.owed().is_empty());
}

/// Fallible steps first, then one apply, then the acknowledgements.
#[test]
fn settlement_applies_once_after_every_fallible_step_then_acknowledges() {
    struct Ordered<'a> {
        journal: &'a Journal,
    }
    impl OwedReturnRetirement for Ordered<'_> {
        type Prepared = ();
        type Error = ();
        fn prepare(&mut self, request: &ReturnSettlementRequest) -> Result<(), ()> {
            for _ in request.iter() {
                self.journal.log.borrow_mut().push("retire");
            }
            Ok(())
        }
        fn apply(&mut self, (): ()) {
            self.journal.log.borrow_mut().push("apply");
        }
    }
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS);
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    let outcome = settle_owed_returns(
        &excluded,
        &guard,
        &journal,
        &mut Ordered { journal: &journal },
    );
    assert!(matches!(outcome, Ok(SettlementOutcome::Settled(_))));
    assert_eq!(
        *journal.log.borrow(),
        [
            "retire",
            "retire",
            "retire",
            "apply",
            "acknowledge",
            "acknowledge",
            "acknowledge"
        ]
    );
}

/// A settlement whose exclusion names another MM than the journal is
/// stale: no retirement, no acknowledgement, the journal untouched.
#[test]
fn a_stale_settlement_has_no_effect() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS);
    let mut backend = Backend::default();
    assert_eq!(
        settle(&spaces, &lock, MM + 1, &journal, &mut backend),
        Ok(SettlementOutcome::Stale)
    );
    assert!(backend.retirements.is_empty() && backend.applied.is_empty());
    assert!(journal.log.borrow().is_empty());
    assert_eq!(journal.owed(), EXTENTS.to_vec());
}

/// A slot freed and reused by a successor between observation and
/// acknowledgement: the old (slot, epoch) acknowledges nothing, and the
/// successor stays owed (never released, never quarantined).
#[test]
fn a_reused_slot_keeps_its_successor_owed() {
    struct Racing<'a> {
        journal: &'a Journal,
    }
    impl OwedReturnRetirement for Racing<'_> {
        type Prepared = ();
        type Error = ();
        fn prepare(&mut self, _: &ReturnSettlementRequest) -> Result<(), ()> {
            // Another settlement freed slot 0, and a successor extent of the
            // same MM took it over before this one acknowledged.
            let mut slots = self.journal.slots.borrow_mut();
            slots[0] = Slot {
                owner: MM,
                start: 0x50000,
                end: 0x51000,
                epoch: slots[0].epoch + 1,
            };
            Ok(())
        }
        fn apply(&mut self, (): ()) {}
    }
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS[..1]);
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    assert_eq!(
        settle_owed_returns(
            &excluded,
            &guard,
            &journal,
            &mut Racing { journal: &journal }
        ),
        Ok(SettlementOutcome::Settled(ReturnSettlementReceipt {
            freed: 0,
            advanced: 0,
            stale: 1,
        }))
    );
    assert_eq!(journal.owed(), vec![(0x50000, 0x51000)]);
}

/// #1482 L1: a pending fork loan naming the MM skips its settlement: no
/// retirement, no acknowledgement, the returns stay owed, and the doorbell
/// answers `ForkLoanPending` (the ring waits for the loan's PendingEdit
/// release). Once the loan settles the same settlement frees every slot.
#[test]
fn a_pending_fork_loan_skips_ring_owned_settlement_until_it_settles() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS);
    let mut backend = Backend::default();
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    let skipped = settle_ring_owned_returns(&excluded, &guard, true, &journal, &mut backend);
    assert_eq!(
        skipped,
        Ok(SettlementOutcome::Skipped(SkipReason::ForkLoanPending))
    );
    assert_eq!(
        doorbell_reply(&skipped),
        Some(SettlementDoorbellReply::ForkLoanPending)
    );
    assert!(backend.retirements.is_empty() && journal.log.borrow().is_empty());
    assert_eq!(journal.owed(), EXTENTS.to_vec());
    let settled = settle_ring_owned_returns(&excluded, &guard, false, &journal, &mut backend);
    assert_eq!(
        doorbell_reply(&settled),
        Some(SettlementDoorbellReply::Settled)
    );
    assert!(journal.owed().is_empty());
}

/// A busy root answers `Reservations`; a failed backend step answers
/// nothing (the carrier's own fault, never a guest reply).
#[test]
fn doorbell_replies_name_the_release_a_refusal_waits_for() {
    type Outcome =
        Result<SettlementOutcome<ReturnSettlementReceipt>, ReturnSettlementError<Refusal, u64>>;
    let busy: Outcome = Err(ReturnSettlementError::Journal(Refusal::Busy));
    assert_eq!(
        doorbell_reply(&busy),
        Some(SettlementDoorbellReply::Reservations)
    );
    let stale: Outcome = Err(ReturnSettlementError::Journal(Refusal::Stale));
    assert_eq!(doorbell_reply(&stale), Some(SettlementDoorbellReply::Stale));
    let failed: Outcome = Err(ReturnSettlementError::Backend(3));
    assert_eq!(doorbell_reply(&failed), None);
}
