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
    settle_owed_returns(&excluded, &guard, SettlementBound::Chunk, journal, backend)
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
            owed_remains: false,
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
        SettlementBound::Chunk,
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
            SettlementBound::Chunk,
            &journal,
            &mut Racing { journal: &journal }
        ),
        Ok(SettlementOutcome::Settled(ReturnSettlementReceipt {
            freed: 0,
            advanced: 0,
            stale: 1,
            owed_remains: false,
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
    let skipped = settle_ring_owned_returns(
        &excluded,
        &CowSettled::for_test(&excluded),
        &guard,
        true,
        &journal,
        &mut backend,
    );
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
    let settled = settle_ring_owned_returns(
        &excluded,
        &CowSettled::for_test(&excluded),
        &guard,
        false,
        &journal,
        &mut backend,
    );
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

/// Records every chunk one exclusion's settlement covered.
#[derive(Default)]
struct Chunks {
    spans: Vec<(u64, u64)>,
    max_pages: u64,
}

impl OwedReturnRetirement for Chunks {
    type Prepared = ();
    type Error = u64;
    fn prepare(&mut self, request: &ReturnSettlementRequest) -> Result<(), u64> {
        let pages = request.iter().map(|owed| owed.range.len() / 4096).sum();
        self.max_pages = self.max_pages.max(pages);
        self.spans.extend(
            request
                .iter()
                .map(|owed| (owed.range.start(), owed.range.end())),
        );
        Ok(())
    }
    fn apply(&mut self, (): ()) {}
}

const GIB_BASE: u64 = 0x1_4000_0000;
const GIB: u64 = 1 << 30;
const CHUNK: u64 = carrick_core_abi::SETTLEMENT_CHUNK_PAGES * 4096;

/// One exclusion: raise it, settle one ring-owned chunk, lower it.
fn one_pause(
    spaces: &carrick_sched_core::AddressSpaces,
    lock: &SettlementLock,
    journal: &Journal,
    backend: &mut Chunks,
) -> PauseSettlement {
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    let outcome = settle_ring_owned_returns(
        &excluded,
        &CowSettled::for_test(&excluded),
        &guard,
        false,
        journal,
        backend,
    );
    pause_settlement(&outcome).unwrap()
}

/// #1482 P0-2: one exclusion settles one chunk of a GiB owed extent and
/// acknowledges exactly that chunk: the slot's cursor moves to the chunk's
/// end and the rest stays owed.
#[test]
fn one_exclusion_settles_and_acknowledges_only_its_chunk() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &[(GIB_BASE, GIB_BASE + GIB)]);
    let mut backend = Chunks::default();
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    assert_eq!(
        settle_ring_owned_returns(
            &excluded,
            &CowSettled::for_test(&excluded),
            &guard,
            false,
            &journal,
            &mut backend
        ),
        Ok(SettlementOutcome::Settled(ReturnSettlementReceipt {
            freed: 0,
            advanced: 1,
            stale: 0,
            owed_remains: true,
        }))
    );
    assert_eq!(backend.spans, [(GIB_BASE, GIB_BASE + CHUNK)]);
    assert_eq!(journal.owed(), [(GIB_BASE + CHUNK, GIB_BASE + GIB)]);
}

/// #1482 P0-2: a doorbell's drive settles a GiB owed extent in 512 bounded
/// exclusions, each of at most 512 pages, each continuing from the cursor
/// the previous one acknowledged (never from the extent's original front),
/// and frees the slot.
#[test]
fn a_gib_extent_settles_one_chunk_per_exclusion_in_one_drive() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &[(GIB_BASE, GIB_BASE + GIB)]);
    let mut backend = Chunks::default();
    let mut pauses = 0u64;
    let reply = settle_in_bounded_pauses::<()>(|| {
        pauses += 1;
        Ok(one_pause(&spaces, &lock, &journal, &mut backend))
    });
    assert_eq!(reply, Ok(SettlementDoorbellReply::Settled));
    assert_eq!(pauses, GIB / CHUNK);
    assert_eq!(backend.max_pages, carrick_core_abi::SETTLEMENT_CHUNK_PAGES);
    let expected: Vec<(u64, u64)> = (0..GIB / CHUNK)
        .map(|chunk| (GIB_BASE + chunk * CHUNK, GIB_BASE + (chunk + 1) * CHUNK))
        .collect();
    assert_eq!(backend.spans, expected, "contiguous chunks from the cursor");
    assert!(journal.owed().is_empty(), "the GiB settled");
}

/// A refused re-raise between chunks ends the drive with that refusal; the
/// chunks already settled stay settled, and the next drive continues from
/// their cursor.
#[test]
fn a_refused_reraise_keeps_the_settled_cursor_for_the_next_drive() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &[(GIB_BASE, GIB_BASE + GIB)]);
    let mut backend = Chunks::default();
    let mut pauses = 0;
    let reply = settle_in_bounded_pauses::<()>(|| {
        pauses += 1;
        if pauses == 3 {
            // A ring editor of the MM took the editor between chunks.
            return Ok(PauseSettlement::answer(SettlementDoorbellReply::Editor));
        }
        Ok(one_pause(&spaces, &lock, &journal, &mut backend))
    });
    assert_eq!(reply, Ok(SettlementDoorbellReply::Editor));
    assert_eq!(journal.owed(), [(GIB_BASE + 2 * CHUNK, GIB_BASE + GIB)]);
    backend.spans.clear();
    assert_eq!(
        one_pause(&spaces, &lock, &journal, &mut backend),
        PauseSettlement {
            reply: SettlementDoorbellReply::Settled,
            owed_remains: true,
        }
    );
    assert_eq!(
        backend.spans,
        [(GIB_BASE + 2 * CHUNK, GIB_BASE + 3 * CHUNK)],
        "the next drive resumes from the cursor"
    );
}

/// A pending fork loan ends the drive at once with its own answer.
#[test]
fn a_skipped_settlement_ends_the_drive() {
    let mut pauses = 0;
    let reply = settle_in_bounded_pauses::<()>(|| {
        pauses += 1;
        Ok(PauseSettlement::answer(
            SettlementDoorbellReply::ForkLoanPending,
        ))
    });
    assert_eq!(reply, Ok(SettlementDoorbellReply::ForkLoanPending));
    assert_eq!(pauses, 1);
}

/// #1482 item 1 ratchet: every exclusion of an MM's EL1 editor settles that
/// MM's owed returns. The carrick-kernel exclusions run the installed
/// settlement hook; the native (ring-owned) carriers call the primitive
/// `try_exclude_editor` directly, and each such production file must settle
/// after it. A new caller of the primitive fails here until it is routed
/// through a settling exclusion (or listed as test-only).
#[test]
fn every_native_exclusion_site_settles_owed_returns() {
    // (file, settlement it runs after the exclusion); `None`: the primitive
    // itself or test-only callers.
    const SITES: &[(&str, Option<&str>)] = &[
        ("carrick-sched-core/src/spaces/notification.rs", None),
        // This ratchet names the primitive it searches for.
        ("carrick-hal/src/return_settlement/tests.rs", None),
        (
            "carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs",
            None,
        ),
        (
            "carrick-el1-linux/src/aarch64_process_tests/native_retirement_tests.rs",
            None,
        ),
        (
            "carrick-x86-cpl0-host/src/cpl0_return_settlement.rs",
            Some("self.settle_excluded("),
        ),
        (
            "carrick-vmm-hvf/src/metadata_grant.rs",
            Some("settle_native_exclusion(custody, exclusion.proof())"),
        ),
        (
            "carrick-vmm-hvf/src/metadata_grant/native_service.rs",
            Some("settle_native_exclusion(&custody, exclusion.proof())"),
        ),
        (
            "carrick-vmm-hvf/src/metadata_grant/return_settlement.rs",
            Some("settle_native_exclusion(custody, exclusion.proof())"),
        ),
    ];
    fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "target") {
                    walk(&path, found);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && std::fs::read_to_string(&path)
                    .is_ok_and(|source| source.contains("try_exclude_editor("))
            {
                found.push(path);
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut found = Vec::new();
    walk(crates, &mut found);
    let mut callers: Vec<String> = found
        .iter()
        .map(|path| {
            path.strip_prefix(crates)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    callers.sort();
    let mut expected: Vec<String> = SITES.iter().map(|(file, _)| (*file).to_owned()).collect();
    expected.sort();
    assert_eq!(
        callers, expected,
        "a new exclusion of an MM's editor must settle its owed returns"
    );
    for (file, settlement) in SITES {
        if let Some(settlement) = settlement {
            let source = std::fs::read_to_string(crates.join(file)).unwrap();
            let exclusion = source.find("try_exclude_editor(").unwrap();
            assert!(
                source[exclusion..].contains(settlement),
                "{file} excludes an editor without settling owed returns after it"
            );
        }
    }
}

/// A recording drain venue for [`drain_owed_return_table`]: a shared table of
/// `capacity` slots, each holder's slot count, and each holder's editor (a
/// held editor refuses the holder's settlement, as `try_exclude_editor`
/// does, and its release advances the holder's `Editor` revision).
struct TableDrain {
    capacity: usize,
    slots: Vec<(ReservationMm, usize)>,
    held: Vec<ReservationMm>,
    editor_revision: std::collections::BTreeMap<u64, u64>,
    attempts: Vec<ReservationMm>,
}

impl TableDrain {
    fn full(holders: &[u64]) -> Self {
        Self {
            capacity: holders.len() * 2,
            slots: holders
                .iter()
                .map(|&mm| (ReservationMm::new(mm).unwrap(), 2))
                .collect(),
            held: Vec::new(),
            editor_revision: holders.iter().map(|&mm| (mm, 10 + mm)).collect(),
            attempts: Vec::new(),
        }
    }
    fn hold(&mut self, mm: u64) {
        self.held.push(ReservationMm::new(mm).unwrap());
    }
    /// The holder's editor leaves: its exact `Editor` release.
    fn release(&mut self, mm: u64) {
        self.held.retain(|held| held.raw() != mm);
        *self.editor_revision.get_mut(&mm).unwrap() += 1;
    }
    fn holders(&self) -> Vec<ReservationMm> {
        self.slots.iter().map(|&(mm, _)| mm).collect()
    }
}

impl OwedReturnDrain for TableDrain {
    type Error = ();
    fn table_full(&self) -> bool {
        self.slots.iter().map(|&(_, n)| n).sum::<usize>() >= self.capacity
    }
    fn observe(&mut self, holder: ReservationMm) -> Option<HolderRevisions> {
        let editor = *self.editor_revision.get(&holder.raw())?;
        Some(HolderRevisions {
            editor,
            reservations: 0,
            pending_edit: 0,
        })
    }
    fn settle(&mut self, holder: ReservationMm) -> Result<SettlementDoorbellReply, ()> {
        self.attempts.push(holder);
        if self.held.contains(&holder) {
            return Ok(SettlementDoorbellReply::Editor);
        }
        if let Some(entry) = self.slots.iter_mut().find(|(mm, _)| *mm == holder) {
            entry.1 = 0;
        }
        Ok(SettlementDoorbellReply::Settled)
    }
}

/// #1482 P0-1, Busy once, then success: a full table whose every holder's
/// editor is held answers the oldest holder's wait authority (its exact MM,
/// release and the revision before the refused attempt), not a rerun. After
/// that holder's release the same drain frees a slot.
#[test]
fn a_full_table_waits_on_its_oldest_busy_holder_then_drains_after_its_release() {
    let mut drain = TableDrain::full(&[5, 3, 9]);
    for mm in [5, 3, 9] {
        drain.hold(mm);
    }
    let holders = drain.holders();
    let refused = drain_owed_return_table(&mut drain, &holders).unwrap();
    let DrainOutcome::Wait(wait) = refused else {
        panic!("every holder busy: wait on one, never rerun ({refused:?})");
    };
    assert_eq!(wait.mm().raw(), 5, "the oldest holder, in the order given");
    assert_eq!(wait.refusal(), carrick_core_abi::HolderRefusal::Editor);
    assert_eq!(wait.revision(), 15, "the revision read before the attempt");
    assert!(drain.table_full(), "nothing was freed");
    assert_eq!(drain.attempts.len(), 3, "every holder was tried once");

    // The holder's release advances exactly the revision the waiter holds.
    drain.release(5);
    assert_ne!(
        drain.observe(wait.mm()).unwrap().of(wait.refusal()),
        wait.revision()
    );
    drain.attempts.clear();
    assert_eq!(
        drain_owed_return_table(&mut drain, &holders).unwrap(),
        DrainOutcome::Room
    );
    assert_eq!(
        drain.attempts,
        [ReservationMm::new(5).unwrap()],
        "one holder freed room"
    );
    assert!(!drain.table_full());
}

/// A busy holder is skipped, not waited on, when a younger holder frees a
/// slot; a table with room is never drained.
#[test]
fn a_drain_waits_only_when_no_holder_frees_a_slot() {
    let mut drain = TableDrain::full(&[5, 3]);
    drain.hold(5);
    let holders = drain.holders();
    assert_eq!(
        drain_owed_return_table(&mut drain, &holders).unwrap(),
        DrainOutcome::Room
    );
    assert_eq!(drain.attempts.len(), 2);
    drain.attempts.clear();
    assert_eq!(
        drain_owed_return_table(&mut drain, &holders).unwrap(),
        DrainOutcome::Room
    );
    assert!(drain.attempts.is_empty(), "room: no holder is touched");
}

/// Holders with no live source are retiring: no wait authority exists, and
/// the drain says so instead of naming a source.
#[test]
fn a_table_of_retiring_holders_has_no_wait_authority() {
    let mut drain = TableDrain::full(&[5]);
    drain.editor_revision.clear();
    drain.hold(5);
    let holders = drain.holders();
    assert_eq!(
        drain_owed_return_table(&mut drain, &holders).unwrap(),
        DrainOutcome::Retiring
    );
}

/// A venue recording the order of its two settlements.
#[derive(Default)]
struct Ordered {
    steps: Vec<&'static str>,
    cow_fails: bool,
}

impl ExclusionSettlement for Ordered {
    type Error = &'static str;
    type Returns = u64;
    fn settle_cow_completions(
        &mut self,
        _: &carrick_sched_core::ExcludedEditor<'_>,
    ) -> Result<(), &'static str> {
        self.steps.push("cow");
        if self.cow_fails {
            return Err("cow");
        }
        Ok(())
    }
    fn settle_owed_returns(
        &mut self,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
        cow: &CowSettled<'_>,
    ) -> Result<u64, &'static str> {
        self.steps.push("returns");
        assert_eq!(cow.mm(), excluded.key());
        Ok(cow.mm())
    }
}

/// #1482 P0-3: the one sequence settles the excluded MM's COW completions
/// before its owed returns, and a failed COW step settles no return.
#[test]
fn an_exclusion_settles_cow_completions_before_owed_returns() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let excluded = spaces.unpublished(MM).unwrap();
    let mut venue = Ordered::default();
    assert_eq!(settle_cow_then_returns(&mut venue, &excluded), Ok(MM));
    assert_eq!(venue.steps, ["cow", "returns"]);
    let mut failed = Ordered {
        cow_fails: true,
        ..Ordered::default()
    };
    assert_eq!(settle_cow_then_returns(&mut failed, &excluded), Err("cow"));
    assert_eq!(failed.steps, ["cow"]);
}

/// #1482 P0-3: a COW proof minted under another MM's exclusion settles
/// nothing: no retirement, no acknowledgement.
#[test]
fn a_cow_proof_for_another_mm_settles_no_return() {
    let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
    let lock = SettlementLock::new();
    let journal = Journal::owing(MM, &EXTENTS);
    let mut backend = Backend::default();
    let other = spaces.unpublished(MM + 1).unwrap();
    let cow = CowSettled::for_test(&other);
    drop(other);
    let excluded = spaces.unpublished(MM).unwrap();
    let guard = lock.lock(&excluded);
    assert_eq!(
        settle_ring_owned_returns(&excluded, &cow, &guard, false, &journal, &mut backend),
        Ok(SettlementOutcome::Stale)
    );
    assert!(backend.retirements.is_empty() && journal.log.borrow().is_empty());
    assert_eq!(journal.owed(), EXTENTS.to_vec());
}
