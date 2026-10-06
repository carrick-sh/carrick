use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use carrick_core_abi::{PublicationFrames, PublicationIdentity, PublicationKind};
use carrick_guest_arch::{GuestIsa, UserRange, UserVa};
use core::cell::Cell;
use core::num::NonZeroU64;

const PAGE: u64 = 0x1000;

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).unwrap()
}
fn mm(raw: u64) -> PublicationMm {
    PublicationMm::new(nz(raw))
}
fn inc(raw: u64) -> MmIncarnation {
    MmIncarnation::new(nz(raw))
}
fn seq(raw: u64) -> EditSequence {
    EditSequence::new(nz(raw))
}
fn root(raw: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(raw)).unwrap()
}
fn backing(frame: u64, owner_generation: u64) -> EditBacking {
    EditBacking {
        frame_id: nz(frame),
        mapping_id: nz(frame + 1000),
        owner_generation: nz(owner_generation),
        inventory_revision: nz(1),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Custody {
    Prepared,
    Live { aliases: u32 },
    Released,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    len: u64,
    facts: LedgerExtent,
    custody: Custody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    NotPrepared,
    NoPriorAlias,
}

#[derive(Default)]
struct TestLedger {
    mms: BTreeMap<PublicationMm, (LedgerMm, MmPublicationState)>,
    extents: BTreeMap<u64, Extent>,
    quarantined: bool,
    /// Extent entries examined by lookups, independent of the consumer.
    examined: Cell<usize>,
}

impl TestLedger {
    fn add_mm(&mut self, key: PublicationMm, incarnation: MmIncarnation, root: RootGpa) {
        self.mms.insert(
            key,
            (LedgerMm { incarnation, root }, MmPublicationState::new()),
        );
    }
    fn add_extent(
        &mut self,
        base: u64,
        len: u64,
        owner: PublicationMm,
        owner_incarnation: MmIncarnation,
        backing: EditBacking,
        custody: Custody,
    ) {
        self.extents.insert(
            base,
            Extent {
                len,
                facts: LedgerExtent {
                    owner,
                    owner_incarnation,
                    backing,
                },
                custody,
            },
        );
    }
    fn locate(&self, output: FrameGpa, len: u64) -> Option<u64> {
        let (&base, extent) = self.extents.range(..=output.raw()).next_back()?;
        self.examined.set(self.examined.get() + 1);
        let end = output.raw().checked_add(len)?;
        (end <= base + extent.len).then_some(base)
    }
    fn custody(&self, base: u64) -> Custody {
        self.extents[&base].custody
    }
}

impl PhysicalLedger for TestLedger {
    type Fault = Fault;
    fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    fn quarantine(&mut self, _mm: Option<PublicationMm>) {
        self.quarantined = true;
    }
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm> {
        self.mms.get(&mm).map(|(facts, _)| *facts)
    }
    fn publication_state(&mut self, mm: PublicationMm) -> Option<&mut MmPublicationState> {
        self.mms.get_mut(&mm).map(|(_, state)| state)
    }
    fn extent(&self, output: FrameGpa, len: GuestLen) -> Option<LedgerExtent> {
        let base = self.locate(output, len.raw())?;
        Some(self.extents[&base].facts)
    }
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Fault> {
        let view = record.view();
        let len = view.output_len().raw();
        let prior = match view.prior_output() {
            Some(prior) => Some(self.locate(prior, len).ok_or(Fault::NoPriorAlias)?),
            None => None,
        };
        if let Some(prior) = prior
            && !matches!(self.custody(prior), Custody::Live { aliases } if aliases > 0)
        {
            return Err(Fault::NoPriorAlias);
        }
        let output = match view.output() {
            Some(output) => Some(self.locate(output, len).ok_or(Fault::NotPrepared)?),
            None => None,
        };
        if let Some(prior) = prior
            && let Some(Extent {
                custody: Custody::Live { aliases },
                ..
            }) = self.extents.get_mut(&prior)
        {
            *aliases -= 1;
        }
        if let Some(output) = output {
            let extent = self.extents.get_mut(&output).ok_or(Fault::NotPrepared)?;
            extent.custody = match extent.custody {
                Custody::Prepared => Custody::Live { aliases: 1 },
                Custody::Live { aliases } => Custody::Live {
                    aliases: aliases + 1,
                },
                Custody::Released => return Err(Fault::NotPrepared),
            };
        }
        Ok(())
    }
    fn release_prepared(&mut self, record: &AuthenticatedPublication) -> Result<(), Fault> {
        let view = record.view();
        let output = view.output().ok_or(Fault::NotPrepared)?;
        let base = self
            .locate(output, view.output_len().raw())
            .ok_or(Fault::NotPrepared)?;
        let extent = self.extents.get_mut(&base).ok_or(Fault::NotPrepared)?;
        if extent.custody != Custody::Prepared {
            return Err(Fault::NotPrepared);
        }
        extent.custody = Custody::Released;
        Ok(())
    }
}

struct Edit {
    kind: PublicationKind,
    outcome: PublicationOutcome,
    drain: PublicationDrain,
    mm: PublicationMm,
    incarnation: MmIncarnation,
    sequence: EditSequence,
    root: RootGpa,
    output: Option<(u64, EditBacking)>,
    prior: Option<u64>,
}

impl Edit {
    fn map(mm: PublicationMm, incarnation: MmIncarnation, root: RootGpa, sequence: u64) -> Self {
        Self {
            kind: PublicationKind::Map,
            outcome: PublicationOutcome::Applied,
            drain: PublicationDrain::Global,
            mm,
            incarnation,
            sequence: seq(sequence),
            root,
            output: None,
            prior: None,
        }
    }
    fn output(mut self, base: u64, backing: EditBacking) -> Self {
        self.output = Some((base, backing));
        self
    }
    fn kind(mut self, kind: PublicationKind) -> Self {
        self.kind = kind;
        self
    }
    fn outcome(mut self, outcome: PublicationOutcome) -> Self {
        self.outcome = outcome;
        self
    }
    fn drain(mut self, drain: PublicationDrain) -> Self {
        self.drain = drain;
        self
    }
    fn prior(mut self, prior: u64) -> Self {
        self.prior = Some(prior);
        self
    }
    fn record(&self) -> MmPublication {
        let view = PublicationView::checked(
            self.kind,
            self.outcome,
            self.drain,
            GuestIsa::Aarch64,
            PublicationIdentity {
                mm: self.mm,
                incarnation: self.incarnation,
                edit_sequence: self.sequence,
                root: self.root,
            },
            UserRange::checked(UserVa::new(0x40_0000), GuestLen::new(PAGE)).unwrap(),
            PublicationFrames {
                output: self.output.map(|(base, _)| FrameGpa::new(base)),
                prior_output: self.prior.map(FrameGpa::new),
                backing: self.output.map(|(_, backing)| backing),
            },
        )
        .unwrap();
        MmPublication::encode(&view)
    }
}

const A: u64 = 1;
const B: u64 = 2;
const A_ROOT: u64 = 0x10_0000;
const B_ROOT: u64 = 0x20_0000;
const A_FRAME: u64 = 0x100_0000;
const B_FRAME: u64 = 0x200_0000;

/// Two live MMs, each with one prepared frame.
fn two_mms() -> TestLedger {
    let mut ledger = TestLedger::default();
    ledger.add_mm(mm(A), inc(1), root(A_ROOT));
    ledger.add_mm(mm(B), inc(1), root(B_ROOT));
    ledger.add_extent(
        A_FRAME,
        PAGE,
        mm(A),
        inc(1),
        backing(10, 5),
        Custody::Prepared,
    );
    ledger.add_extent(
        B_FRAME,
        PAGE,
        mm(B),
        inc(1),
        backing(20, 5),
        Custody::Prepared,
    );
    ledger
}

fn a_map(sequence: u64) -> Edit {
    Edit::map(mm(A), inc(1), root(A_ROOT), sequence).output(A_FRAME, backing(10, 5))
}

#[test]
fn two_mms_apply_independently() {
    let mut ledger = two_mms();
    let b = Edit::map(mm(B), inc(1), root(B_ROOT), 1).output(B_FRAME, backing(20, 5));
    let report = consume(&mut ledger, [a_map(1).record(), b.record()]).unwrap();
    assert_eq!((report.applied, report.released), (2, 0));
    assert_eq!(ledger.custody(A_FRAME), Custody::Live { aliases: 1 });
    assert_eq!(ledger.custody(B_FRAME), Custody::Live { aliases: 1 });
    assert!(!ledger.quarantined);
}

#[test]
fn output_owned_by_another_mm_quarantines() {
    let mut ledger = two_mms();
    // MM A names B's frame with B's exact backing identity.
    let edit = Edit::map(mm(A), inc(1), root(A_ROOT), 1).output(B_FRAME, backing(20, 5));
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::ForeignOutput);
    assert_eq!(ledger.custody(B_FRAME), Custody::Prepared);
    assert!(ledger.quarantined);
}

#[test]
fn root_of_another_mm_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::map(mm(A), inc(1), root(B_ROOT), 1).output(A_FRAME, backing(10, 5));
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::RootMismatch);
}

#[test]
fn stale_incarnation_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::map(mm(A), inc(2), root(A_ROOT), 1).output(A_FRAME, backing(10, 5));
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::StaleIncarnation);
    assert_eq!(err.index, 0);
    assert_eq!(ledger.custody(A_FRAME), Custody::Prepared);
}

#[test]
fn stale_owner_generation_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::map(mm(A), inc(1), root(A_ROOT), 1).output(A_FRAME, backing(10, 4));
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::StaleOwnerGeneration);
    assert_eq!(ledger.custody(A_FRAME), Custody::Prepared);
}

#[test]
fn backing_identity_mismatch_quarantines() {
    let mut ledger = two_mms();
    let mut wrong = backing(10, 5);
    wrong.mapping_id = nz(9999);
    let edit = Edit::map(mm(A), inc(1), root(A_ROOT), 1).output(A_FRAME, wrong);
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::BackingMismatch);
}

#[test]
fn recycled_slot_rejects_predecessor_records() {
    let mut ledger = two_mms();
    // Slot A retired and recycled: same key, incarnation 2, same root page
    // and a frame left over from incarnation 1 still in the ledger.
    ledger.add_mm(mm(A), inc(2), root(A_ROOT));
    let old = a_map(1);
    let err = consume(&mut ledger, [old.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::StaleIncarnation);

    // The successor naming the predecessor's frame is foreign, even with the
    // exact backing identity.
    let mut ledger = two_mms();
    ledger.add_mm(mm(A), inc(2), root(A_ROOT));
    let successor = Edit::map(mm(A), inc(2), root(A_ROOT), 1).output(A_FRAME, backing(10, 5));
    let err = consume(&mut ledger, [successor.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::ForeignOutput);
    assert_eq!(ledger.custody(A_FRAME), Custody::Prepared);
}

#[test]
fn edit_sequence_must_increase_per_mm() {
    let mut ledger = two_mms();
    ledger.add_extent(
        A_FRAME + PAGE,
        PAGE,
        mm(A),
        inc(1),
        backing(11, 5),
        Custody::Prepared,
    );
    let second = Edit::map(mm(A), inc(1), root(A_ROOT), 3).output(A_FRAME + PAGE, backing(11, 5));
    // B's sequence space is independent of A's.
    let b = Edit::map(mm(B), inc(1), root(B_ROOT), 1).output(B_FRAME, backing(20, 5));
    consume(&mut ledger, [a_map(3).record(), b.record()]).unwrap();
    let err = consume(&mut ledger, [second.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::SequenceRegression);
    assert_eq!(ledger.custody(A_FRAME + PAGE), Custody::Prepared);
}

#[test]
fn refused_releases_prepared_custody() {
    let mut ledger = two_mms();
    let edit = a_map(1).outcome(PublicationOutcome::Refused);
    let report = consume(&mut ledger, [edit.record()]).unwrap();
    assert_eq!((report.applied, report.released), (0, 1));
    assert_eq!(ledger.custody(A_FRAME), Custody::Released);
}

#[test]
fn rolled_back_releases_prepared_custody() {
    let mut ledger = two_mms();
    let edit = a_map(1).outcome(PublicationOutcome::RolledBack);
    let report = consume(&mut ledger, [edit.record()]).unwrap();
    assert_eq!((report.applied, report.released), (0, 1));
    assert_eq!(ledger.custody(A_FRAME), Custody::Released);
}

#[test]
fn refused_with_stale_owner_cannot_release_custody() {
    let mut ledger = two_mms();
    let edit = Edit::map(mm(A), inc(1), root(A_ROOT), 1)
        .output(A_FRAME, backing(10, 4))
        .outcome(PublicationOutcome::Refused);
    let err = consume(&mut ledger, [edit.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::StaleOwnerGeneration);
    assert_eq!(ledger.custody(A_FRAME), Custody::Prepared);
}

#[test]
fn local_only_blocks_retirement_until_global_drain() {
    let mut ledger = two_mms();
    let edit = a_map(4).drain(PublicationDrain::LocalOnly);
    consume(&mut ledger, [edit.record()]).unwrap();
    assert_eq!(
        retirement_permitted(&mut ledger, mm(A)),
        Err(RetirementBlocked::LocalDrainPending(seq(4)))
    );
    // Unrelated MM is not blocked.
    assert_eq!(retirement_permitted(&mut ledger, mm(B)), Ok(()));
    // A drain that predates the LocalOnly record does not acknowledge it.
    assert_eq!(
        acknowledge_global_drain(&mut ledger, mm(A), seq(3)),
        Err(DrainAckError::StaleAcknowledgement)
    );
    assert!(retirement_permitted(&mut ledger, mm(A)).is_err());
    acknowledge_global_drain(&mut ledger, mm(A), seq(4)).unwrap();
    assert_eq!(retirement_permitted(&mut ledger, mm(A)), Ok(()));
}

#[test]
fn global_record_acknowledges_earlier_local_only() {
    let mut ledger = two_mms();
    consume(
        &mut ledger,
        [a_map(1).drain(PublicationDrain::LocalOnly).record()],
    )
    .unwrap();
    let protect = Edit::map(mm(A), inc(1), root(A_ROOT), 2).kind(PublicationKind::Protect);
    // A refused record made no stores and drains nothing.
    consume(
        &mut ledger,
        [protect
            .outcome(PublicationOutcome::Refused)
            .drain(PublicationDrain::Global)
            .record()],
    )
    .unwrap();
    assert!(retirement_permitted(&mut ledger, mm(A)).is_err());
    let protect = Edit::map(mm(A), inc(1), root(A_ROOT), 3).kind(PublicationKind::Protect);
    consume(&mut ledger, [protect.record()]).unwrap();
    assert_eq!(retirement_permitted(&mut ledger, mm(A)), Ok(()));
}

#[test]
fn quarantine_is_sticky_and_stops_the_batch() {
    let mut ledger = two_mms();
    let bad = Edit::map(mm(A), inc(9), root(A_ROOT), 1).output(A_FRAME, backing(10, 5));
    let b = Edit::map(mm(B), inc(1), root(B_ROOT), 1).output(B_FRAME, backing(20, 5));
    let err = consume(&mut ledger, [bad.record(), b.record()]).unwrap_err();
    assert_eq!((err.index, err.mm), (0, Some(mm(A))));
    assert_eq!(ledger.custody(B_FRAME), Custody::Prepared);
    let err = consume(&mut ledger, [b.record()]).unwrap_err();
    assert_eq!(err.cause, QuarantineCause::AlreadyQuarantined);
    assert_eq!(
        retirement_permitted(&mut ledger, mm(B)),
        Err(RetirementBlocked::Quarantined)
    );
}

#[test]
fn torn_record_quarantines_as_malformed() {
    let mut ledger = two_mms();
    let mut record = a_map(1).record();
    // SAFETY: test-only byte corruption of a plain `repr(C)` Copy record with
    // no padding-sensitive invariants; decode must reject it.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut record as *mut MmPublication).cast::<u8>(),
            MmPublication::SIZE,
        )
    };
    bytes[88] ^= 1;
    let err = consume(&mut ledger, [record]).unwrap_err();
    assert_eq!(
        err.cause,
        QuarantineCause::Malformed(PublicationDecodeError::Digest)
    );
}

#[test]
fn cow_repoint_moves_alias_from_prior_to_output() {
    let mut ledger = two_mms();
    consume(&mut ledger, [a_map(1).record()]).unwrap();
    ledger.add_extent(
        A_FRAME + PAGE,
        PAGE,
        mm(A),
        inc(1),
        backing(11, 5),
        Custody::Prepared,
    );
    let repoint = Edit::map(mm(A), inc(1), root(A_ROOT), 2)
        .kind(PublicationKind::CowRepoint)
        .output(A_FRAME + PAGE, backing(11, 5))
        .prior(A_FRAME);
    consume(&mut ledger, [repoint.record()]).unwrap();
    assert_eq!(ledger.custody(A_FRAME), Custody::Live { aliases: 0 });
    assert_eq!(ledger.custody(A_FRAME + PAGE), Custody::Live { aliases: 1 });
}

/// Adversarial population: many unrelated extents (other MMs and the same
/// MM) must not change how many ledger entries the consumer touches.
fn visits_with_population(unrelated: u64) -> (usize, usize) {
    let mut ledger = two_mms();
    for i in 0..unrelated {
        let base = 0x1000_0000 + i * PAGE;
        let owner = if i % 2 == 0 { mm(B) } else { mm(A) };
        ledger.add_extent(
            base,
            PAGE,
            owner,
            inc(1),
            backing(100 + i, 5),
            Custody::Prepared,
        );
    }
    for i in 0..unrelated / 4 {
        ledger.add_mm(mm(100 + i), inc(1), root(0x4000_0000 + i * PAGE));
    }
    ledger.add_extent(
        A_FRAME + PAGE,
        PAGE,
        mm(A),
        inc(1),
        backing(11, 5),
        Custody::Prepared,
    );
    let records: Vec<MmPublication> = [
        a_map(1).record(),
        Edit::map(mm(A), inc(1), root(A_ROOT), 2)
            .kind(PublicationKind::CowRepoint)
            .output(A_FRAME + PAGE, backing(11, 5))
            .prior(A_FRAME)
            .record(),
        Edit::map(mm(B), inc(1), root(B_ROOT), 1)
            .output(B_FRAME, backing(20, 5))
            .outcome(PublicationOutcome::Refused)
            .record(),
        Edit::map(mm(A), inc(1), root(A_ROOT), 3)
            .kind(PublicationKind::Unmap)
            .prior(A_FRAME + PAGE)
            .record(),
    ]
    .into();
    ledger.examined.set(0);
    let report = consume(&mut ledger, records).unwrap();
    (report.ledger_visits, ledger.examined.get())
}

#[test]
fn visits_bounded_by_records_and_touched_edges() {
    let small = visits_with_population(8);
    let large = visits_with_population(8192);
    assert_eq!(small, large);
    // 4 records: 4 MM lookups + 3 outputs + 2 applied priors.
    assert_eq!(small.0, 9);
}
