use super::*;
use carrick_core_abi::{
    EditSequence, PublicationIdentity, PublicationShape, PublishedOutput, PublishedPrior,
};
use carrick_guest_arch::{FrameGpa, UserRange};
use core::cell::Cell;

const PAGE: u64 = 0x1000;
const A: u64 = 1;
const B: u64 = 2;
const A_ROOT: u64 = 0x10_0000;
const B_ROOT: u64 = 0x20_0000;
const A_FRAME: u64 = 0x100_0000;
const B_FRAME: u64 = 0x200_0000;
const EXTENT: u64 = 1024 * PAGE;
const VA: u64 = 0x40_0000;
const GEN: u64 = 5;

const RW: EditPermissions = EditPermissions {
    readable: true,
    writable: true,
    executable: false,
    user: true,
};
const RO: EditPermissions = EditPermissions {
    readable: true,
    writable: false,
    executable: false,
    user: true,
};

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).unwrap()
}
fn key(mm: u64, incarnation: u64) -> MmIncarnationKey {
    MmIncarnationKey {
        mm: PublicationMm::new(nz(mm)),
        incarnation: MmIncarnation::new(nz(incarnation)),
    }
}
fn counter(raw: u64) -> PublicationCounter {
    PublicationCounter::new(nz(raw))
}
fn root(raw: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(raw)).unwrap()
}
fn owner_gen(raw: u64) -> OwnerGeneration {
    OwnerGeneration::new(nz(raw))
}
fn ring(raw: u64) -> RingId {
    RingId(nz(raw))
}
fn ipa(raw: u64) -> Stage1Ipa {
    Stage1Ipa::new(raw)
}
fn len(raw: u64) -> GuestLen {
    GuestLen::new(raw)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {}

#[derive(Default)]
struct TestLedger {
    book: PublicationBook,
    mms: BTreeMap<PublicationMm, LedgerMm>,
    extents: BTreeMap<u64, (u64, ExtentCustody)>,
    released: Vec<(MmIncarnationKey, DeferredRelease)>,
    tables: u64,
    /// Ledger entries examined by lookups, independent of the consumer.
    examined: Cell<usize>,
}

impl TestLedger {
    fn add_mm(&mut self, key: MmIncarnationKey, root: RootGpa, isa: GuestIsa) {
        self.mms.insert(
            key.mm,
            LedgerMm {
                incarnation: key.incarnation,
                root,
                isa,
            },
        );
        self.book.register_mm(key);
    }
    fn add_extent(&mut self, base: u64, bytes: u64, owner: MmIncarnationKey) {
        self.extents
            .insert(base, (bytes, ExtentCustody::new(owner, owner_gen(GEN))));
    }
    fn custody_at(&mut self, base: u64) -> &mut ExtentCustody {
        &mut self.extents.get_mut(&base).unwrap().1
    }
    fn share(&mut self, base: u64, to: MmIncarnationKey) -> EdgeGeneration {
        // SAFETY: the test plays the host share path.
        unsafe { self.custody_at(base).mint_shared_edge(to) }.unwrap()
    }
    fn begin_cow(&self, base: u64) -> Result<CowTransition, CowBlocked> {
        self.book.begin_cow(ipa(base), len(self.extents[&base].0))
    }
    fn cow_share(&mut self, base: u64, to: MmIncarnationKey) -> Result<EdgeGeneration, CowBlocked> {
        let proof = self.begin_cow(base)?;
        let custody = &mut self.extents.get_mut(&base).unwrap().1;
        // SAFETY: the test plays fork custody for exactly this extent.
        unsafe { self.book.mint_cow_edge(custody, to, proof) }
    }
    fn issue_spec(
        &mut self,
        mm: MmIncarnationKey,
        output: u64,
        bytes: u64,
        access: ExtentAccess,
        max_permissions: EditPermissions,
    ) -> Result<PublishedOutput, AdmissionBlocked> {
        let spec = AdmissionTicket {
            output: ipa(output),
            leaf: EditLeafSize::Page,
            len: len(bytes),
            owner_generation: owner_gen(GEN),
            access,
            inventory_revision: InventoryRevision::new(nz(1)),
            max_permissions,
            table_grants: TableGrantCount(2),
        };
        let slot = self.book.admission_permitted(mm)?;
        let ticket = self.book.issue_ticket(slot, spec)?;
        Ok(PublishedOutput {
            address: spec.output,
            leaf: spec.leaf,
            ticket,
            owner_generation: spec.owner_generation,
            access,
            inventory_revision: spec.inventory_revision,
        })
    }
    fn issue(
        &mut self,
        mm: MmIncarnationKey,
        output: u64,
        access: ExtentAccess,
    ) -> PublishedOutput {
        self.issue_spec(mm, output, PAGE, access, RW).unwrap()
    }
    /// A live alias published earlier at `va`.
    fn add_alias(
        &mut self,
        mm: MmIncarnationKey,
        va: u64,
        frame: u64,
        access: ExtentAccess,
        permissions: EditPermissions,
    ) {
        let generation = AliasGeneration(nz(self.book.seq().unwrap()));
        new_alias(
            &mut self.book,
            mm,
            UserVa::new(va),
            Alias {
                frame: ipa(frame),
                len: len(PAGE),
                leaf: EditLeafSize::Page,
                owner_generation: owner_gen(GEN),
                access,
                permissions,
                ceiling: RW,
                present: true,
                generation,
                use_seq: 0,
            },
        )
        .unwrap();
    }
    fn state(&self, mm: MmIncarnationKey) -> &MmPublicationState {
        self.book.state(mm).unwrap()
    }
    fn quarantined(&self, mm: MmIncarnationKey) -> bool {
        self.book.quarantined(mm)
    }
    fn reusable(&self, frame: u64) -> bool {
        self.book.frame_reusable(ipa(frame), len(PAGE))
    }
}

impl PhysicalLedger for TestLedger {
    type Fault = Fault;
    fn book(&self) -> &PublicationBook {
        &self.book
    }
    fn book_mut(&mut self) -> &mut PublicationBook {
        &mut self.book
    }
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm> {
        self.mms.get(&mm).copied()
    }
    fn custody(&self, address: Stage1Ipa, bytes: GuestLen) -> Option<&ExtentCustody> {
        let (&base, (extent, custody)) = self.extents.range(..=address.raw()).next_back()?;
        self.examined.set(self.examined.get() + 1);
        (address.raw().checked_add(bytes.raw())? <= base + extent).then_some(custody)
    }
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Fault> {
        self.tables += u64::from(record.view().table_grants().0);
        Ok(())
    }
    fn release(&mut self, mm: MmIncarnationKey, release: DeferredRelease) -> Result<(), Fault> {
        self.released.push((mm, release));
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Edit {
    shape: PublicationShape,
    mm: MmIncarnationKey,
    counter: u64,
    root: RootGpa,
    va: u64,
    bytes: u64,
    output: Option<PublishedOutput>,
    prior: Option<PublishedPrior>,
}

impl Edit {
    fn new(mm: MmIncarnationKey, counter: u64, root_raw: u64) -> Self {
        Self {
            shape: PublicationShape {
                kind: PublicationKind::Map,
                outcome: PublicationOutcome::Applied,
                drain: PublicationDrain::ArmBroadcastAsid,
                isa: GuestIsa::Aarch64,
                permissions: RW,
                table_grants: TableGrantCount(0),
            },
            mm,
            counter,
            root: root(root_raw),
            va: VA,
            bytes: PAGE,
            output: None,
            prior: None,
        }
    }
    fn a(counter: u64) -> Self {
        Self::new(key(A, 1), counter, A_ROOT)
    }
    fn b(counter: u64) -> Self {
        Self::new(key(B, 1), counter, B_ROOT)
    }
    fn output(mut self, output: PublishedOutput) -> Self {
        self.output = Some(output);
        self
    }
    fn prior(mut self, address: u64) -> Self {
        self.prior = Some(PublishedPrior {
            address: ipa(address),
            leaf: EditLeafSize::Page,
            owner_generation: owner_gen(GEN),
        });
        self
    }
    fn kind(mut self, kind: PublicationKind) -> Self {
        self.shape.kind = kind;
        self
    }
    fn outcome(mut self, outcome: PublicationOutcome) -> Self {
        self.shape.outcome = outcome;
        if outcome == PublicationOutcome::Refused {
            self.shape.drain = PublicationDrain::Local;
        }
        self
    }
    fn drain(mut self, isa: GuestIsa, drain: PublicationDrain) -> Self {
        self.shape.isa = isa;
        self.shape.drain = drain;
        self
    }
    fn local(self) -> Self {
        self.drain(GuestIsa::Aarch64, PublicationDrain::Local)
    }
    fn permissions(mut self, permissions: EditPermissions) -> Self {
        self.shape.permissions = permissions;
        self
    }
    fn grants(mut self, grants: u8) -> Self {
        self.shape.table_grants = TableGrantCount(grants);
        self
    }
    fn at(mut self, va: u64) -> Self {
        self.va = va;
        self
    }
    fn bytes(mut self, bytes: u64) -> Self {
        self.bytes = bytes;
        self
    }
    fn unmap(counter: u64, frame: u64) -> Self {
        Self::a(counter)
            .kind(PublicationKind::Unmap)
            .prior(frame)
            .permissions(RO)
    }
    fn protect(counter: u64, frame: u64, permissions: EditPermissions) -> Self {
        Self::a(counter)
            .kind(PublicationKind::Protect)
            .prior(frame)
            .permissions(permissions)
    }
    fn view(&self) -> Result<PublicationView, PublicationDecodeError> {
        PublicationView::checked(
            self.shape,
            PublicationIdentity {
                mm: self.mm.mm,
                incarnation: self.mm.incarnation,
                counter: counter(self.counter),
                edit_sequence: EditSequence::new(nz(self.counter + 1000)),
                root: self.root,
            },
            UserRange::checked(UserVa::new(self.va), len(self.bytes)).unwrap(),
            self.output,
            self.prior,
        )
    }
    fn record(&self) -> MmPublication {
        MmPublication::encode(&self.view().unwrap())
    }
}

/// Two live ARM MMs, each owning one extent; A also has an RO alias of its
/// first frame at `VA` when `with_alias`.
fn two_mms() -> TestLedger {
    let mut ledger = TestLedger::default();
    ledger.add_mm(key(A, 1), root(A_ROOT), GuestIsa::Aarch64);
    ledger.add_mm(key(B, 1), root(B_ROOT), GuestIsa::Aarch64);
    ledger.add_extent(A_FRAME, EXTENT, key(A, 1));
    ledger.add_extent(B_FRAME, EXTENT, key(B, 1));
    ledger
}

/// Each edit travels on its own MM's ring.
fn consume_edits(
    ledger: &mut TestLedger,
    edits: &[Edit],
    published: &[(MmIncarnationKey, PublicationCounter)],
) -> ConsumeReport<Fault> {
    let mut by_mm: BTreeMap<MmIncarnationKey, Vec<MmPublication>> = BTreeMap::new();
    for edit in edits {
        by_mm.entry(edit.mm).or_default().push(edit.record());
    }
    let batches: Vec<RingBatch<'_>> = by_mm
        .iter()
        .map(|(mm, records)| RingBatch {
            ring: ring(mm.mm.raw().get()),
            bound: *mm,
            records,
        })
        .collect();
    consume(ledger, &batches, published)
}

fn run(ledger: &mut TestLedger, edits: &[Edit]) -> ConsumeReport<Fault> {
    consume_edits(ledger, edits, &[])
}

fn only_cause(report: &ConsumeReport<Fault>) -> QuarantineCause<Fault> {
    assert_eq!(report.quarantined.len(), 1, "{report:?}");
    report.quarantined[0].cause
}

fn a_map(ledger: &mut TestLedger, counter: u64, frame: u64) -> Edit {
    let out = ledger.issue(key(A, 1), frame, ExtentAccess::Owner);
    Edit::a(counter).output(out)
}

fn clean(report: &ConsumeReport<Fault>) {
    assert!(report.quarantined.is_empty(), "{report:?}");
}

// Round 4: aliases keyed by (mm, incarnation, VA).

#[test]
fn same_frame_at_two_vas_keeps_both_aliases() {
    let mut ledger = two_mms();
    let x = a_map(&mut ledger, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let y = Edit::a(2).output(out).at(VA + 0x10_0000);
    let report = run(&mut ledger, &[x, y]);
    clean(&report);
    assert_eq!(report.applied, 2);
    assert_eq!(ledger.book.alias_count(), 2);
    let report = run(&mut ledger, &[Edit::unmap(3, A_FRAME)]);
    clean(&report);
    // The alias at Y still maps F: F is neither released for reuse nor
    // forgotten.
    assert!(
        ledger
            .book
            .alias(key(A, 1), UserVa::new(VA + 0x10_0000))
            .is_some()
    );
    assert!(!ledger.reusable(A_FRAME));
    run(&mut ledger, &[Edit::unmap(4, A_FRAME).at(VA + 0x10_0000)]);
    assert!(ledger.reusable(A_FRAME));
}

#[test]
fn fresh_map_over_a_live_alias_quarantines() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let map = a_map(&mut ledger, 1, A_FRAME + PAGE);
    assert_eq!(
        only_cause(&run(&mut ledger, &[map])),
        QuarantineCause::VaOccupied
    );
}

#[test]
fn multi_leaf_map_is_one_alias_removed_by_one_unmap() {
    let mut ledger = two_mms();
    let out = ledger
        .issue_spec(key(A, 1), A_FRAME, 2 * PAGE, ExtentAccess::Owner, RW)
        .unwrap();
    let map = Edit::a(1).output(out).bytes(2 * PAGE);
    let unmap = Edit::unmap(2, A_FRAME).bytes(2 * PAGE);
    let report = run(&mut ledger, &[map, unmap]);
    clean(&report);
    assert_eq!(report.applied, 2);
    assert_eq!(ledger.book.alias_count(), 0);
    assert!(ledger.book.frame_reusable(ipa(A_FRAME), len(2 * PAGE)));
}

#[test]
fn prior_must_name_the_alias_at_its_va() {
    // Another MM's frame named at a VA where this MM has a different alias.
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::unmap(1, B_FRAME)])),
        QuarantineCause::PriorFrameMismatch
    );
    assert!(ledger.book.alias(key(B, 1), UserVa::new(VA)).is_some());
    assert!(ledger.released.is_empty());

    // No alias of this MM at that VA.
    let mut ledger = two_mms();
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let repoint = Edit::unmap(1, B_FRAME)
        .kind(PublicationKind::CowRepoint)
        .output(out);
    assert_eq!(
        only_cause(&run(&mut ledger, &[repoint])),
        QuarantineCause::NoPriorAlias
    );

    // The span must be the alias's whole span.
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    assert_eq!(
        only_cause(&run(
            &mut ledger,
            &[Edit::unmap(1, A_FRAME).bytes(2 * PAGE)]
        )),
        QuarantineCause::SpanMismatch
    );
}

#[test]
fn prior_generation_must_match() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger
        .book
        .aliases
        .get_mut(&(key(A, 1), VA))
        .unwrap()
        .owner_generation = owner_gen(GEN + 1);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::unmap(1, A_FRAME)])),
        QuarantineCause::StalePriorGeneration
    );
}

// Round 4: writable reachability is derived.

#[test]
fn rolled_back_protect_to_rw_blocks_cow_until_drained() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    assert!(ledger.begin_cow(A_FRAME).is_ok());
    let rolled = Edit::protect(1, A_FRAME, RW)
        .outcome(PublicationOutcome::RolledBack)
        .local();
    clean(&run(&mut ledger, &[rolled]));
    assert_eq!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::PendingWritable(key(A, 1), counter(1)))
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)).unwrap();
    assert!(ledger.begin_cow(A_FRAME).is_ok());
}

#[test]
fn writable_alias_needs_a_named_drained_downgrade_before_cow() {
    let mut ledger = two_mms();
    let map = a_map(&mut ledger, 1, A_FRAME);
    run(&mut ledger, &[map]);
    assert_eq!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::WritableAlias(key(A, 1), UserVa::new(VA)))
    );
    // A priorless downgrade or COW arming cannot even be expressed.
    for kind in [PublicationKind::Protect, PublicationKind::ArmCow] {
        let priorless = Edit::a(2).kind(kind).permissions(RO);
        assert_eq!(priorless.view(), Err(PublicationDecodeError::Prior));
    }
    assert!(ledger.begin_cow(A_FRAME).is_err());
    // The named downgrade with a Local drain still leaves a possibly-cached
    // writable translation.
    run(&mut ledger, &[Edit::protect(2, A_FRAME, RO).local()]);
    assert_eq!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::PendingWritable(key(A, 1), counter(2)))
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert!(ledger.cow_share(A_FRAME, key(B, 1)).is_ok());
}

#[test]
fn outstanding_writable_ticket_blocks_cow() {
    let mut ledger = two_mms();
    ledger
        .issue_spec(key(A, 1), A_FRAME, PAGE, ExtentAccess::Owner, RO)
        .unwrap();
    assert!(ledger.begin_cow(A_FRAME).is_ok());
    let out = ledger.issue(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner);
    assert_eq!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::WritableTicket(key(A, 1), out.ticket))
    );
}

#[test]
fn cow_proof_is_rederived_at_mint() {
    let mut ledger = two_mms();
    let proof = ledger.begin_cow(A_FRAME).unwrap();
    ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let custody = &mut ledger.extents.get_mut(&A_FRAME).unwrap().1;
    // SAFETY: the test plays fork custody for exactly this extent.
    let minted = unsafe { ledger.book.mint_cow_edge(custody, key(B, 1), proof) };
    assert!(matches!(minted, Err(CowBlocked::WritableTicket(..))));
}

// Round 4: settlements reference the alias, and frames wait for them.

#[test]
fn release_waits_behind_earlier_settlements_of_the_alias() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RW);
    let downgrade = Edit::protect(1, A_FRAME, RO).local();
    let unmap =
        Edit::unmap(2, A_FRAME).drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    clean(&run(&mut ledger, &[downgrade, unmap]));
    // The frame is neither released nor reusable by B: the downgrade's
    // possibly-cached writable translation still names it.
    assert!(ledger.released.is_empty());
    assert!(!ledger.reusable(A_FRAME));
    assert!(ledger.begin_cow(A_FRAME).is_err());
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)),
        Ok(1)
    );
    assert!(matches!(
        ledger.released[..],
        [(_, DeferredRelease::Prior { frame, .. })] if frame == ipa(A_FRAME)
    ));
    assert!(ledger.reusable(A_FRAME));
}

#[test]
fn x86_producer_cannot_settle_debt_with_an_arm_claim() {
    let mut ledger = two_mms();
    ledger.mms.get_mut(&key(A, 1).mm).unwrap().isa = GuestIsa::X86_64;
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(
        key(A, 1),
        VA + PAGE,
        A_FRAME + PAGE,
        ExtentAccess::Owner,
        RO,
    );
    let unmap = Edit::unmap(1, A_FRAME).drain(GuestIsa::X86_64, PublicationDrain::Local);
    let forged = Edit::protect(2, A_FRAME + PAGE, RO)
        .at(VA + PAGE)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastAsid);
    let report = run(&mut ledger, &[unmap, forged]);
    assert_eq!(only_cause(&report), QuarantineCause::IsaMismatch);
    assert!(ledger.released.is_empty(), "frame freed under x86 debt");
}

#[test]
fn x86_shootdown_claim_never_clears_debt() {
    let mut ledger = two_mms();
    ledger.mms.get_mut(&key(A, 1).mm).unwrap().isa = GuestIsa::X86_64;
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(
        key(A, 1),
        VA + PAGE,
        A_FRAME + PAGE,
        ExtentAccess::Owner,
        RO,
    );
    let local = Edit::unmap(1, A_FRAME).drain(GuestIsa::X86_64, PublicationDrain::Local);
    let claim = Edit::protect(2, A_FRAME + PAGE, RO)
        .at(VA + PAGE)
        .drain(GuestIsa::X86_64, PublicationDrain::X86ShootdownClaim);
    clean(&run(&mut ledger, &[local, claim]));
    assert!(ledger.released.is_empty());
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(3)),
        Err(DrainAckError::Unconsumed)
    );
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)),
        Ok(1)
    );
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(2))
    );
}

#[test]
fn arm_span_broadcast_does_not_clear_other_spans() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(
        key(A, 1),
        VA + PAGE,
        A_FRAME + PAGE,
        ExtentAccess::Owner,
        RO,
    );
    let local = Edit::unmap(1, A_FRAME).local();
    let span = Edit::unmap(2, A_FRAME + PAGE)
        .at(VA + PAGE)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    clean(&run(&mut ledger, &[local, span]));
    assert!(matches!(
        ledger.released[..],
        [(_, DeferredRelease::Prior { frame, .. })] if frame == ipa(A_FRAME + PAGE)
    ));
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(1))
    );
    ledger.add_alias(
        key(A, 1),
        VA + 2 * PAGE,
        A_FRAME + 2 * PAGE,
        ExtentAccess::Owner,
        RO,
    );
    run(
        &mut ledger,
        &[Edit::protect(3, A_FRAME + 2 * PAGE, RO).at(VA + 2 * PAGE)],
    );
    assert_eq!(ledger.released.len(), 2);
    assert_eq!(ledger.state(key(A, 1)).oldest_drain_debt(), None);
}

#[test]
fn cow_repoint_moves_alias_and_holds_prior_until_drain() {
    let mut ledger = two_mms();
    let map = a_map(&mut ledger, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner);
    let repoint = Edit::unmap(2, A_FRAME)
        .kind(PublicationKind::CowRepoint)
        .output(out)
        .local();
    clean(&run(&mut ledger, &[map, repoint]));
    let alias = ledger.book.alias(key(A, 1), UserVa::new(VA)).unwrap();
    assert_eq!(alias.frame, ipa(A_FRAME + PAGE));
    assert!(ledger.released.is_empty());
    assert!(matches!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::PendingWritable(..))
    ));
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(ledger.released.len(), 1);
    assert!(ledger.reusable(A_FRAME));
}

// Round 4: admission is a reservation; all held settlements count.

#[test]
fn rolled_back_tickets_are_bounded_by_admission() {
    let mut ledger = two_mms();
    let mut outs = Vec::new();
    for i in 0..MAX_HELD_PER_MM as u64 {
        outs.push(
            ledger
                .issue_spec(key(A, 1), A_FRAME + i * PAGE, PAGE, ExtentAccess::Owner, RW)
                .unwrap(),
        );
    }
    // The 257th admission is refused.
    assert_eq!(
        ledger.book.admission_permitted(key(A, 1)),
        Err(AdmissionBlocked::Backpressure)
    );
    let rolled: Vec<Edit> = outs
        .iter()
        .enumerate()
        .map(|(i, out)| {
            Edit::a(i as u64 + 1)
                .output(*out)
                .at(VA + i as u64 * PAGE)
                .outcome(PublicationOutcome::RolledBack)
                .local()
        })
        .collect();
    clean(&run(&mut ledger, &rolled));
    assert_eq!(ledger.state(key(A, 1)).held_settlements(), MAX_HELD_PER_MM);
    assert_eq!(
        ledger.book.admission_permitted(key(A, 1)),
        Err(AdmissionBlocked::Backpressure)
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(MAX_HELD_PER_MM as u64)).unwrap();
    assert!(ledger.book.admission_permitted(key(A, 1)).is_ok());
}

#[test]
fn untracked_held_settlements_backpressure_the_producer() {
    let mut ledger = two_mms();
    let total = MAX_HELD_PER_MM as u64 + 10;
    let mut unmaps = Vec::new();
    for i in 0..total {
        ledger.add_alias(
            key(A, 1),
            VA + i * PAGE,
            A_FRAME + i * PAGE,
            ExtentAccess::Owner,
            RO,
        );
        unmaps.push(
            Edit::unmap(i + 1, A_FRAME + i * PAGE)
                .at(VA + i * PAGE)
                .local(),
        );
    }
    let report = consume_edits(&mut ledger, &unmaps, &[(key(A, 1), counter(total))]);
    clean(&report);
    assert_eq!(
        (report.applied, report.backpressured),
        (MAX_HELD_PER_MM, 10)
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(MAX_HELD_PER_MM as u64)).unwrap();
    let report = consume(
        &mut ledger,
        &[RingBatch {
            ring: ring(A),
            bound: key(A, 1),
            records: &[],
        }],
        &[(key(A, 1), counter(total))],
    );
    clean(&report);
    assert_eq!(report.applied, 10);
}

#[test]
fn debt_without_custody_is_compacted() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let edits: Vec<Edit> = (1..=1000)
        .map(|c| Edit::protect(c, A_FRAME, RO).local())
        .collect();
    clean(&run(&mut ledger, &edits));
    let state = ledger.state(key(A, 1));
    assert_eq!(state.held_settlements(), 0);
    assert_eq!(state.oldest_drain_debt(), Some(counter(1)));
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(999)).unwrap();
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(1000))
    );
}

#[test]
fn retirement_requires_the_host_barrier() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    assert_eq!(
        retirement_permitted(&ledger.book, key(A, 1)),
        Err(RetirementBlocked::AdmissionOpen)
    );
    close_admission(&mut ledger.book, key(A, 1), Some(counter(2))).unwrap();
    assert_eq!(
        ledger.book.admission_permitted(key(A, 1)),
        Err(AdmissionBlocked::Closed)
    );
    assert_eq!(
        retirement_permitted(&ledger.book, key(A, 1)),
        Err(RetirementBlocked::OpenTickets(1))
    );
    run(&mut ledger, &[Edit::a(1).output(out).local()]);
    assert_eq!(
        retirement_permitted(&ledger.book, key(A, 1)),
        Err(RetirementBlocked::UnconsumedRecords)
    );
    run(&mut ledger, &[Edit::protect(2, A_FRAME, RO).local()]);
    assert_eq!(
        retirement_permitted(&ledger.book, key(A, 1)),
        Err(RetirementBlocked::DrainDebt(counter(1)))
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(retirement_permitted(&ledger.book, key(A, 1)), Ok(()));
}

// Producer attribution.

#[test]
fn forged_identity_quarantines_producer_not_victim() {
    let mut ledger = two_mms();
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    let b = Edit::protect(1, B_FRAME, RO);
    let b = Edit {
        mm: key(B, 1),
        root: root(B_ROOT),
        ..b
    };
    run(&mut ledger, &[b]);
    let forged = [b.record()];
    let report = consume(
        &mut ledger,
        &[RingBatch {
            ring: ring(1),
            bound: key(A, 1),
            records: &forged,
        }],
        &[],
    );
    assert_eq!(only_cause(&report), QuarantineCause::ProducerMismatch);
    assert_eq!(report.quarantined[0].mm, key(A, 1));
    assert!(!ledger.quarantined(key(B, 1)));
}

#[test]
fn malformed_record_quarantines_only_its_producer() {
    let mut ledger = two_mms();
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    let mut record = Edit::a(1)
        .kind(PublicationKind::Protect)
        .prior(A_FRAME)
        .record();
    // SAFETY: test-only corruption of a plain `repr(C)` Copy record; decode
    // must reject it.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut record as *mut MmPublication).cast::<u8>(),
            MmPublication::SIZE,
        )
    };
    bytes[40] ^= 1;
    let b = Edit::protect(1, B_FRAME, RO);
    let b = [Edit {
        mm: key(B, 1),
        root: root(B_ROOT),
        ..b
    }
    .record()];
    let report = consume(
        &mut ledger,
        &[
            RingBatch {
                ring: ring(1),
                bound: key(A, 1),
                records: &[record],
            },
            RingBatch {
                ring: ring(2),
                bound: key(B, 1),
                records: &b,
            },
        ],
        &[],
    );
    assert_eq!(
        only_cause(&report),
        QuarantineCause::Malformed(PublicationDecodeError::Digest)
    );
    assert_eq!(report.applied, 1);
}

// Tickets.

#[test]
fn rolled_back_then_refused_same_ticket_does_not_free_early() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let rolled = Edit::a(1)
        .output(out)
        .outcome(PublicationOutcome::RolledBack)
        .local();
    let refused = Edit::a(2).output(out).outcome(PublicationOutcome::Refused);
    assert_eq!(
        only_cause(&run(&mut ledger, &[rolled, refused])),
        QuarantineCause::NoTicket
    );
    assert!(ledger.released.is_empty());
    assert!(!ledger.reusable(A_FRAME));
}

#[test]
fn rolled_back_local_holds_ticket_until_host_ack() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let edit = Edit::a(1)
        .output(out)
        .outcome(PublicationOutcome::RolledBack)
        .local();
    clean(&run(&mut ledger, &[edit]));
    assert!(ledger.released.is_empty());
    assert!(matches!(
        ledger.begin_cow(A_FRAME),
        Err(CowBlocked::WritableTicket(..))
    ));
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)),
        Ok(1)
    );
    assert_eq!(
        ledger.released,
        [(key(A, 1), DeferredRelease::HeldOutput(out.ticket))]
    );
    assert!(ledger.reusable(A_FRAME));
}

#[test]
fn applied_needs_an_outstanding_matching_ticket() {
    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    out.ticket = TicketId::new(nz(999));
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::NoTicket
    );

    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    out.address = ipa(A_FRAME + PAGE);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::TicketMismatch
    );

    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let exec = EditPermissions {
        executable: true,
        ..RW
    };
    assert_eq!(
        only_cause(&run(
            &mut ledger,
            &[Edit::a(1).output(out).permissions(exec)]
        )),
        QuarantineCause::PermissionEscalation
    );

    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out).grants(3)])),
        QuarantineCause::TableGrantOverrun
    );
}

#[test]
fn read_only_ticket_cannot_be_protected_writable() {
    let mut ledger = two_mms();
    let out = ledger
        .issue_spec(key(A, 1), A_FRAME, PAGE, ExtentAccess::Owner, RO)
        .unwrap();
    let map = Edit::a(1).output(out).permissions(RO);
    let report = run(&mut ledger, &[map, Edit::protect(2, A_FRAME, RW)]);
    assert_eq!(only_cause(&report), QuarantineCause::PermissionEscalation);
    assert_eq!(report.applied, 1);
}

#[test]
fn applied_accounts_table_grants_and_consumes_ticket() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[Edit::a(1).output(out).grants(2)]);
    assert_eq!(report.applied, 1);
    assert_eq!(ledger.tables, 2);
    assert_eq!(ledger.state(key(A, 1)).open_tickets(), 0);
}

#[test]
fn refused_releases_its_own_ticket_only() {
    let mut ledger = two_mms();
    let mine = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    ledger.issue(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner);
    let edit = Edit::a(1).output(mine).outcome(PublicationOutcome::Refused);
    let report = run(&mut ledger, &[edit]);
    assert_eq!((report.applied, report.released), (0, 1));
    assert_eq!(
        ledger.released,
        [(key(A, 1), DeferredRelease::Ticket(mine.ticket))]
    );
    assert_eq!(ledger.state(key(A, 1)).open_tickets(), 1);
}

#[test]
fn refused_with_stale_owner_cannot_release_custody() {
    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    out.owner_generation = owner_gen(GEN - 1);
    let edit = Edit::a(1).output(out).outcome(PublicationOutcome::Refused);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::StaleOwnerGeneration
    );
    assert!(ledger.released.is_empty());
}

// Shared frames.

#[test]
fn foreign_output_without_edge_quarantines() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), B_FRAME, ExtentAccess::Owner);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::ForeignOutput
    );
    assert!(!ledger.quarantined(key(B, 1)));
}

#[test]
fn foreign_output_with_exact_edge_applies() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    clean(&report);
    assert_eq!(report.applied, 1);
}

#[test]
fn stale_edge_generation_quarantines() {
    let mut ledger = two_mms();
    let old = ledger.share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), B_FRAME, ExtentAccess::Edge(old));
    ledger.custody_at(B_FRAME).revoke_edge(key(A, 1));
    ledger.share(B_FRAME, key(A, 1));
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::StaleEdge
    );
}

#[test]
fn owner_death_leaves_edge_only_custody() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1));
    assert_eq!(
        ledger.custody_at(B_FRAME).retire_owner(),
        OwnerRetired::EdgeOnly { edges: 1 }
    );
    let out = ledger.issue(key(A, 1), B_FRAME, ExtentAccess::Edge(edge));
    assert_eq!(run(&mut ledger, &[Edit::a(1).output(out)]).applied, 1);
    let custody = ledger.custody_at(B_FRAME);
    assert_eq!(
        custody.admits(key(B, 1), ExtentAccess::Owner),
        Err(AccessDenied::Foreign)
    );
    custody.revoke_edge(key(A, 1));
    assert_eq!(custody.retire_owner(), OwnerRetired::Reclaimable);
}

#[test]
fn cow_edge_forbids_writable_mapping() {
    let mut ledger = two_mms();
    let edge = ledger.cow_share(B_FRAME, key(A, 1)).unwrap();
    let out = ledger
        .issue_spec(key(A, 1), B_FRAME, PAGE, ExtentAccess::Edge(edge), RW)
        .unwrap();
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::CowWritable
    );

    let mut ledger = two_mms();
    let edge = ledger.cow_share(B_FRAME, key(A, 1)).unwrap();
    let out = ledger
        .issue_spec(key(A, 1), B_FRAME, PAGE, ExtentAccess::Edge(edge), RO)
        .unwrap();
    assert_eq!(
        run(&mut ledger, &[Edit::a(1).output(out).permissions(RO)]).applied,
        1
    );
    let out = ledger
        .issue_spec(key(B, 1), B_FRAME + PAGE, PAGE, ExtentAccess::Owner, RW)
        .unwrap();
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::b(1).output(out)])),
        QuarantineCause::CowWritable
    );
}

#[test]
fn writable_protect_of_cow_shared_frame_quarantines() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.cow_share(A_FRAME, key(B, 1)).unwrap();
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::protect(1, A_FRAME, RW)])),
        QuarantineCause::CowWritable
    );
}

// Identity.

#[test]
fn stale_incarnation_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::new(key(A, 2), 1, A_ROOT)
        .kind(PublicationKind::Protect)
        .prior(A_FRAME)
        .permissions(RO);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::StaleIncarnation
    );
    assert!(!ledger.quarantined(key(A, 1)));
}

#[test]
fn root_of_another_mm_quarantines() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let edit = Edit {
        root: root(B_ROOT),
        ..Edit::protect(1, A_FRAME, RO)
    };
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::RootMismatch
    );
}

#[test]
fn stale_owner_generation_quarantines() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    ledger.custody_at(A_FRAME).owner_generation = owner_gen(GEN + 1);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::StaleOwnerGeneration
    );
}

#[test]
fn recycled_slot_rejects_predecessor_records() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), A_FRAME, ExtentAccess::Owner);
    ledger.add_mm(key(A, 2), root(A_ROOT), GuestIsa::Aarch64);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::StaleIncarnation
    );
    let stale = Edit::new(key(A, 2), 1, A_ROOT).output(out);
    assert_eq!(
        only_cause(&run(&mut ledger, &[stale])),
        QuarantineCause::NoTicket
    );
}

// Ordering.

#[test]
fn counters_order_records_across_rings() {
    let mut ledger = two_mms();
    let first = a_map(&mut ledger, 1, A_FRAME);
    let second =
        Edit::unmap(2, A_FRAME).drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    let ring_one = [second.record()];
    let ring_two = [first.record()];
    let report = consume(
        &mut ledger,
        &[
            RingBatch {
                ring: ring(1),
                bound: key(A, 1),
                records: &ring_one,
            },
            RingBatch {
                ring: ring(2),
                bound: key(A, 1),
                records: &ring_two,
            },
        ],
        &[(key(A, 1), counter(2))],
    );
    clean(&report);
    assert_eq!(report.applied, 2);
    assert_eq!(ledger.book.alias_count(), 0);
}

#[test]
fn contiguous_batch_beyond_deferral_bound_applies() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let edits: Vec<Edit> = (1..=257).map(|c| Edit::protect(c, A_FRAME, RO)).collect();
    let report = consume_edits(&mut ledger, &edits, &[(key(A, 1), counter(257))]);
    clean(&report);
    assert_eq!(report.applied, 257);
}

#[test]
fn record_closing_the_gap_is_always_accepted() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let later: Vec<Edit> = (2..=257).map(|c| Edit::protect(c, A_FRAME, RO)).collect();
    let report = run(&mut ledger, &later);
    clean(&report);
    assert_eq!(report.deferred, 256);
    let report = consume_edits(
        &mut ledger,
        &[Edit::protect(1, A_FRAME, RO)],
        &[(key(A, 1), counter(257))],
    );
    clean(&report);
    assert_eq!(report.applied, 257);
}

#[test]
fn deferral_beyond_bound_quarantines() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    let later: Vec<Edit> = (2..=258).map(|c| Edit::protect(c, A_FRAME, RO)).collect();
    assert_eq!(
        only_cause(&run(&mut ledger, &later)),
        QuarantineCause::DeferralOverflow
    );
}

#[test]
fn lost_record_quarantines_only_that_mm() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    let b = Edit {
        mm: key(B, 1),
        root: root(B_ROOT),
        ..Edit::protect(1, B_FRAME, RO)
    };
    let report = consume_edits(
        &mut ledger,
        &[Edit::protect(2, A_FRAME, RO), b],
        &[(key(A, 1), counter(2)), (key(B, 1), counter(1))],
    );
    assert_eq!(only_cause(&report), QuarantineCause::LostRecord);
    assert_eq!(report.quarantined[0].mm, key(A, 1));
    assert_eq!(report.applied, 1);
}

#[test]
fn duplicate_counter_quarantines() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    run(&mut ledger, &[Edit::protect(1, A_FRAME, RO)]);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::protect(1, A_FRAME, RO)])),
        QuarantineCause::DuplicateCounter
    );
}

#[test]
fn quarantine_is_per_mm_and_sticky() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), VA, A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(key(B, 1), VA, B_FRAME, ExtentAccess::Owner, RO);
    let bad = Edit {
        root: root(B_ROOT),
        ..Edit::protect(1, A_FRAME, RO)
    };
    let b = Edit {
        mm: key(B, 1),
        root: root(B_ROOT),
        ..Edit::protect(1, B_FRAME, RO)
    };
    let report = run(&mut ledger, &[bad, b]);
    assert_eq!(only_cause(&report), QuarantineCause::RootMismatch);
    assert_eq!(report.applied, 1);
    let report = run(&mut ledger, &[Edit::protect(2, A_FRAME, RO)]);
    assert_eq!((report.applied, report.quarantined.len()), (0, 0));
    assert_eq!(
        retirement_permitted(&ledger.book, key(A, 1)),
        Err(RetirementBlocked::Quarantined)
    );
}

/// Adversarial population: many unrelated extents, aliases, tickets and MMs
/// must not change how many entries the consumer touches.
fn visits_with_population(unrelated: u64) -> (usize, usize) {
    let mut ledger = two_mms();
    for i in 0..unrelated {
        let base = 0x1000_0000 + i * PAGE;
        let owner = if i % 2 == 0 { key(B, 1) } else { key(A, 1) };
        ledger.add_extent(base, PAGE, owner);
        ledger.add_alias(owner, 0x8000_0000 + i * PAGE, base, ExtentAccess::Owner, RO);
    }
    for i in 0..unrelated / 4 {
        ledger.add_mm(
            key(100 + i, 1),
            root(0x4000_0000 + i * PAGE),
            GuestIsa::Aarch64,
        );
    }
    let map = a_map(&mut ledger, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner);
    let refused = ledger.issue(key(B, 1), B_FRAME, ExtentAccess::Owner);
    let edits = [
        map,
        Edit::unmap(2, A_FRAME)
            .kind(PublicationKind::CowRepoint)
            .output(out),
        Edit::b(1)
            .output(refused)
            .outcome(PublicationOutcome::Refused),
        Edit::unmap(3, A_FRAME + PAGE).local(),
    ];
    ledger.examined.set(0);
    let report = consume_edits(&mut ledger, &edits, &[(key(A, 1), counter(3))]);
    clean(&report);
    (report.ledger_visits, ledger.examined.get())
}

#[test]
fn visits_bounded_by_records_and_touched_edges() {
    let small = visits_with_population(8);
    let large = visits_with_population(8192);
    assert_eq!(small, large);
    // 2 batches; map: ticket, custody, VA check; repoint: ticket, custody,
    // prior; refused: ticket, custody; unmap: prior.
    assert_eq!(small.0, 11);
}
