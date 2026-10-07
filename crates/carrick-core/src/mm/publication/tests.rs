use super::*;
use alloc::collections::BTreeSet;
use carrick_core_abi::{EditSequence, PublicationIdentity, PublicationShape, PublishedOutput};
use carrick_guest_arch::{FrameGpa, UserRange};
use core::cell::Cell;

const PAGE: u64 = 0x1000;
const A: u64 = 1;
const B: u64 = 2;
const A_ROOT: u64 = 0x10_0000;
const B_ROOT: u64 = 0x20_0000;
const A_FRAME: u64 = 0x100_0000;
const B_FRAME: u64 = 0x200_0000;
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
fn ticket_id(raw: u64) -> TicketId {
    TicketId::new(nz(raw))
}
fn ring(raw: u64) -> RingId {
    RingId(nz(raw))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    NoTicket,
    NoAlias,
}

#[derive(Default)]
struct TestLedger {
    mms: BTreeMap<PublicationMm, LedgerMm>,
    states: BTreeMap<MmIncarnationKey, MmPublicationState>,
    quarantined: BTreeSet<MmIncarnationKey>,
    extents: BTreeMap<u64, (u64, ExtentCustody)>,
    tickets: BTreeMap<(MmIncarnationKey, TicketId), AdmissionTicket>,
    held: BTreeSet<(MmIncarnationKey, TicketId)>,
    aliases: BTreeMap<(MmIncarnationKey, u64), LedgerAlias>,
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
        self.states.insert(key, MmPublicationState::new());
    }
    fn add_extent(&mut self, base: u64, len: u64, owner: MmIncarnationKey) {
        self.extents
            .insert(base, (len, ExtentCustody::new(owner, owner_gen(GEN))));
    }
    fn custody_at(&mut self, base: u64) -> &mut ExtentCustody {
        &mut self.extents.get_mut(&base).unwrap().1
    }
    fn share(&mut self, base: u64, to: MmIncarnationKey) -> EdgeGeneration {
        // SAFETY: the test plays the host share path.
        unsafe { self.custody_at(base).mint_shared_edge(to) }.unwrap()
    }
    fn cow_share(&mut self, base: u64, to: MmIncarnationKey) -> EdgeGeneration {
        let custody = self.custody_at(base);
        let proof = custody.begin_cow().unwrap();
        // SAFETY: the test plays fork custody.
        unsafe { custody.mint_cow_edge(to, proof) }.unwrap()
    }
    fn issue_with(
        &mut self,
        mm: MmIncarnationKey,
        id: u64,
        output: u64,
        access: ExtentAccess,
        max_permissions: EditPermissions,
    ) -> PublishedOutput {
        let ticket = AdmissionTicket {
            output: Stage1Ipa::new(output),
            leaf: EditLeafSize::Page,
            len: GuestLen::new(PAGE),
            owner_generation: owner_gen(GEN),
            access,
            inventory_revision: InventoryRevision::new(nz(1)),
            max_permissions,
            table_grants: TableGrantCount(2),
        };
        self.tickets.insert((mm, ticket_id(id)), ticket);
        PublishedOutput {
            address: ticket.output,
            leaf: ticket.leaf,
            ticket: ticket_id(id),
            owner_generation: ticket.owner_generation,
            access,
            inventory_revision: ticket.inventory_revision,
        }
    }
    fn issue(
        &mut self,
        mm: MmIncarnationKey,
        id: u64,
        output: u64,
        access: ExtentAccess,
    ) -> PublishedOutput {
        self.issue_with(mm, id, output, access, RW)
    }
    /// A live alias published earlier, at `VA`.
    fn add_alias(
        &mut self,
        mm: MmIncarnationKey,
        frame: u64,
        access: ExtentAccess,
        permissions: EditPermissions,
    ) {
        if permissions.writable {
            self.custody_at(frame).writable_published().unwrap();
        }
        self.aliases.insert(
            (mm, frame),
            LedgerAlias {
                va: UserVa::new(VA),
                len: GuestLen::new(PAGE),
                owner_generation: owner_gen(GEN),
                access,
                permissions,
                max_permissions: RW,
            },
        );
    }
    fn state(&self, mm: MmIncarnationKey) -> &MmPublicationState {
        &self.states[&mm]
    }
}

impl PhysicalLedger for TestLedger {
    type Fault = Fault;
    fn mm_quarantined(&self, mm: MmIncarnationKey) -> bool {
        self.quarantined.contains(&mm)
    }
    fn quarantine_mm(&mut self, mm: MmIncarnationKey) {
        self.quarantined.insert(mm);
    }
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm> {
        self.mms.get(&mm).copied()
    }
    fn publication_state(&mut self, mm: MmIncarnationKey) -> Option<&mut MmPublicationState> {
        self.states.get_mut(&mm)
    }
    fn ticket(&self, mm: MmIncarnationKey, ticket: TicketId) -> Option<AdmissionTicket> {
        self.examined.set(self.examined.get() + 1);
        self.tickets.get(&(mm, ticket)).copied()
    }
    fn outstanding_tickets(&self, mm: MmIncarnationKey) -> usize {
        self.tickets
            .keys()
            .filter(|(owner, _)| *owner == mm)
            .count()
    }
    fn custody(&self, address: Stage1Ipa) -> Option<&ExtentCustody> {
        let (&base, (len, custody)) = self.extents.range(..=address.raw()).next_back()?;
        self.examined.set(self.examined.get() + 1);
        (address.raw() < base + len).then_some(custody)
    }
    fn custody_mut(&mut self, address: Stage1Ipa) -> Option<&mut ExtentCustody> {
        let (&base, (len, custody)) = self.extents.range_mut(..=address.raw()).next_back()?;
        (address.raw() < base + *len).then_some(custody)
    }
    fn alias(&self, mm: MmIncarnationKey, address: Stage1Ipa) -> Option<LedgerAlias> {
        self.examined.set(self.examined.get() + 1);
        self.aliases.get(&(mm, address.raw())).copied()
    }
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Fault> {
        let view = record.view();
        let key = view.key();
        if let Some(prior) = view.prior() {
            match view.kind() {
                PublicationKind::CowRepoint | PublicationKind::Unmap => {
                    self.aliases
                        .remove(&(key, prior.address.raw()))
                        .ok_or(Fault::NoAlias)?;
                }
                PublicationKind::Protect => {
                    self.aliases
                        .get_mut(&(key, prior.address.raw()))
                        .ok_or(Fault::NoAlias)?
                        .permissions = view.permissions();
                }
                _ => {}
            }
        }
        if let Some(out) = view.output() {
            let ticket = self
                .tickets
                .remove(&(key, out.ticket))
                .ok_or(Fault::NoTicket)?;
            self.aliases.insert(
                (key, out.address.raw()),
                LedgerAlias {
                    va: view.span().start(),
                    len: ticket.len,
                    owner_generation: ticket.owner_generation,
                    access: ticket.access,
                    permissions: view.permissions(),
                    max_permissions: ticket.max_permissions,
                },
            );
            self.tables += u64::from(view.table_grants().0);
        }
        Ok(())
    }
    fn hold_ticket(&mut self, mm: MmIncarnationKey, ticket: TicketId) -> Result<(), Fault> {
        self.tickets.remove(&(mm, ticket)).ok_or(Fault::NoTicket)?;
        self.held.insert((mm, ticket));
        Ok(())
    }
    fn release(&mut self, mm: MmIncarnationKey, release: DeferredRelease) -> Result<(), Fault> {
        match release {
            DeferredRelease::Ticket(id) => {
                self.tickets.remove(&(mm, id)).ok_or(Fault::NoTicket)?;
            }
            DeferredRelease::HeldOutput(id) => {
                if !self.held.remove(&(mm, id)) {
                    return Err(Fault::NoTicket);
                }
            }
            DeferredRelease::Prior(_) => {}
        }
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
            address: Stage1Ipa::new(address),
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
    fn protect_ro(counter: u64) -> Self {
        Self::a(counter)
            .kind(PublicationKind::Protect)
            .permissions(RO)
    }
    fn record(&self) -> MmPublication {
        let view = PublicationView::checked(
            self.shape,
            PublicationIdentity {
                mm: self.mm.mm,
                incarnation: self.mm.incarnation,
                counter: counter(self.counter),
                edit_sequence: EditSequence::new(nz(self.counter + 1000)),
                root: self.root,
            },
            UserRange::checked(UserVa::new(self.va), GuestLen::new(PAGE)).unwrap(),
            self.output,
            self.prior,
        )
        .unwrap();
        MmPublication::encode(&view)
    }
}

/// Two live ARM MMs, each owning a 16-page extent.
fn two_mms() -> TestLedger {
    let mut ledger = TestLedger::default();
    ledger.add_mm(key(A, 1), root(A_ROOT), GuestIsa::Aarch64);
    ledger.add_mm(key(B, 1), root(B_ROOT), GuestIsa::Aarch64);
    ledger.add_extent(A_FRAME, 16 * PAGE, key(A, 1));
    ledger.add_extent(B_FRAME, 16 * PAGE, key(B, 1));
    ledger
}

/// Each edit travels on its own MM's ring (ring id = mm key).
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

fn a_map(ledger: &mut TestLedger, counter: u64, id: u64, frame: u64) -> Edit {
    let out = ledger.issue(key(A, 1), id, frame, ExtentAccess::Owner);
    Edit::a(counter).output(out)
}

fn retire_ready(ledger: &mut TestLedger, mm: MmIncarnationKey, through: u64) {
    close_admission(ledger, mm, Some(counter(through))).unwrap();
}

#[test]
fn two_mms_apply_independently() {
    let mut ledger = two_mms();
    let a = a_map(&mut ledger, 1, 1, A_FRAME);
    let out = ledger.issue(key(B, 1), 1, B_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[a, Edit::b(1).output(out)]);
    assert_eq!((report.applied, report.quarantined.len()), (2, 0));
    assert!(ledger.aliases.contains_key(&(key(A, 1), A_FRAME)));
    assert!(ledger.aliases.contains_key(&(key(B, 1), B_FRAME)));
}

// Round 3 item 1: ISA and drain authority come from the producer.

#[test]
fn x86_producer_cannot_settle_debt_with_an_arm_claim() {
    let mut ledger = two_mms();
    ledger.mms.get_mut(&key(A, 1).mm).unwrap().isa = GuestIsa::X86_64;
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    let unmap = Edit::a(1)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::X86_64, PublicationDrain::Local);
    let forged = Edit::protect_ro(2).drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastAsid);
    let report = run(&mut ledger, &[unmap, forged]);
    assert_eq!(only_cause(&report), QuarantineCause::IsaMismatch);
    assert_eq!(report.quarantined[0].mm, key(A, 1));
    assert!(ledger.released.is_empty(), "frame freed under x86 debt");
}

// Round 3 item 2: attribution to the ring's bound producer.

#[test]
fn forged_identity_quarantines_producer_not_victim() {
    let mut ledger = two_mms();
    run(
        &mut ledger,
        &[Edit::b(1).kind(PublicationKind::Protect).permissions(RO)],
    );
    // Ring 1 is bound to A but carries a duplicate of B's counter 1.
    let forged = [Edit::b(1)
        .kind(PublicationKind::Protect)
        .permissions(RO)
        .record()];
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
    assert_eq!(report.quarantined[0].ring, Some(ring(1)));
    assert!(!ledger.mm_quarantined(key(B, 1)));
}

#[test]
fn malformed_record_quarantines_only_its_producer() {
    let mut ledger = two_mms();
    let mut record = Edit::protect_ro(1).record();
    // SAFETY: test-only corruption of a plain `repr(C)` Copy record; decode
    // must reject it.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut record as *mut MmPublication).cast::<u8>(),
            MmPublication::SIZE,
        )
    };
    bytes[40] ^= 1;
    let b = [Edit::b(1)
        .kind(PublicationKind::Protect)
        .permissions(RO)
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

// Round 3 item 3: rolled-back tickets cannot be spent again.

#[test]
fn rolled_back_then_refused_same_ticket_does_not_free_early() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    let rolled = Edit::a(1)
        .output(out)
        .outcome(PublicationOutcome::RolledBack)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    let refused = Edit::a(2).output(out).outcome(PublicationOutcome::Refused);
    let report = run(&mut ledger, &[rolled, refused]);
    assert_eq!(only_cause(&report), QuarantineCause::NoTicket);
    assert!(ledger.released.is_empty());
    assert!(ledger.held.contains(&(key(A, 1), ticket_id(1))));
}

#[test]
fn rolled_back_local_holds_ticket_until_host_ack() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    let edit = Edit::a(1)
        .output(out)
        .outcome(PublicationOutcome::RolledBack)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    run(&mut ledger, &[edit]);
    assert!(ledger.released.is_empty());
    assert_eq!(ledger.outstanding_tickets(key(A, 1)), 0);
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)),
        Ok(1)
    );
    assert_eq!(
        ledger.released,
        [(key(A, 1), DeferredRelease::HeldOutput(ticket_id(1)))]
    );
}

// Round 3 item 4: aliases keep their permission ceiling.

#[test]
fn read_only_ticket_cannot_be_protected_writable() {
    let mut ledger = two_mms();
    let out = ledger.issue_with(key(A, 1), 1, A_FRAME, ExtentAccess::Owner, RO);
    let map = Edit::a(1).output(out).permissions(RO);
    let protect = Edit::a(2).kind(PublicationKind::Protect).prior(A_FRAME);
    let report = run(&mut ledger, &[map, protect]);
    assert_eq!(only_cause(&report), QuarantineCause::PermissionEscalation);
    assert_eq!(report.applied, 1);
}

#[test]
fn records_without_output_or_prior_cannot_grant_write() {
    for kind in [PublicationKind::Publish, PublicationKind::ArmCow] {
        let mut ledger = two_mms();
        let report = run(&mut ledger, &[Edit::a(1).kind(kind)]);
        assert_eq!(
            only_cause(&report),
            QuarantineCause::PermissionEscalation,
            "{kind:?}"
        );
    }
}

// Round 3 item 5: span must be the prior alias's VA span.

#[test]
fn prior_span_must_match_alias_va() {
    for kind in [PublicationKind::Unmap, PublicationKind::Protect] {
        let mut ledger = two_mms();
        ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RW);
        let edit = Edit::a(1)
            .kind(kind)
            .prior(A_FRAME)
            .permissions(RO)
            .at(VA + PAGE);
        let report = run(&mut ledger, &[edit]);
        assert_eq!(
            only_cause(&report),
            QuarantineCause::SpanMismatch,
            "{kind:?}"
        );
    }
}

// Round 3 item 6: bounded work.

#[test]
fn contiguous_batch_beyond_deferral_bound_applies() {
    let mut ledger = two_mms();
    let edits: Vec<Edit> = (1..=257).map(Edit::protect_ro).collect();
    let report = consume_edits(&mut ledger, &edits, &[(key(A, 1), counter(257))]);
    assert_eq!((report.applied, report.quarantined.len()), (257, 0));
}

#[test]
fn record_closing_the_gap_is_always_accepted() {
    let mut ledger = two_mms();
    let later: Vec<Edit> = (2..=257).map(Edit::protect_ro).collect();
    let report = run(&mut ledger, &later);
    assert_eq!((report.deferred, report.quarantined.len()), (256, 0));
    let report = consume_edits(
        &mut ledger,
        &[Edit::protect_ro(1)],
        &[(key(A, 1), counter(257))],
    );
    assert_eq!((report.applied, report.quarantined.len()), (257, 0));
    assert_eq!(ledger.state(key(A, 1)).deferred_records(), 0);
}

#[test]
fn deferral_beyond_bound_quarantines() {
    let mut ledger = two_mms();
    let later: Vec<Edit> = (2..=258).map(Edit::protect_ro).collect();
    assert_eq!(
        only_cause(&run(&mut ledger, &later)),
        QuarantineCause::DeferralOverflow
    );
}

#[test]
fn debt_without_custody_is_compacted() {
    let mut ledger = two_mms();
    let edits: Vec<Edit> = (1..=1000)
        .map(|c| Edit::protect_ro(c).drain(GuestIsa::Aarch64, PublicationDrain::Local))
        .collect();
    run(&mut ledger, &edits);
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
fn held_custody_applies_admission_backpressure() {
    let mut ledger = two_mms();
    let frames = MAX_HELD_SETTLEMENTS_PER_MM as u64;
    ledger.add_extent(0x1000_0000, frames * PAGE, key(A, 1));
    let mut edits = Vec::new();
    for i in 0..frames {
        let frame = 0x1000_0000 + i * PAGE;
        let va = VA + i * PAGE;
        ledger.add_alias(key(A, 1), frame, ExtentAccess::Owner, RO);
        ledger.aliases.get_mut(&(key(A, 1), frame)).unwrap().va = UserVa::new(va);
        edits.push(
            Edit::a(i + 1)
                .kind(PublicationKind::Unmap)
                .prior(frame)
                .at(va)
                .drain(GuestIsa::Aarch64, PublicationDrain::Local),
        );
    }
    assert_eq!(admission_permitted(&mut ledger, key(A, 1)), Ok(()));
    run(&mut ledger, &edits);
    assert_eq!(
        admission_permitted(&mut ledger, key(A, 1)),
        Err(AdmissionBlocked::Backpressure)
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(frames)).unwrap();
    assert_eq!(admission_permitted(&mut ledger, key(A, 1)), Ok(()));
}

// Round 3 item 7: retirement barrier.

#[test]
fn retirement_requires_the_host_barrier() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::AdmissionOpen)
    );
    retire_ready(&mut ledger, key(A, 1), 2);
    assert_eq!(
        admission_permitted(&mut ledger, key(A, 1)),
        Err(AdmissionBlocked::Closed)
    );
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::OutstandingTickets(1))
    );
    let map = Edit::a(1)
        .output(out)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    run(&mut ledger, &[map]);
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::UnconsumedRecords)
    );
    run(
        &mut ledger,
        &[Edit::protect_ro(2).drain(GuestIsa::Aarch64, PublicationDrain::Local)],
    );
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::DrainDebt(counter(1)))
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(retirement_permitted(&mut ledger, key(A, 1)), Ok(()));
}

// Round 3 item 8: COW edges need a write-downgrade transition.

#[test]
fn cow_edge_requires_drained_write_downgrade() {
    let mut ledger = two_mms();
    let map = a_map(&mut ledger, 1, 1, A_FRAME);
    run(&mut ledger, &[map]);
    assert_eq!(
        ledger.custody_at(A_FRAME).begin_cow(),
        Err(CowTransitionError::WritableAliasesLive(1))
    );
    let downgrade = Edit::a(2)
        .kind(PublicationKind::Protect)
        .prior(A_FRAME)
        .permissions(RO)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    run(&mut ledger, &[downgrade]);
    // Downgraded but not drained: a remote CPU may still write.
    assert!(ledger.custody_at(A_FRAME).begin_cow().is_err());
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    let proof = ledger.custody_at(A_FRAME).begin_cow().unwrap();
    // A writable alias published after the proof makes it stale.
    let map = a_map(&mut ledger, 3, 2, A_FRAME + PAGE).at(VA + PAGE);
    run(&mut ledger, &[map]);
    // SAFETY: the test plays fork custody.
    let minted = unsafe { ledger.custody_at(A_FRAME).mint_cow_edge(key(B, 1), proof) };
    assert_eq!(minted, Err(CowTransitionError::Stale));
}

// Shared frames.

#[test]
fn foreign_output_without_edge_quarantines() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::ForeignOutput);
    assert!(!ledger.mm_quarantined(key(B, 1)));
}

#[test]
fn foreign_output_with_exact_edge_applies() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!((report.applied, report.quarantined.len()), (1, 0));
}

#[test]
fn stale_edge_generation_quarantines() {
    let mut ledger = two_mms();
    let old = ledger.share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(old));
    ledger.custody_at(B_FRAME).revoke_edge(key(A, 1));
    ledger.share(B_FRAME, key(A, 1));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::StaleEdge);
}

#[test]
fn owner_death_leaves_edge_only_custody() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1));
    assert_eq!(
        ledger.custody_at(B_FRAME).retire_owner(),
        OwnerRetired::EdgeOnly { edges: 1 }
    );
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
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
    let edge = ledger.cow_share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::CowWritable
    );

    let mut ledger = two_mms();
    let edge = ledger.cow_share(B_FRAME, key(A, 1));
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out).permissions(RO)]);
    assert_eq!(report.applied, 1);
    let out = ledger.issue(key(B, 1), 1, B_FRAME, ExtentAccess::Owner);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::b(1).output(out)])),
        QuarantineCause::CowWritable
    );
}

#[test]
fn writable_protect_of_cow_shared_frame_quarantines() {
    let mut ledger = two_mms();
    ledger.cow_share(A_FRAME, key(B, 1));
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    let protect = Edit::a(1).kind(PublicationKind::Protect).prior(A_FRAME);
    assert_eq!(
        only_cause(&run(&mut ledger, &[protect])),
        QuarantineCause::CowWritable
    );
}

// Prior output.

#[test]
fn prior_of_another_mm_quarantines() {
    for kind in [PublicationKind::CowRepoint, PublicationKind::Unmap] {
        let mut ledger = two_mms();
        ledger.add_alias(key(B, 1), B_FRAME, ExtentAccess::Owner, RO);
        let mut edit = Edit::a(1).kind(kind).prior(B_FRAME).permissions(RO);
        if kind == PublicationKind::CowRepoint {
            let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
            edit = edit.output(out);
        }
        let report = run(&mut ledger, &[edit]);
        assert_eq!(
            only_cause(&report),
            QuarantineCause::ForeignPrior,
            "{kind:?}"
        );
        assert!(ledger.aliases.contains_key(&(key(B, 1), B_FRAME)));
        assert!(ledger.released.is_empty());
    }
}

#[test]
fn prior_length_and_generation_must_match() {
    let unmap = Edit::a(1).kind(PublicationKind::Unmap).prior(A_FRAME);
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    ledger.aliases.get_mut(&(key(A, 1), A_FRAME)).unwrap().len = GuestLen::new(2 * PAGE);
    assert_eq!(
        only_cause(&run(&mut ledger, &[unmap])),
        QuarantineCause::PriorLength
    );

    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    ledger
        .aliases
        .get_mut(&(key(A, 1), A_FRAME))
        .unwrap()
        .owner_generation = owner_gen(GEN + 1);
    assert_eq!(
        only_cause(&run(&mut ledger, &[unmap])),
        QuarantineCause::StalePriorGeneration
    );
}

// Identity.

#[test]
fn stale_incarnation_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::new(key(A, 2), 1, A_ROOT)
        .kind(PublicationKind::Protect)
        .permissions(RO);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::StaleIncarnation
    );
    assert!(!ledger.mm_quarantined(key(A, 1)));
}

#[test]
fn root_of_another_mm_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::new(key(A, 1), 1, B_ROOT)
        .kind(PublicationKind::Protect)
        .permissions(RO);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::RootMismatch
    );
}

#[test]
fn stale_owner_generation_quarantines() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    ledger.custody_at(A_FRAME).owner_generation = owner_gen(GEN + 1);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::StaleOwnerGeneration
    );
}

#[test]
fn recycled_slot_rejects_predecessor_records() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    ledger.states.remove(&key(A, 1));
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

// Admission.

#[test]
fn applied_needs_an_outstanding_matching_ticket() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    ledger.tickets.clear();
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::NoTicket
    );

    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    out.address = Stage1Ipa::new(A_FRAME + PAGE);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out)])),
        QuarantineCause::TicketMismatch
    );

    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
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
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::a(1).output(out).grants(3)])),
        QuarantineCause::TableGrantOverrun
    );
}

#[test]
fn applied_accounts_table_grants_and_consumes_ticket() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[Edit::a(1).output(out).grants(2)]);
    assert_eq!(report.applied, 1);
    assert_eq!(ledger.tables, 2);
    assert!(ledger.tickets.is_empty());
    assert_eq!(ledger.custody_at(A_FRAME).writable_aliases(), 1);
}

#[test]
fn refused_releases_its_own_ticket_only() {
    let mut ledger = two_mms();
    let mine = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    ledger.issue(key(A, 1), 2, A_FRAME + PAGE, ExtentAccess::Owner);
    let edit = Edit::a(1).output(mine).outcome(PublicationOutcome::Refused);
    let report = run(&mut ledger, &[edit]);
    assert_eq!((report.applied, report.released), (0, 1));
    assert_eq!(
        ledger.released,
        [(key(A, 1), DeferredRelease::Ticket(ticket_id(1)))]
    );
    assert!(ledger.tickets.contains_key(&(key(A, 1), ticket_id(2))));
}

#[test]
fn refused_with_stale_owner_cannot_release_custody() {
    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    out.owner_generation = owner_gen(GEN - 1);
    let edit = Edit::a(1).output(out).outcome(PublicationOutcome::Refused);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::StaleOwnerGeneration
    );
    assert!(ledger.released.is_empty());
}

// Drains.

#[test]
fn x86_shootdown_claim_never_clears_debt() {
    let mut ledger = two_mms();
    ledger.mms.get_mut(&key(A, 1).mm).unwrap().isa = GuestIsa::X86_64;
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    let local = Edit::a(1)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::X86_64, PublicationDrain::Local);
    let claim = Edit::protect_ro(2).drain(GuestIsa::X86_64, PublicationDrain::X86ShootdownClaim);
    run(&mut ledger, &[local, claim]);
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
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner, RO);
    ledger.add_alias(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner, RO);
    let local = Edit::a(1)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    let span = Edit::a(2)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME + PAGE)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    run(&mut ledger, &[local, span]);
    assert!(matches!(
        ledger.released[..],
        [(_, DeferredRelease::Prior(PublishedPrior { address, .. }))] if address.raw() == A_FRAME + PAGE
    ));
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(1))
    );
    run(&mut ledger, &[Edit::protect_ro(3)]);
    assert_eq!(ledger.released.len(), 2);
    assert_eq!(ledger.state(key(A, 1)).oldest_drain_debt(), None);
}

#[test]
fn cow_repoint_moves_alias_and_holds_prior_until_drain() {
    let mut ledger = two_mms();
    let map = a_map(&mut ledger, 1, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), 2, A_FRAME + PAGE, ExtentAccess::Owner);
    let repoint = Edit::a(2)
        .kind(PublicationKind::CowRepoint)
        .output(out)
        .prior(A_FRAME)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    run(&mut ledger, &[map, repoint]);
    assert!(!ledger.aliases.contains_key(&(key(A, 1), A_FRAME)));
    assert!(ledger.aliases.contains_key(&(key(A, 1), A_FRAME + PAGE)));
    assert!(ledger.released.is_empty());
    // The old writable alias is still live until the drain settles.
    assert_eq!(ledger.custody_at(A_FRAME).writable_aliases(), 2);
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(ledger.released.len(), 1);
    assert_eq!(ledger.custody_at(A_FRAME).writable_aliases(), 1);
}

// Ordering.

#[test]
fn counters_order_records_across_rings() {
    let mut ledger = two_mms();
    let first = a_map(&mut ledger, 1, 1, A_FRAME);
    let second = Edit::a(2)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .permissions(RO)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
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
    assert_eq!((report.applied, report.quarantined.len()), (2, 0));
    assert!(ledger.aliases.is_empty());
}

#[test]
fn lost_record_quarantines_only_that_mm() {
    let mut ledger = two_mms();
    let b = Edit::b(1).kind(PublicationKind::Protect).permissions(RO);
    let report = consume_edits(
        &mut ledger,
        &[Edit::protect_ro(2), b],
        &[(key(A, 1), counter(2)), (key(B, 1), counter(1))],
    );
    assert_eq!(only_cause(&report), QuarantineCause::LostRecord);
    assert_eq!(report.quarantined[0].mm, key(A, 1));
    assert_eq!(report.applied, 1);
}

#[test]
fn duplicate_counter_quarantines() {
    let mut ledger = two_mms();
    run(&mut ledger, &[Edit::protect_ro(1)]);
    assert_eq!(
        only_cause(&run(&mut ledger, &[Edit::protect_ro(1)])),
        QuarantineCause::DuplicateCounter
    );
}

#[test]
fn quarantine_is_per_mm_and_sticky() {
    let mut ledger = two_mms();
    let bad = Edit::new(key(A, 1), 1, B_ROOT)
        .kind(PublicationKind::Protect)
        .permissions(RO);
    let b = Edit::b(1).kind(PublicationKind::Protect).permissions(RO);
    let report = run(&mut ledger, &[bad, b]);
    assert_eq!(only_cause(&report), QuarantineCause::RootMismatch);
    assert_eq!(report.applied, 1);
    let report = run(&mut ledger, &[Edit::protect_ro(2)]);
    assert_eq!((report.applied, report.quarantined.len()), (0, 0));
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::Quarantined)
    );
}

/// Adversarial population: many unrelated extents, aliases, tickets and MMs
/// must not change how many ledger entries the consumer touches.
fn visits_with_population(unrelated: u64) -> (usize, usize) {
    let mut ledger = two_mms();
    for i in 0..unrelated {
        let base = 0x1000_0000 + i * PAGE;
        let owner = if i % 2 == 0 { key(B, 1) } else { key(A, 1) };
        ledger.add_extent(base, PAGE, owner);
        ledger.add_alias(owner, base, ExtentAccess::Owner, RO);
        ledger.issue(owner, 1000 + i, base, ExtentAccess::Owner);
    }
    for i in 0..unrelated / 4 {
        ledger.add_mm(
            key(100 + i, 1),
            root(0x4000_0000 + i * PAGE),
            GuestIsa::Aarch64,
        );
    }
    let map = a_map(&mut ledger, 1, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), 2, A_FRAME + PAGE, ExtentAccess::Owner);
    let refused = ledger.issue(key(B, 1), 3, B_FRAME, ExtentAccess::Owner);
    let edits = [
        map,
        Edit::a(2)
            .kind(PublicationKind::CowRepoint)
            .output(out)
            .prior(A_FRAME)
            .permissions(RO),
        Edit::b(1)
            .output(refused)
            .outcome(PublicationOutcome::Refused),
        Edit::a(3)
            .kind(PublicationKind::Unmap)
            .prior(A_FRAME + PAGE)
            .permissions(RO)
            .drain(GuestIsa::Aarch64, PublicationDrain::Local),
    ];
    ledger.examined.set(0);
    let report = consume_edits(&mut ledger, &edits, &[(key(A, 1), counter(3))]);
    assert!(report.quarantined.is_empty(), "{report:?}");
    (report.ledger_visits, ledger.examined.get())
}

#[test]
fn visits_bounded_by_records_and_touched_edges() {
    let small = visits_with_population(8);
    let large = visits_with_population(8192);
    assert_eq!(small, large);
    // 2 batches + 3 tickets + 3 custodies + 2 priors.
    assert_eq!(small.0, 10);
}
