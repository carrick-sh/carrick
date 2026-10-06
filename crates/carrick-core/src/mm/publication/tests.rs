use super::*;
use carrick_core_abi::{
    EditSequence, MmIncarnation, PublicationIdentity, PublicationShape, PublishedOutput,
};
use carrick_guest_arch::{FrameGpa, UserRange, UserVa};
use core::cell::Cell;
use core::num::NonZeroU64;

const PAGE: u64 = 0x1000;
const A: u64 = 1;
const B: u64 = 2;
const A_ROOT: u64 = 0x10_0000;
const B_ROOT: u64 = 0x20_0000;
const A_FRAME: u64 = 0x100_0000;
const B_FRAME: u64 = 0x200_0000;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    NoTicket,
    NoAlias,
    Postcondition,
}

#[derive(Default)]
struct TestLedger {
    mms: BTreeMap<PublicationMm, LedgerMm>,
    states: BTreeMap<MmIncarnationKey, MmPublicationState>,
    quarantined: BTreeSet<MmIncarnationKey>,
    carrier: bool,
    extents: BTreeMap<u64, (u64, ExtentCustody)>,
    tickets: BTreeMap<(MmIncarnationKey, TicketId), AdmissionTicket>,
    aliases: BTreeMap<(MmIncarnationKey, u64), LedgerAlias>,
    released: Vec<(MmIncarnationKey, DeferredRelease)>,
    tables: u64,
    fail_postcondition: bool,
    /// Ledger entries examined by lookups, independent of the consumer.
    examined: Cell<usize>,
}

impl TestLedger {
    fn add_mm(&mut self, key: MmIncarnationKey, root: RootGpa) {
        self.mms.insert(
            key.mm,
            LedgerMm {
                incarnation: key.incarnation,
                root,
            },
        );
        self.states.insert(key, MmPublicationState::new());
    }
    fn add_extent(&mut self, base: u64, len: u64, owner: MmIncarnationKey) {
        self.extents
            .insert(base, (len, ExtentCustody::new(owner, owner_gen(GEN))));
    }
    fn custody_mut(&mut self, base: u64) -> &mut ExtentCustody {
        &mut self.extents.get_mut(&base).unwrap().1
    }
    fn share(&mut self, base: u64, to: MmIncarnationKey, kind: EdgeKind) -> EdgeGeneration {
        // SAFETY: the test plays the host share / fork custody path.
        unsafe { self.custody_mut(base).mint_edge(to, kind) }.unwrap()
    }
    fn issue(
        &mut self,
        mm: MmIncarnationKey,
        id: u64,
        output: u64,
        access: ExtentAccess,
    ) -> PublishedOutput {
        let ticket = AdmissionTicket {
            output: Stage1Ipa::new(output),
            leaf: EditLeafSize::Page,
            len: GuestLen::new(PAGE),
            owner_generation: owner_gen(GEN),
            access,
            inventory_revision: InventoryRevision::new(nz(1)),
            max_permissions: RW,
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
    fn add_alias(&mut self, mm: MmIncarnationKey, address: u64, access: ExtentAccess) {
        self.aliases.insert(
            (mm, address),
            LedgerAlias {
                len: GuestLen::new(PAGE),
                owner_generation: owner_gen(GEN),
                access,
            },
        );
    }
    fn state(&self, mm: MmIncarnationKey) -> &MmPublicationState {
        &self.states[&mm]
    }
}

impl PhysicalLedger for TestLedger {
    type Fault = Fault;
    fn carrier_quarantined(&self) -> bool {
        self.carrier
    }
    fn quarantine_carrier(&mut self) {
        self.carrier = true;
    }
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
    fn custody(&self, address: Stage1Ipa) -> Option<&ExtentCustody> {
        let (&base, (len, custody)) = self.extents.range(..=address.raw()).next_back()?;
        self.examined.set(self.examined.get() + 1);
        (address.raw() < base + len).then_some(custody)
    }
    fn alias(&self, mm: MmIncarnationKey, address: Stage1Ipa) -> Option<LedgerAlias> {
        self.examined.set(self.examined.get() + 1);
        self.aliases.get(&(mm, address.raw())).copied()
    }
    fn postcondition(&self, _record: &AuthenticatedPublication) -> Result<(), Fault> {
        if self.fail_postcondition {
            Err(Fault::Postcondition)
        } else {
            Ok(())
        }
    }
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Fault> {
        let view = record.view();
        let key = view.key();
        if let Some(prior) = view.prior()
            && matches!(
                view.kind(),
                PublicationKind::CowRepoint | PublicationKind::Unmap
            )
        {
            self.aliases
                .remove(&(key, prior.address.raw()))
                .ok_or(Fault::NoAlias)?;
        }
        if let Some(out) = view.output() {
            let ticket = self
                .tickets
                .remove(&(key, out.ticket))
                .ok_or(Fault::NoTicket)?;
            self.aliases.insert(
                (key, out.address.raw()),
                LedgerAlias {
                    len: ticket.len,
                    owner_generation: ticket.owner_generation,
                    access: ticket.access,
                },
            );
            self.tables += u64::from(view.table_grants().0);
        }
        Ok(())
    }
    fn release(&mut self, mm: MmIncarnationKey, release: DeferredRelease) -> Result<(), Fault> {
        if let DeferredRelease::Ticket(id) = release {
            self.tickets.remove(&(mm, id)).ok_or(Fault::NoTicket)?;
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
            UserRange::checked(UserVa::new(0x40_0000), GuestLen::new(PAGE)).unwrap(),
            self.output,
            self.prior,
        )
        .unwrap();
        MmPublication::encode(&view)
    }
}

/// Two live MMs, each owning one frame.
fn two_mms() -> TestLedger {
    let mut ledger = TestLedger::default();
    ledger.add_mm(key(A, 1), root(A_ROOT));
    ledger.add_mm(key(B, 1), root(B_ROOT));
    ledger.add_extent(A_FRAME, 16 * PAGE, key(A, 1));
    ledger.add_extent(B_FRAME, 16 * PAGE, key(B, 1));
    ledger
}

fn run(ledger: &mut TestLedger, edits: &[Edit]) -> ConsumeReport<Fault> {
    consume(ledger, edits.iter().map(Edit::record), &[]).unwrap()
}

fn only_cause(report: &ConsumeReport<Fault>) -> QuarantineCause<Fault> {
    assert_eq!(report.quarantined.len(), 1, "{report:?}");
    report.quarantined[0].cause
}

fn a_map(ledger: &mut TestLedger, counter: u64, id: u64, frame: u64) -> Edit {
    let out = ledger.issue(key(A, 1), id, frame, ExtentAccess::Owner);
    Edit::a(counter).output(out)
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

// H1: shared frames.

#[test]
fn foreign_output_without_edge_quarantines() {
    let mut ledger = two_mms();
    // Even a host ticket cannot make B's frame A's without an edge.
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::ForeignOutput);
    assert!(ledger.mm_quarantined(key(A, 1)));
    assert!(!ledger.mm_quarantined(key(B, 1)));
}

#[test]
fn foreign_output_with_exact_edge_applies() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1), EdgeKind::Shared);
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!((report.applied, report.quarantined.len()), (1, 0));
}

#[test]
fn stale_edge_generation_quarantines() {
    let mut ledger = two_mms();
    let old = ledger.share(B_FRAME, key(A, 1), EdgeKind::Shared);
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(old));
    // The host revokes and re-mints after the ticket was issued.
    ledger.custody_mut(B_FRAME).revoke_edge(key(A, 1));
    ledger.share(B_FRAME, key(A, 1), EdgeKind::Shared);
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::StaleEdge);
}

#[test]
fn owner_death_leaves_edge_only_custody() {
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1), EdgeKind::Shared);
    assert_eq!(
        ledger.custody_mut(B_FRAME).retire_owner(),
        OwnerRetired::EdgeOnly { edges: 1 }
    );
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(report.applied, 1);
    let custody = ledger.custody_mut(B_FRAME);
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
    let edge = ledger.share(B_FRAME, key(A, 1), EdgeKind::CowInherited);
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::CowWritable);

    // Read-only through the COW edge is fine.
    let mut ledger = two_mms();
    let edge = ledger.share(B_FRAME, key(A, 1), EdgeKind::CowInherited);
    let out = ledger.issue(key(A, 1), 1, B_FRAME, ExtentAccess::Edge(edge));
    let report = run(&mut ledger, &[Edit::a(1).output(out).permissions(RO)]);
    assert_eq!(report.applied, 1);
    // ...but the owner may not map it writable while the edge exists.
    let out = ledger.issue(key(B, 1), 1, B_FRAME, ExtentAccess::Owner);
    let report = run(&mut ledger, &[Edit::b(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::CowWritable);
}

#[test]
fn writable_protect_of_cow_shared_frame_quarantines() {
    let mut ledger = two_mms();
    ledger.share(A_FRAME, key(B, 1), EdgeKind::CowInherited);
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let protect = Edit::a(1).kind(PublicationKind::Protect).prior(A_FRAME);
    let report = run(&mut ledger, &[protect]);
    assert_eq!(only_cause(&report), QuarantineCause::CowWritable);
}

// H2: prior output.

#[test]
fn prior_of_another_mm_quarantines() {
    for kind in [PublicationKind::CowRepoint, PublicationKind::Unmap] {
        let mut ledger = two_mms();
        ledger.add_alias(key(B, 1), B_FRAME, ExtentAccess::Owner);
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
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner);
    ledger.aliases.get_mut(&(key(A, 1), A_FRAME)).unwrap().len = GuestLen::new(2 * PAGE);
    let unmap = Edit::a(1).kind(PublicationKind::Unmap).prior(A_FRAME);
    assert_eq!(
        only_cause(&run(&mut ledger, &[unmap])),
        QuarantineCause::PriorLength
    );

    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner);
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
    let edit = Edit::new(key(A, 2), 1, A_ROOT);
    let report = run(
        &mut ledger,
        &[edit.kind(PublicationKind::Protect).permissions(RO)],
    );
    assert_eq!(only_cause(&report), QuarantineCause::StaleIncarnation);
    assert!(!ledger.mm_quarantined(key(A, 1)));
}

#[test]
fn root_of_another_mm_quarantines() {
    let mut ledger = two_mms();
    let edit = Edit::new(key(A, 1), 1, B_ROOT).kind(PublicationKind::Protect);
    let report = run(&mut ledger, &[edit.permissions(RO)]);
    assert_eq!(only_cause(&report), QuarantineCause::RootMismatch);
}

#[test]
fn stale_owner_generation_quarantines() {
    let mut ledger = two_mms();
    let mut out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    ledger.custody_mut(A_FRAME).owner_generation = owner_gen(GEN + 1);
    out.owner_generation = owner_gen(GEN);
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::StaleOwnerGeneration);
}

#[test]
fn recycled_slot_rejects_predecessor_records() {
    let mut ledger = two_mms();
    let out = ledger.issue(key(A, 1), 1, A_FRAME, ExtentAccess::Owner);
    // Slot A retires and is recycled as incarnation 2 with the same root.
    ledger.states.remove(&key(A, 1));
    ledger.add_mm(key(A, 2), root(A_ROOT));
    let report = run(&mut ledger, &[Edit::a(1).output(out)]);
    assert_eq!(only_cause(&report), QuarantineCause::StaleIncarnation);
    // The successor cannot spend its predecessor's ticket or frame.
    let stale = Edit::new(key(A, 2), 1, A_ROOT).output(out);
    let report = run(&mut ledger, &[stale]);
    assert_eq!(only_cause(&report), QuarantineCause::NoTicket);
}

// H6: admission.

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
}

#[test]
fn postcondition_hook_failure_quarantines() {
    let mut ledger = two_mms();
    ledger.fail_postcondition = true;
    let edit = a_map(&mut ledger, 1, 1, A_FRAME);
    assert_eq!(
        only_cause(&run(&mut ledger, &[edit])),
        QuarantineCause::Postcondition(Fault::Postcondition)
    );
    assert!(ledger.aliases.is_empty());
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

// H4: drains.

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
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::DrainDebt(counter(1)))
    );
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)),
        Ok(1)
    );
    assert_eq!(
        ledger.released,
        [(key(A, 1), DeferredRelease::Ticket(ticket_id(1)))]
    );
    assert_eq!(retirement_permitted(&mut ledger, key(A, 1)), Ok(()));
}

#[test]
fn x86_shootdown_claim_never_clears_debt() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner);
    let local = Edit::a(1)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::X86_64, PublicationDrain::Local);
    let claim = Edit::a(2)
        .kind(PublicationKind::Protect)
        .permissions(RO)
        .drain(GuestIsa::X86_64, PublicationDrain::X86ShootdownClaim);
    run(&mut ledger, &[local, claim]);
    // The unmapped frame stays held: a remote CPU may still translate it.
    assert!(ledger.released.is_empty());
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(1))
    );
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(3)),
        Err(DrainAckError::Unconsumed)
    );
    // A host drain through counter 1 settles only that debt.
    assert_eq!(
        acknowledge_global_drain(&mut ledger, key(A, 1), counter(1)),
        Ok(1)
    );
    assert!(matches!(
        ledger.released[..],
        [(_, DeferredRelease::Prior(PublishedPrior { address, .. }))] if address.raw() == A_FRAME
    ));
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::DrainDebt(counter(2)))
    );
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(retirement_permitted(&mut ledger, key(A, 1)), Ok(()));
}

#[test]
fn arm_span_broadcast_does_not_clear_other_spans() {
    let mut ledger = two_mms();
    ledger.add_alias(key(A, 1), A_FRAME, ExtentAccess::Owner);
    ledger.add_alias(key(A, 1), A_FRAME + PAGE, ExtentAccess::Owner);
    let local = Edit::a(1)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    let span = Edit::a(2)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME + PAGE)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    run(&mut ledger, &[local, span]);
    // Only the broadcast record's own prior returns.
    assert!(matches!(
        ledger.released[..],
        [(_, DeferredRelease::Prior(PublishedPrior { address, .. }))] if address.raw() == A_FRAME + PAGE
    ));
    assert_eq!(
        ledger.state(key(A, 1)).oldest_drain_debt(),
        Some(counter(1))
    );

    // An ASID-wide broadcast settles every earlier debt.
    let asid = Edit::a(3).kind(PublicationKind::Protect).permissions(RO);
    run(&mut ledger, &[asid]);
    assert_eq!(ledger.released.len(), 2);
    assert_eq!(retirement_permitted(&mut ledger, key(A, 1)), Ok(()));
}

#[test]
fn local_debt_is_per_mm() {
    let mut ledger = two_mms();
    let protect = Edit::a(1)
        .kind(PublicationKind::Protect)
        .permissions(RO)
        .drain(GuestIsa::Aarch64, PublicationDrain::Local);
    run(&mut ledger, &[protect]);
    assert!(retirement_permitted(&mut ledger, key(A, 1)).is_err());
    assert_eq!(retirement_permitted(&mut ledger, key(B, 1)), Ok(()));
}

// H5: dense counters.

#[test]
fn counters_order_records_across_rings() {
    let mut ledger = two_mms();
    let first = a_map(&mut ledger, 1, 1, A_FRAME);
    let second = Edit::a(2)
        .kind(PublicationKind::Unmap)
        .prior(A_FRAME)
        .drain(GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan);
    // Ring 2 drained before ring 1: the unmap arrives first.
    let report = consume(
        &mut ledger,
        [second.record(), first.record()],
        &[(key(A, 1), counter(2))],
    )
    .unwrap();
    assert_eq!((report.applied, report.quarantined.len()), (2, 0));
    assert!(ledger.aliases.is_empty());
}

#[test]
fn late_record_is_held_until_its_gap_fills() {
    let mut ledger = two_mms();
    let first = a_map(&mut ledger, 1, 1, A_FRAME);
    let second = Edit::a(2).kind(PublicationKind::Protect).permissions(RO);
    // Counter 1 was not yet published when the watermark was read.
    let report = consume(&mut ledger, [second.record()], &[]).unwrap();
    assert_eq!((report.applied, report.deferred), (0, 1));
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::UnsettledRecords)
    );
    let report = consume(&mut ledger, [first.record()], &[(key(A, 1), counter(2))]).unwrap();
    assert_eq!((report.applied, report.deferred), (2, 0));
}

#[test]
fn lost_record_quarantines_only_that_mm() {
    let mut ledger = two_mms();
    let second = Edit::a(2).kind(PublicationKind::Protect).permissions(RO);
    let b = Edit::b(1).kind(PublicationKind::Protect).permissions(RO);
    let report = consume(
        &mut ledger,
        [second.record(), b.record()],
        &[(key(A, 1), counter(2)), (key(B, 1), counter(1))],
    )
    .unwrap();
    assert_eq!(only_cause(&report), QuarantineCause::LostRecord);
    assert_eq!(report.quarantined[0].mm, key(A, 1));
    assert_eq!(report.applied, 1);
    assert!(!ledger.mm_quarantined(key(B, 1)));
}

#[test]
fn duplicate_counter_quarantines() {
    let mut ledger = two_mms();
    let protect = Edit::a(1).kind(PublicationKind::Protect).permissions(RO);
    run(&mut ledger, &[protect]);
    assert_eq!(
        only_cause(&run(&mut ledger, &[protect])),
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
    let good = Edit::a(2).kind(PublicationKind::Protect).permissions(RO);
    let report = run(&mut ledger, &[good]);
    assert_eq!((report.applied, report.quarantined.len()), (0, 0));
    assert_eq!(
        retirement_permitted(&mut ledger, key(A, 1)),
        Err(RetirementBlocked::Quarantined)
    );
}

#[test]
fn torn_record_quarantines_the_carrier() {
    let mut ledger = two_mms();
    let edit = a_map(&mut ledger, 1, 1, A_FRAME);
    let mut record = edit.record();
    // SAFETY: test-only corruption of a plain `repr(C)` Copy record; decode
    // must reject it.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut record as *mut MmPublication).cast::<u8>(),
            MmPublication::SIZE,
        )
    };
    bytes[88] ^= 1;
    assert_eq!(
        consume(&mut ledger, [record], &[]),
        Err(CarrierQuarantine::Malformed {
            index: 0,
            reason: PublicationDecodeError::Digest
        })
    );
    assert_eq!(
        consume(&mut ledger, [edit.record()], &[]),
        Err(CarrierQuarantine::AlreadyQuarantined)
    );
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
    acknowledge_global_drain(&mut ledger, key(A, 1), counter(2)).unwrap();
    assert_eq!(ledger.released.len(), 1);
}

/// Adversarial population: many unrelated extents, aliases, tickets and MMs
/// must not change how many ledger entries the consumer touches.
fn visits_with_population(unrelated: u64) -> (usize, usize) {
    let mut ledger = two_mms();
    for i in 0..unrelated {
        let base = 0x1000_0000 + i * PAGE;
        let owner = if i % 2 == 0 { key(B, 1) } else { key(A, 1) };
        ledger.add_extent(base, PAGE, owner);
        ledger.add_alias(owner, base, ExtentAccess::Owner);
        ledger.issue(owner, 1000 + i, base, ExtentAccess::Owner);
    }
    for i in 0..unrelated / 4 {
        ledger.add_mm(key(100 + i, 1), root(0x4000_0000 + i * PAGE));
    }
    let map = a_map(&mut ledger, 1, 1, A_FRAME);
    let out = ledger.issue(key(A, 1), 2, A_FRAME + PAGE, ExtentAccess::Owner);
    let refused = ledger.issue(key(B, 1), 3, B_FRAME, ExtentAccess::Owner);
    let records = [
        map.record(),
        Edit::a(2)
            .kind(PublicationKind::CowRepoint)
            .output(out)
            .prior(A_FRAME)
            .permissions(RO)
            .record(),
        Edit::b(1)
            .output(refused)
            .outcome(PublicationOutcome::Refused)
            .record(),
        Edit::a(3)
            .kind(PublicationKind::Unmap)
            .prior(A_FRAME + PAGE)
            .drain(GuestIsa::Aarch64, PublicationDrain::Local)
            .record(),
    ];
    ledger.examined.set(0);
    let report = consume(&mut ledger, records, &[(key(A, 1), counter(3))]).unwrap();
    assert!(report.quarantined.is_empty(), "{report:?}");
    (report.ledger_visits, ledger.examined.get())
}

#[test]
fn visits_bounded_by_records_and_touched_edges() {
    let small = visits_with_population(8);
    let large = visits_with_population(8192);
    assert_eq!(small, large);
    // 4 MM lookups + 3 tickets + 3 custodies + 2 priors.
    assert_eq!(small.0, 12);
}
