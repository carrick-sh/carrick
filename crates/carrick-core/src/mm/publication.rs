//! Neutral host consumer for MMU publication v2 records.
//!
//! Threat model: the EL1/CPL0 kernel that edits descriptors and publishes
//! records is Carrick's own code. This consumer is a fail-closed *checker*
//! against kernel bugs and against anything guest user code can influence;
//! it is not a hardened boundary against a malicious kernel, and Carrick
//! makes no adversarial security claim.
//!
//! The guest plans and executes every descriptor edit and publishes one
//! [`MmPublication`] per settled edit into a ring the host bound to exactly
//! one producer MM. The host's part is:
//!
//! 1. **Admission, before any store**: while [`admission_permitted`] holds,
//!    the ledger issues an [`AdmissionTicket`] naming the output, its leaf,
//!    the exact extent access (owner or one share edge), the permission
//!    ceiling and table grants.
//! 2. **Consumption**: [`consume`] attributes every record to its ring's
//!    bound MM, takes ISA and drain authority from host-owned identity,
//!    orders records by their dense [`PublicationCounter`], authenticates
//!    each against the ticket, the extent's live custody and the publisher's
//!    exact prior alias (frame, VA span, length, owner generation, permission
//!    ceiling), then applies it or moves its custody.
//! 3. **Drain settlement**: custody a remote CPU may still translate to (a
//!    replaced prior, a rolled-back output, a write permission being
//!    revoked) is held until a drain the host trusts covers it.
//!
//! Remaining trust assumption: the host does not re-walk guest descriptors.
//! It checks that every named frame, span and permission is one it
//! authorized, and relies on stage-2 confinement for the rest: guest stores
//! can only name frames stage-2 exposes to the VM, each exposed frame is
//! under a ticket or an authenticated alias, and a kernel bug that stores a
//! descriptor without publishing it is outside what this checker can see.
//!
//! Any mismatch quarantines the producer's bound MM, never an MM a record
//! merely names. The host never authors a corrective edit.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use carrick_core_abi::{
    EdgeGeneration, ExtentAccess, InventoryRevision, MmIncarnation, MmIncarnationKey,
    MmPublication, OwnerGeneration, PublicationCounter, PublicationDecodeError, PublicationDrain,
    PublicationKind, PublicationMm, PublicationOutcome, PublicationView, PublishedPrior, Stage1Ipa,
    TableGrantCount, TicketId, leaf_bytes,
};
use carrick_guest_arch::{EditLeafSize, EditPermissions, GuestIsa, GuestLen, RootGpa, UserVa};
use core::num::NonZeroU64;

/// Out-of-order records held per MM after the contiguous prefix has been
/// consumed. Exceeding it means the producer is not draining in order.
pub const MAX_DEFERRED_PER_MM: usize = 256;

/// Held custody (replaced priors, rolled-back outputs) per MM before
/// [`admission_permitted`] applies backpressure to new tickets.
pub const MAX_HELD_SETTLEMENTS_PER_MM: usize = 256;

/// Host-assigned identity of one publication ring.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RingId(pub NonZeroU64);

/// Ledger facts for one live MM slot, including the ISA its kernel runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMm {
    pub incarnation: MmIncarnation,
    pub root: RootGpa,
    pub isa: GuestIsa,
}

/// Host admission for one prepared output, issued before the guest may store
/// a descriptor naming it. An Applied record must match an outstanding one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionTicket {
    pub output: Stage1Ipa,
    pub leaf: EditLeafSize,
    pub len: GuestLen,
    pub owner_generation: OwnerGeneration,
    pub access: ExtentAccess,
    pub inventory_revision: InventoryRevision,
    pub max_permissions: EditPermissions,
    pub table_grants: TableGrantCount,
}

/// One live alias the ledger recorded for an exact (mm, incarnation): its
/// user VA span, frame identity, current permissions and the ceiling its
/// ticket authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerAlias {
    pub va: UserVa,
    pub len: GuestLen,
    pub owner_generation: OwnerGeneration,
    pub access: ExtentAccess,
    pub permissions: EditPermissions,
    pub max_permissions: EditPermissions,
}

/// Why a share edge exists. Shared edges carry MAP_SHARED / attach_shared
/// semantics and may be writable; COW edges come from fork custody and are
/// read-only for every holder, including the owner, while any exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeKind {
    Shared,
    CowInherited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareEdge {
    pub generation: EdgeGeneration,
    pub kind: EdgeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDenied {
    /// Neither the owner nor the holder of any edge.
    Foreign,
    /// An edge exists for this MM but with a different generation.
    StaleEdge,
}

/// Remaining custody after the owner retires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerRetired {
    /// Share edges keep the extent alive; it is now edge-only.
    EdgeOnly { edges: usize },
    /// No owner and no edges: the extent may return to capacity.
    Reclaimable,
}

/// Proof that no writable alias of an extent was live (published and not yet
/// drained away) when it was taken. Only [`ExtentCustody::begin_cow`] creates
/// one, and [`ExtentCustody::mint_cow_edge`] rejects it if a writable alias
/// has appeared since.
#[derive(Debug, Eq, PartialEq)]
pub struct CowTransition {
    writable_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CowTransitionError {
    /// Writable aliases are live or their downgrade has not drained.
    WritableAliasesLive(u32),
    /// A writable alias was published after the transition began.
    Stale,
    Exhausted,
}

/// Owner plus host-minted share edges for one physical extent, keyed by the
/// exact (mm, incarnation) and edge generation, and a count of live writable
/// aliases that only the consumer maintains. Every ledger embeds this, so
/// owner-or-edge authentication has one implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentCustody {
    owner: Option<MmIncarnationKey>,
    owner_generation: OwnerGeneration,
    edges: BTreeMap<MmIncarnationKey, ShareEdge>,
    cow_edges: usize,
    next_edge: u64,
    writable_aliases: u32,
    writable_epoch: u64,
}

impl ExtentCustody {
    pub fn new(owner: MmIncarnationKey, owner_generation: OwnerGeneration) -> Self {
        Self {
            owner: Some(owner),
            owner_generation,
            edges: BTreeMap::new(),
            cow_edges: 0,
            next_edge: 0,
            writable_aliases: 0,
            writable_epoch: 0,
        }
    }
    pub const fn owner(&self) -> Option<MmIncarnationKey> {
        self.owner
    }
    pub const fn owner_generation(&self) -> OwnerGeneration {
        self.owner_generation
    }
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
    pub fn edge(&self, mm: MmIncarnationKey) -> Option<ShareEdge> {
        self.edges.get(&mm).copied()
    }
    /// Writable aliases published and not yet drained away.
    pub const fn writable_aliases(&self) -> u32 {
        self.writable_aliases
    }

    fn mint(&mut self, mm: MmIncarnationKey, kind: EdgeKind) -> Option<EdgeGeneration> {
        self.next_edge = self.next_edge.checked_add(1)?;
        let generation = EdgeGeneration::new(NonZeroU64::new(self.next_edge)?);
        if kind == EdgeKind::CowInherited {
            self.cow_edges = self.cow_edges.checked_add(1)?;
        }
        if let Some(old) = self.edges.insert(mm, ShareEdge { generation, kind })
            && old.kind == EdgeKind::CowInherited
        {
            self.cow_edges = self.cow_edges.saturating_sub(1);
        }
        Some(generation)
    }

    /// Mint a fresh shared (MAP_SHARED / attach_shared) edge for `mm`.
    ///
    /// # Safety
    /// Only the host share/attach_shared path may call this, after it has
    /// itself authorized `mm` to reach this extent. A guest record never
    /// mints an edge.
    pub unsafe fn mint_shared_edge(&mut self, mm: MmIncarnationKey) -> Option<EdgeGeneration> {
        self.mint(mm, EdgeKind::Shared)
    }

    /// Begin a fork-custody transition: succeeds only when no writable alias
    /// is live, i.e. every one was downgraded or removed and that drain
    /// settled.
    pub fn begin_cow(&self) -> Result<CowTransition, CowTransitionError> {
        if self.writable_aliases != 0 {
            return Err(CowTransitionError::WritableAliasesLive(
                self.writable_aliases,
            ));
        }
        Ok(CowTransition {
            writable_epoch: self.writable_epoch,
        })
    }

    /// Mint a fork-custody (COW) edge for `mm` under a transition proof.
    ///
    /// # Safety
    /// Only fork custody may call this, after it has itself authorized `mm`
    /// to inherit this extent.
    pub unsafe fn mint_cow_edge(
        &mut self,
        mm: MmIncarnationKey,
        proof: CowTransition,
    ) -> Result<EdgeGeneration, CowTransitionError> {
        if proof.writable_epoch != self.writable_epoch || self.writable_aliases != 0 {
            return Err(CowTransitionError::Stale);
        }
        self.mint(mm, EdgeKind::CowInherited)
            .ok_or(CowTransitionError::Exhausted)
    }

    pub fn revoke_edge(&mut self, mm: MmIncarnationKey) -> Option<ShareEdge> {
        let edge = self.edges.remove(&mm)?;
        if edge.kind == EdgeKind::CowInherited {
            self.cow_edges = self.cow_edges.saturating_sub(1);
        }
        Some(edge)
    }

    /// The owner died: custody continues through its edges, refcounted.
    pub fn retire_owner(&mut self) -> OwnerRetired {
        self.owner = None;
        match self.edges.len() {
            0 => OwnerRetired::Reclaimable,
            edges => OwnerRetired::EdgeOnly { edges },
        }
    }

    /// Authenticate `access` by `mm`: the exact owner, or its exact edge.
    pub fn admits(&self, mm: MmIncarnationKey, access: ExtentAccess) -> Result<(), AccessDenied> {
        match access {
            ExtentAccess::Owner if self.owner == Some(mm) => Ok(()),
            ExtentAccess::Owner => Err(AccessDenied::Foreign),
            ExtentAccess::Edge(generation) => match self.edges.get(&mm) {
                Some(edge) if edge.generation == generation => Ok(()),
                Some(_) => Err(AccessDenied::StaleEdge),
                None => Err(AccessDenied::Foreign),
            },
        }
    }

    /// COW safety: no holder may map the extent writable while any fork
    /// custody edge shares it.
    pub fn writable_allowed(&self, mm: MmIncarnationKey, access: ExtentAccess) -> bool {
        self.cow_edges == 0
            && match access {
                ExtentAccess::Owner => true,
                ExtentAccess::Edge(_) => self
                    .edges
                    .get(&mm)
                    .is_some_and(|edge| edge.kind == EdgeKind::Shared),
            }
    }

    fn writable_published(&mut self) -> Option<()> {
        self.writable_aliases = self.writable_aliases.checked_add(1)?;
        self.writable_epoch = self.writable_epoch.checked_add(1)?;
        Some(())
    }

    fn writable_drained(&mut self) -> Option<()> {
        self.writable_aliases = self.writable_aliases.checked_sub(1)?;
        Some(())
    }
}

/// Custody returned to the ledger, after the drain covering it if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredRelease {
    /// A refused edit's own outstanding ticket (no store happened).
    Ticket(TicketId),
    /// A rolled-back edit's ticket, already moved out of Outstanding by
    /// [`PhysicalLedger::hold_ticket`]; it can no longer be spent.
    HeldOutput(TicketId),
    /// A replaced or removed prior alias's frame.
    Prior(PublishedPrior),
}

/// Everything one record leaves held until its drain settles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Settlement {
    release: Option<DeferredRelease>,
    /// A writable alias of this frame stops being live once drained.
    writable_drop: Option<Stage1Ipa>,
}
impl Settlement {
    const fn is_empty(&self) -> bool {
        self.release.is_none() && self.writable_drop.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    Open,
    Closed {
        final_through: Option<PublicationCounter>,
    },
}

/// Publication bookkeeping for one (mm, incarnation). The ledger stores it
/// next to the MM; only this module changes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmPublicationState {
    next: PublicationCounter,
    deferred: BTreeMap<PublicationCounter, PublicationView>,
    /// Records with stores but nothing held, compacted to one range.
    uncovered: Option<(PublicationCounter, PublicationCounter)>,
    held: BTreeMap<PublicationCounter, Settlement>,
    admission: Admission,
}

impl Default for MmPublicationState {
    fn default() -> Self {
        Self::new()
    }
}

impl MmPublicationState {
    pub const fn new() -> Self {
        Self {
            next: PublicationCounter::FIRST,
            deferred: BTreeMap::new(),
            uncovered: None,
            held: BTreeMap::new(),
            admission: Admission::Open,
        }
    }
    /// The next counter this MM must publish.
    pub const fn next_counter(&self) -> PublicationCounter {
        self.next
    }
    /// Oldest record with stores not yet covered by a trusted drain.
    pub fn oldest_drain_debt(&self) -> Option<PublicationCounter> {
        let held = self.held.keys().next().copied();
        let uncovered = self.uncovered.map(|(first, _)| first);
        match (held, uncovered) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Records that still hold custody until a drain settles.
    pub fn held_settlements(&self) -> usize {
        self.held.len()
    }
    pub fn deferred_records(&self) -> usize {
        self.deferred.len()
    }
    fn settle_through(&mut self, through: PublicationCounter) -> Vec<Settlement> {
        if let Some((first, last)) = self.uncovered {
            self.uncovered = if last <= through {
                None
            } else if first <= through {
                through.next().map(|after| (after, last))
            } else {
                Some((first, last))
            };
        }
        let later = match through.next() {
            Some(after) => self.held.split_off(&after),
            None => BTreeMap::new(),
        };
        core::mem::replace(&mut self.held, later)
            .into_values()
            .collect()
    }
    fn hold(&mut self, counter: PublicationCounter, settlement: Settlement) {
        if settlement.is_empty() {
            self.uncovered = Some(match self.uncovered {
                Some((first, _)) => (first, counter),
                None => (counter, counter),
            });
        } else {
            self.held.insert(counter, settlement);
        }
    }
}

/// A record that passed every ledger check. Only [`consume`] constructs it,
/// so a ledger can never apply or release an unauthenticated record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPublication {
    view: PublicationView,
    ticket: Option<AdmissionTicket>,
    prior: Option<LedgerAlias>,
}

impl AuthenticatedPublication {
    pub const fn view(&self) -> &PublicationView {
        &self.view
    }
    pub const fn ticket(&self) -> Option<AdmissionTicket> {
        self.ticket
    }
    pub const fn prior_alias(&self) -> Option<LedgerAlias> {
        self.prior
    }
}

/// The host's physical ledger, as seen by the neutral consumer. Every lookup
/// is by stage-1 IPA or exact identity; none resolves a user VA.
pub trait PhysicalLedger {
    type Fault: Copy + core::fmt::Debug;

    /// Per-MM quarantine: sticky; other MMs keep running.
    fn mm_quarantined(&self, mm: MmIncarnationKey) -> bool;
    fn quarantine_mm(&mut self, mm: MmIncarnationKey);

    /// Live incarnation, root and ISA of `mm`'s slot.
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm>;
    fn publication_state(&mut self, mm: MmIncarnationKey) -> Option<&mut MmPublicationState>;

    /// An *outstanding* ticket issued to exactly `mm`; held tickets are not
    /// returned.
    fn ticket(&self, mm: MmIncarnationKey, ticket: TicketId) -> Option<AdmissionTicket>;
    fn outstanding_tickets(&self, mm: MmIncarnationKey) -> usize;
    /// Live custody of the extent containing `address`.
    fn custody(&self, address: Stage1Ipa) -> Option<&ExtentCustody>;
    fn custody_mut(&mut self, address: Stage1Ipa) -> Option<&mut ExtentCustody>;
    /// The live alias `mm` holds at stage-1 output `address`.
    fn alias(&self, mm: MmIncarnationKey, address: Stage1Ipa) -> Option<LedgerAlias>;

    /// Commit an Applied record all-or-nothing: consume its ticket and publish
    /// the output alias (VA = span start, ceiling = ticket ceiling) with its
    /// table grants; update a protected alias's permissions; drop a replaced
    /// or removed prior alias. Prior custody is not returned here.
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Self::Fault>;
    /// Move a rolled-back edit's ticket out of Outstanding into held
    /// custody, atomically: from now on it cannot be spent or released by
    /// any record, only by [`DeferredRelease::HeldOutput`].
    fn hold_ticket(&mut self, mm: MmIncarnationKey, ticket: TicketId) -> Result<(), Self::Fault>;
    /// Return custody to capacity.
    fn release(
        &mut self,
        mm: MmIncarnationKey,
        release: DeferredRelease,
    ) -> Result<(), Self::Fault>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineCause<F> {
    UnknownMm,
    StaleIncarnation,
    Malformed(PublicationDecodeError),
    /// The record names an MM other than its ring's bound producer.
    ProducerMismatch,
    /// The record's ISA disagrees with the producer's host-owned ISA.
    IsaMismatch,
    RootMismatch,
    DuplicateCounter,
    LostRecord,
    DeferralOverflow,
    NoTicket,
    TicketMismatch,
    PermissionEscalation,
    TableGrantOverrun,
    UnbackedOutput,
    StaleOwnerGeneration,
    ForeignOutput,
    StaleEdge,
    CowWritable,
    ForeignPrior,
    PriorLength,
    StalePriorGeneration,
    /// The record's span is not the VA span of its authenticated prior.
    SpanMismatch,
    CustodyAccounting,
    Ledger(F),
}

/// One producer quarantined by this batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quarantine<F> {
    pub ring: Option<RingId>,
    pub mm: MmIncarnationKey,
    pub counter: Option<PublicationCounter>,
    pub cause: QuarantineCause<F>,
}

/// Records drained from one ring, attributed to the producer MM the host
/// bound to that ring.
#[derive(Clone, Copy, Debug)]
pub struct RingBatch<'a> {
    pub ring: RingId,
    pub bound: MmIncarnationKey,
    pub records: &'a [MmPublication],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsumeReport<F> {
    pub applied: usize,
    pub released: usize,
    pub deferred: usize,
    /// Ledger lookups made by the consumer: a constant per record and per
    /// batch, never a function of unrelated extents, aliases or MMs.
    pub ledger_visits: usize,
    pub quarantined: Vec<Quarantine<F>>,
}

const fn permissions_within(asked: EditPermissions, allowed: EditPermissions) -> bool {
    (!asked.readable || allowed.readable)
        && (!asked.writable || allowed.writable)
        && (!asked.executable || allowed.executable)
        && (!asked.user || allowed.user)
}

/// Ceiling for a record that names neither an output nor a prior alias
/// (Publish, ArmCow, a downgrade-only Protect): never write or execute.
const NO_GRANT_CEILING: EditPermissions = EditPermissions {
    readable: true,
    writable: false,
    executable: false,
    user: true,
};

fn authenticate<L: PhysicalLedger>(
    ledger: &L,
    live: LedgerMm,
    view: PublicationView,
    visits: &mut usize,
) -> Result<AuthenticatedPublication, QuarantineCause<L::Fault>> {
    use QuarantineCause as Q;
    let key = view.key();
    if live.root != view.root() {
        return Err(Q::RootMismatch);
    }
    let span = view.span();
    let mut ticket = None;
    let mut ceiling = NO_GRANT_CEILING;
    if let Some(out) = view.output() {
        *visits += 1;
        let issued = ledger.ticket(key, out.ticket).ok_or(Q::NoTicket)?;
        if issued.owner_generation != out.owner_generation {
            return Err(Q::StaleOwnerGeneration);
        }
        if issued.output != out.address
            || issued.leaf != out.leaf
            || issued.len != span.len()
            || issued.access != out.access
            || issued.inventory_revision != out.inventory_revision
        {
            return Err(Q::TicketMismatch);
        }
        if view.table_grants() > issued.table_grants {
            return Err(Q::TableGrantOverrun);
        }
        *visits += 1;
        let custody = ledger.custody(out.address).ok_or(Q::UnbackedOutput)?;
        if custody.owner_generation() != out.owner_generation {
            return Err(Q::StaleOwnerGeneration);
        }
        custody
            .admits(key, out.access)
            .map_err(|denied| match denied {
                AccessDenied::Foreign => Q::ForeignOutput,
                AccessDenied::StaleEdge => Q::StaleEdge,
            })?;
        if view.permissions().writable && !custody.writable_allowed(key, out.access) {
            return Err(Q::CowWritable);
        }
        ceiling = issued.max_permissions;
        ticket = Some(issued);
    }
    let mut prior_alias = None;
    if let Some(prior) = view.prior()
        && view.outcome() != PublicationOutcome::Refused
    {
        *visits += 1;
        let alias = ledger.alias(key, prior.address).ok_or(Q::ForeignPrior)?;
        if alias.len.raw() != leaf_bytes(prior.leaf) {
            return Err(Q::PriorLength);
        }
        if alias.owner_generation != prior.owner_generation {
            return Err(Q::StalePriorGeneration);
        }
        // Postcondition the host can check without walking descriptors: the
        // edit's span is exactly the VA span of the alias it names.
        if alias.va != span.start() || alias.len != span.len() {
            return Err(Q::SpanMismatch);
        }
        if view.output().is_none() {
            ceiling = alias.max_permissions;
        }
        if view.kind() == PublicationKind::Protect && view.permissions().writable {
            *visits += 1;
            let custody = ledger.custody(prior.address).ok_or(Q::ForeignPrior)?;
            if !custody.writable_allowed(key, alias.access) {
                return Err(Q::CowWritable);
            }
        }
        prior_alias = Some(alias);
    }
    if view.outcome() != PublicationOutcome::Refused
        && !permissions_within(view.permissions(), ceiling)
    {
        return Err(Q::PermissionEscalation);
    }
    Ok(AuthenticatedPublication {
        view,
        ticket,
        prior: prior_alias,
    })
}

/// How much of the guest's drain claim the host trusts, given the
/// producer's host-owned ISA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustedDrain {
    /// Remote CPUs may still translate this record's span.
    None,
    /// This record's own span was broadcast-invalidated.
    OwnSpan,
    /// The whole ASID was broadcast-invalidated: every earlier debt settles.
    WholeMm,
}

const fn trusted_drain(producer_isa: GuestIsa, drain: PublicationDrain) -> TrustedDrain {
    match (producer_isa, drain) {
        (GuestIsa::Aarch64, PublicationDrain::ArmBroadcastAsid) => TrustedDrain::WholeMm,
        (GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan) => TrustedDrain::OwnSpan,
        // x86 shootdown claims are kernel assertions the host does not
        // observe; only the host's own `acknowledge_global_drain` clears x86
        // debt.
        _ => TrustedDrain::None,
    }
}

fn custody_step<L: PhysicalLedger>(
    ledger: &mut L,
    address: Stage1Ipa,
    step: fn(&mut ExtentCustody) -> Option<()>,
) -> Result<(), QuarantineCause<L::Fault>> {
    ledger
        .custody_mut(address)
        .and_then(step)
        .ok_or(QuarantineCause::CustodyAccounting)
}

fn complete<L: PhysicalLedger>(
    ledger: &mut L,
    key: MmIncarnationKey,
    settlement: Settlement,
) -> Result<usize, QuarantineCause<L::Fault>> {
    if let Some(frame) = settlement.writable_drop {
        custody_step(ledger, frame, ExtentCustody::writable_drained)?;
    }
    match settlement.release {
        Some(release) => {
            ledger
                .release(key, release)
                .map_err(QuarantineCause::Ledger)?;
            Ok(1)
        }
        None => Ok(0),
    }
}

fn settle<L: PhysicalLedger>(
    ledger: &mut L,
    producer_isa: GuestIsa,
    record: &AuthenticatedPublication,
    report: &mut ConsumeReport<L::Fault>,
) -> Result<(), QuarantineCause<L::Fault>> {
    let view = record.view;
    let key = view.key();
    let writable = view.permissions().writable;
    let mut settlement = Settlement::default();
    match view.outcome() {
        PublicationOutcome::Refused => {
            // No store happened: this edit's own outstanding ticket returns.
            if let Some(out) = view.output() {
                ledger
                    .release(key, DeferredRelease::Ticket(out.ticket))
                    .map_err(QuarantineCause::Ledger)?;
                report.released += 1;
            }
            return Ok(());
        }
        PublicationOutcome::RolledBack => {
            if let Some(out) = view.output() {
                ledger
                    .hold_ticket(key, out.ticket)
                    .map_err(QuarantineCause::Ledger)?;
                settlement.release = Some(DeferredRelease::HeldOutput(out.ticket));
            }
        }
        PublicationOutcome::Applied => {
            ledger.apply(record).map_err(QuarantineCause::Ledger)?;
            report.applied += 1;
            if let Some(out) = view.output()
                && writable
            {
                custody_step(ledger, out.address, ExtentCustody::writable_published)?;
            }
            if let (Some(prior), Some(alias)) = (view.prior(), record.prior) {
                match view.kind() {
                    PublicationKind::CowRepoint | PublicationKind::Unmap => {
                        settlement.release = Some(DeferredRelease::Prior(prior));
                        if alias.permissions.writable {
                            settlement.writable_drop = Some(prior.address);
                        }
                    }
                    PublicationKind::Protect if alias.permissions.writable && !writable => {
                        settlement.writable_drop = Some(prior.address);
                    }
                    PublicationKind::Protect if !alias.permissions.writable && writable => {
                        custody_step(ledger, prior.address, ExtentCustody::writable_published)?;
                    }
                    _ => {}
                }
            }
        }
    }
    let mut settled = Vec::new();
    {
        let state = ledger
            .publication_state(key)
            .ok_or(QuarantineCause::UnknownMm)?;
        match trusted_drain(producer_isa, view.drain()) {
            TrustedDrain::None => state.hold(view.counter(), settlement),
            TrustedDrain::OwnSpan => settled.push(settlement),
            TrustedDrain::WholeMm => {
                settled.extend(state.settle_through(view.counter()));
                settled.push(settlement);
            }
        }
    }
    for settlement in settled {
        report.released += complete(ledger, key, settlement)?;
    }
    Ok(())
}

fn quarantine_mm<L: PhysicalLedger>(
    ledger: &mut L,
    report: &mut ConsumeReport<L::Fault>,
    ring: Option<RingId>,
    mm: MmIncarnationKey,
    counter: Option<PublicationCounter>,
    cause: QuarantineCause<L::Fault>,
) {
    ledger.quarantine_mm(mm);
    if let Some(state) = ledger.publication_state(mm) {
        state.deferred.clear();
    }
    report.quarantined.push(Quarantine {
        ring,
        mm,
        counter,
        cause,
    });
}

/// Consume one round drained from every ring at a common point.
///
/// Each record is attributed to its ring's bound MM; a record naming any
/// other identity, or an ISA other than the producer's, quarantines the
/// producer. `published` holds per-MM published-through counters the caller
/// read (acquire) *before* snapshotting the rings: every record at or below
/// that counter is visible in this round or an earlier one, so a missing one
/// is lost and quarantines its MM. The contiguous prefix is consumed first;
/// only records still beyond a gap count against [`MAX_DEFERRED_PER_MM`].
pub fn consume<L: PhysicalLedger>(
    ledger: &mut L,
    batches: &[RingBatch<'_>],
    published: &[(MmIncarnationKey, PublicationCounter)],
) -> ConsumeReport<L::Fault> {
    let mut report = ConsumeReport {
        applied: 0,
        released: 0,
        deferred: 0,
        ledger_visits: 0,
        quarantined: Vec::new(),
    };
    let mut groups: BTreeMap<
        MmIncarnationKey,
        (LedgerMm, BTreeMap<PublicationCounter, PublicationView>),
    > = BTreeMap::new();
    let mut ring_of: BTreeMap<MmIncarnationKey, RingId> = BTreeMap::new();
    for batch in batches {
        let bound = batch.bound;
        let ring = Some(batch.ring);
        if ledger.mm_quarantined(bound) {
            continue;
        }
        report.ledger_visits += 1;
        let live = match ledger.mm(bound.mm) {
            Some(live) if live.incarnation == bound.incarnation => live,
            Some(_) => {
                quarantine_mm(
                    ledger,
                    &mut report,
                    ring,
                    bound,
                    None,
                    QuarantineCause::StaleIncarnation,
                );
                continue;
            }
            None => {
                quarantine_mm(
                    ledger,
                    &mut report,
                    ring,
                    bound,
                    None,
                    QuarantineCause::UnknownMm,
                );
                continue;
            }
        };
        ring_of.insert(bound, batch.ring);
        for record in batch.records {
            if ledger.mm_quarantined(bound) {
                break;
            }
            let view = match record.decode() {
                Ok(view) => view,
                Err(reason) => {
                    quarantine_mm(
                        ledger,
                        &mut report,
                        ring,
                        bound,
                        None,
                        QuarantineCause::Malformed(reason),
                    );
                    break;
                }
            };
            let counter = Some(view.counter());
            let cause = if view.key() != bound {
                Some(QuarantineCause::ProducerMismatch)
            } else if view.isa() != live.isa {
                Some(QuarantineCause::IsaMismatch)
            } else {
                let group = groups
                    .entry(bound)
                    .or_insert_with(|| (live, BTreeMap::new()));
                let Some(state) = ledger.publication_state(bound) else {
                    quarantine_mm(
                        ledger,
                        &mut report,
                        ring,
                        bound,
                        counter,
                        QuarantineCause::UnknownMm,
                    );
                    break;
                };
                let duplicate = view.counter() < state.next
                    || state.deferred.contains_key(&view.counter())
                    || group.1.insert(view.counter(), view).is_some();
                duplicate.then_some(QuarantineCause::DuplicateCounter)
            };
            if let Some(cause) = cause {
                quarantine_mm(ledger, &mut report, ring, bound, counter, cause);
                break;
            }
        }
    }
    for (key, (live, mut incoming)) in groups {
        let ring = ring_of.get(&key).copied();
        loop {
            if ledger.mm_quarantined(key) {
                break;
            }
            let Some(state) = ledger.publication_state(key) else {
                break;
            };
            let next = state.next;
            let Some(view) = incoming
                .remove(&next)
                .or_else(|| state.deferred.remove(&next))
            else {
                break;
            };
            let Some(successor) = next.next() else {
                quarantine_mm(
                    ledger,
                    &mut report,
                    ring,
                    key,
                    Some(next),
                    QuarantineCause::LostRecord,
                );
                break;
            };
            state.next = successor;
            let outcome = authenticate(ledger, live, view, &mut report.ledger_visits)
                .and_then(|record| settle(ledger, live.isa, &record, &mut report));
            if let Err(cause) = outcome {
                quarantine_mm(ledger, &mut report, ring, key, Some(next), cause);
            }
        }
        if ledger.mm_quarantined(key) {
            continue;
        }
        let Some(state) = ledger.publication_state(key) else {
            continue;
        };
        state.deferred.append(&mut incoming);
        let deferred = state.deferred.len();
        if deferred > MAX_DEFERRED_PER_MM {
            quarantine_mm(
                ledger,
                &mut report,
                ring,
                key,
                None,
                QuarantineCause::DeferralOverflow,
            );
        } else {
            report.deferred += deferred;
        }
    }
    for &(key, through) in published {
        if ledger.mm_quarantined(key) {
            continue;
        }
        let Some(state) = ledger.publication_state(key) else {
            continue;
        };
        let next = state.next;
        if next <= through {
            let ring = ring_of.get(&key).copied();
            quarantine_mm(
                ledger,
                &mut report,
                ring,
                key,
                Some(next),
                QuarantineCause::LostRecord,
            );
        }
    }
    report
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainAckError<F> {
    UnknownMm,
    Quarantined,
    /// The acknowledgement names a counter not yet consumed.
    Unconsumed,
    Settlement(QuarantineCause<F>),
}

/// Record a drain the host itself performed over `mm`, covering every edit
/// through `through`. Settles that debt and returns its held custody.
/// Returns the number of custody releases.
pub fn acknowledge_global_drain<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
    through: PublicationCounter,
) -> Result<usize, DrainAckError<L::Fault>> {
    if ledger.mm_quarantined(mm) {
        return Err(DrainAckError::Quarantined);
    }
    let state = ledger
        .publication_state(mm)
        .ok_or(DrainAckError::UnknownMm)?;
    if through >= state.next {
        return Err(DrainAckError::Unconsumed);
    }
    let settled = state.settle_through(through);
    let mut released = 0;
    for settlement in settled {
        match complete(ledger, mm, settlement) {
            Ok(count) => released += count,
            Err(cause) => {
                ledger.quarantine_mm(mm);
                return Err(DrainAckError::Settlement(cause));
            }
        }
    }
    Ok(released)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBlocked {
    UnknownMm,
    Quarantined,
    Closed,
    /// Held custody awaiting drains has reached its bound.
    Backpressure,
}

/// Whether the ledger may issue a new ticket to `mm`. Ledgers call this
/// before every admission, which bounds release-bearing drain debt.
pub fn admission_permitted<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
) -> Result<(), AdmissionBlocked> {
    if ledger.mm_quarantined(mm) {
        return Err(AdmissionBlocked::Quarantined);
    }
    let state = ledger
        .publication_state(mm)
        .ok_or(AdmissionBlocked::UnknownMm)?;
    if state.admission != Admission::Open {
        return Err(AdmissionBlocked::Closed);
    }
    if state.held.len() >= MAX_HELD_SETTLEMENTS_PER_MM {
        return Err(AdmissionBlocked::Backpressure);
    }
    Ok(())
}

/// Host retirement barrier, step one: close admission and record the final
/// published-through counter, read after the producer stopped.
pub fn close_admission<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
    final_through: Option<PublicationCounter>,
) -> Result<(), AdmissionBlocked> {
    let state = ledger
        .publication_state(mm)
        .ok_or(AdmissionBlocked::UnknownMm)?;
    state.admission = Admission::Closed { final_through };
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementBlocked {
    UnknownMm,
    Quarantined,
    AdmissionOpen,
    OutstandingTickets(usize),
    /// The final published-through counter has not been consumed.
    UnconsumedRecords,
    /// Out-of-order records are still waiting for an earlier counter.
    UnsettledRecords,
    /// A record with stores is not yet covered by a trusted drain.
    DrainDebt(PublicationCounter),
}

/// Gate for MM retirement and capacity return: admission closed, no
/// outstanding tickets, the final published-through counter consumed, and
/// every held custody and drain debt settled.
pub fn retirement_permitted<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
) -> Result<(), RetirementBlocked> {
    if ledger.mm_quarantined(mm) {
        return Err(RetirementBlocked::Quarantined);
    }
    let outstanding = ledger.outstanding_tickets(mm);
    let state = ledger
        .publication_state(mm)
        .ok_or(RetirementBlocked::UnknownMm)?;
    let Admission::Closed { final_through } = state.admission else {
        return Err(RetirementBlocked::AdmissionOpen);
    };
    if outstanding != 0 {
        return Err(RetirementBlocked::OutstandingTickets(outstanding));
    }
    if final_through.is_some_and(|through| state.next <= through) {
        return Err(RetirementBlocked::UnconsumedRecords);
    }
    if !state.deferred.is_empty() {
        return Err(RetirementBlocked::UnsettledRecords);
    }
    if let Some(debt) = state.oldest_drain_debt() {
        return Err(RetirementBlocked::DrainDebt(debt));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
