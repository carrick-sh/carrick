//! Neutral host consumer for MMU publication v2 records.
//!
//! The guest plans and executes every descriptor edit and publishes one
//! [`MmPublication`] per settled edit. The host's part is:
//!
//! 1. **Admission, before any store**: the ledger issues an
//!    [`AdmissionTicket`] naming the output, its leaf, the exact extent access
//!    (owner or one share edge), the maximum permissions and table grants.
//! 2. **Consumption**: [`consume`] orders records per (mm, incarnation) by
//!    their dense [`PublicationCounter`], authenticates each against the
//!    ticket, the extent's live custody and the publisher's exact prior alias,
//!    then applies it or releases this edit's own ticket.
//! 3. **Drain settlement**: custody that a remote CPU may still translate to
//!    (a replaced prior, a rolled-back output) is held as drain debt until a
//!    drain the host trusts covers it.
//!
//! The consumer never plans, walks or undoes a descriptor and never resolves
//! the informational user span. Any mismatch quarantines the publishing MM
//! (a malformed, unattributable record quarantines the carrier): the host has
//! no authority to author a corrective edit.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use carrick_core_abi::{
    EdgeGeneration, ExtentAccess, InventoryRevision, MmIncarnationKey, MmPublication,
    OwnerGeneration, PublicationCounter, PublicationDecodeError, PublicationDrain, PublicationKind,
    PublicationMm, PublicationOutcome, PublicationView, PublishedPrior, Stage1Ipa, TableGrantCount,
    TicketId, leaf_bytes,
};
use carrick_guest_arch::{EditLeafSize, EditPermissions, GuestIsa, GuestLen, RootGpa};

/// Out-of-order records held per MM while an earlier counter is in flight on
/// another ring. Exceeding it means the producer is not draining in order.
pub const MAX_DEFERRED_PER_MM: usize = 256;

/// Ledger facts for one live MM slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMm {
    pub incarnation: carrick_core_abi::MmIncarnation,
    pub root: RootGpa,
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

/// One live alias the ledger recorded for an exact (mm, incarnation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerAlias {
    pub len: GuestLen,
    pub owner_generation: OwnerGeneration,
    pub access: ExtentAccess,
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

/// Owner plus host-minted share edges for one physical extent, keyed by the
/// exact (mm, incarnation) and edge generation. Every ledger embeds this, so
/// owner-or-edge authentication has one implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentCustody {
    owner: Option<MmIncarnationKey>,
    owner_generation: OwnerGeneration,
    edges: BTreeMap<MmIncarnationKey, ShareEdge>,
    cow_edges: usize,
    next_edge: u64,
}

impl ExtentCustody {
    pub fn new(owner: MmIncarnationKey, owner_generation: OwnerGeneration) -> Self {
        Self {
            owner: Some(owner),
            owner_generation,
            edges: BTreeMap::new(),
            cow_edges: 0,
            next_edge: 0,
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

    /// Mint a fresh edge for `mm`, replacing any older edge it held.
    ///
    /// # Safety
    /// Only the host share/attach_shared path or fork custody may call this,
    /// after it has itself authorized `mm` to reach this extent. A guest
    /// record never mints an edge.
    pub unsafe fn mint_edge(
        &mut self,
        mm: MmIncarnationKey,
        kind: EdgeKind,
    ) -> Option<EdgeGeneration> {
        self.next_edge = self.next_edge.checked_add(1)?;
        let generation = EdgeGeneration::new(core::num::NonZeroU64::new(self.next_edge)?);
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
}

/// Custody a ledger may return only after the drain covering it settles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredRelease {
    /// A replaced or removed prior alias's frame.
    Prior(PublishedPrior),
    /// A rolled-back edit's own prepared ticket.
    Ticket(TicketId),
}

/// Publication bookkeeping for one (mm, incarnation). The ledger stores it
/// next to the MM; only this module changes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmPublicationState {
    next: PublicationCounter,
    pending: BTreeMap<PublicationCounter, Option<DeferredRelease>>,
    deferred: BTreeMap<PublicationCounter, PublicationView>,
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
            pending: BTreeMap::new(),
            deferred: BTreeMap::new(),
        }
    }
    /// The next counter this MM must publish.
    pub const fn next_counter(&self) -> PublicationCounter {
        self.next
    }
    /// Oldest record with stores not yet covered by a trusted drain.
    pub fn oldest_drain_debt(&self) -> Option<PublicationCounter> {
        self.pending.keys().next().copied()
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
/// is by stage-1 IPA or exact identity; none takes a user VA.
pub trait PhysicalLedger {
    type Fault: Copy + core::fmt::Debug;

    /// Carrier-wide quarantine, for records that cannot be attributed.
    fn carrier_quarantined(&self) -> bool;
    fn quarantine_carrier(&mut self);
    /// Per-MM quarantine: sticky; other MMs keep running.
    fn mm_quarantined(&self, mm: MmIncarnationKey) -> bool;
    fn quarantine_mm(&mut self, mm: MmIncarnationKey);

    /// Live incarnation and root of `mm`'s slot.
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm>;
    fn publication_state(&mut self, mm: MmIncarnationKey) -> Option<&mut MmPublicationState>;

    /// An outstanding ticket issued to exactly `mm`.
    fn ticket(&self, mm: MmIncarnationKey, ticket: TicketId) -> Option<AdmissionTicket>;
    /// Live custody of the extent containing `address`.
    fn custody(&self, address: Stage1Ipa) -> Option<&ExtentCustody>;
    /// The live alias `mm` holds at stage-1 output `address`.
    fn alias(&self, mm: MmIncarnationKey, address: Stage1Ipa) -> Option<LedgerAlias>;

    /// Bounded postcondition over the settled record (Applied/RolledBack).
    /// A ledger that does not read guest descriptors returns `Ok`; then
    /// safety rests on stage-2 confinement: guest stores can only name frames
    /// the stage-2 tables expose to that VM, and every exposed frame is under
    /// a ticket or a ledger alias authenticated here.
    fn postcondition(&self, record: &AuthenticatedPublication) -> Result<(), Self::Fault> {
        let _ = record;
        Ok(())
    }

    /// Commit an Applied record all-or-nothing: consume its ticket, publish
    /// the output alias and its table grants, drop the prior alias. Prior
    /// custody is not returned here; see [`PhysicalLedger::release`].
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Self::Fault>;
    /// Return custody: a refused/rolled-back edit's own ticket, or a replaced
    /// prior frame once its drain has settled.
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
    Postcondition(F),
    Ledger(F),
}

/// One MM quarantined by this batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quarantine<F> {
    pub mm: MmIncarnationKey,
    pub counter: Option<PublicationCounter>,
    pub cause: QuarantineCause<F>,
}

/// The whole batch was refused and the carrier quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierQuarantine {
    AlreadyQuarantined,
    Malformed {
        index: usize,
        reason: PublicationDecodeError,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsumeReport<F> {
    pub applied: usize,
    pub released: usize,
    pub deferred: usize,
    /// Ledger lookups made by the consumer: a constant per record, never a
    /// function of unrelated extents, aliases or MMs.
    pub ledger_visits: usize,
    pub quarantined: Vec<Quarantine<F>>,
}

fn authenticate<L: PhysicalLedger>(
    ledger: &L,
    view: PublicationView,
    visits: &mut usize,
) -> Result<AuthenticatedPublication, QuarantineCause<L::Fault>> {
    use QuarantineCause as Q;
    let key = view.key();
    *visits += 1;
    let live = ledger.mm(key.mm).ok_or(Q::UnknownMm)?;
    if live.incarnation != key.incarnation {
        return Err(Q::StaleIncarnation);
    }
    if live.root != view.root() {
        return Err(Q::RootMismatch);
    }
    let len = view.span().len();
    let mut ticket = None;
    if let Some(out) = view.output() {
        *visits += 1;
        let issued = ledger.ticket(key, out.ticket).ok_or(Q::NoTicket)?;
        if issued.owner_generation != out.owner_generation {
            return Err(Q::StaleOwnerGeneration);
        }
        if issued.output != out.address
            || issued.leaf != out.leaf
            || issued.len != len
            || issued.access != out.access
            || issued.inventory_revision != out.inventory_revision
        {
            return Err(Q::TicketMismatch);
        }
        if !permissions_within(view.permissions(), issued.max_permissions) {
            return Err(Q::PermissionEscalation);
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
        if view.kind() == PublicationKind::Protect && view.permissions().writable {
            *visits += 1;
            let custody = ledger.custody(prior.address).ok_or(Q::ForeignPrior)?;
            if !custody.writable_allowed(key, alias.access) {
                return Err(Q::CowWritable);
            }
        }
        prior_alias = Some(alias);
    }
    let record = AuthenticatedPublication {
        view,
        ticket,
        prior: prior_alias,
    };
    if view.outcome() != PublicationOutcome::Refused {
        ledger.postcondition(&record).map_err(Q::Postcondition)?;
    }
    Ok(record)
}

const fn permissions_within(asked: EditPermissions, allowed: EditPermissions) -> bool {
    (!asked.readable || allowed.readable)
        && (!asked.writable || allowed.writable)
        && (!asked.executable || allowed.executable)
        && (!asked.user || allowed.user)
}

/// How much of the guest's drain claim the host trusts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustedDrain {
    /// Remote CPUs may still translate this record's span.
    None,
    /// This record's own span was broadcast-invalidated.
    OwnSpan,
    /// The whole ASID was broadcast-invalidated: every earlier debt settles.
    WholeMm,
}

const fn trusted_drain(isa: GuestIsa, drain: PublicationDrain) -> TrustedDrain {
    match (isa, drain) {
        (GuestIsa::Aarch64, PublicationDrain::ArmBroadcastAsid) => TrustedDrain::WholeMm,
        (GuestIsa::Aarch64, PublicationDrain::ArmBroadcastSpan) => TrustedDrain::OwnSpan,
        // x86 shootdown claims are guest assertions; only the host's own
        // `acknowledge_global_drain` clears x86 debt.
        _ => TrustedDrain::None,
    }
}

fn settle<L: PhysicalLedger>(
    ledger: &mut L,
    record: &AuthenticatedPublication,
    report: &mut ConsumeReport<L::Fault>,
) -> Result<(), QuarantineCause<L::Fault>> {
    let view = record.view;
    let key = view.key();
    let release = match view.outcome() {
        PublicationOutcome::Refused => {
            // No store happened: this edit's own ticket returns now.
            if let Some(out) = view.output() {
                ledger
                    .release(key, DeferredRelease::Ticket(out.ticket))
                    .map_err(QuarantineCause::Ledger)?;
                report.released += 1;
            }
            None
        }
        PublicationOutcome::RolledBack => view.output().map(|o| DeferredRelease::Ticket(o.ticket)),
        PublicationOutcome::Applied => {
            ledger.apply(record).map_err(QuarantineCause::Ledger)?;
            report.applied += 1;
            match view.kind() {
                PublicationKind::CowRepoint | PublicationKind::Unmap => {
                    view.prior().map(DeferredRelease::Prior)
                }
                _ => None,
            }
        }
    };
    if view.outcome() == PublicationOutcome::Refused {
        return Ok(());
    }
    let mut settled = Vec::new();
    {
        let state = ledger
            .publication_state(key)
            .ok_or(QuarantineCause::UnknownMm)?;
        match trusted_drain(view.isa(), view.drain()) {
            TrustedDrain::None => {
                state.pending.insert(view.counter(), release);
            }
            TrustedDrain::OwnSpan => settled.extend(release),
            TrustedDrain::WholeMm => {
                settled.extend(core::mem::take(&mut state.pending).into_values().flatten());
                settled.extend(release);
            }
        }
    }
    for release in settled {
        ledger
            .release(key, release)
            .map_err(QuarantineCause::Ledger)?;
        report.released += 1;
    }
    Ok(())
}

fn quarantine_mm<L: PhysicalLedger>(
    ledger: &mut L,
    report: &mut ConsumeReport<L::Fault>,
    mm: MmIncarnationKey,
    counter: Option<PublicationCounter>,
    cause: QuarantineCause<L::Fault>,
) {
    ledger.quarantine_mm(mm);
    if let Some(state) = ledger.publication_state(mm) {
        state.deferred.clear();
    }
    report.quarantined.push(Quarantine { mm, counter, cause });
}

/// Consume one batch drained from every ring at a common point.
///
/// `published` holds per-MM published-through counters the caller read
/// (acquire) *before* snapshotting the rings: every record at or below that
/// counter is visible in this batch or an earlier one, so a missing one is
/// lost and quarantines its MM. Records beyond a gap are held, in order,
/// until the gap fills.
pub fn consume<L, I>(
    ledger: &mut L,
    records: I,
    published: &[(MmIncarnationKey, PublicationCounter)],
) -> Result<ConsumeReport<L::Fault>, CarrierQuarantine>
where
    L: PhysicalLedger,
    I: IntoIterator<Item = MmPublication>,
{
    if ledger.carrier_quarantined() {
        return Err(CarrierQuarantine::AlreadyQuarantined);
    }
    let mut views = Vec::new();
    for (index, record) in records.into_iter().enumerate() {
        match record.decode() {
            Ok(view) => views.push(view),
            Err(reason) => {
                ledger.quarantine_carrier();
                return Err(CarrierQuarantine::Malformed { index, reason });
            }
        }
    }
    let mut report = ConsumeReport {
        applied: 0,
        released: 0,
        deferred: 0,
        ledger_visits: 0,
        quarantined: Vec::new(),
    };
    let mut touched = BTreeSet::new();
    for view in views {
        let key = view.key();
        if ledger.mm_quarantined(key) {
            continue;
        }
        let live = ledger.mm(key.mm);
        let Some(state) = ledger.publication_state(key) else {
            let cause = match live {
                Some(live) if live.incarnation != key.incarnation => {
                    QuarantineCause::StaleIncarnation
                }
                _ => QuarantineCause::UnknownMm,
            };
            quarantine_mm(ledger, &mut report, key, Some(view.counter()), cause);
            continue;
        };
        let duplicate = view.counter() < state.next || state.deferred.contains_key(&view.counter());
        let overflow = state.deferred.len() >= MAX_DEFERRED_PER_MM;
        if !duplicate && !overflow {
            state.deferred.insert(view.counter(), view);
            touched.insert(key);
            continue;
        }
        let cause = if duplicate {
            QuarantineCause::DuplicateCounter
        } else {
            QuarantineCause::DeferralOverflow
        };
        quarantine_mm(ledger, &mut report, key, Some(view.counter()), cause);
    }
    for key in touched {
        loop {
            if ledger.mm_quarantined(key) {
                break;
            }
            let Some(state) = ledger.publication_state(key) else {
                break;
            };
            let next = state.next;
            let Some(view) = state.deferred.remove(&next) else {
                break;
            };
            let Some(successor) = next.next() else {
                quarantine_mm(
                    ledger,
                    &mut report,
                    key,
                    Some(next),
                    QuarantineCause::LostRecord,
                );
                break;
            };
            state.next = successor;
            let outcome = authenticate(ledger, view, &mut report.ledger_visits)
                .and_then(|record| settle(ledger, &record, &mut report));
            if let Err(cause) = outcome {
                quarantine_mm(ledger, &mut report, key, Some(next), cause);
            }
        }
        if let Some(state) = ledger.publication_state(key) {
            report.deferred += state.deferred.len();
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
            quarantine_mm(
                ledger,
                &mut report,
                key,
                Some(next),
                QuarantineCause::LostRecord,
            );
        }
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainAckError<F> {
    UnknownMm,
    Quarantined,
    /// The acknowledgement names a counter not yet consumed.
    Unconsumed,
    Ledger(F),
}

/// Record a drain the host itself performed over `mm`, covering every edit
/// through `through`. Settles that debt and returns its held custody.
/// Returns the number of custody releases.
pub fn acknowledge_global_drain<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
    through: PublicationCounter,
) -> Result<usize, DrainAckError<L::Fault>> {
    if ledger.carrier_quarantined() || ledger.mm_quarantined(mm) {
        return Err(DrainAckError::Quarantined);
    }
    let state = ledger
        .publication_state(mm)
        .ok_or(DrainAckError::UnknownMm)?;
    if through >= state.next {
        return Err(DrainAckError::Unconsumed);
    }
    let later = match through.next() {
        Some(after) => state.pending.split_off(&after),
        None => BTreeMap::new(),
    };
    let settled = core::mem::replace(&mut state.pending, later);
    let mut released = 0;
    for release in settled.into_values().flatten() {
        if let Err(fault) = ledger.release(mm, release) {
            ledger.quarantine_mm(mm);
            return Err(DrainAckError::Ledger(fault));
        }
        released += 1;
    }
    Ok(released)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementBlocked {
    UnknownMm,
    Quarantined,
    /// A record with stores is not yet covered by a trusted drain.
    DrainDebt(PublicationCounter),
    /// Out-of-order records are still waiting for an earlier counter.
    UnsettledRecords,
}

/// Gate for MM retirement and capacity return: a remote CPU may still
/// translate to this MM's frames until a trusted drain covers every record
/// with stores.
pub fn retirement_permitted<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
) -> Result<(), RetirementBlocked> {
    if ledger.carrier_quarantined() || ledger.mm_quarantined(mm) {
        return Err(RetirementBlocked::Quarantined);
    }
    let state = ledger
        .publication_state(mm)
        .ok_or(RetirementBlocked::UnknownMm)?;
    if let Some(debt) = state.oldest_drain_debt() {
        return Err(RetirementBlocked::DrainDebt(debt));
    }
    if !state.deferred.is_empty() {
        return Err(RetirementBlocked::UnsettledRecords);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
