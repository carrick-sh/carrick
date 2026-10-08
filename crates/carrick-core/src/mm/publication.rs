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
//! one producer MM. The host keeps one [`PublicationBook`] (embedded in its
//! physical ledger) that owns the facts every check derives from:
//!
//! - **aliases**, keyed by exact (mm, incarnation, VA) and holding their
//!   frame, span, leaf, permissions, ticket ceiling and generation;
//! - **tickets**, issued against an [`AdmissionSlot`] before any store;
//! - **held settlements**: custody and possibly-cached writable
//!   translations that wait for a drain the host trusts;
//! - a **frame-use index** over all three, from which writable
//!   reachability and frame reuse are *derived* rather than counted.
//!
//! [`consume`] attributes every record to its ring's bound MM, takes ISA and
//! drain authority from host-owned identity, orders records by their dense
//! [`PublicationCounter`], authenticates each (ticket, live extent custody,
//! and the exact prior alias at the record's VA naming the same frame, span,
//! leaf and owner generation), then applies it or moves its custody.
//!
//! Remaining trust assumption: the host does not re-walk guest descriptors.
//! It checks that every named frame, span and permission is one it
//! authorized and that every alias change names the alias it changes, and
//! relies on stage-2 confinement for the rest: guest stores can only name
//! frames stage-2 exposes to the VM, and a kernel bug that stores a
//! descriptor without publishing it is outside what this checker can see.
//!
//! Any mismatch quarantines the producer's bound MM, never an MM a record
//! merely names. The host never authors a corrective edit.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use carrick_core_abi::{
    EdgeGeneration, ExtentAccess, InventoryRevision, MmIncarnation, MmIncarnationKey,
    MmPublication, OwnerGeneration, PublicationCounter, PublicationDecodeError, PublicationDrain,
    PublicationKind, PublicationMm, PublicationOutcome, PublicationView, Stage1Ipa,
    TableGrantCount, TicketId,
};
use carrick_guest_arch::{EditLeafSize, EditPermissions, GuestIsa, GuestLen, RootGpa, UserVa};
use core::num::NonZeroU64;

/// Out-of-order records held per MM after the contiguous prefix has been
/// consumed. Exceeding it means the producer is not draining in order.
pub const MAX_DEFERRED_PER_MM: usize = 256;

/// Admission slots (reserved, outstanding or held tickets) plus held
/// settlements per MM. Admission refuses beyond it, and [`consume`] stops
/// accepting records that would add a held settlement until a drain frees
/// room.
pub const MAX_HELD_PER_MM: usize = 256;

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

/// Generation of one alias incarnation; never reused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AliasGeneration(NonZeroU64);

/// One alias of an exact (mm, incarnation) at one VA span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Alias {
    pub frame: Stage1Ipa,
    pub len: GuestLen,
    pub leaf: EditLeafSize,
    pub owner_generation: OwnerGeneration,
    pub access: ExtentAccess,
    pub permissions: EditPermissions,
    pub ceiling: EditPermissions,
    /// False for a prepared alias that a later `Publish` makes present.
    pub present: bool,
    pub generation: AliasGeneration,
    /// This alias's entry in the frame-use index.
    use_seq: u64,
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

/// Custody returned to the ledger, after the drain covering it if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredRelease {
    /// A refused edit's own outstanding ticket (no store happened).
    Ticket(TicketId),
    /// A rolled-back edit's ticket. It left Outstanding at settlement and
    /// could not be spent since; its drain has now settled.
    HeldOutput(TicketId),
    /// One alias incarnation's use of a frame ended and its drain settled.
    Prior {
        frame: Stage1Ipa,
        len: GuestLen,
        alias: AliasGeneration,
    },
}

/// A reserved admission slot for one MM. Consumed by
/// [`PublicationBook::issue_ticket`] or returned by
/// [`PublicationBook::cancel_slot`]; it counts against [`MAX_HELD_PER_MM`]
/// until the ticket it becomes is settled.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmissionSlot {
    mm: MmIncarnationKey,
}

/// Proof that an extent range had no writable reachability: no writable
/// alias, no outstanding writable ticket, no held translation that may
/// still be writable on another CPU. [`PublicationBook::mint_cow_edge`]
/// re-derives the predicate before minting, so a proof cannot go stale.
#[derive(Debug, Eq, PartialEq)]
pub struct CowTransition {
    base: u64,
    len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CowBlocked {
    WritableAlias(MmIncarnationKey, UserVa),
    WritableTicket(MmIncarnationKey, TicketId),
    PendingWritable(MmIncarnationKey, PublicationCounter),
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameUse {
    Alias {
        mm: MmIncarnationKey,
        va: u64,
    },
    Ticket {
        mm: MmIncarnationKey,
        ticket: TicketId,
    },
    /// A translation that may still be writable on another CPU.
    PendingWritable {
        mm: MmIncarnationKey,
        counter: PublicationCounter,
    },
    /// An ended alias whose frame must not be reused before its drain.
    PendingRelease {
        mm: MmIncarnationKey,
        alias: AliasGeneration,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TicketState {
    Outstanding,
    /// Rolled back: no longer spendable; may have been transiently
    /// writable until its drain settles.
    Held {
        transient_writable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TicketRecord {
    spec: AdmissionTicket,
    state: TicketState,
    seq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Release {
    HeldTicket(TicketId),
    Prior {
        frame: Stage1Ipa,
        len: GuestLen,
        alias: AliasGeneration,
        seq: u64,
    },
}

/// Everything one record leaves held until its drain settles. Each part
/// references an exact use-index entry, never a bare frame address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Settlement {
    alias: Option<AliasGeneration>,
    writable_use: Option<(Stage1Ipa, u64)>,
    release: Option<Release>,
}
impl Settlement {
    const fn is_empty(&self) -> bool {
        self.writable_use.is_none() && self.release.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    Open,
    Closed {
        final_through: Option<PublicationCounter>,
    },
}

/// Publication bookkeeping for one (mm, incarnation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmPublicationState {
    next: PublicationCounter,
    deferred: BTreeMap<PublicationCounter, PublicationView>,
    /// Records with stores but nothing held, compacted to one range.
    uncovered: Option<(PublicationCounter, PublicationCounter)>,
    held: BTreeMap<PublicationCounter, Settlement>,
    tickets: BTreeMap<TicketId, TicketRecord>,
    reserved: usize,
    admission: Admission,
    quarantined: bool,
}

impl MmPublicationState {
    const fn new() -> Self {
        Self {
            next: PublicationCounter::FIRST,
            deferred: BTreeMap::new(),
            uncovered: None,
            held: BTreeMap::new(),
            tickets: BTreeMap::new(),
            reserved: 0,
            admission: Admission::Open,
            quarantined: false,
        }
    }
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
    pub fn held_settlements(&self) -> usize {
        self.held.len()
    }
    pub fn deferred_records(&self) -> usize {
        self.deferred.len()
    }
    /// Reserved, outstanding and held tickets.
    pub fn open_tickets(&self) -> usize {
        self.tickets.len() + self.reserved
    }
    fn admission_load(&self) -> usize {
        self.tickets.len() + self.reserved + self.held.len()
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
}

/// The host's publication facts: aliases, tickets, held settlements and the
/// frame-use index they derive from. Embedded in the physical ledger; only
/// this module changes it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicationBook {
    states: BTreeMap<MmIncarnationKey, MmPublicationState>,
    aliases: BTreeMap<(MmIncarnationKey, u64), Alias>,
    uses: BTreeMap<(u64, u64), (u64, FrameUse)>,
    alias_pending: BTreeSet<(AliasGeneration, PublicationCounter)>,
    next_seq: u64,
    next_ticket: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBlocked {
    UnknownMm,
    Quarantined,
    Closed,
    /// Slots plus held settlements reached [`MAX_HELD_PER_MM`].
    Backpressure,
    WrongMm,
    Exhausted,
}

impl PublicationBook {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register_mm(&mut self, mm: MmIncarnationKey) {
        self.states.insert(mm, MmPublicationState::new());
    }
    pub fn state(&self, mm: MmIncarnationKey) -> Option<&MmPublicationState> {
        self.states.get(&mm)
    }
    pub fn quarantined(&self, mm: MmIncarnationKey) -> bool {
        self.states.get(&mm).is_some_and(|state| state.quarantined)
    }
    /// The alias `mm` holds at exactly `va`.
    pub fn alias(&self, mm: MmIncarnationKey, va: UserVa) -> Option<Alias> {
        self.aliases.get(&(mm, va.raw())).copied()
    }
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    fn seq(&mut self) -> Option<u64> {
        self.next_seq = self.next_seq.checked_add(1)?;
        Some(self.next_seq)
    }

    fn add_use(&mut self, frame: Stage1Ipa, len: GuestLen, what: FrameUse) -> Option<u64> {
        let seq = self.seq()?;
        self.uses.insert((frame.raw(), seq), (len.raw(), what));
        Some(seq)
    }

    fn remove_use_at(&mut self, frame: Stage1Ipa, seq: u64) {
        self.uses.remove(&(frame.raw(), seq));
    }

    /// Reserve an admission slot for `mm`. Ledgers take one before every
    /// ticket, which bounds tickets plus held settlements.
    pub fn admission_permitted(
        &mut self,
        mm: MmIncarnationKey,
    ) -> Result<AdmissionSlot, AdmissionBlocked> {
        let state = self
            .states
            .get_mut(&mm)
            .ok_or(AdmissionBlocked::UnknownMm)?;
        if state.quarantined {
            return Err(AdmissionBlocked::Quarantined);
        }
        if state.admission != Admission::Open {
            return Err(AdmissionBlocked::Closed);
        }
        if state.admission_load() >= MAX_HELD_PER_MM {
            return Err(AdmissionBlocked::Backpressure);
        }
        state.reserved += 1;
        Ok(AdmissionSlot { mm })
    }

    pub fn cancel_slot(&mut self, slot: AdmissionSlot) {
        if let Some(state) = self.states.get_mut(&slot.mm) {
            state.reserved = state.reserved.saturating_sub(1);
        }
    }

    /// Turn a reserved slot into an outstanding ticket. The ledger has
    /// already validated the frame custody the ticket names.
    pub fn issue_ticket(
        &mut self,
        slot: AdmissionSlot,
        spec: AdmissionTicket,
    ) -> Result<TicketId, AdmissionBlocked> {
        let mm = slot.mm;
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(AdmissionBlocked::Exhausted)?;
        let id =
            TicketId::new(NonZeroU64::new(self.next_ticket).ok_or(AdmissionBlocked::Exhausted)?);
        let seq = self
            .add_use(spec.output, spec.len, FrameUse::Ticket { mm, ticket: id })
            .ok_or(AdmissionBlocked::Exhausted)?;
        let state = self.states.get_mut(&mm).ok_or(AdmissionBlocked::WrongMm)?;
        state.reserved = state.reserved.saturating_sub(1);
        state.tickets.insert(
            id,
            TicketRecord {
                spec,
                state: TicketState::Outstanding,
                seq,
            },
        );
        Ok(id)
    }

    fn outstanding_ticket(&self, mm: MmIncarnationKey, id: TicketId) -> Option<AdmissionTicket> {
        let record = self.states.get(&mm)?.tickets.get(&id)?;
        (record.state == TicketState::Outstanding).then_some(record.spec)
    }

    fn va_free(&self, mm: MmIncarnationKey, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let before = self
            .aliases
            .range((mm, 0)..=(mm, start))
            .next_back()
            .is_some_and(|(&(_, va), alias)| va + alias.len.raw() > start);
        let inside = self.aliases.range((mm, start)..(mm, end)).next().is_some();
        !before && !inside
    }

    fn writable_use(&self, what: FrameUse) -> Option<CowBlocked> {
        match what {
            FrameUse::Alias { mm, va } => self
                .aliases
                .get(&(mm, va))
                .is_some_and(|alias| alias.permissions.writable)
                .then_some(CowBlocked::WritableAlias(mm, UserVa::new(va))),
            FrameUse::Ticket { mm, ticket } => {
                let record = self.states.get(&mm)?.tickets.get(&ticket)?;
                let writable = match record.state {
                    TicketState::Outstanding => record.spec.max_permissions.writable,
                    TicketState::Held { transient_writable } => transient_writable,
                };
                writable.then_some(CowBlocked::WritableTicket(mm, ticket))
            }
            FrameUse::PendingWritable { mm, counter } => {
                Some(CowBlocked::PendingWritable(mm, counter))
            }
            FrameUse::PendingRelease { .. } => None,
        }
    }

    fn writable_reachability(&self, base: u64, len: u64) -> Result<(), CowBlocked> {
        let end = base.checked_add(len).ok_or(CowBlocked::Exhausted)?;
        for (_, &(_, what)) in self.uses.range((base, 0)..(end, 0)) {
            if let Some(blocked) = self.writable_use(what) {
                return Err(blocked);
            }
        }
        Ok(())
    }

    /// Begin a fork-custody transition over one extent: succeeds only when
    /// the derived writable reachability of the range is empty.
    pub fn begin_cow(&self, base: Stage1Ipa, len: GuestLen) -> Result<CowTransition, CowBlocked> {
        self.writable_reachability(base.raw(), len.raw())?;
        Ok(CowTransition {
            base: base.raw(),
            len: len.raw(),
        })
    }

    /// Mint a fork-custody (COW) edge under a transition proof, re-deriving
    /// the predicate first.
    ///
    /// # Safety
    /// Only fork custody may call this, with the custody of exactly the
    /// extent the proof covers, after it has authorized `mm` to inherit it.
    pub unsafe fn mint_cow_edge(
        &self,
        custody: &mut ExtentCustody,
        mm: MmIncarnationKey,
        proof: CowTransition,
    ) -> Result<EdgeGeneration, CowBlocked> {
        self.writable_reachability(proof.base, proof.len)?;
        custody
            .mint(mm, EdgeKind::CowInherited)
            .ok_or(CowBlocked::Exhausted)
    }

    /// Whether any alias, ticket or held settlement still references a byte
    /// of the range. A ledger must not reuse a frame until this is true.
    pub fn frame_reusable(&self, base: Stage1Ipa, len: GuestLen) -> bool {
        let Some(end) = base.raw().checked_add(len.raw()) else {
            return false;
        };
        self.uses.range((base.raw(), 0)..(end, 0)).next().is_none()
    }
}

/// A record that passed every check. Only [`consume`] constructs it, so a
/// ledger can never apply an unauthenticated record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPublication {
    view: PublicationView,
    ticket: Option<AdmissionTicket>,
    prior: Option<Alias>,
}

impl AuthenticatedPublication {
    pub const fn view(&self) -> &PublicationView {
        &self.view
    }
    pub const fn ticket(&self) -> Option<AdmissionTicket> {
        self.ticket
    }
    pub const fn prior_alias(&self) -> Option<Alias> {
        self.prior
    }
}

/// The host's physical ledger, as seen by the neutral consumer. Every lookup
/// is by stage-1 IPA or exact identity; none resolves a user VA.
pub trait PhysicalLedger {
    type Fault: Copy + core::fmt::Debug;

    fn book(&self) -> &PublicationBook;
    fn book_mut(&mut self) -> &mut PublicationBook;

    /// Live incarnation, root and ISA of `mm`'s slot.
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm>;
    /// Live custody of the one extent wholly containing the range.
    fn custody(&self, address: Stage1Ipa, len: GuestLen) -> Option<&ExtentCustody>;

    /// Physical side effects of an authenticated Applied record (stage-2,
    /// frame inventory). The book's aliases and tickets are updated by the
    /// consumer, not here.
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Self::Fault>;
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
    /// A fresh mapping over a VA span that already has an alias.
    VaOccupied,
    /// No alias of this MM at the record's VA.
    NoPriorAlias,
    /// The alias at the record's VA holds a different frame.
    PriorFrameMismatch,
    PriorLeafMismatch,
    StalePriorGeneration,
    /// The record's span is not the alias's whole VA span.
    SpanMismatch,
    IndexExhausted,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeReport<F> {
    pub applied: usize,
    pub released: usize,
    pub deferred: usize,
    /// Records left unconsumed because their MM's held settlements reached
    /// [`MAX_HELD_PER_MM`]; they are consumed after a drain frees room.
    pub backpressured: usize,
    /// Ledger and book lookups made by the consumer: a constant per record
    /// and per batch, never a function of unrelated extents, aliases or MMs.
    pub ledger_visits: usize,
    pub quarantined: Vec<Quarantine<F>>,
}

const fn permissions_within(asked: EditPermissions, allowed: EditPermissions) -> bool {
    (!asked.readable || allowed.readable)
        && (!asked.writable || allowed.writable)
        && (!asked.executable || allowed.executable)
        && (!asked.user || allowed.user)
}

fn authenticate<L: PhysicalLedger>(
    ledger: &L,
    live: LedgerMm,
    view: PublicationView,
    visits: &mut usize,
) -> Result<AuthenticatedPublication, QuarantineCause<L::Fault>> {
    use QuarantineCause as Q;
    let key = view.key();
    let book = ledger.book();
    if live.root != view.root() {
        return Err(Q::RootMismatch);
    }
    let span = view.span();
    let refused = view.outcome() == PublicationOutcome::Refused;
    let mut ticket = None;
    if let Some(out) = view.output() {
        *visits += 1;
        let issued = book
            .outstanding_ticket(key, out.ticket)
            .ok_or(Q::NoTicket)?;
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
        let custody = ledger
            .custody(out.address, span.len())
            .ok_or(Q::UnbackedOutput)?;
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
    if !refused {
        if let Some(prior) = view.prior() {
            *visits += 1;
            let alias = book.alias(key, span.start()).ok_or(Q::NoPriorAlias)?;
            if alias.frame != prior.address {
                return Err(Q::PriorFrameMismatch);
            }
            if alias.leaf != prior.leaf {
                return Err(Q::PriorLeafMismatch);
            }
            if alias.len != span.len() {
                return Err(Q::SpanMismatch);
            }
            if alias.owner_generation != prior.owner_generation {
                return Err(Q::StalePriorGeneration);
            }
            let gains_write = view.permissions().writable && !alias.permissions.writable;
            if view.output().is_none() && gains_write {
                *visits += 1;
                let custody = ledger
                    .custody(alias.frame, alias.len)
                    .ok_or(Q::NoPriorAlias)?;
                if !custody.writable_allowed(key, alias.access) {
                    return Err(Q::CowWritable);
                }
            }
            prior_alias = Some(alias);
        } else {
            *visits += 1;
            if !book.va_free(key, span.start().raw(), span.len().raw()) {
                return Err(Q::VaOccupied);
            }
        }
        let ceiling = match (ticket, prior_alias) {
            (Some(issued), _) => issued.max_permissions,
            (None, Some(alias)) => alias.ceiling,
            (None, None) => return Err(Q::NoPriorAlias),
        };
        if !permissions_within(view.permissions(), ceiling) {
            return Err(Q::PermissionEscalation);
        }
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

fn complete<L: PhysicalLedger>(
    ledger: &mut L,
    key: MmIncarnationKey,
    counter: PublicationCounter,
    settlement: Settlement,
) -> Result<usize, QuarantineCause<L::Fault>> {
    let book = ledger.book_mut();
    if let Some(alias) = settlement.alias {
        book.alias_pending.remove(&(alias, counter));
    }
    if let Some((frame, seq)) = settlement.writable_use {
        book.remove_use_at(frame, seq);
    }
    let release = match settlement.release {
        None => return Ok(0),
        Some(Release::HeldTicket(id)) => {
            if let Some(record) = book
                .states
                .get_mut(&key)
                .and_then(|state| state.tickets.remove(&id))
            {
                book.remove_use_at(record.spec.output, record.seq);
            }
            DeferredRelease::HeldOutput(id)
        }
        Some(Release::Prior {
            frame,
            len,
            alias,
            seq,
        }) => {
            book.remove_use_at(frame, seq);
            DeferredRelease::Prior { frame, len, alias }
        }
    };
    ledger
        .release(key, release)
        .map_err(QuarantineCause::Ledger)?;
    Ok(1)
}

fn new_alias(
    book: &mut PublicationBook,
    key: MmIncarnationKey,
    va: UserVa,
    mut alias: Alias,
) -> Option<()> {
    alias.use_seq = book.add_use(
        alias.frame,
        alias.len,
        FrameUse::Alias {
            mm: key,
            va: va.raw(),
        },
    )?;
    book.aliases.insert((key, va.raw()), alias);
    Some(())
}

fn drop_alias(book: &mut PublicationBook, key: MmIncarnationKey, va: UserVa) {
    if let Some(alias) = book.aliases.remove(&(key, va.raw())) {
        book.remove_use_at(alias.frame, alias.use_seq);
    }
}

/// Apply an authenticated record to the book and build what it leaves held.
fn record_effects<L: PhysicalLedger>(
    ledger: &mut L,
    record: &AuthenticatedPublication,
) -> Result<Settlement, QuarantineCause<L::Fault>> {
    use QuarantineCause as Q;
    let view = record.view;
    let key = view.key();
    let counter = view.counter();
    let span = view.span();
    let permissions = view.permissions();
    let mut settlement = Settlement {
        alias: record.prior.map(|alias| alias.generation),
        ..Settlement::default()
    };
    let pending_writable = |book: &mut PublicationBook, alias: &Alias| {
        book.add_use(
            alias.frame,
            alias.len,
            FrameUse::PendingWritable { mm: key, counter },
        )
        .map(|seq| (alias.frame, seq))
    };
    match view.outcome() {
        PublicationOutcome::Refused => {}
        PublicationOutcome::RolledBack => {
            let book = ledger.book_mut();
            if let Some(out) = view.output()
                && let Some(ticket) = book
                    .states
                    .get_mut(&key)
                    .and_then(|state| state.tickets.get_mut(&out.ticket))
            {
                ticket.state = TicketState::Held {
                    transient_writable: permissions.writable,
                };
                settlement.release = Some(Release::HeldTicket(out.ticket));
            }
            // A rolled-back grant of write may still be cached elsewhere.
            if let Some(alias) = record.prior
                && view.output().is_none()
                && permissions.writable
                && !alias.permissions.writable
            {
                settlement.writable_use =
                    Some(pending_writable(book, &alias).ok_or(Q::IndexExhausted)?);
            }
        }
        PublicationOutcome::Applied => {
            ledger.apply(record).map_err(Q::Ledger)?;
            let book = ledger.book_mut();
            if let Some(alias) = record.prior {
                let loses_write = alias.permissions.writable && !permissions.writable;
                match view.kind() {
                    PublicationKind::Unmap | PublicationKind::CowRepoint => {
                        drop_alias(book, key, span.start());
                        let seq = book
                            .add_use(
                                alias.frame,
                                alias.len,
                                FrameUse::PendingRelease {
                                    mm: key,
                                    alias: alias.generation,
                                },
                            )
                            .ok_or(Q::IndexExhausted)?;
                        settlement.release = Some(Release::Prior {
                            frame: alias.frame,
                            len: alias.len,
                            alias: alias.generation,
                            seq,
                        });
                        if alias.permissions.writable {
                            settlement.writable_use =
                                Some(pending_writable(book, &alias).ok_or(Q::IndexExhausted)?);
                        }
                    }
                    PublicationKind::Coalesce => {
                        drop_alias(book, key, span.start());
                        if loses_write {
                            settlement.writable_use =
                                Some(pending_writable(book, &alias).ok_or(Q::IndexExhausted)?);
                        }
                    }
                    _ => {
                        if let Some(live) = book.aliases.get_mut(&(key, span.start().raw())) {
                            live.permissions = permissions;
                            if view.kind() == PublicationKind::Publish {
                                live.present = true;
                            }
                        }
                        if loses_write {
                            settlement.writable_use =
                                Some(pending_writable(book, &alias).ok_or(Q::IndexExhausted)?);
                        }
                    }
                }
            }
            if let (Some(out), Some(ticket)) = (view.output(), record.ticket) {
                if let Some(record) = book
                    .states
                    .get_mut(&key)
                    .and_then(|state| state.tickets.remove(&out.ticket))
                {
                    book.remove_use_at(record.spec.output, record.seq);
                }
                let generation = book
                    .seq()
                    .and_then(NonZeroU64::new)
                    .map(AliasGeneration)
                    .ok_or(Q::IndexExhausted)?;
                new_alias(
                    book,
                    key,
                    span.start(),
                    Alias {
                        frame: out.address,
                        len: span.len(),
                        leaf: out.leaf,
                        owner_generation: out.owner_generation,
                        access: out.access,
                        permissions,
                        ceiling: ticket.max_permissions,
                        present: view.kind() != PublicationKind::Prepare,
                        generation,
                        use_seq: 0,
                    },
                )
                .ok_or(Q::IndexExhausted)?;
            }
        }
    }
    Ok(settlement)
}

fn settle<L: PhysicalLedger>(
    ledger: &mut L,
    producer_isa: GuestIsa,
    record: &AuthenticatedPublication,
    report: &mut ConsumeReport<L::Fault>,
) -> Result<(), QuarantineCause<L::Fault>> {
    let view = record.view;
    let key = view.key();
    let counter = view.counter();
    if view.outcome() == PublicationOutcome::Refused {
        // No store happened: this edit's own outstanding ticket returns.
        if let Some(out) = view.output() {
            let book = ledger.book_mut();
            if let Some(ticket) = book
                .states
                .get_mut(&key)
                .and_then(|state| state.tickets.remove(&out.ticket))
            {
                book.remove_use_at(ticket.spec.output, ticket.seq);
            }
            ledger
                .release(key, DeferredRelease::Ticket(out.ticket))
                .map_err(QuarantineCause::Ledger)?;
            report.released += 1;
        }
        return Ok(());
    }
    let settlement = record_effects(ledger, record)?;
    if view.outcome() == PublicationOutcome::Applied {
        report.applied += 1;
    }
    let mut due: Vec<(PublicationCounter, Settlement)> = Vec::new();
    {
        let book = ledger.book_mut();
        let waits_behind_alias = settlement.alias.is_some_and(|alias| {
            book.alias_pending
                .range((alias, PublicationCounter::FIRST)..(alias, counter))
                .next()
                .is_some()
        });
        let trust = match trusted_drain(producer_isa, view.drain()) {
            // A release never overtakes an earlier held settlement of the
            // same alias: settle it in counter order with that one.
            TrustedDrain::OwnSpan if waits_behind_alias => TrustedDrain::None,
            trust => trust,
        };
        let state = book
            .states
            .get_mut(&key)
            .ok_or(QuarantineCause::UnknownMm)?;
        match trust {
            TrustedDrain::None => {
                if settlement.is_empty() {
                    state.uncovered = Some(match state.uncovered {
                        Some((first, _)) => (first, counter),
                        None => (counter, counter),
                    });
                } else {
                    state.held.insert(counter, settlement);
                    if let Some(alias) = settlement.alias {
                        book.alias_pending.insert((alias, counter));
                    }
                }
            }
            TrustedDrain::OwnSpan => due.push((counter, settlement)),
            TrustedDrain::WholeMm => {
                let earlier = state
                    .held
                    .range(..counter)
                    .map(|(&at, _)| at)
                    .collect::<Vec<_>>();
                let settled = state.settle_through(counter);
                due.extend(earlier.into_iter().zip(settled));
                due.push((counter, settlement));
            }
        }
    }
    for (at, settlement) in due {
        report.released += complete(ledger, key, at, settlement)?;
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
    if let Some(state) = ledger.book_mut().states.get_mut(&mm) {
        state.quarantined = true;
        state.deferred.clear();
    }
    report.quarantined.push(Quarantine {
        ring,
        mm,
        counter,
        cause,
    });
}

/// Whether consuming `view` may add a held settlement.
fn may_hold(producer_isa: GuestIsa, view: &PublicationView) -> bool {
    view.outcome() != PublicationOutcome::Refused
        && trusted_drain(producer_isa, view.drain()) != TrustedDrain::WholeMm
        && (view.output().is_some() || view.prior().is_some())
}

type Groups = BTreeMap<MmIncarnationKey, (LedgerMm, BTreeMap<PublicationCounter, PublicationView>)>;

/// Consume one round drained from every ring at a common point.
///
/// Each record is attributed to its ring's bound MM; a record naming any
/// other identity, or an ISA other than the producer's, quarantines the
/// producer. `published` holds per-MM published-through counters the caller
/// read (acquire) *before* snapshotting the rings: every record at or below
/// that counter is visible in this round or an earlier one, so a missing one
/// is lost and quarantines its MM. The contiguous prefix is consumed first;
/// only records still beyond a gap count against [`MAX_DEFERRED_PER_MM`].
/// A record that may add a held settlement while its MM is at
/// [`MAX_HELD_PER_MM`] stays unconsumed (backpressure) until a drain frees
/// room; a published-through counter is then not yet due.
pub fn consume<L: PhysicalLedger>(
    ledger: &mut L,
    batches: &[RingBatch<'_>],
    published: &[(MmIncarnationKey, PublicationCounter)],
) -> ConsumeReport<L::Fault> {
    let mut report = ConsumeReport {
        applied: 0,
        released: 0,
        deferred: 0,
        backpressured: 0,
        ledger_visits: 0,
        quarantined: Vec::new(),
    };
    let mut groups = Groups::new();
    let mut ring_of: BTreeMap<MmIncarnationKey, RingId> = BTreeMap::new();
    for batch in batches {
        let bound = batch.bound;
        let ring = Some(batch.ring);
        if ledger.book().quarantined(bound) {
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
        // An empty batch still revisits records held back earlier.
        groups
            .entry(bound)
            .or_insert_with(|| (live, BTreeMap::new()));
        for record in batch.records {
            if ledger.book().quarantined(bound) {
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
                match ledger.book().state(bound) {
                    None => Some(QuarantineCause::UnknownMm),
                    Some(state) => {
                        let duplicate = view.counter() < state.next
                            || state.deferred.contains_key(&view.counter())
                            || group.1.insert(view.counter(), view).is_some();
                        duplicate.then_some(QuarantineCause::DuplicateCounter)
                    }
                }
            };
            if let Some(cause) = cause {
                quarantine_mm(ledger, &mut report, ring, bound, counter, cause);
                break;
            }
        }
    }
    let mut backpressured = BTreeSet::new();
    for (key, (live, mut incoming)) in groups {
        let ring = ring_of.get(&key).copied();
        loop {
            let book = ledger.book_mut();
            let Some(state) = book.states.get_mut(&key) else {
                break;
            };
            if state.quarantined {
                break;
            }
            let next = state.next;
            let Some(view) = incoming
                .remove(&next)
                .or_else(|| state.deferred.remove(&next))
            else {
                break;
            };
            if may_hold(live.isa, &view) && state.held.len() >= MAX_HELD_PER_MM {
                state.deferred.insert(next, view);
                backpressured.insert(key);
                break;
            }
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
        let Some(state) = ledger.book_mut().states.get_mut(&key) else {
            continue;
        };
        if state.quarantined {
            continue;
        }
        state.deferred.append(&mut incoming);
        let deferred = state.deferred.len();
        if backpressured.contains(&key) {
            report.backpressured += deferred;
        } else if deferred > MAX_DEFERRED_PER_MM {
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
        if backpressured.contains(&key) {
            continue;
        }
        let Some(state) = ledger.book().state(key) else {
            continue;
        };
        if state.quarantined {
            continue;
        }
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
/// through `through`. Settles that debt in counter order and returns its
/// held custody. Returns the number of custody releases.
pub fn acknowledge_global_drain<L: PhysicalLedger>(
    ledger: &mut L,
    mm: MmIncarnationKey,
    through: PublicationCounter,
) -> Result<usize, DrainAckError<L::Fault>> {
    let state = ledger
        .book_mut()
        .states
        .get_mut(&mm)
        .ok_or(DrainAckError::UnknownMm)?;
    if state.quarantined {
        return Err(DrainAckError::Quarantined);
    }
    if through >= state.next {
        return Err(DrainAckError::Unconsumed);
    }
    let counters = state
        .held
        .range(..=through)
        .map(|(&counter, _)| counter)
        .collect::<Vec<_>>();
    let settled = state.settle_through(through);
    let mut released = 0;
    for (counter, settlement) in counters.into_iter().zip(settled) {
        match complete(ledger, mm, counter, settlement) {
            Ok(count) => released += count,
            Err(cause) => {
                if let Some(state) = ledger.book_mut().states.get_mut(&mm) {
                    state.quarantined = true;
                }
                return Err(DrainAckError::Settlement(cause));
            }
        }
    }
    Ok(released)
}

/// Host retirement barrier, step one: close admission and record the final
/// published-through counter, read after the producer stopped.
pub fn close_admission(
    book: &mut PublicationBook,
    mm: MmIncarnationKey,
    final_through: Option<PublicationCounter>,
) -> Result<(), AdmissionBlocked> {
    let state = book
        .states
        .get_mut(&mm)
        .ok_or(AdmissionBlocked::UnknownMm)?;
    state.admission = Admission::Closed { final_through };
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementBlocked {
    UnknownMm,
    Quarantined,
    AdmissionOpen,
    OpenTickets(usize),
    /// The final published-through counter has not been consumed.
    UnconsumedRecords,
    /// Out-of-order or backpressured records are still waiting.
    UnsettledRecords,
    /// A record with stores is not yet covered by a trusted drain.
    DrainDebt(PublicationCounter),
}

/// Gate for MM retirement and capacity return: admission closed, no
/// reserved, outstanding or held tickets, the final published-through
/// counter consumed, and every held settlement and drain debt settled.
pub fn retirement_permitted(
    book: &PublicationBook,
    mm: MmIncarnationKey,
) -> Result<(), RetirementBlocked> {
    let state = book.state(mm).ok_or(RetirementBlocked::UnknownMm)?;
    if state.quarantined {
        return Err(RetirementBlocked::Quarantined);
    }
    let Admission::Closed { final_through } = state.admission else {
        return Err(RetirementBlocked::AdmissionOpen);
    };
    if state.open_tickets() != 0 {
        return Err(RetirementBlocked::OpenTickets(state.open_tickets()));
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
