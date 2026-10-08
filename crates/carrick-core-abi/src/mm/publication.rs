//! MMU publication v2: one guest-to-host record shared by ARM and x86.
//!
//! The guest plans and executes every descriptor edit (an `EditIntent`) under
//! its exact-MM editor, then publishes one fixed 128-byte record describing
//! the settled outcome. The host never plans or walks descriptors; it only
//! authenticates the record against its own physical ledger and the admission
//! ticket it issued before any store. Address domains stay distinct in the
//! typed view: the informational user span ([`UserRange`], never resolved by
//! the host), the translation root ([`RootGpa`]) and the output/prior frames
//! ([`Stage1Ipa`], the address the guest descriptor names). The host maps a
//! stage-1 IPA to its own global-frame inventory; under non-identity HVPatch
//! the two are different numbers, so the record never carries the latter.
//!
//! An indeterminate outcome (stores neither settled nor undone) is
//! deliberately not representable: it remains guest-fatal and never crosses
//! this boundary as data.

use carrick_guest_arch::{
    EditLeafSize, EditPermissions, GuestIsa, GuestLen, RootGpa, UserRange, UserVa,
};
use core::cell::UnsafeCell;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Smallest descriptor granule a publication may name.
pub const PUBLICATION_GRANULE: u64 = 4096;

macro_rules! nonzero_id {
    ($($(#[doc = $doc:expr])* $name:ident),+ $(,)?) => {$(
        $(#[doc = $doc])*
        #[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug, ::core::cmp::Eq, ::core::hash::Hash, ::core::cmp::Ord, ::core::cmp::PartialEq, ::core::cmp::PartialOrd)]
        pub struct $name(NonZeroU64);
        impl $name {
            pub const fn new(raw: NonZeroU64) -> Self {
                Self(raw)
            }
            pub const fn raw(self) -> NonZeroU64 {
                self.0
            }
        }
    )+};
}

nonzero_id!(
    /// Exact MM key named by the edit owner; not a host pid or a root address.
    PublicationMm,
    /// Incarnation of one MM slot. A recycled slot keeps its key and receives
    /// a new incarnation, so a stale record cannot authenticate against the
    /// successor.
    MmIncarnation,
    /// Dense per-(mm, incarnation) publication counter, assigned under the
    /// exact-MM editor starting at 1. Distinct from the `EditOwner`
    /// generation: a gap means a lost record.
    PublicationCounter,
    /// The `EditOwner` generation of the publishing edit (diagnostic identity).
    EditSequence,
    /// Host-issued admission ticket for one prepared output, minted before
    /// the guest may store a descriptor naming it.
    TicketId,
    /// Host owner generation of a backing extent.
    OwnerGeneration,
    /// Generation of one host-minted share edge on an extent.
    EdgeGeneration,
    /// Host frame-inventory revision at ticket issue.
    InventoryRevision,
);

impl PublicationCounter {
    pub const FIRST: Self = Self(NonZeroU64::MIN);
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// A stage-1 output address: the IPA a guest descriptor names. Never a
/// global-frame IPA, host VA or user VA.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::hash::Hash,
    ::core::cmp::Ord,
    ::core::cmp::PartialEq,
    ::core::cmp::PartialOrd,
)]
pub struct Stage1Ipa(u64);
impl Stage1Ipa {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Exact (mm, incarnation) key: every per-MM authority keys on both.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::hash::Hash,
    ::core::cmp::Ord,
    ::core::cmp::PartialEq,
    ::core::cmp::PartialOrd,
)]
pub struct MmIncarnationKey {
    pub mm: PublicationMm,
    pub incarnation: MmIncarnation,
}

/// How the publisher reaches the output extent: as its owner, or through
/// one exact host-minted share edge.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::hash::Hash,
    ::core::cmp::Ord,
    ::core::cmp::PartialEq,
    ::core::cmp::PartialOrd,
)]
pub enum ExtentAccess {
    Owner,
    Edge(EdgeGeneration),
}

/// Number of interior table pages the edit linked from its grant list.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::Ord,
    ::core::cmp::PartialEq,
    ::core::cmp::PartialOrd,
)]
pub struct TableGrantCount(pub u8);

pub const fn leaf_bytes(leaf: EditLeafSize) -> u64 {
    match leaf {
        EditLeafSize::Page => PUBLICATION_GRANULE,
        EditLeafSize::Block2M => 2 << 20,
        EditLeafSize::Block1G => 1 << 30,
    }
}
const fn leaf_to_wire(leaf: Option<EditLeafSize>) -> u8 {
    match leaf {
        None => 0,
        Some(EditLeafSize::Page) => 1,
        Some(EditLeafSize::Block2M) => 2,
        Some(EditLeafSize::Block1G) => 3,
    }
}
const fn leaf_from_wire(raw: u8) -> Result<Option<EditLeafSize>, ()> {
    match raw {
        0 => Ok(None),
        1 => Ok(Some(EditLeafSize::Page)),
        2 => Ok(Some(EditLeafSize::Block2M)),
        3 => Ok(Some(EditLeafSize::Block1G)),
        _ => Err(()),
    }
}

const PERM_R: u8 = 1;
const PERM_W: u8 = 2;
const PERM_X: u8 = 4;
const PERM_U: u8 = 8;
const fn permissions_to_wire(p: EditPermissions) -> u8 {
    (if p.readable { PERM_R } else { 0 })
        | (if p.writable { PERM_W } else { 0 })
        | (if p.executable { PERM_X } else { 0 })
        | (if p.user { PERM_U } else { 0 })
}
const fn permissions_from_wire(raw: u8) -> Option<EditPermissions> {
    if raw & !(PERM_R | PERM_W | PERM_X | PERM_U) != 0 {
        return None;
    }
    Some(EditPermissions {
        readable: raw & PERM_R != 0,
        writable: raw & PERM_W != 0,
        executable: raw & PERM_X != 0,
        user: raw & PERM_U != 0,
    })
}

/// The descriptor operation class, mirroring `EditOperation` without ISA bits.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(u8)]
pub enum PublicationKind {
    Prepare = 1,
    Map = 2,
    Publish = 3,
    Protect = 4,
    ArmCow = 5,
    CowRepoint = 6,
    Unmap = 7,
    Coalesce = 8,
}
impl PublicationKind {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Prepare,
            2 => Self::Map,
            3 => Self::Publish,
            4 => Self::Protect,
            5 => Self::ArmCow,
            6 => Self::CowRepoint,
            7 => Self::Unmap,
            8 => Self::Coalesce,
            _ => return None,
        })
    }
    /// Kinds that name a new output frame under a host admission ticket.
    pub const fn names_output(self) -> bool {
        matches!(
            self,
            Self::Prepare | Self::Map | Self::CowRepoint | Self::Coalesce
        )
    }
    /// Kinds that change an existing alias. Each must name it: no record
    /// changes an alias's state without naming its frame and span.
    pub const fn requires_prior(self) -> bool {
        !matches!(self, Self::Prepare | Self::Map)
    }
}

/// Settled guest outcome. There is intentionally no indeterminate variant.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(u8)]
pub enum PublicationOutcome {
    /// Every store landed and the claimed drain completed.
    Applied = 1,
    /// Validation refused the edit before any live store.
    Refused = 2,
    /// Stores landed, then the guest restored every prior word.
    RolledBack = 3,
}
impl PublicationOutcome {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Applied,
            2 => Self::Refused,
            3 => Self::RolledBack,
            _ => return None,
        })
    }
}

/// The translation drain the guest claims it completed. The claim is
/// ISA-specific; the consumer decides how much of it to trust.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
#[repr(u8)]
pub enum PublicationDrain {
    /// Only the publishing CPU was drained.
    Local = 1,
    /// AArch64 inner-shareable invalidation of exactly this record's span.
    ArmBroadcastSpan = 2,
    /// AArch64 inner-shareable invalidation of the whole ASID.
    ArmBroadcastAsid = 3,
    /// x86 guest-claimed IPI shootdown. Never trusted to clear drain debt.
    X86ShootdownClaim = 4,
}
impl PublicationDrain {
    const fn from_wire(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Local,
            2 => Self::ArmBroadcastSpan,
            3 => Self::ArmBroadcastAsid,
            4 => Self::X86ShootdownClaim,
            _ => return None,
        })
    }
    pub const fn valid_for(self, isa: GuestIsa) -> bool {
        match self {
            Self::Local => true,
            Self::ArmBroadcastSpan | Self::ArmBroadcastAsid => matches!(isa, GuestIsa::Aarch64),
            Self::X86ShootdownClaim => matches!(isa, GuestIsa::X86_64),
        }
    }
}

const fn isa_to_wire(isa: GuestIsa) -> u8 {
    match isa {
        GuestIsa::Aarch64 => 1,
        GuestIsa::X86_64 => 2,
    }
}
const fn isa_from_wire(raw: u8) -> Option<GuestIsa> {
    match raw {
        1 => Some(GuestIsa::Aarch64),
        2 => Some(GuestIsa::X86_64),
        _ => None,
    }
}

/// Fixed 128-byte wire record. Fields are private: producers encode from a
/// typed [`PublicationView`] and consumers decode back to one, so no bare
/// `u64` crosses the boundary in either direction.
#[repr(C, align(8))]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct MmPublication {
    revision: u8,
    kind: u8,
    outcome: u8,
    drain: u8,
    isa: u8,
    permissions: u8,
    /// Low nibble: output/target leaf. High nibble: prior leaf. 0 = none.
    leaves: u8,
    table_grants: u8,
    mm: u64,
    incarnation: u64,
    counter: u64,
    edit_sequence: u64,
    root: u64,
    span_va: u64,
    span_len: u64,
    output: u64,
    prior_output: u64,
    ticket: u64,
    owner_generation: u64,
    prior_owner_generation: u64,
    edge_generation: u64,
    inventory_revision: u64,
    digest: u64,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<MmPublication>() == 128);
    assert!(align_of::<MmPublication>() == 8);
    assert!(offset_of!(MmPublication, revision) == 0);
    assert!(offset_of!(MmPublication, kind) == 1);
    assert!(offset_of!(MmPublication, outcome) == 2);
    assert!(offset_of!(MmPublication, drain) == 3);
    assert!(offset_of!(MmPublication, isa) == 4);
    assert!(offset_of!(MmPublication, permissions) == 5);
    assert!(offset_of!(MmPublication, leaves) == 6);
    assert!(offset_of!(MmPublication, table_grants) == 7);
    assert!(offset_of!(MmPublication, mm) == 8);
    assert!(offset_of!(MmPublication, incarnation) == 16);
    assert!(offset_of!(MmPublication, counter) == 24);
    assert!(offset_of!(MmPublication, edit_sequence) == 32);
    assert!(offset_of!(MmPublication, root) == 40);
    assert!(offset_of!(MmPublication, span_va) == 48);
    assert!(offset_of!(MmPublication, span_len) == 56);
    assert!(offset_of!(MmPublication, output) == 64);
    assert!(offset_of!(MmPublication, prior_output) == 72);
    assert!(offset_of!(MmPublication, ticket) == 80);
    assert!(offset_of!(MmPublication, owner_generation) == 88);
    assert!(offset_of!(MmPublication, prior_owner_generation) == 96);
    assert!(offset_of!(MmPublication, edge_generation) == 104);
    assert!(offset_of!(MmPublication, inventory_revision) == 112);
    assert!(offset_of!(MmPublication, digest) == 120);
};

/// Identity of the publishing edit.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PublicationIdentity {
    pub mm: PublicationMm,
    pub incarnation: MmIncarnation,
    pub counter: PublicationCounter,
    pub edit_sequence: EditSequence,
    pub root: RootGpa,
}

/// A new output named under a host admission ticket.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PublishedOutput {
    pub address: Stage1Ipa,
    pub leaf: EditLeafSize,
    pub ticket: TicketId,
    pub owner_generation: OwnerGeneration,
    pub access: ExtentAccess,
    pub inventory_revision: InventoryRevision,
}

/// One exact prior alias the edit removed or replaced.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PublishedPrior {
    pub address: Stage1Ipa,
    pub leaf: EditLeafSize,
    pub owner_generation: OwnerGeneration,
}

/// Typed content of one publication. Construct with [`PublicationView::checked`].
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PublicationView {
    kind: PublicationKind,
    outcome: PublicationOutcome,
    drain: PublicationDrain,
    isa: GuestIsa,
    permissions: EditPermissions,
    table_grants: TableGrantCount,
    identity: PublicationIdentity,
    span: UserRange,
    output: Option<PublishedOutput>,
    prior: Option<PublishedPrior>,
}

/// Why a record or view was rejected. Every variant is a quarantine cause at
/// the consumer; none is a retry signal.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PublicationDecodeError {
    Revision,
    Kind,
    Outcome,
    Drain,
    Isa,
    Permissions,
    Leaf,
    Identity,
    Root,
    Span,
    Output,
    Prior,
    TableGrants,
    Digest,
}

const fn aligned(raw: u64, bytes: u64) -> bool {
    raw & (bytes - 1) == 0
}

/// Shape of one publication, before validation.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PublicationShape {
    pub kind: PublicationKind,
    pub outcome: PublicationOutcome,
    pub drain: PublicationDrain,
    pub isa: GuestIsa,
    pub permissions: EditPermissions,
    pub table_grants: TableGrantCount,
}

impl PublicationView {
    /// Validate shape:
    /// - span page-aligned and non-empty;
    /// - output (and its ticket) present exactly for output kinds, aligned to
    ///   its leaf, with the span starting on that leaf boundary (parent-block
    ///   alignment for `Block2M`/`Block1G` and `Coalesce`);
    /// - a prior for every kind that changes an existing alias (all but
    ///   `Prepare`/`Map`), aligned to its own leaf and covering exactly the
    ///   span as a whole number of its leaves (the alias's actual extent);
    ///   `Coalesce` keeps the prior's frame and only grows its leaf;
    /// - `ArmCow` never grants write;
    /// - drain claim valid for the ISA; a refused edit claims no drain;
    /// - table grants only under an output ticket.
    pub fn checked(
        shape: PublicationShape,
        identity: PublicationIdentity,
        span: UserRange,
        output: Option<PublishedOutput>,
        prior: Option<PublishedPrior>,
    ) -> Result<Self, PublicationDecodeError> {
        use PublicationDecodeError as E;
        let PublicationShape {
            kind,
            outcome,
            drain,
            isa,
            permissions,
            table_grants,
        } = shape;
        let start = span.start().raw();
        let len = span.len().raw();
        if span.is_empty()
            || !aligned(start, PUBLICATION_GRANULE)
            || !aligned(len, PUBLICATION_GRANULE)
        {
            return Err(E::Span);
        }
        if !drain.valid_for(isa)
            || (outcome == PublicationOutcome::Refused && drain != PublicationDrain::Local)
        {
            return Err(E::Drain);
        }
        if kind.names_output() != output.is_some() {
            return Err(E::Output);
        }
        if let Some(out) = output {
            let bytes = leaf_bytes(out.leaf);
            let fits = out.address.raw().checked_add(len).is_some();
            let whole_leaf = kind != PublicationKind::Coalesce || len == bytes;
            if !aligned(out.address.raw(), bytes)
                || !aligned(start, bytes)
                || !aligned(len, bytes)
                || !fits
                || !whole_leaf
            {
                return Err(E::Output);
            }
        }
        if output.is_none() && table_grants.0 != 0 {
            return Err(E::TableGrants);
        }
        if kind.requires_prior() != prior.is_some() {
            return Err(E::Prior);
        }
        if let Some(p) = prior {
            let bytes = leaf_bytes(p.leaf);
            if !aligned(p.address.raw(), bytes)
                || !aligned(len, bytes)
                || p.address.raw().checked_add(len).is_none()
            {
                return Err(E::Prior);
            }
            if kind == PublicationKind::Coalesce
                && output.is_none_or(|o| o.address != p.address || leaf_bytes(o.leaf) <= bytes)
            {
                return Err(E::Prior);
            }
        }
        if kind == PublicationKind::ArmCow && permissions.writable {
            return Err(E::Permissions);
        }
        Ok(Self {
            kind,
            outcome,
            drain,
            isa,
            permissions,
            table_grants,
            identity,
            span,
            output,
            prior,
        })
    }

    pub const fn kind(&self) -> PublicationKind {
        self.kind
    }
    pub const fn outcome(&self) -> PublicationOutcome {
        self.outcome
    }
    pub const fn drain(&self) -> PublicationDrain {
        self.drain
    }
    pub const fn isa(&self) -> GuestIsa {
        self.isa
    }
    pub const fn permissions(&self) -> EditPermissions {
        self.permissions
    }
    pub const fn table_grants(&self) -> TableGrantCount {
        self.table_grants
    }
    pub const fn identity(&self) -> PublicationIdentity {
        self.identity
    }
    pub const fn key(&self) -> MmIncarnationKey {
        MmIncarnationKey {
            mm: self.identity.mm,
            incarnation: self.identity.incarnation,
        }
    }
    pub const fn counter(&self) -> PublicationCounter {
        self.identity.counter
    }
    pub const fn root(&self) -> RootGpa {
        self.identity.root
    }
    /// Informational only: the host must never resolve this user span.
    pub const fn span(&self) -> UserRange {
        self.span
    }
    pub const fn output(&self) -> Option<PublishedOutput> {
        self.output
    }
    pub const fn prior(&self) -> Option<PublishedPrior> {
        self.prior
    }
}

/// Integrity digest over the first 120 bytes (FNV-1a, 64-bit). It detects a
/// torn or mis-sized record; it is not a cryptographic authenticator, so the
/// consumer still authenticates every field against its own ledger.
fn digest_words(words: &[u64; 15]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

impl MmPublication {
    pub const REVISION: u8 = 2;
    pub const SIZE: usize = 128;

    fn header_word(&self) -> u64 {
        u64::from_le_bytes([
            self.revision,
            self.kind,
            self.outcome,
            self.drain,
            self.isa,
            self.permissions,
            self.leaves,
            self.table_grants,
        ])
    }

    fn words(&self) -> [u64; 15] {
        [
            self.header_word(),
            self.mm,
            self.incarnation,
            self.counter,
            self.edit_sequence,
            self.root,
            self.span_va,
            self.span_len,
            self.output,
            self.prior_output,
            self.ticket,
            self.owner_generation,
            self.prior_owner_generation,
            self.edge_generation,
            self.inventory_revision,
        ]
    }

    /// Encode a validated view and seal it with its digest.
    pub fn encode(view: &PublicationView) -> Self {
        let out = view.output;
        let prior = view.prior;
        let id = view.identity;
        let mut record = Self {
            revision: Self::REVISION,
            kind: view.kind as u8,
            outcome: view.outcome as u8,
            drain: view.drain as u8,
            isa: isa_to_wire(view.isa),
            permissions: permissions_to_wire(view.permissions),
            leaves: leaf_to_wire(out.map(|o| o.leaf)) | leaf_to_wire(prior.map(|p| p.leaf)) << 4,
            table_grants: view.table_grants.0,
            mm: id.mm.raw().get(),
            incarnation: id.incarnation.raw().get(),
            counter: id.counter.raw().get(),
            edit_sequence: id.edit_sequence.raw().get(),
            root: id.root.address().raw(),
            span_va: view.span.start().raw(),
            span_len: view.span.len().raw(),
            output: out.map_or(0, |o| o.address.raw()),
            prior_output: prior.map_or(0, |p| p.address.raw()),
            ticket: out.map_or(0, |o| o.ticket.raw().get()),
            owner_generation: out.map_or(0, |o| o.owner_generation.raw().get()),
            prior_owner_generation: prior.map_or(0, |p| p.owner_generation.raw().get()),
            edge_generation: match out.map(|o| o.access) {
                Some(ExtentAccess::Edge(edge)) => edge.raw().get(),
                _ => 0,
            },
            inventory_revision: out.map_or(0, |o| o.inventory_revision.raw().get()),
            digest: 0,
        };
        record.digest = digest_words(&record.words());
        record
    }

    /// Decode and validate every field. Any failure is a quarantine cause.
    pub fn decode(&self) -> Result<PublicationView, PublicationDecodeError> {
        use PublicationDecodeError as E;
        if self.revision != Self::REVISION {
            return Err(E::Revision);
        }
        if self.digest != digest_words(&self.words()) {
            return Err(E::Digest);
        }
        let kind = PublicationKind::from_wire(self.kind).ok_or(E::Kind)?;
        let outcome = PublicationOutcome::from_wire(self.outcome).ok_or(E::Outcome)?;
        let drain = PublicationDrain::from_wire(self.drain).ok_or(E::Drain)?;
        let isa = isa_from_wire(self.isa).ok_or(E::Isa)?;
        let permissions = permissions_from_wire(self.permissions).ok_or(E::Permissions)?;
        let out_leaf = leaf_from_wire(self.leaves & 0xf).map_err(|()| E::Leaf)?;
        let prior_leaf = leaf_from_wire(self.leaves >> 4).map_err(|()| E::Leaf)?;
        let nz = |raw: u64, e: E| NonZeroU64::new(raw).ok_or(e);
        let identity = PublicationIdentity {
            mm: PublicationMm::new(nz(self.mm, E::Identity)?),
            incarnation: MmIncarnation::new(nz(self.incarnation, E::Identity)?),
            counter: PublicationCounter::new(nz(self.counter, E::Identity)?),
            edit_sequence: EditSequence::new(nz(self.edit_sequence, E::Identity)?),
            root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(self.root))
                .ok_or(E::Root)?,
        };
        let span = UserRange::checked(UserVa::new(self.span_va), GuestLen::new(self.span_len))
            .ok_or(E::Span)?;
        let output = match out_leaf {
            None => {
                if [
                    self.output,
                    self.ticket,
                    self.owner_generation,
                    self.edge_generation,
                    self.inventory_revision,
                ] != [0; 5]
                {
                    return Err(E::Output);
                }
                None
            }
            Some(leaf) => Some(PublishedOutput {
                address: Stage1Ipa::new(self.output),
                leaf,
                ticket: TicketId::new(nz(self.ticket, E::Output)?),
                owner_generation: OwnerGeneration::new(nz(self.owner_generation, E::Output)?),
                access: match NonZeroU64::new(self.edge_generation) {
                    None => ExtentAccess::Owner,
                    Some(edge) => ExtentAccess::Edge(EdgeGeneration::new(edge)),
                },
                inventory_revision: InventoryRevision::new(nz(self.inventory_revision, E::Output)?),
            }),
        };
        let prior = match prior_leaf {
            None => {
                if self.prior_output != 0 || self.prior_owner_generation != 0 {
                    return Err(E::Prior);
                }
                None
            }
            Some(leaf) => Some(PublishedPrior {
                address: Stage1Ipa::new(self.prior_output),
                leaf,
                owner_generation: OwnerGeneration::new(nz(self.prior_owner_generation, E::Prior)?),
            }),
        };
        PublicationView::checked(
            PublicationShape {
                kind,
                outcome,
                drain,
                isa,
                permissions,
                table_grants: TableGrantCount(self.table_grants),
            },
            identity,
            span,
            output,
            prior,
        )
    }
}

/// One counter on its own cache line, so producer and consumer stores do
/// not false-share.
#[repr(C, align(64))]
struct RingIndex(AtomicU64);

/// Bounded single-producer/single-consumer record ring for later per-vCPU
/// use. The producer is the publishing CPU; the consumer is the host drain.
/// `head` and `tail` are free-running counters; slot = counter & (N - 1).
/// The ring may live in guest-writable memory, so the consumer treats both
/// indices and every slot as untrusted: it clamps occupancy to `N` and reads
/// slots with volatile copies before decoding them.
#[repr(C, align(64))]
pub struct PublicationRing<const N: usize> {
    head: RingIndex,
    tail: RingIndex,
    watermark: u64,
    slots: [UnsafeCell<MmPublication>; N],
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(PublicationRing<1>, head) == 0);
    assert!(offset_of!(PublicationRing<1>, tail) == 64);
    assert!(offset_of!(PublicationRing<1>, watermark) == 128);
    assert!(offset_of!(PublicationRing<1>, slots) == 136);
    assert!(core::mem::size_of::<RingIndex>() == 64);
};

// SAFETY: slot access is partitioned by the head/tail protocol. The single
// producer writes only slots in [head, tail + N) before releasing `head`; the
// single consumer reads only slots in [tail, head) after acquiring `head` and
// releases them by storing `tail`. `split` takes `&mut self`, so at most one
// producer and one consumer handle exist at a time.
unsafe impl<const N: usize> Sync for PublicationRing<N> {}

/// The ring could not accept a record; the producer must request a drain
/// before continuing. The caller still holds the record; nothing was dropped.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct RingFull;

/// The indices describe more than `N` records: the ring is corrupt and its
/// producer must be quarantined.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct RingCorrupt;

/// Occupancy after a successful push.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum RingPressure {
    Below,
    /// Occupancy reached the watermark: request a host drain now.
    AtWatermark,
}

const EMPTY_RECORD: MmPublication = MmPublication {
    revision: 0,
    kind: 0,
    outcome: 0,
    drain: 0,
    isa: 0,
    permissions: 0,
    leaves: 0,
    table_grants: 0,
    mm: 0,
    incarnation: 0,
    counter: 0,
    edit_sequence: 0,
    root: 0,
    span_va: 0,
    span_len: 0,
    output: 0,
    prior_output: 0,
    ticket: 0,
    owner_generation: 0,
    prior_owner_generation: 0,
    edge_generation: 0,
    inventory_revision: 0,
    digest: 0,
};

impl<const N: usize> PublicationRing<N> {
    const CAPACITY: u64 = N as u64;
    const MASK: u64 = Self::CAPACITY.wrapping_sub(1);

    /// `None` unless `N` is a nonzero power of two and the watermark is in
    /// `1..=N`.
    pub fn new(watermark: usize) -> Option<Self> {
        if !N.is_power_of_two() || watermark == 0 || watermark > N {
            return None;
        }
        Some(Self {
            head: RingIndex(AtomicU64::new(0)),
            tail: RingIndex(AtomicU64::new(0)),
            watermark: u64::try_from(watermark).ok()?,
            slots: core::array::from_fn(|_| UnsafeCell::new(EMPTY_RECORD)),
        })
    }

    pub fn split(&mut self) -> (RingProducer<'_, N>, RingConsumer<'_, N>) {
        let ring: &Self = self;
        (RingProducer { ring }, RingConsumer { ring })
    }

    fn slot(&self, counter: u64) -> Option<&UnsafeCell<MmPublication>> {
        self.slots.get(usize::try_from(counter & Self::MASK).ok()?)
    }
}

pub struct RingProducer<'a, const N: usize> {
    ring: &'a PublicationRing<N>,
}

impl<const N: usize> RingProducer<'_, N> {
    pub fn push(&mut self, record: &MmPublication) -> Result<RingPressure, RingFull> {
        let ring = self.ring;
        let head = ring.head.0.load(Ordering::Relaxed);
        let tail = ring.tail.0.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used >= PublicationRing::<N>::CAPACITY {
            return Err(RingFull);
        }
        let slot = ring.slot(head).ok_or(RingFull)?;
        // SAFETY: `head - tail < N`, so this slot is outside [tail, head) and
        // the consumer does not read it until `head` is released below. The
        // pointer comes from a live `UnsafeCell` in this ring.
        unsafe { core::ptr::write_volatile(slot.get(), *record) };
        ring.head.0.store(head.wrapping_add(1), Ordering::Release);
        if used + 1 >= ring.watermark {
            Ok(RingPressure::AtWatermark)
        } else {
            Ok(RingPressure::Below)
        }
    }
}

pub struct RingConsumer<'a, const N: usize> {
    ring: &'a PublicationRing<N>,
}

impl<const N: usize> RingConsumer<'_, N> {
    /// Pop one record. A head that runs more than `N` ahead of the tail is
    /// corruption, never an occupancy.
    pub fn pop(&mut self) -> Result<Option<MmPublication>, RingCorrupt> {
        let ring = self.ring;
        let tail = ring.tail.0.load(Ordering::Relaxed);
        let head = ring.head.0.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used > PublicationRing::<N>::CAPACITY {
            return Err(RingCorrupt);
        }
        if used == 0 {
            return Ok(None);
        }
        let slot = ring.slot(tail).ok_or(RingCorrupt)?;
        // SAFETY: `tail < head <= tail + N`, and the acquire load of `head`
        // orders the producer's write of this slot before this read. The
        // producer does not overwrite it until `tail` is released below. The
        // volatile copy reads the slot exactly once; decode validates it.
        let record = unsafe { core::ptr::read_volatile(slot.get()) };
        ring.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(Some(record))
    }

    /// Pop the records visible at one head snapshot, in ring order. A
    /// producer that keeps refilling cannot extend the drain: the work is
    /// bounded by the snapshot occupancy, at most `N`.
    pub fn drain_into(
        &mut self,
        out: &mut alloc::vec::Vec<MmPublication>,
    ) -> Result<usize, RingCorrupt> {
        self.drain_with(out, |_| {})
    }

    fn drain_with(
        &mut self,
        out: &mut alloc::vec::Vec<MmPublication>,
        mut after_pop: impl FnMut(&mut Self),
    ) -> Result<usize, RingCorrupt> {
        let ring = self.ring;
        let tail = ring.tail.0.load(Ordering::Relaxed);
        let head = ring.head.0.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used > PublicationRing::<N>::CAPACITY {
            return Err(RingCorrupt);
        }
        let snapshot = usize::try_from(used).map_err(|_| RingCorrupt)?;
        out.try_reserve(snapshot).map_err(|_| RingCorrupt)?;
        let mut count = 0;
        while count < snapshot {
            let Some(record) = self.pop()? else {
                return Err(RingCorrupt);
            };
            out.push(record);
            count += 1;
            after_pop(self);
        }
        Ok(count)
    }

    #[cfg(test)]
    fn corrupt_head(&self, head: u64) {
        self.ring.head.0.store(head, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
