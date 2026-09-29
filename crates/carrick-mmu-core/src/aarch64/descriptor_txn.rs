//! Guest-owned live stage-1 descriptor transactions.
//!
//! # Ownership
//!
//! A live stage-1 image has exactly one descriptor writer. On the lane where
//! guest EL1 owns an address space's live tables, that writer is EL1: every
//! host-facing engine operation that would edit live descriptors (bulk grant
//! preparation, permission changes, retirement, copyout residency and fork
//! COW repointing) is described as one [`DescriptorTxn`], submitted through a
//! [`DescriptorTxnSlot`], executed in EL1 by `execute_descriptor_txn` under
//! the exact-MM editor, and answered with one [`DescriptorReceipt`]. The host
//! manager on that lane is marked [`super::LiveDescriptorOwner::Guest`] and
//! refuses every live store (`sync_to_host`, snapshot restore and rollback
//! publication) with [`super::PageTableError::GuestOwnsLiveDescriptors`].
//! Offline construction (an unpublished fork child or exec image) and other
//! backend venues are outside this protocol.
//!
//! # Identities
//!
//! A transaction names four distinct domains, none of which may substitute
//! for another:
//!
//! * [`DescriptorTxnId`]: the exact MM key plus a host-chosen, nonzero
//!   transaction generation. Receipts bind to this pair.
//! * `root`: the primary stage-1 table IPA the host authenticated for that MM
//!   (the TTBR0 base). EL1 refuses a transaction whose root is not the root of
//!   the published space it is editing ([`DescriptorRefusal::StaleRoot`]).
//! * semantic VA spans and their output IPAs.
//! * [`BackingIdentity`]: the frame, mapping, stage-2 owner generation and
//!   inventory revision that authenticated the output IPA *before* the host
//!   submitted the transaction. No valid descriptor can therefore precede
//!   backing and inventory readiness: the host cannot construct a
//!   [`DescriptorOp::Prepare`] or [`DescriptorOp::CowRepoint`] without them.
//!
//! # Table capacity
//!
//! The host remains the single allocator of stage-1 table-page identity (two
//! allocators on one arena reissued the same page; see the 2026-09-27
//! incident). A transaction that must create hierarchy or split a coarse
//! block consumes host-reserved, unlinked pages from its [`TableGrants`],
//! which must lie in the EL1-reachable primary arena. A transaction that
//! needs more pages than it carries, or a table reachable only through an
//! extension arena, is refused whole before the first store
//! ([`DescriptorRefusal::TablesExhausted`],
//! [`DescriptorRefusal::TableOutsidePrimary`]). The receipt reports how many
//! grants were linked; the host returns the unused suffix to its allocator.
//!
//! # Atomicity and rollback
//!
//! `execute_descriptor_txn` validates the complete range, grant need and
//! journal capacity before the first live store. New hierarchy and split
//! tables are filled while unlinked and published child-before-parent after a
//! store barrier; replacing a valid block with a table is break-before-make.
//! Every live store is a compare-exchange against the validated value and is
//! journaled, so a failure after publication restores the exact pre-image
//! ([`DescriptorOutcome::RolledBack`]). A rollback that itself cannot restore
//! a word is [`DescriptorOutcome::Indeterminate`] and must be fatal.
//!
//! # Receipts required by backing adapters
//!
//! A host adapter must not repoint inventory, retire an old owner, commit
//! residency or return table grants until it holds a
//! [`VerifiedDescriptorReceipt`], which only [`DescriptorTxn::verify_receipt`]
//! can construct: the receipt must name the exact submitted transaction id,
//! carry the digest of the exact submitted operation, and report an applied
//! outcome. The verified receipt exposes the exact resident pages (never the
//! whole grant), the linked-grant prefix, and, for COW, the exact
//! old/new outputs and backing identity the guest installed. The adapter still
//! compares that backing identity with its current inventory owner generation
//! before retiring the old owner; a receipt proves what EL1 wrote, not that the
//! host's inventory has not since moved.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;

use super::{
    GuestLeafPublication, GuestPermissionEdit, LeafAccess, PA_MASK_4KIB, PT_PAGE, SubstrateGpa,
};

/// Wire protocol revision of [`DescriptorTxnSlot`]. Both venues must agree.
pub const DESCRIPTOR_TXN_PROTOCOL_VERSION: u64 = 1;

/// Maximum host-reserved table pages carried by one transaction. A 2 MiB
/// grant needs at most one L1, one L2 and two L3 tables when it straddles a
/// 2 MiB boundary; one coarse-block split per span end needs at most two
/// more pages per level below 1 GiB.
pub const MAX_TABLE_GRANTS: usize = 8;

/// Highest translated TTBR0 VA plus one (48-bit, 4 KiB granule, 4 levels).
const VA_LIMIT: u64 = 1 << 48;

/// Exact MM and host-chosen transaction generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DescriptorTxnId {
    pub mm_key: NonZeroU64,
    pub generation: NonZeroU64,
}

/// The backing identity the host authenticated for an output IPA before
/// submitting a transaction that exposes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackingIdentity {
    pub frame_id: NonZeroU64,
    pub mapping_id: NonZeroU64,
    pub owner_generation: NonZeroU64,
    pub inventory_revision: NonZeroU64,
}

/// One page-aligned semantic VA span. `len == 0` is the empty span.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PageSpan {
    pub va: u64,
    pub len: u64,
}

impl PageSpan {
    pub const EMPTY: Self = Self { va: 0, len: 0 };

    #[must_use]
    pub const fn new(va: u64, len: u64) -> Self {
        Self { va, len }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Exclusive end, or `None` on overflow.
    #[must_use]
    pub const fn end(self) -> Option<u64> {
        self.va.checked_add(self.len)
    }

    /// A nonempty, page-aligned span inside the translated TTBR0 range.
    #[must_use]
    pub fn is_well_formed(self) -> bool {
        self.len != 0
            && self.va.is_multiple_of(PT_PAGE)
            && self.len.is_multiple_of(PT_PAGE)
            && self.end().is_some_and(|end| end <= VA_LIMIT)
    }

    #[must_use]
    pub fn contains_span(self, inner: Self) -> bool {
        inner.is_empty()
            || (inner.va >= self.va
                && matches!((inner.end(), self.end()), (Some(a), Some(b)) if a <= b))
    }

    #[must_use]
    pub fn contains(self, va: u64) -> bool {
        va >= self.va && self.end().is_some_and(|end| va < end)
    }
}

/// One live descriptor operation. Every variant names the exact semantic
/// span it may edit; nothing outside that span changes except split parents
/// replaced by an equivalent table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorOp {
    /// Install an authenticated private-anonymous grant as prepared L3 leaves
    /// and make exactly the `resident` sub-span valid. Target leaves must be
    /// invalid and not already prepared; retired leases are replaced.
    Prepare {
        publication: GuestLeafPublication,
        resident: PageSpan,
        backing: BackingIdentity,
    },
    /// Make prepared leaves resident for an exact span whose retained output
    /// must start at `expected_ipa`, if the leaf permissions admit `access`.
    /// Used for host copyout into prepared pages and for guest first touch.
    Publish {
        span: PageSpan,
        expected_ipa: SubstrateGpa,
        access: LeafAccess,
    },
    /// Change permissions on prepared and/or resident private leaves. The
    /// software write/execute ceiling bounds the result; COW-armed leaves are
    /// refused. Prepared leaves stay invalid.
    Protect(GuestPermissionEdit),
    /// Retire prepared and resident private leaves, retaining outputs for the
    /// host's lease reconciliation.
    Retire(PageSpan),
    /// Repoint one COW-armed resident private page from `old_ipa` to the
    /// private copy at `new_ipa`, restoring the recorded write permission.
    /// The copy itself must be complete before submission.
    CowRepoint {
        va: u64,
        old_ipa: SubstrateGpa,
        new_ipa: SubstrateGpa,
        backing: BackingIdentity,
    },
}

impl DescriptorOp {
    const KIND_PREPARE: u64 = 1;
    const KIND_PUBLISH: u64 = 2;
    const KIND_PROTECT: u64 = 3;
    const KIND_RETIRE: u64 = 4;
    const KIND_COW_REPOINT: u64 = 5;

    /// The complete semantic span this operation may edit.
    #[must_use]
    pub fn span(&self) -> PageSpan {
        match *self {
            Self::Prepare { publication, .. } => PageSpan::new(publication.va, publication.len),
            Self::Publish { span, .. } | Self::Retire(span) => span,
            Self::Protect(edit) => PageSpan::new(edit.va, edit.len),
            Self::CowRepoint { va, .. } => PageSpan::new(va, PT_PAGE),
        }
    }

    /// The backing identity whose readiness this operation relies on.
    #[must_use]
    pub fn backing(&self) -> Option<BackingIdentity> {
        match *self {
            Self::Prepare { backing, .. } | Self::CowRepoint { backing, .. } => Some(backing),
            _ => None,
        }
    }

    fn kind(&self) -> u64 {
        match self {
            Self::Prepare { .. } => Self::KIND_PREPARE,
            Self::Publish { .. } => Self::KIND_PUBLISH,
            Self::Protect(_) => Self::KIND_PROTECT,
            Self::Retire(_) => Self::KIND_RETIRE,
            Self::CowRepoint { .. } => Self::KIND_COW_REPOINT,
        }
    }

    /// Kind plus six payload words, the wire and digest encoding.
    fn encode(&self) -> (u64, [u64; 6]) {
        let bool_word = |flag: bool, shift: u32| u64::from(flag) << shift;
        let payload = match *self {
            Self::Prepare {
                publication,
                resident,
                ..
            } => [
                publication.va,
                publication.ipa,
                publication.len,
                bool_word(publication.writable, 0) | bool_word(publication.executable, 1),
                resident.va,
                resident.len,
            ],
            Self::Publish {
                span,
                expected_ipa,
                access,
            } => [span.va, span.len, expected_ipa.raw(), access as u64, 0, 0],
            Self::Protect(edit) => [
                edit.va,
                edit.len,
                bool_word(edit.readable, 0)
                    | bool_word(edit.writable, 1)
                    | bool_word(edit.executable, 2),
                0,
                0,
                0,
            ],
            Self::Retire(span) => [span.va, span.len, 0, 0, 0, 0],
            Self::CowRepoint {
                va,
                old_ipa,
                new_ipa,
                ..
            } => [va, old_ipa.raw(), new_ipa.raw(), 0, 0, 0],
        };
        (self.kind(), payload)
    }

    fn decode(kind: u64, payload: [u64; 6], backing: Option<BackingIdentity>) -> Option<Self> {
        let access = |raw| match raw {
            0 => Some(LeafAccess::Read),
            1 => Some(LeafAccess::Write),
            2 => Some(LeafAccess::Execute),
            _ => None,
        };
        match kind {
            Self::KIND_PREPARE if payload[3] & !0b11 == 0 => Some(Self::Prepare {
                publication: GuestLeafPublication {
                    va: payload[0],
                    ipa: payload[1],
                    len: payload[2],
                    writable: payload[3] & 1 != 0,
                    executable: payload[3] & 2 != 0,
                },
                resident: PageSpan::new(payload[4], payload[5]),
                backing: backing?,
            }),
            Self::KIND_PUBLISH => Some(Self::Publish {
                span: PageSpan::new(payload[0], payload[1]),
                expected_ipa: SubstrateGpa(payload[2]),
                access: access(payload[3])?,
            }),
            Self::KIND_PROTECT if payload[2] & !0b111 == 0 => {
                Some(Self::Protect(GuestPermissionEdit {
                    va: payload[0],
                    len: payload[1],
                    readable: payload[2] & 1 != 0,
                    writable: payload[2] & 2 != 0,
                    executable: payload[2] & 4 != 0,
                }))
            }
            Self::KIND_RETIRE => Some(Self::Retire(PageSpan::new(payload[0], payload[1]))),
            Self::KIND_COW_REPOINT => Some(Self::CowRepoint {
                va: payload[0],
                old_ipa: SubstrateGpa(payload[1]),
                new_ipa: SubstrateGpa(payload[2]),
                backing: backing?,
            }),
            _ => None,
        }
    }
}

/// Host-reserved, unlinked table pages in the EL1-reachable primary arena.
/// EL1 consumes them in order; the receipt reports the linked prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableGrants {
    len: u8,
    pages: [u64; MAX_TABLE_GRANTS],
}

impl TableGrants {
    pub const NONE: Self = Self {
        len: 0,
        pages: [0; MAX_TABLE_GRANTS],
    };

    /// `None` when there are too many pages, a page is not table-aligned or
    /// zero, or a page repeats.
    #[must_use]
    pub fn new(pages: &[SubstrateGpa]) -> Option<Self> {
        if pages.len() > MAX_TABLE_GRANTS {
            return None;
        }
        let mut grants = Self::NONE;
        for (index, page) in pages.iter().enumerate() {
            let raw = page.raw();
            if raw == 0
                || !raw.is_multiple_of(PT_PAGE)
                || raw & !PA_MASK_4KIB != 0
                || grants.pages[..index].contains(&raw)
            {
                return None;
            }
            grants.pages[index] = raw;
        }
        grants.len = pages.len() as u8;
        Some(grants)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.pages[..usize::from(self.len)]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pages after the first `linked`, which the host must return.
    #[must_use]
    pub fn unused_after(&self, linked: usize) -> &[u64] {
        self.as_slice().get(linked..).unwrap_or(&[])
    }
}

/// One authenticated live descriptor transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorTxn {
    pub id: DescriptorTxnId,
    /// Primary stage-1 table IPA (TTBR0 base) the host authenticated.
    pub root: SubstrateGpa,
    pub op: DescriptorOp,
    pub tables: TableGrants,
}

fn mix(hash: u64, word: u64) -> u64 {
    let x = (hash ^ word).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^ (x >> 29)
}

impl DescriptorTxn {
    /// Fingerprint of every field EL1 acts on. A receipt carries the digest
    /// of what EL1 decoded and executed, so it cannot authenticate a
    /// different operation that happens to share an id.
    #[must_use]
    pub fn digest(&self) -> u64 {
        let (kind, payload) = self.op.encode();
        let mut hash = mix(DESCRIPTOR_TXN_PROTOCOL_VERSION, self.id.mm_key.get());
        hash = mix(hash, self.id.generation.get());
        hash = mix(hash, self.root.raw());
        hash = mix(hash, kind);
        for word in payload {
            hash = mix(hash, word);
        }
        let backing = self.op.backing();
        for word in [
            backing.map_or(0, |b| b.frame_id.get()),
            backing.map_or(0, |b| b.mapping_id.get()),
            backing.map_or(0, |b| b.owner_generation.get()),
            backing.map_or(0, |b| b.inventory_revision.get()),
        ] {
            hash = mix(hash, word);
        }
        hash = mix(hash, self.tables.len() as u64);
        for &page in self.tables.as_slice() {
            hash = mix(hash, page);
        }
        hash
    }

    /// Authenticate a guest receipt against this exact submission.
    pub fn verify_receipt(
        &self,
        receipt: &DescriptorReceipt,
    ) -> Result<VerifiedDescriptorReceipt, ReceiptError> {
        if receipt.id != self.id {
            return Err(ReceiptError::WrongTransaction);
        }
        if receipt.digest != self.digest() {
            return Err(ReceiptError::DigestMismatch);
        }
        let DescriptorOutcome::Applied(applied) = receipt.outcome else {
            return Err(ReceiptError::NotApplied(receipt.outcome));
        };
        let expected_resident = match self.op {
            DescriptorOp::Prepare { resident, .. } => resident,
            DescriptorOp::Publish { span, .. } => span,
            _ => PageSpan::EMPTY,
        };
        if usize::from(applied.tables_linked) > self.tables.len()
            || applied.resident != expected_resident
            || applied.pages != self.op.span().len / PT_PAGE
        {
            return Err(ReceiptError::InconsistentReceipt);
        }
        Ok(VerifiedDescriptorReceipt {
            txn: *self,
            applied,
        })
    }
}

/// Why EL1 did not apply a transaction. Wire codes are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DescriptorRefusal {
    BadRange = 1,
    StaleRoot = 2,
    TableOutsidePrimary = 3,
    MissingTable = 4,
    NotPrivateAnonymous = 5,
    PermissionWidening = 6,
    CowArmed = 7,
    AlreadyValid = 8,
    Occupied = 9,
    Malformed = 10,
    NotPrepared = 11,
    WrongBacking = 12,
    PermissionDenied = 13,
    NotCowArmed = 14,
    TablesExhausted = 15,
    BadTableGrant = 16,
    JournalCapacity = 17,
    Contended = 18,
    BadEncoding = 19,
    WrongMm = 20,
}

impl DescriptorRefusal {
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::BadRange,
            2 => Self::StaleRoot,
            3 => Self::TableOutsidePrimary,
            4 => Self::MissingTable,
            5 => Self::NotPrivateAnonymous,
            6 => Self::PermissionWidening,
            7 => Self::CowArmed,
            8 => Self::AlreadyValid,
            9 => Self::Occupied,
            10 => Self::Malformed,
            11 => Self::NotPrepared,
            12 => Self::WrongBacking,
            13 => Self::PermissionDenied,
            14 => Self::NotCowArmed,
            15 => Self::TablesExhausted,
            16 => Self::BadTableGrant,
            17 => Self::JournalCapacity,
            18 => Self::Contended,
            19 => Self::BadEncoding,
            20 => Self::WrongMm,
            _ => return None,
        })
    }
}

/// Exact effect of an applied transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorApplied {
    /// Semantic 4 KiB pages covered by the operation span.
    pub pages: u64,
    /// Exact pages that are resident because of this operation: the
    /// `resident` sub-span of a prepare, the span of a publish, else empty.
    pub resident: PageSpan,
    /// Prefix of [`TableGrants`] now linked into the live graph.
    pub tables_linked: u8,
    /// Live descriptor words replaced (journaled compare-exchanges).
    pub live_stores: u32,
    /// Whether the caller must invalidate the MM's ASID before reuse.
    pub flush_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorOutcome {
    Applied(DescriptorApplied),
    /// Refused before the first live store.
    Refused(DescriptorRefusal),
    /// Failed after publication; every journaled live store was restored.
    /// The caller must still invalidate the ASID.
    RolledBack(DescriptorRefusal),
    /// Rollback could not restore the pre-image. Fatal for the MM.
    Indeterminate(DescriptorRefusal),
}

/// EL1's answer to one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorReceipt {
    pub id: DescriptorTxnId,
    /// Digest of the transaction EL1 decoded and executed.
    pub digest: u64,
    pub outcome: DescriptorOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    WrongTransaction,
    DigestMismatch,
    NotApplied(DescriptorOutcome),
    InconsistentReceipt,
}

/// Proof that EL1 applied one exact host submission. Only
/// [`DescriptorTxn::verify_receipt`] constructs it; backing adapters require
/// it before inventory repoint, old-owner retirement, residency commit or
/// table-grant return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedDescriptorReceipt {
    txn: DescriptorTxn,
    applied: DescriptorApplied,
}

/// The exact COW repoint EL1 installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCowRepoint {
    pub mm_key: NonZeroU64,
    pub va: u64,
    pub old_ipa: SubstrateGpa,
    pub new_ipa: SubstrateGpa,
    pub backing: BackingIdentity,
}

impl VerifiedDescriptorReceipt {
    #[must_use]
    pub fn txn(&self) -> &DescriptorTxn {
        &self.txn
    }

    #[must_use]
    pub fn id(&self) -> DescriptorTxnId {
        self.txn.id
    }

    #[must_use]
    pub fn applied(&self) -> DescriptorApplied {
        self.applied
    }

    /// Exact pages made resident; commit residency for these only.
    #[must_use]
    pub fn resident(&self) -> PageSpan {
        self.applied.resident
    }

    /// Table grants the host must return to its allocator.
    #[must_use]
    pub fn unused_table_grants(&self) -> &[u64] {
        self.txn
            .tables
            .unused_after(usize::from(self.applied.tables_linked))
    }

    #[must_use]
    pub fn cow_repoint(&self) -> Option<VerifiedCowRepoint> {
        match self.txn.op {
            DescriptorOp::CowRepoint {
                va,
                old_ipa,
                new_ipa,
                backing,
            } => Some(VerifiedCowRepoint {
                mm_key: self.txn.id.mm_key,
                va,
                old_ipa,
                new_ipa,
                backing,
            }),
            _ => None,
        }
    }

    /// Backing identity of a prepare, for residency publication.
    #[must_use]
    pub fn prepared_backing(&self) -> Option<(GuestLeafPublication, BackingIdentity)> {
        match self.txn.op {
            DescriptorOp::Prepare {
                publication,
                backing,
                ..
            } => Some((publication, backing)),
            _ => None,
        }
    }
}

/// Hardware access to one live stage-1 table graph, by table physical
/// address. EL1 implements it over the primary-table alias; tests implement
/// it over host memory and can inject failures.
pub trait LiveDescriptorWords {
    /// Load one descriptor. Addresses outside the reachable primary arena
    /// are [`DescriptorRefusal::TableOutsidePrimary`].
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal>;
    /// Replace exactly `current` by `new`. `Ok(false)` means the word no
    /// longer holds the validated value: editor exclusion was violated.
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal>;
    /// Store into a granted table page that no walker can reach yet.
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal>;
    /// Make every earlier store visible to hardware table walkers before a
    /// following link store (`DSB ISHST` on AArch64).
    fn publish_barrier(&self);
    /// Complete break-before-make for `[va, va + len)` in this MM's ASID
    /// (`DSB ISH; TLBI VAE1IS...; DSB ISH`).
    fn invalidate_range(&self, va: u64, len: u64);
}

/// One journaled live store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct JournalEntry {
    pub pa: u64,
    pub before: u64,
    pub after: u64,
    /// Nonzero for the second half of a break-before-make: undoing this entry
    /// must be followed by invalidating `[bbm_va, bbm_va + bbm_len)`.
    pub bbm_va: u64,
    pub bbm_len: u64,
}

/// Storage for live-store journals. Capacity is reserved before the first
/// live store; a failed reservation refuses the transaction.
pub trait DescriptorJournal {
    fn reserve(&mut self, entries: usize) -> bool;
    fn push(&mut self, entry: JournalEntry) -> bool;
    fn entries(&self) -> &[JournalEntry];
    fn clear(&mut self);
}

/// Inline storage for small transactions with fallible heap spill.
#[derive(Debug, Default)]
pub struct InlineJournal {
    inline: [JournalEntry; Self::INLINE],
    len: usize,
    spill: Vec<JournalEntry>,
    spilled: bool,
}

impl InlineJournal {
    pub const INLINE: usize = 8;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DescriptorJournal for InlineJournal {
    fn reserve(&mut self, entries: usize) -> bool {
        self.clear();
        if entries <= Self::INLINE {
            return true;
        }
        self.spilled = self.spill.try_reserve_exact(entries).is_ok();
        self.spilled
    }

    fn push(&mut self, entry: JournalEntry) -> bool {
        if self.spilled {
            if self.spill.len() == self.spill.capacity() {
                return false;
            }
            self.spill.push(entry);
            return true;
        }
        let Some(slot) = self.inline.get_mut(self.len) else {
            return false;
        };
        *slot = entry;
        self.len += 1;
        true
    }

    fn entries(&self) -> &[JournalEntry] {
        if self.spilled {
            &self.spill
        } else {
            &self.inline[..self.len]
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.spill.clear();
        self.spilled = false;
    }
}

/// Fixed-capacity journal over caller storage.
#[derive(Debug)]
pub struct SliceJournal<'a> {
    storage: &'a mut [JournalEntry],
    len: usize,
}

impl<'a> SliceJournal<'a> {
    pub fn new(storage: &'a mut [JournalEntry]) -> Self {
        Self { storage, len: 0 }
    }
}

impl DescriptorJournal for SliceJournal<'_> {
    fn reserve(&mut self, entries: usize) -> bool {
        self.len = 0;
        entries <= self.storage.len()
    }

    fn push(&mut self, entry: JournalEntry) -> bool {
        let Some(slot) = self.storage.get_mut(self.len) else {
            return false;
        };
        *slot = entry;
        self.len += 1;
        true
    }

    fn entries(&self) -> &[JournalEntry] {
        &self.storage[..self.len]
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

pub const DESCRIPTOR_TXN_IDLE: u32 = 0;
pub const DESCRIPTOR_TXN_HOST_WRITING: u32 = 1;
pub const DESCRIPTOR_TXN_SUBMITTED: u32 = 2;
pub const DESCRIPTOR_TXN_GUEST_APPLYING: u32 = 3;
pub const DESCRIPTOR_TXN_RECEIPT: u32 = 4;
pub const DESCRIPTOR_TXN_HOST_CONSUMING: u32 = 5;

const OUTCOME_APPLIED: u64 = 1;
const OUTCOME_REFUSED: u64 = 2;
const OUTCOME_ROLLED_BACK: u64 = 3;
const OUTCOME_INDETERMINATE: u64 = 4;

/// Single-flight host-to-EL1 descriptor transaction transport.
///
/// The host alone moves IDLE -> HOST_WRITING -> SUBMITTED (release), and may
/// withdraw an unclaimed SUBMITTED transaction back to IDLE. EL1 alone moves
/// SUBMITTED -> GUEST_APPLYING (acquire/release CAS) while holding the exact
/// MM editor, executes, writes the receipt, and releases -> RECEIPT. The host
/// alone moves RECEIPT -> HOST_CONSUMING -> IDLE after authenticating the
/// receipt against its own retained copy of the submission; it never trusts
/// the transaction words it reads back. While SUBMITTED or GUEST_APPLYING,
/// [`Self::pending_covering`] lets either venue recognize a fault inside the
/// operation span as an in-flight edit rather than a missing mapping.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct DescriptorTxnSlot {
    state: AtomicU32,
    mm_key: AtomicU64,
    generation: AtomicU64,
    root: AtomicU64,
    kind: AtomicU64,
    payload: [AtomicU64; 6],
    backing: [AtomicU64; 4],
    tables_len: AtomicU64,
    tables: [AtomicU64; MAX_TABLE_GRANTS],
    receipt_digest: AtomicU64,
    receipt_outcome: AtomicU64,
    receipt_refusal: AtomicU64,
    receipt_pages: AtomicU64,
    receipt_resident_va: AtomicU64,
    receipt_resident_len: AtomicU64,
    receipt_tables_linked: AtomicU64,
    receipt_live_stores: AtomicU64,
    receipt_flush: AtomicU64,
}

impl Default for DescriptorTxnSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl DescriptorTxnSlot {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(DESCRIPTOR_TXN_IDLE),
            mm_key: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            root: AtomicU64::new(0),
            kind: AtomicU64::new(0),
            payload: [const { AtomicU64::new(0) }; 6],
            backing: [const { AtomicU64::new(0) }; 4],
            tables_len: AtomicU64::new(0),
            tables: [const { AtomicU64::new(0) }; MAX_TABLE_GRANTS],
            receipt_digest: AtomicU64::new(0),
            receipt_outcome: AtomicU64::new(0),
            receipt_refusal: AtomicU64::new(0),
            receipt_pages: AtomicU64::new(0),
            receipt_resident_va: AtomicU64::new(0),
            receipt_resident_len: AtomicU64::new(0),
            receipt_tables_linked: AtomicU64::new(0),
            receipt_live_stores: AtomicU64::new(0),
            receipt_flush: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn state(&self) -> u32 {
        self.state.load(Ordering::Acquire)
    }

    /// Host: publish one transaction. `false` when the slot is busy.
    pub fn submit(&self, txn: &DescriptorTxn) -> bool {
        if self
            .state
            .compare_exchange(
                DESCRIPTOR_TXN_IDLE,
                DESCRIPTOR_TXN_HOST_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let (kind, payload) = txn.op.encode();
        self.mm_key.store(txn.id.mm_key.get(), Ordering::Relaxed);
        self.generation
            .store(txn.id.generation.get(), Ordering::Relaxed);
        self.root.store(txn.root.raw(), Ordering::Relaxed);
        self.kind.store(kind, Ordering::Relaxed);
        for (word, value) in self.payload.iter().zip(payload) {
            word.store(value, Ordering::Relaxed);
        }
        let backing = txn.op.backing().map_or([0; 4], |b| {
            [
                b.frame_id.get(),
                b.mapping_id.get(),
                b.owner_generation.get(),
                b.inventory_revision.get(),
            ]
        });
        for (word, value) in self.backing.iter().zip(backing) {
            word.store(value, Ordering::Relaxed);
        }
        self.tables_len
            .store(txn.tables.len() as u64, Ordering::Relaxed);
        for (index, word) in self.tables.iter().enumerate() {
            word.store(
                txn.tables.as_slice().get(index).copied().unwrap_or(0),
                Ordering::Relaxed,
            );
        }
        self.state
            .store(DESCRIPTOR_TXN_SUBMITTED, Ordering::Release);
        true
    }

    /// Host: withdraw an exact submission EL1 has not claimed.
    pub fn withdraw(&self, id: DescriptorTxnId) -> bool {
        if self.state.load(Ordering::Acquire) != DESCRIPTOR_TXN_SUBMITTED
            || self.mm_key.load(Ordering::Relaxed) != id.mm_key.get()
            || self.generation.load(Ordering::Relaxed) != id.generation.get()
        {
            return false;
        }
        self.state
            .compare_exchange(
                DESCRIPTOR_TXN_SUBMITTED,
                DESCRIPTOR_TXN_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Either venue: an in-flight transaction for `mm_key` covers `va`.
    #[must_use]
    pub fn pending_covering(&self, mm_key: u64, va: u64) -> bool {
        if !matches!(
            self.state.load(Ordering::Acquire),
            DESCRIPTOR_TXN_SUBMITTED | DESCRIPTOR_TXN_GUEST_APPLYING
        ) || self.mm_key.load(Ordering::Relaxed) != mm_key
        {
            return false;
        }
        let payload: [u64; 6] = core::array::from_fn(|i| self.payload[i].load(Ordering::Relaxed));
        let kind = self.kind.load(Ordering::Relaxed);
        let span = match kind {
            DescriptorOp::KIND_PREPARE => PageSpan::new(payload[0], payload[2]),
            DescriptorOp::KIND_PUBLISH | DescriptorOp::KIND_PROTECT | DescriptorOp::KIND_RETIRE => {
                PageSpan::new(payload[0], payload[1])
            }
            DescriptorOp::KIND_COW_REPOINT => PageSpan::new(payload[0], PT_PAGE),
            _ => return false,
        };
        span.contains(va & !(PT_PAGE - 1))
    }

    fn load_txn(&self) -> Result<DescriptorTxn, Option<DescriptorTxnId>> {
        let id = NonZeroU64::new(self.mm_key.load(Ordering::Relaxed)).and_then(|mm_key| {
            Some(DescriptorTxnId {
                mm_key,
                generation: NonZeroU64::new(self.generation.load(Ordering::Relaxed))?,
            })
        });
        let id = id.ok_or(None)?;
        let words: [u64; 4] = core::array::from_fn(|i| self.backing[i].load(Ordering::Relaxed));
        let backing = (|| {
            Some(BackingIdentity {
                frame_id: NonZeroU64::new(words[0])?,
                mapping_id: NonZeroU64::new(words[1])?,
                owner_generation: NonZeroU64::new(words[2])?,
                inventory_revision: NonZeroU64::new(words[3])?,
            })
        })();
        let payload: [u64; 6] = core::array::from_fn(|i| self.payload[i].load(Ordering::Relaxed));
        let op = DescriptorOp::decode(self.kind.load(Ordering::Relaxed), payload, backing)
            .ok_or(Some(id))?;
        let tables_len =
            usize::try_from(self.tables_len.load(Ordering::Relaxed)).map_err(|_| Some(id))?;
        if tables_len > MAX_TABLE_GRANTS {
            return Err(Some(id));
        }
        let pages: [SubstrateGpa; MAX_TABLE_GRANTS] =
            core::array::from_fn(|i| SubstrateGpa(self.tables[i].load(Ordering::Relaxed)));
        let tables = TableGrants::new(&pages[..tables_len]).ok_or(Some(id))?;
        Ok(DescriptorTxn {
            id,
            root: SubstrateGpa(self.root.load(Ordering::Relaxed)),
            op,
            tables,
        })
    }

    /// EL1: claim the submitted transaction for `mm_key`. The caller must
    /// already hold that MM's exact editor and must publish a receipt for
    /// every successful claim.
    pub fn claim_for_mm(&self, mm_key: u64) -> Option<ClaimedDescriptorTxn<'_>> {
        if self.state.load(Ordering::Acquire) != DESCRIPTOR_TXN_SUBMITTED
            || self.mm_key.load(Ordering::Relaxed) != mm_key
        {
            return None;
        }
        self.state
            .compare_exchange(
                DESCRIPTOR_TXN_SUBMITTED,
                DESCRIPTOR_TXN_GUEST_APPLYING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        if self.mm_key.load(Ordering::Relaxed) != mm_key {
            // The host withdrew and resubmitted for another MM between the
            // preview and the claim. Leave it for its own MM.
            self.state
                .store(DESCRIPTOR_TXN_SUBMITTED, Ordering::Release);
            return None;
        }
        Some(ClaimedDescriptorTxn {
            slot: self,
            txn: self.load_txn(),
        })
    }

    fn publish_receipt(&self, receipt: &DescriptorReceipt) {
        let (outcome, refusal, applied) = match receipt.outcome {
            DescriptorOutcome::Applied(applied) => (OUTCOME_APPLIED, 0, Some(applied)),
            DescriptorOutcome::Refused(r) => (OUTCOME_REFUSED, r as u32, None),
            DescriptorOutcome::RolledBack(r) => (OUTCOME_ROLLED_BACK, r as u32, None),
            DescriptorOutcome::Indeterminate(r) => (OUTCOME_INDETERMINATE, r as u32, None),
        };
        self.receipt_digest.store(receipt.digest, Ordering::Relaxed);
        self.receipt_outcome.store(outcome, Ordering::Relaxed);
        self.receipt_refusal
            .store(u64::from(refusal), Ordering::Relaxed);
        let applied = applied.unwrap_or(DescriptorApplied {
            pages: 0,
            resident: PageSpan::EMPTY,
            tables_linked: 0,
            live_stores: 0,
            flush_required: !matches!(receipt.outcome, DescriptorOutcome::Refused(_)),
        });
        self.receipt_pages.store(applied.pages, Ordering::Relaxed);
        self.receipt_resident_va
            .store(applied.resident.va, Ordering::Relaxed);
        self.receipt_resident_len
            .store(applied.resident.len, Ordering::Relaxed);
        self.receipt_tables_linked
            .store(u64::from(applied.tables_linked), Ordering::Relaxed);
        self.receipt_live_stores
            .store(u64::from(applied.live_stores), Ordering::Relaxed);
        self.receipt_flush
            .store(u64::from(applied.flush_required), Ordering::Relaxed);
        self.state.store(DESCRIPTOR_TXN_RECEIPT, Ordering::Release);
    }

    /// Host: consume the receipt for exactly `id`, returning the slot to
    /// IDLE. The caller authenticates it with [`DescriptorTxn::verify_receipt`]
    /// against its retained submission.
    pub fn take_receipt(&self, id: DescriptorTxnId) -> Option<DescriptorReceipt> {
        if self.state.load(Ordering::Acquire) != DESCRIPTOR_TXN_RECEIPT
            || self.mm_key.load(Ordering::Relaxed) != id.mm_key.get()
            || self.generation.load(Ordering::Relaxed) != id.generation.get()
        {
            return None;
        }
        self.state
            .compare_exchange(
                DESCRIPTOR_TXN_RECEIPT,
                DESCRIPTOR_TXN_HOST_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let refusal = || {
            u32::try_from(self.receipt_refusal.load(Ordering::Relaxed))
                .ok()
                .and_then(DescriptorRefusal::from_code)
                .unwrap_or(DescriptorRefusal::BadEncoding)
        };
        let outcome = match self.receipt_outcome.load(Ordering::Relaxed) {
            OUTCOME_APPLIED => DescriptorOutcome::Applied(DescriptorApplied {
                pages: self.receipt_pages.load(Ordering::Relaxed),
                resident: PageSpan::new(
                    self.receipt_resident_va.load(Ordering::Relaxed),
                    self.receipt_resident_len.load(Ordering::Relaxed),
                ),
                tables_linked: u8::try_from(self.receipt_tables_linked.load(Ordering::Relaxed))
                    .unwrap_or(u8::MAX),
                live_stores: u32::try_from(self.receipt_live_stores.load(Ordering::Relaxed))
                    .unwrap_or(u32::MAX),
                flush_required: self.receipt_flush.load(Ordering::Relaxed) != 0,
            }),
            OUTCOME_REFUSED => DescriptorOutcome::Refused(refusal()),
            OUTCOME_ROLLED_BACK => DescriptorOutcome::RolledBack(refusal()),
            _ => DescriptorOutcome::Indeterminate(refusal()),
        };
        let receipt = DescriptorReceipt {
            id,
            digest: self.receipt_digest.load(Ordering::Relaxed),
            outcome,
        };
        self.state.store(DESCRIPTOR_TXN_IDLE, Ordering::Release);
        Some(receipt)
    }
}

/// A claimed submission. Dropping it without [`Self::complete`] would wedge
/// the slot, so completion consumes it and always publishes a receipt.
#[derive(Debug)]
#[must_use = "a claimed descriptor transaction must publish a receipt"]
pub struct ClaimedDescriptorTxn<'a> {
    slot: &'a DescriptorTxnSlot,
    txn: Result<DescriptorTxn, Option<DescriptorTxnId>>,
}

impl ClaimedDescriptorTxn<'_> {
    /// The decoded transaction, or the refusal EL1 must report for it.
    pub fn txn(&self) -> Result<&DescriptorTxn, DescriptorRefusal> {
        self.txn
            .as_ref()
            .map_err(|_| DescriptorRefusal::BadEncoding)
    }

    /// Publish EL1's outcome. A malformed submission receives a
    /// `BadEncoding` refusal regardless of `outcome`.
    pub fn complete(self, outcome: DescriptorOutcome) -> DescriptorReceipt {
        let receipt = match self.txn {
            Ok(txn) => DescriptorReceipt {
                id: txn.id,
                digest: txn.digest(),
                outcome,
            },
            Err(id) => DescriptorReceipt {
                // An undecodable id cannot be consumed by the host; it is
                // withdrawn by teardown. Report it under a sentinel id.
                id: id.unwrap_or(DescriptorTxnId {
                    mm_key: NonZeroU64::MIN,
                    generation: NonZeroU64::MIN,
                }),
                digest: 0,
                outcome: DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding),
            },
        };
        self.slot.publish_receipt(&receipt);
        receipt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    pub(super) fn backing(seed: u64) -> BackingIdentity {
        BackingIdentity {
            frame_id: nz(seed),
            mapping_id: nz(seed + 1),
            owner_generation: nz(seed + 2),
            inventory_revision: nz(seed + 3),
        }
    }

    fn prepare_txn(generation: u64) -> DescriptorTxn {
        DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(7),
                generation: nz(generation),
            },
            root: SubstrateGpa(0x8800_0000_0000),
            op: DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: 0x4000_0000,
                    ipa: 0x9b_4000_0000,
                    len: 4 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
                resident: PageSpan::new(0x4000_1000, PT_PAGE),
                backing: backing(40),
            },
            tables: TableGrants::new(&[SubstrateGpa(0x8800_0000_4000)]).unwrap(),
        }
    }

    fn applied(txn: &DescriptorTxn, tables_linked: u8) -> DescriptorReceipt {
        let resident = match txn.op {
            DescriptorOp::Prepare { resident, .. } => resident,
            DescriptorOp::Publish { span, .. } => span,
            _ => PageSpan::EMPTY,
        };
        DescriptorReceipt {
            id: txn.id,
            digest: txn.digest(),
            outcome: DescriptorOutcome::Applied(DescriptorApplied {
                pages: txn.op.span().len / PT_PAGE,
                resident,
                tables_linked,
                live_stores: 5,
                flush_required: true,
            }),
        }
    }

    #[test]
    fn table_grants_reject_unaligned_zero_duplicate_and_oversized_sets() {
        assert!(TableGrants::new(&[SubstrateGpa(0)]).is_none());
        assert!(TableGrants::new(&[SubstrateGpa(0x1001)]).is_none());
        assert!(TableGrants::new(&[SubstrateGpa(0x2000), SubstrateGpa(0x2000)]).is_none());
        assert!(TableGrants::new(&[SubstrateGpa(0x2000); MAX_TABLE_GRANTS + 1]).is_none());
        let grants = TableGrants::new(&[SubstrateGpa(0x2000), SubstrateGpa(0x3000)]).unwrap();
        assert_eq!(grants.unused_after(1), &[0x3000]);
        assert_eq!(grants.unused_after(2), &[] as &[u64]);
    }

    #[test]
    fn every_operation_round_trips_through_the_slot_wire_encoding() {
        let ops = [
            prepare_txn(1).op,
            DescriptorOp::Publish {
                span: PageSpan::new(0x5000, 2 * PT_PAGE),
                expected_ipa: SubstrateGpa(0x7000),
                access: LeafAccess::Write,
            },
            DescriptorOp::Protect(GuestPermissionEdit {
                va: 0x6000,
                len: PT_PAGE,
                readable: true,
                writable: false,
                executable: true,
            }),
            DescriptorOp::Retire(PageSpan::new(0x8000, 3 * PT_PAGE)),
            DescriptorOp::CowRepoint {
                va: 0x9000,
                old_ipa: SubstrateGpa(0xa000),
                new_ipa: SubstrateGpa(0xb000),
                backing: backing(90),
            },
        ];
        for (generation, op) in ops.into_iter().enumerate() {
            let txn = DescriptorTxn {
                op,
                ..prepare_txn(generation as u64 + 1)
            };
            let slot = DescriptorTxnSlot::new();
            assert!(slot.submit(&txn));
            assert!(!slot.submit(&txn), "single flight");
            let claimed = slot.claim_for_mm(7).expect("claim");
            assert_eq!(claimed.txn(), Ok(&txn));
            let receipt = claimed.complete(applied(&txn, 1).outcome);
            assert_eq!(slot.take_receipt(txn.id), Some(receipt));
            assert_eq!(slot.state(), DESCRIPTOR_TXN_IDLE);
            assert!(txn.verify_receipt(&receipt).is_ok());
        }
    }

    #[test]
    fn slot_claims_only_the_exact_mm_and_releases_only_the_exact_receipt() {
        let slot = DescriptorTxnSlot::new();
        let txn = prepare_txn(3);
        assert!(slot.submit(&txn));
        assert!(slot.pending_covering(7, 0x4000_2abc));
        assert!(!slot.pending_covering(7, 0x4000_4000));
        assert!(!slot.pending_covering(8, 0x4000_2000));
        assert!(slot.claim_for_mm(8).is_none());
        let claimed = slot.claim_for_mm(7).unwrap();
        assert!(slot.pending_covering(7, 0x4000_0000));
        assert!(
            !slot.withdraw(txn.id),
            "a claimed transaction cannot be withdrawn"
        );
        let _ = claimed.complete(DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot));
        assert!(!slot.pending_covering(7, 0x4000_0000));
        let stale = DescriptorTxnId {
            mm_key: nz(7),
            generation: nz(2),
        };
        assert!(slot.take_receipt(stale).is_none());
        let receipt = slot.take_receipt(txn.id).unwrap();
        assert_eq!(
            txn.verify_receipt(&receipt),
            Err(ReceiptError::NotApplied(DescriptorOutcome::Refused(
                DescriptorRefusal::StaleRoot
            )))
        );
    }

    #[test]
    fn unclaimed_submission_is_withdrawn_exactly() {
        let slot = DescriptorTxnSlot::new();
        let txn = prepare_txn(4);
        assert!(slot.submit(&txn));
        let other = DescriptorTxnId {
            mm_key: nz(7),
            generation: nz(5),
        };
        assert!(!slot.withdraw(other));
        assert!(slot.withdraw(txn.id));
        assert!(slot.claim_for_mm(7).is_none());
        assert_eq!(slot.state(), DESCRIPTOR_TXN_IDLE);
    }

    #[test]
    fn a_malformed_submission_is_refused_without_guest_interpretation() {
        let slot = DescriptorTxnSlot::new();
        let txn = prepare_txn(6);
        assert!(slot.submit(&txn));
        slot.kind.store(99, Ordering::Relaxed);
        let claimed = slot.claim_for_mm(7).unwrap();
        assert_eq!(claimed.txn(), Err(DescriptorRefusal::BadEncoding));
        let receipt = claimed.complete(DescriptorOutcome::Applied(DescriptorApplied {
            pages: 4,
            resident: PageSpan::EMPTY,
            tables_linked: 0,
            live_stores: 0,
            flush_required: false,
        }));
        assert_eq!(
            receipt.outcome,
            DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding)
        );
        let taken = slot.take_receipt(txn.id).unwrap();
        assert!(txn.verify_receipt(&taken).is_err());
    }

    #[test]
    fn receipts_authenticate_the_exact_submission_and_its_effect() {
        let txn = prepare_txn(9);
        let good = applied(&txn, 1);
        let verified = txn.verify_receipt(&good).unwrap();
        assert_eq!(verified.resident(), PageSpan::new(0x4000_1000, PT_PAGE));
        assert_eq!(verified.unused_table_grants(), &[] as &[u64]);
        assert_eq!(
            verified.prepared_backing().map(|(_, backing)| backing),
            Some(backing(40))
        );
        assert!(verified.cow_repoint().is_none());

        // Same id, different operation: a stale owner generation.
        let mut stale_owner = txn;
        if let DescriptorOp::Prepare {
            ref mut backing, ..
        } = stale_owner.op
        {
            backing.owner_generation = nz(1000);
        }
        assert_eq!(
            stale_owner.verify_receipt(&good),
            Err(ReceiptError::DigestMismatch)
        );
        // Another generation of the same MM.
        let later = prepare_txn(10);
        assert_eq!(
            later.verify_receipt(&good),
            Err(ReceiptError::WrongTransaction)
        );
        // An applied receipt cannot claim residency the op did not name, or
        // link more grants than it carried.
        let mut whole_grant = good;
        if let DescriptorOutcome::Applied(ref mut applied) = whole_grant.outcome {
            applied.resident = PageSpan::new(0x4000_0000, 4 * PT_PAGE);
        }
        assert_eq!(
            txn.verify_receipt(&whole_grant),
            Err(ReceiptError::InconsistentReceipt)
        );
        let mut overlinked = good;
        if let DescriptorOutcome::Applied(ref mut applied) = overlinked.outcome {
            applied.tables_linked = 2;
        }
        assert_eq!(
            txn.verify_receipt(&overlinked),
            Err(ReceiptError::InconsistentReceipt)
        );
        let partial = applied(&txn, 0);
        assert_eq!(
            txn.verify_receipt(&partial).unwrap().unused_table_grants(),
            &[0x8800_0000_4000]
        );
    }

    #[test]
    fn cow_receipt_names_the_exact_repoint_for_the_backing_adapter() {
        let txn = DescriptorTxn {
            op: DescriptorOp::CowRepoint {
                va: 0x4000_3000,
                old_ipa: SubstrateGpa(0x9b_0000_0000),
                new_ipa: SubstrateGpa(0x9c_0000_0000),
                backing: backing(70),
            },
            tables: TableGrants::NONE,
            ..prepare_txn(11)
        };
        let verified = txn.verify_receipt(&applied(&txn, 0)).unwrap();
        assert_eq!(
            verified.cow_repoint(),
            Some(VerifiedCowRepoint {
                mm_key: nz(7),
                va: 0x4000_3000,
                old_ipa: SubstrateGpa(0x9b_0000_0000),
                new_ipa: SubstrateGpa(0x9c_0000_0000),
                backing: backing(70),
            })
        );
        assert!(verified.resident().is_empty());
    }

    #[test]
    fn journals_reserve_before_use_and_spill_only_when_needed() {
        let mut journal = InlineJournal::new();
        assert!(journal.reserve(2));
        assert!(journal.push(JournalEntry::default()));
        assert!(journal.push(JournalEntry {
            pa: 8,
            ..JournalEntry::default()
        }));
        assert_eq!(journal.entries().len(), 2);
        assert!(journal.reserve(20));
        for pa in 0..20 {
            assert!(journal.push(JournalEntry {
                pa,
                ..JournalEntry::default()
            }));
        }
        assert_eq!(journal.entries().len(), 20);
        assert_eq!(journal.entries()[19].pa, 19);

        let mut storage = [JournalEntry::default(); 2];
        let mut fixed = SliceJournal::new(&mut storage);
        assert!(!fixed.reserve(3));
        assert!(fixed.reserve(2));
        assert!(fixed.push(JournalEntry::default()));
        assert!(fixed.push(JournalEntry::default()));
        assert!(!fixed.push(JournalEntry::default()));
    }
}
