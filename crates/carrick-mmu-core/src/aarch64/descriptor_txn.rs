//! Guest-owned live stage-1 descriptor transactions.
//!
//! # Ownership
//!
//! A live stage-1 image has exactly one descriptor writer. On the lane where
//! guest EL1 owns an address space's live tables, that writer is EL1: every
//! host-facing engine operation that would edit live descriptors (bulk grant
//! preparation, permission changes, retirement, copyout residency and fork
//! COW repointing) is described as one [`DescriptorTxn`], submitted through a
//! [`DescriptorTxnSlot`], executed in EL1 by [`execute_descriptor_txn`] under
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
//! The reverse direction is bounded the same way: an alias munmap
//! ([`TerminalEdit::unmap_reclaiming`]) unlinks the spare sub-tables its
//! retirement empties, by the host editor's own reclaim predicate, and names
//! at most [`MAX_RECLAIMED_TABLES`] of them in the receipt; the host returns
//! them to its allocator exactly once, from a verified receipt.
//!
//! # Atomicity and rollback
//!
//! [`execute_descriptor_txn`] validates the complete range, grant need and
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

pub mod copy_window;

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;

use super::{
    AP_MASK, AP_PRIV_RO, AP_RO, AP_RW, El1PrivateLeafState, GuestLeafPublication,
    GuestPermissionEdit, LeafAccess, NON_GLOBAL, PA_MASK_1GIB, PA_MASK_2MIB, PA_MASK_4KIB,
    PA_MASK_TABLE, PT_PAGE, SW_EL1_COW, SW_EL1_MAY_EXEC, SW_EL1_MAY_WRITE, SW_EL1_PRIVATE,
    SW_RETIRED, SubstrateGpa, TYPE_BITS, TYPE_BLOCK, TYPE_TABLE_OR_PAGE, USER_PAGE_FLAGS, UXN,
    VALID, el1_cow, el1_private_leaf_state, terminal_descriptor_permits_el0,
};

/// Wire protocol revision of [`DescriptorTxnSlot`]. Both venues must agree.
pub const DESCRIPTOR_TXN_PROTOCOL_VERSION: u64 = 10;

/// Maximum host-reserved table pages carried by one transaction. A 2 MiB
/// grant needs at most one L1, one L2 and two L3 tables when it straddles a
/// 2 MiB boundary; one coarse-block split per span end needs at most two
/// more pages per level below 1 GiB.
pub const MAX_TABLE_GRANTS: usize = 8;

/// Maximum emptied table pages one reclaiming [`DescriptorOp::Terminal`]
/// may unlink and return in its receipt, symmetric with the grants a
/// transaction may carry. A span that would empty more is refused whole at
/// plan time ([`DescriptorRefusal::ReclaimCapacity`]) and the host splits
/// it; splitting preserves the result because an L2 table is judged after
/// every in-range L3 decision below it, in either venue.
pub const MAX_RECLAIMED_TABLES: usize = MAX_TABLE_GRANTS;

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
    /// Repoint a private compound from `old_ipa` to the private copy at
    /// `new_ipa`. Tagged resident leaves recover only recorded write intent;
    /// backend user leaves use exact per-page permissions, and kernel leaves
    /// retain EL1-only access. Invalid neighbors retain residency and access.
    /// EL1 copies every page before publishing the span under one journal.
    CowRepoint {
        access: CowRepointAccess,
        va: u64,
        len: u64,
        old_ipa: SubstrateGpa,
        new_ipa: SubstrateGpa,
        backing: BackingIdentity,
    },
    /// Map already-populated backing with explicit alias access.
    /// Unlike CowRepoint, this never copies bytes. The host retains exact-MM
    /// exclusion and authenticated backing until the verified receipt.
    MapAlias {
        access: AliasAccess,
        span: PageSpan,
        target_ipa: SubstrateGpa,
        backing: BackingIdentity,
    },
    /// Apply one host-originated range rule with exactly the host editor's
    /// per-terminal definition ([`super::TerminalRule`], the one
    /// `PageTableManager::apply_rule` uses): fork COW arming, mprotect,
    /// munmap retirement, retired-leaf reset and BUS-tail tags. Terminals
    /// that already satisfy it are skipped without a split, covered blocks
    /// are edited in place, and only range edges split. `edit` carries the
    /// image construction mode and the IPA window no valid output may name.
    Terminal { span: PageSpan, edit: TerminalEdit },
}

/// Permissions of a populated alias. Deferred backing retains its output
/// while remaining invalid and read-only until the later protection commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasAccess {
    Deferred,
    User { writable: bool, executable: bool },
}
impl AliasAccess {
    fn wire(self) -> u64 {
        match self {
            Self::Deferred => 0,
            Self::User {
                writable,
                executable,
            } => 1 | (u64::from(writable) << 1) | (u64::from(executable) << 2),
        }
    }
    fn from_wire(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Deferred),
            1 | 3 | 5 | 7 => Some(Self::User {
                writable: raw & 2 != 0,
                executable: raw & 4 != 0,
            }),
            _ => None,
        }
    }
}

/// Access authority for an exact COW span. Tagged private leaves record their
/// own write intent. Other backend-owned user leaves carry the per-page write
/// decisions already established by the exact-MM protection authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowRepointAccess {
    RecordedPrivate,
    User { writable_pages: u8 },
    Kernel,
}

impl CowRepointAccess {
    fn wire(self) -> u64 {
        match self {
            Self::RecordedPrivate => 0,
            Self::Kernel => 1,
            Self::User { writable_pages } => 2 | (u64::from(writable_pages) << 8),
        }
    }

    fn from_wire(word: u64) -> Option<Self> {
        match word {
            0 => Some(Self::RecordedPrivate),
            1 => Some(Self::Kernel),
            value if value & !0xf00 == 2 => Some(Self::User {
                writable_pages: (value >> 8) as u8,
            }),
            _ => None,
        }
    }

    fn covers(self, len: u64) -> bool {
        match self {
            Self::User { writable_pages } => u64::from(writable_pages) < (1_u64 << (len / PT_PAGE)),
            _ => true,
        }
    }
}

/// How [`DescriptorOp::Terminal`] edits its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalEdit {
    /// The shared per-terminal rule.
    pub rule: super::TerminalRule,
    /// The live image builds nG leaves (every HVPatch MM does).
    pub asid_scoped: bool,
    /// IPA window no valid output may name (the in-kernel GIC).
    pub excluded_ipa: u64,
    pub excluded_len: u64,
    /// After the rule, unlink every spare L3/L2 sub-table in the span that
    /// the rule left reclaimable (the shared `reclaimable_entry`
    /// predicate, exactly `PageTableManager::unmap_aliased`'s reclaim), up to
    /// this many tables; 0 disables reclaim. Only the plain munmap
    /// retirement rule may reclaim. EL1 unlinks each table under
    /// break-before-make in the same journal as the rule and names the freed
    /// pages in [`DescriptorApplied::reclaimed`]; the host returns them to its
    /// allocator only from a verified receipt, i.e. after EL1's
    /// inner-shareable ASID invalidation completed. That invalidation is what
    /// the host editor's single-vCPU gate stands in for (it has no all-vCPU
    /// TLBI), so the guest lane needs no such gate.
    pub reclaim_budget: u8,
}

impl TerminalEdit {
    /// Fork COW arming of one parent range: `PtOp::ForkReadOnly`, or
    /// `PtOp::KernelReadOnly` for Carrick-owned EL1 pages (EL1 read-only,
    /// EL0 no access, with `executable` choosing UXN).
    #[must_use]
    pub const fn fork_arm(
        kernel_only: bool,
        executable: bool,
        asid_scoped: bool,
        excluded_ipa: u64,
        excluded_len: u64,
    ) -> Self {
        let op = if kernel_only {
            super::PtOp::KernelReadOnly { exec: executable }
        } else {
            super::PtOp::ForkReadOnly
        };
        Self {
            rule: super::TerminalRule::pt(op),
            asid_scoped,
            excluded_ipa,
            excluded_len,
            reclaim_budget: 0,
        }
    }

    /// `munmap` of an alias (`PageTableManager::unmap_aliased`): retire the
    /// range, then reclaim the sub-tables it emptied. The host narrows the
    /// budget to its plan before submission.
    #[must_use]
    pub const fn unmap_reclaiming(asid_scoped: bool, excluded_ipa: u64, excluded_len: u64) -> Self {
        Self {
            rule: super::TerminalRule::pt(super::PtOp::Retire),
            asid_scoped,
            excluded_ipa,
            excluded_len,
            reclaim_budget: MAX_RECLAIMED_TABLES as u8,
        }
    }

    /// Whether this edit's reclaim request is well formed: within the
    /// receipt bound, and only after plain munmap retirement.
    fn reclaim_well_formed(self) -> bool {
        self.reclaim_budget == 0
            || (usize::from(self.reclaim_budget) <= MAX_RECLAIMED_TABLES
                && self.rule == super::TerminalRule::pt(super::PtOp::Retire))
    }

    fn excludes(self, output: u64, len: u64) -> bool {
        super::PageTableLayoutConfig::new(0, 0, self.excluded_ipa, self.excluded_len)
            .ipa_overlaps_excluded(output, len)
    }

    const OP_NONE: u64 = 0;
    const OP_INVALIDATE: u64 = 1;
    const OP_RETIRE: u64 = 2;
    const OP_READ_ONLY: u64 = 3;
    const OP_FORK_READ_ONLY: u64 = 4;
    const OP_READ_WRITE: u64 = 5;
    const OP_KERNEL_READ_ONLY: u64 = 6;
    const RULE_BUS_FAULT: u64 = 7;
    const EXEC: u64 = 1 << 3;
    const RESET_RETIRED: u64 = 1 << 4;
    const DENY_HOST_BUFFERS: u64 = 1 << 5;
    const FORK_ARM: u64 = 1 << 6;
    const ASID_SCOPED: u64 = 1 << 7;
    const RECLAIM_SHIFT: u32 = 8;
    const KNOWN: u64 = 0xffff;

    fn wire(self) -> u64 {
        use super::{PtOp, TerminalRule};
        let scoped = if self.asid_scoped {
            Self::ASID_SCOPED
        } else {
            0
        };
        let flag = |on: bool, bit: u64| if on { bit } else { 0 };
        let scoped = scoped | (u64::from(self.reclaim_budget) << Self::RECLAIM_SHIFT);
        match self.rule {
            TerminalRule::BusFault => Self::RULE_BUS_FAULT | scoped,
            TerminalRule::Pt {
                op,
                reset_retired,
                deny_host_buffers,
                fork_arm,
            } => {
                let (code, exec) = match op {
                    None => (Self::OP_NONE, false),
                    Some(PtOp::Invalidate) => (Self::OP_INVALIDATE, false),
                    Some(PtOp::Retire) => (Self::OP_RETIRE, false),
                    Some(PtOp::ReadOnly { exec }) => (Self::OP_READ_ONLY, exec),
                    Some(PtOp::ForkReadOnly) => (Self::OP_FORK_READ_ONLY, false),
                    Some(PtOp::ReadWrite { exec }) => (Self::OP_READ_WRITE, exec),
                    Some(PtOp::KernelReadOnly { exec }) => (Self::OP_KERNEL_READ_ONLY, exec),
                };
                code | flag(exec, Self::EXEC)
                    | flag(reset_retired, Self::RESET_RETIRED)
                    | flag(deny_host_buffers, Self::DENY_HOST_BUFFERS)
                    | flag(fork_arm, Self::FORK_ARM)
                    | scoped
            }
        }
    }

    fn from_wire(word: u64, excluded_ipa: u64, excluded_len: u64) -> Option<Self> {
        use super::{PtOp, TerminalRule};
        if word & !Self::KNOWN != 0 {
            return None;
        }
        let reclaim_budget = (word >> Self::RECLAIM_SHIFT) as u8;
        let exec = word & Self::EXEC != 0;
        let flags = word & (Self::RESET_RETIRED | Self::DENY_HOST_BUFFERS | Self::FORK_ARM);
        let op = match word & 0b111 {
            Self::OP_NONE => None,
            Self::OP_INVALIDATE => Some(PtOp::Invalidate),
            Self::OP_RETIRE => Some(PtOp::Retire),
            Self::OP_READ_ONLY => Some(PtOp::ReadOnly { exec }),
            Self::OP_FORK_READ_ONLY => Some(PtOp::ForkReadOnly),
            Self::OP_READ_WRITE => Some(PtOp::ReadWrite { exec }),
            Self::OP_KERNEL_READ_ONLY => Some(PtOp::KernelReadOnly { exec }),
            _ => {
                // BusFault carries no op, execute bit or composition flags.
                if exec || flags != 0 {
                    return None;
                }
                let edit = Self {
                    rule: TerminalRule::BusFault,
                    asid_scoped: word & Self::ASID_SCOPED != 0,
                    excluded_ipa,
                    excluded_len,
                    reclaim_budget,
                };
                return edit.reclaim_well_formed().then_some(edit);
            }
        };
        // Only ops with an execute choice may carry the execute bit.
        let has_exec = matches!(
            op,
            Some(PtOp::ReadOnly { .. } | PtOp::ReadWrite { .. } | PtOp::KernelReadOnly { .. })
        );
        if exec && !has_exec {
            return None;
        }
        let edit = Self {
            rule: TerminalRule::Pt {
                op,
                reset_retired: word & Self::RESET_RETIRED != 0,
                deny_host_buffers: word & Self::DENY_HOST_BUFFERS != 0,
                fork_arm: word & Self::FORK_ARM != 0,
            },
            asid_scoped: word & Self::ASID_SCOPED != 0,
            excluded_ipa,
            excluded_len,
            reclaim_budget,
        };
        edit.reclaim_well_formed().then_some(edit)
    }
}

impl DescriptorOp {
    const KIND_PREPARE: u64 = 1;
    const KIND_PUBLISH: u64 = 2;
    const KIND_PROTECT: u64 = 3;
    const KIND_RETIRE: u64 = 4;
    const KIND_COW_REPOINT: u64 = 5;
    const KIND_TERMINAL: u64 = 6;
    const KIND_MAP_ALIAS: u64 = 7;

    /// The complete semantic span this operation may edit.
    #[must_use]
    pub fn span(&self) -> PageSpan {
        match *self {
            Self::Prepare { publication, .. } => PageSpan::new(publication.va, publication.len),
            Self::Publish { span, .. }
            | Self::Retire(span)
            | Self::Terminal { span, .. }
            | Self::MapAlias { span, .. } => span,
            Self::Protect(edit) => PageSpan::new(edit.va, edit.len),
            Self::CowRepoint { va, len, .. } => PageSpan::new(va, len),
        }
    }

    /// The backing identity whose readiness this operation relies on.
    #[must_use]
    pub fn backing(&self) -> Option<BackingIdentity> {
        match *self {
            Self::Prepare { backing, .. }
            | Self::CowRepoint { backing, .. }
            | Self::MapAlias { backing, .. } => Some(backing),
            _ => None,
        }
    }

    /// Emptied tables this operation may unlink and return (0: none).
    #[must_use]
    pub fn reclaim_budget(&self) -> usize {
        match *self {
            Self::Terminal { edit, .. } => usize::from(edit.reclaim_budget),
            _ => 0,
        }
    }

    fn kind(&self) -> u64 {
        match self {
            Self::Prepare { .. } => Self::KIND_PREPARE,
            Self::Publish { .. } => Self::KIND_PUBLISH,
            Self::Protect(_) => Self::KIND_PROTECT,
            Self::Retire(_) => Self::KIND_RETIRE,
            Self::CowRepoint { .. } => Self::KIND_COW_REPOINT,
            Self::Terminal { .. } => Self::KIND_TERMINAL,
            Self::MapAlias { .. } => Self::KIND_MAP_ALIAS,
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
                access,
                va,
                len,
                old_ipa,
                new_ipa,
                ..
            } => [va, old_ipa.raw(), new_ipa.raw(), len, access.wire(), 0],
            Self::MapAlias {
                access,
                span,
                target_ipa,
                ..
            } => [span.va, span.len, target_ipa.raw(), access.wire(), 0, 0],
            Self::Terminal { span, edit } => [
                span.va,
                span.len,
                edit.wire(),
                edit.excluded_ipa,
                edit.excluded_len,
                0,
            ],
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
                access: CowRepointAccess::from_wire(payload[4])?,
                len: payload[3],
                va: payload[0],
                old_ipa: SubstrateGpa(payload[1]),
                new_ipa: SubstrateGpa(payload[2]),
                backing: backing?,
            }),
            Self::KIND_MAP_ALIAS => Some(Self::MapAlias {
                access: AliasAccess::from_wire(payload[3])?,
                span: PageSpan::new(payload[0], payload[1]),
                target_ipa: SubstrateGpa(payload[2]),
                backing: backing?,
            }),
            Self::KIND_TERMINAL => Some(Self::Terminal {
                span: PageSpan::new(payload[0], payload[1]),
                edit: TerminalEdit::from_wire(payload[2], payload[3], payload[4])?,
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

/// Table pages a reclaiming [`DescriptorOp::Terminal`] unlinked from the
/// live graph (or consumed from its grants and never linked), in unlink
/// order. EL1 reports them; the host returns them to its allocator only
/// after [`DescriptorTxn::verify_receipt`] checked them against the
/// submission and `PageTableManager::settle_guest_descriptor_receipt`
/// checked them against its own arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimedTables {
    len: u8,
    pages: [u64; MAX_RECLAIMED_TABLES],
}

impl ReclaimedTables {
    pub const NONE: Self = Self {
        len: 0,
        pages: [0; MAX_RECLAIMED_TABLES],
    };

    /// The raw list, as EL1 reported it; `None` over the bound. Contents are
    /// validated by receipt verification, never here.
    #[must_use]
    pub fn from_pages(pages: &[u64]) -> Option<Self> {
        let mut tables = Self::NONE;
        for &pa in pages {
            if !tables.push(pa) {
                return None;
            }
        }
        Some(tables)
    }

    fn push(&mut self, pa: u64) -> bool {
        let Some(slot) = self.pages.get_mut(usize::from(self.len)) else {
            return false;
        };
        *slot = pa;
        self.len += 1;
        true
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
            || !self.reclaimed_consistent(&applied)
        {
            return Err(ReceiptError::InconsistentReceipt);
        }
        Ok(VerifiedDescriptorReceipt {
            txn: *self,
            applied,
        })
    }
}

impl DescriptorTxn {
    /// A receipt's reclaimed list may name only distinct table pages in the
    /// spare tail of this transaction's primary arena (never the root or a
    /// boot table), no more than the submission's budget, and none of the
    /// grants the host already takes back as unused.
    fn reclaimed_consistent(&self, applied: &DescriptorApplied) -> bool {
        let reclaimed = applied.reclaimed.as_slice();
        let unused = self.tables.unused_after(usize::from(applied.tables_linked));
        reclaimed.len() <= self.op.reclaim_budget()
            && reclaimed.iter().enumerate().all(|(index, &pa)| {
                pa & !PA_MASK_4KIB == 0
                    && super::primary_spare_table(self.root.raw(), pa)
                    && !reclaimed[..index].contains(&pa)
                    && !unused.contains(&pa)
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
    ExcludedOutput = 21,
    /// A reclaiming edit would empty more tables than its budget (or than
    /// one receipt carries): the host must split the span.
    ReclaimCapacity = 22,
    /// The MM's tables lack the two preallocated EL1 COW copy-alias leaves,
    /// so EL1 cannot copy the page without allocating (a provisioning
    /// defect of that image, distinct from exhausted table grants).
    CopyWindowAbsent = 23,
    /// The operation's span names the Carrick-owned EL1 COW copy window
    /// ([`copy_window::COW_COPY_WINDOW_BASE`]); only EL1's bounded copy may
    /// write those leaves.
    CarrickOwnedWindow = 24,
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
            21 => Self::ExcludedOutput,
            22 => Self::ReclaimCapacity,
            23 => Self::CopyWindowAbsent,
            24 => Self::CarrickOwnedWindow,
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
    /// Prefix of [`TableGrants`] EL1 consumed. A consumed grant is linked
    /// into the live graph unless a reclaiming edit dropped it again, in
    /// which case it is also named in `reclaimed`.
    pub tables_linked: u8,
    /// Table pages this operation unlinked (or consumed and dropped), which
    /// the host must return to its allocator exactly once.
    pub reclaimed: ReclaimedTables,
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

    /// Emptied tables EL1 unlinked (after its break-before-make
    /// invalidation completed), which the host must return to its allocator.
    #[must_use]
    pub fn reclaimed_tables(&self) -> &[u64] {
        self.applied.reclaimed.as_slice()
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
                ..
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
    receipt_reclaimed_len: AtomicU64,
    receipt_reclaimed: [AtomicU64; MAX_RECLAIMED_TABLES],
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
            receipt_reclaimed_len: AtomicU64::new(0),
            receipt_reclaimed: [const { AtomicU64::new(0) }; MAX_RECLAIMED_TABLES],
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

    /// EL1: a submission for `mm_key` is waiting to be claimed.
    #[must_use]
    pub fn submitted_for(&self, mm_key: u64) -> bool {
        self.state.load(Ordering::Acquire) == DESCRIPTOR_TXN_SUBMITTED
            && self.mm_key.load(Ordering::Relaxed) == mm_key
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
            DescriptorOp::KIND_PUBLISH
            | DescriptorOp::KIND_PROTECT
            | DescriptorOp::KIND_RETIRE
            | DescriptorOp::KIND_TERMINAL => PageSpan::new(payload[0], payload[1]),
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
            reclaimed: ReclaimedTables::NONE,
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
        self.receipt_reclaimed_len
            .store(applied.reclaimed.len() as u64, Ordering::Relaxed);
        for (index, word) in self.receipt_reclaimed.iter().enumerate() {
            word.store(
                applied
                    .reclaimed
                    .as_slice()
                    .get(index)
                    .copied()
                    .unwrap_or(0),
                Ordering::Relaxed,
            );
        }
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
        let reclaimed = || {
            let len = usize::try_from(self.receipt_reclaimed_len.load(Ordering::Relaxed)).ok()?;
            let words: [u64; MAX_RECLAIMED_TABLES] =
                core::array::from_fn(|i| self.receipt_reclaimed[i].load(Ordering::Relaxed));
            ReclaimedTables::from_pages(words.get(..len)?)
        };
        let outcome = match self.receipt_outcome.load(Ordering::Relaxed) {
            // An applied receipt whose freed-table list does not decode
            // leaves the linkage unknown: indeterminate, never applied.
            OUTCOME_APPLIED => match reclaimed() {
                Some(reclaimed) => DescriptorOutcome::Applied(DescriptorApplied {
                    pages: self.receipt_pages.load(Ordering::Relaxed),
                    resident: PageSpan::new(
                        self.receipt_resident_va.load(Ordering::Relaxed),
                        self.receipt_resident_len.load(Ordering::Relaxed),
                    ),
                    tables_linked: u8::try_from(self.receipt_tables_linked.load(Ordering::Relaxed))
                        .unwrap_or(u8::MAX),
                    reclaimed,
                    live_stores: u32::try_from(self.receipt_live_stores.load(Ordering::Relaxed))
                        .unwrap_or(u32::MAX),
                    flush_required: self.receipt_flush.load(Ordering::Relaxed) != 0,
                }),
                None => DescriptorOutcome::Indeterminate(DescriptorRefusal::BadEncoding),
            },
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

/// Architectural maintenance a live table editor issues. EL1 implements it
/// with `DSB ISHST` and ASID-scoped `TLBI VAE1IS`; host tests record it.
pub trait TableMaintenance {
    fn publish_barrier(&self);
    fn invalidate_range(&self, va: u64, len: u64);
}

/// No-op maintenance for callers that change only terminal permissions or
/// residency and perform their own trailing ASID invalidation. Those callers
/// supply no table grants. Live alias replacement and table linking require
/// real maintenance, including intermediate break-before-make invalidations;
/// they must not use this implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct CallerInvalidatesAsid;

impl TableMaintenance for CallerInvalidatesAsid {
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

/// The EL1-reachable primary table arena as an aligned array of atomics.
pub struct PrimaryTableWords<'m, M: TableMaintenance + ?Sized> {
    words: *mut AtomicU64,
    physical_base: u64,
    byte_len: usize,
    maintenance: &'m M,
}

impl<'m, M: TableMaintenance + ?Sized> PrimaryTableWords<'m, M> {
    /// # Safety
    ///
    /// `words` must be an aligned, writable, hardware-visible array of
    /// descriptor words covering `byte_len` bytes of the primary table arena
    /// whose first byte is `physical_base`, valid for this value's lifetime.
    /// The caller holds the exact-MM editor for every graph it edits here.
    pub unsafe fn new(
        words: *mut AtomicU64,
        physical_base: u64,
        byte_len: usize,
        maintenance: &'m M,
    ) -> Result<Self, DescriptorRefusal> {
        if words.is_null()
            || !(words as usize).is_multiple_of(core::mem::align_of::<AtomicU64>())
            || !physical_base.is_multiple_of(PT_PAGE)
        {
            return Err(DescriptorRefusal::BadRange);
        }
        Ok(Self {
            words,
            physical_base,
            byte_len,
            maintenance,
        })
    }

    fn word(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        let offset = pa
            .checked_sub(self.physical_base)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        if !offset.is_multiple_of(core::mem::size_of::<u64>())
            || offset
                .checked_add(core::mem::size_of::<u64>())
                .is_none_or(|end| end > self.byte_len)
        {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        // SAFETY: `new`'s contract covers `byte_len`; the checked, aligned
        // offset stays inside it.
        Ok(unsafe { &*self.words.add(offset / core::mem::size_of::<u64>()) })
    }
}

impl<M: TableMaintenance + ?Sized> LiveDescriptorWords for PrimaryTableWords<'_, M> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        Ok(self.word(pa)?.load(Ordering::Acquire))
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.word(pa)?.store(value, Ordering::Release);
        Ok(())
    }

    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        self.maintenance.publish_barrier();
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        self.maintenance.invalidate_range(va, len);
    }
}

const fn entry_span(level: usize) -> u64 {
    match level {
        0 => 1 << 39,
        1 => 1 << 30,
        2 => 1 << 21,
        _ => PT_PAGE,
    }
}

const fn output_mask(level: usize) -> u64 {
    match level {
        1 => PA_MASK_1GIB,
        2 => PA_MASK_2MIB,
        3 => PA_MASK_4KIB,
        _ => 0,
    }
}

fn is_table(descriptor: u64, level: usize) -> bool {
    level < 3 && descriptor & VALID != 0 && descriptor & TYPE_BITS == TYPE_TABLE_OR_PAGE
}

/// Child `index` of a split L1/L2 terminal, exactly as the host editor
/// splits one: same attributes, stride-advanced output, invalid children of
/// an invalid parent, and empty children of an empty parent.
fn expand(parent: u64, level: usize, index: u64) -> u64 {
    let (parent_mask, child_mask, stride, child_type) = match level {
        1 => (PA_MASK_1GIB, PA_MASK_2MIB, 1u64 << 21, TYPE_BLOCK),
        _ => (PA_MASK_2MIB, PA_MASK_4KIB, PT_PAGE, TYPE_TABLE_OR_PAGE),
    };
    let base = parent & parent_mask;
    let valid = parent & VALID != 0;
    if !valid && base == 0 {
        return 0;
    }
    let child =
        ((base + index * stride) & child_mask) | (parent & !parent_mask & !TYPE_BITS) | child_type;
    if valid { child } else { child & !VALID }
}

#[derive(Clone, Copy)]
enum Loc {
    /// A word reachable by hardware walkers: journaled compare-exchange.
    Live(u64),
    /// A word in a granted table not yet linked; `None` while planning.
    Fresh(Option<u64>),
}

struct Executor<'a, W: ?Sized, J: ?Sized> {
    words: &'a W,
    op: DescriptorOp,
    start: u64,
    end: u64,
    apply: bool,
    grants: &'a [u64],
    grants_used: usize,
    journal: &'a mut J,
    planned_live_stores: usize,
    /// Primary arena base (the root): bounds which tables are spare.
    root: u64,
    /// Emptied tables this operation may unlink; 0 disables reclaim.
    reclaim_budget: usize,
    /// Tables unlinked so far (counted while planning, named while applying).
    reclaimed_count: usize,
    reclaimed: ReclaimedTables,
}

impl<W: LiveDescriptorWords + ?Sized, J: DescriptorJournal + ?Sized> Executor<'_, W, J> {
    /// Visit the in-range entries of a live table. Returns whether the table
    /// is now reclaimable: a reclaiming op, a reclaimable level, a spare page,
    /// and every entry reclaimable by the shared predicate, judged on the
    /// value each in-range entry holds after this op and on the untouched
    /// value of every other entry.
    fn visit_live_table(
        &mut self,
        table_pa: u64,
        level: usize,
        table_base: u64,
    ) -> Result<bool, DescriptorRefusal> {
        let span = entry_span(level);
        let coverage_end = table_base.saturating_add(span.saturating_mul(512));
        let lo = self.start.max(table_base);
        let hi = self.end.min(coverage_end);
        if lo >= hi {
            return Ok(false);
        }
        let (first, last) = ((lo - table_base) / span, (hi - 1 - table_base) / span);
        let mut reclaimable = self.reclaim_budget != 0
            && super::sub_table_level_reclaimable(level)
            && super::primary_spare_table(self.root, table_pa);
        for index in first..=last {
            let pa = table_pa + index * 8;
            let descriptor = self.words.load(pa)?;
            let entry_va = table_base + index * span;
            let after = self.visit_entry(level, Loc::Live(pa), descriptor, entry_va)?;
            reclaimable = reclaimable && super::reclaimable_entry(after, level, entry_va);
        }
        if !reclaimable {
            return Ok(false);
        }
        for index in (0..first).chain(last + 1..512) {
            let descriptor = self.words.load(table_pa + index * 8)?;
            if !super::reclaimable_entry(descriptor, level, table_base + index * span) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Record one reclaimed table page (unknown while planning a grant).
    fn note_reclaimed(&mut self, table: Option<u64>) -> Result<(), DescriptorRefusal> {
        self.reclaimed_count += 1;
        if self.reclaimed_count > self.reclaim_budget {
            return Err(DescriptorRefusal::ReclaimCapacity);
        }
        if self.apply
            && !self
                .reclaimed
                .push(table.ok_or(DescriptorRefusal::Malformed)?)
        {
            return Err(DescriptorRefusal::ReclaimCapacity);
        }
        Ok(())
    }

    /// Replace the entry at `loc` that links (or would link) a reclaimed
    /// table with an empty entry. Breaking a valid link is break-before-make
    /// without a make: the invalidation of the entry's whole span completes
    /// before the page can be reported free, so no walker on any PE can still
    /// reach it when the host reissues it. Undoing the store relinks the
    /// unchanged table, an invalid-to-valid transition that needs no
    /// invalidation.
    fn unlink(
        &mut self,
        loc: Loc,
        descriptor: u64,
        base: u64,
        level: usize,
        table: Option<u64>,
    ) -> Result<(), DescriptorRefusal> {
        self.note_reclaimed(table)?;
        if descriptor == 0 {
            return Ok(());
        }
        self.store(loc, descriptor, 0, None)?;
        if self.apply && matches!(loc, Loc::Live(_)) && descriptor & VALID != 0 {
            self.words.publish_barrier();
            self.words.invalidate_range(base, entry_span(level));
        }
        Ok(())
    }

    /// Visit one entry and return the descriptor it holds after this op.
    fn visit_entry(
        &mut self,
        level: usize,
        loc: Loc,
        descriptor: u64,
        base: u64,
    ) -> Result<u64, DescriptorRefusal> {
        let span = entry_span(level);
        if is_table(descriptor, level) {
            return match loc {
                Loc::Live(_) => {
                    let child = descriptor & PA_MASK_TABLE;
                    if self.visit_live_table(child, level + 1, base)? {
                        self.unlink(loc, descriptor, base, level, Some(child))?;
                        Ok(0)
                    } else {
                        Ok(descriptor)
                    }
                }
                Loc::Fresh(_) => Err(DescriptorRefusal::Malformed),
            };
        }
        let covers_entry = self.start <= base && base + span <= self.end;
        if let DescriptorOp::Terminal { edit, .. } = self.op {
            let Some(armed) =
                super::terminal_rule_edit(edit.asid_scoped, edit.rule, descriptor, level, base)
                    .map_err(|refusal| match refusal {
                        super::TerminalRefusal::Occupied => DescriptorRefusal::Occupied,
                        super::TerminalRefusal::Resident => DescriptorRefusal::AlreadyValid,
                        super::TerminalRefusal::Malformed => DescriptorRefusal::Malformed,
                    })?
            else {
                return Ok(descriptor);
            };
            if level == 0 {
                return Err(DescriptorRefusal::Malformed);
            }
            if level < 3 && !covers_entry {
                return self.descend(level, loc, descriptor, base);
            }
            if armed & VALID != 0 && edit.excludes(armed & output_mask(level), span) {
                return Err(DescriptorRefusal::ExcludedOutput);
            }
            if armed != descriptor {
                self.store(loc, descriptor, armed, None)?;
            }
            return Ok(armed);
        }
        if level == 0 {
            if descriptor != 0 {
                return Err(DescriptorRefusal::Malformed);
            }
            if !matches!(
                self.op,
                DescriptorOp::Prepare { .. } | DescriptorOp::MapAlias { .. }
            ) {
                return Err(DescriptorRefusal::MissingTable);
            }
        }
        if level == 3 || (level > 0 && covers_entry && self.op_edits_blocks(level, base)) {
            let updated = self.edit(descriptor, level, base)?;
            if updated != descriptor {
                if matches!(self.op, DescriptorOp::MapAlias { .. })
                    && matches!(loc, Loc::Live(_))
                    && descriptor & VALID != 0
                {
                    // The alias can replace output and attributes. Invalidate
                    // the old terminal before exposing its replacement; keep
                    // both stores in the same rollback journal.
                    self.store(loc, descriptor, 0, None)?;
                    if self.apply {
                        self.words.publish_barrier();
                        self.words.invalidate_range(base, span);
                    }
                    self.store(loc, 0, updated, Some((base, span)))?;
                } else {
                    self.store(loc, descriptor, updated, None)?;
                }
            }
            return Ok(updated);
        }
        self.descend(level, loc, descriptor, base)
    }

    fn op_edits_blocks(&self, level: usize, base: u64) -> bool {
        match self.op {
            DescriptorOp::MapAlias {
                span, target_ipa, ..
            } => {
                // Match map_aliased's 2 MiB blocks. A contiguous output is
                // not sufficient: its base must align to the block itself.
                level == 2
                    && (target_ipa.raw() + (base - span.va)).is_multiple_of(entry_span(level))
            }
            DescriptorOp::Publish { .. } | DescriptorOp::Protect(_) | DescriptorOp::Retire(_) => {
                true
            }
            _ => false,
        }
    }

    /// Replace a coarse or empty entry by a granted table, filled while
    /// unlinked, edited, then linked child-before-parent. Returns the
    /// entry's new descriptor. A reclaiming op whose edit leaves the new
    /// table reclaimable drops it instead of linking it, exactly as the host
    /// editor's split followed by its reclaim frees it.
    fn descend(
        &mut self,
        level: usize,
        loc: Loc,
        descriptor: u64,
        base: u64,
    ) -> Result<u64, DescriptorRefusal> {
        let valid = descriptor & VALID != 0;
        let empty = !valid && descriptor & output_mask(level) == 0;
        if level > 0 && !valid && descriptor & (TYPE_TABLE_OR_PAGE & !VALID) != 0 {
            // An invalidated table pointer records no output to split.
            return Err(DescriptorRefusal::Malformed);
        }
        if empty
            && !matches!(
                self.op,
                DescriptorOp::Prepare { .. }
                    | DescriptorOp::Terminal { .. }
                    | DescriptorOp::MapAlias { .. }
            )
        {
            return Err(DescriptorRefusal::MissingTable);
        }
        let grant = self.take_grant()?;
        if let Some(table) = grant {
            for index in 0..512 {
                let child = if level == 0 {
                    0
                } else {
                    expand(descriptor, level, index)
                };
                self.words.store_unlinked(table + index * 8, child)?;
            }
        }
        let child_span = entry_span(level + 1);
        let lo = self.start.max(base);
        let hi = self.end.min(base + entry_span(level));
        let child_at = |index: u64| {
            if level == 0 {
                0
            } else {
                expand(descriptor, level, index)
            }
        };
        let (first, last) = ((lo - base) / child_span, (hi - 1 - base) / child_span);
        let mut reclaimable =
            self.reclaim_budget != 0 && super::sub_table_level_reclaimable(level + 1);
        for index in first..=last {
            let child_loc = Loc::Fresh(grant.map(|table| table + index * 8));
            let child_va = base + index * child_span;
            let after = self.visit_entry(level + 1, child_loc, child_at(index), child_va)?;
            reclaimable = reclaimable && super::reclaimable_entry(after, level + 1, child_va);
        }
        if reclaimable
            && (0..first).chain(last + 1..512).all(|index| {
                super::reclaimable_entry(child_at(index), level + 1, base + index * child_span)
            })
        {
            // Every granted page is primary spare (checked before the first
            // store), so the dropped grant returns like an unlinked table.
            self.unlink(loc, descriptor, base, level, grant)?;
            return Ok(0);
        }
        let table_descriptor = grant.map_or(TYPE_TABLE_OR_PAGE, |table| {
            (table & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE
        });
        let span = entry_span(level);
        match loc {
            Loc::Fresh(_) => self.store(loc, descriptor, table_descriptor, None)?,
            Loc::Live(_) => {
                if self.apply {
                    self.words.publish_barrier();
                }
                if valid {
                    // Break-before-make: a valid block becomes invalid and
                    // is invalidated before the equivalent table appears.
                    self.store(loc, descriptor, 0, None)?;
                    if self.apply {
                        self.words.invalidate_range(base, span);
                    }
                    self.store(loc, 0, table_descriptor, Some((base, span)))?;
                } else {
                    self.store(loc, descriptor, table_descriptor, Some((base, span)))?;
                }
            }
        }
        Ok(table_descriptor)
    }

    fn take_grant(&mut self) -> Result<Option<u64>, DescriptorRefusal> {
        let index = self.grants_used;
        self.grants_used += 1;
        if !self.apply {
            return Ok(None);
        }
        self.grants
            .get(index)
            .copied()
            .map(Some)
            .ok_or(DescriptorRefusal::TablesExhausted)
    }

    fn store(
        &mut self,
        loc: Loc,
        before: u64,
        after: u64,
        undo_invalidate: Option<(u64, u64)>,
    ) -> Result<(), DescriptorRefusal> {
        match loc {
            Loc::Fresh(None) => Ok(()),
            Loc::Fresh(Some(pa)) => self.words.store_unlinked(pa, after),
            Loc::Live(pa) => {
                if !self.apply {
                    self.planned_live_stores += 1;
                    return Ok(());
                }
                if !self.words.compare_exchange(pa, before, after)? {
                    return Err(DescriptorRefusal::Contended);
                }
                let (bbm_va, bbm_len) = undo_invalidate.unwrap_or((0, 0));
                if !self.journal.push(JournalEntry {
                    pa,
                    before,
                    after,
                    bbm_va,
                    bbm_len,
                }) {
                    // Capacity was reserved from the plan; a shortfall means
                    // the graph changed underneath. Undo this store now.
                    let _ = self.words.compare_exchange(pa, after, before);
                    return Err(DescriptorRefusal::JournalCapacity);
                }
                Ok(())
            }
        }
    }

    fn edit(&self, descriptor: u64, level: usize, base: u64) -> Result<u64, DescriptorRefusal> {
        let state = el1_private_leaf_state(descriptor);
        match self.op {
            DescriptorOp::MapAlias {
                access,
                span,
                target_ipa,
                ..
            } => {
                let output = target_ipa.raw() + (base - span.va);
                let flags = if level == 3 {
                    USER_PAGE_FLAGS
                } else {
                    super::USER_BLOCK_FLAGS
                };
                let flags = match access {
                    AliasAccess::Deferred => (flags & !AP_MASK & !VALID) | AP_RO,
                    AliasAccess::User {
                        writable,
                        executable,
                    } => {
                        let flags = if writable {
                            flags
                        } else {
                            (flags & !AP_MASK) | AP_RO
                        };
                        if executable { flags } else { flags | UXN }
                    }
                };
                Ok(output | flags | NON_GLOBAL)
            }
            DescriptorOp::Prepare {
                publication,
                resident,
                ..
            } => {
                if descriptor & VALID != 0 {
                    return Err(DescriptorRefusal::AlreadyValid);
                }
                match state {
                    El1PrivateLeafState::Prepared => return Err(DescriptorRefusal::Occupied),
                    El1PrivateLeafState::Malformed => return Err(DescriptorRefusal::Malformed),
                    _ => {}
                }
                let output = (publication.ipa + (base - publication.va)) & PA_MASK_4KIB;
                let residency = if resident.contains(base) { VALID } else { 0 };
                Ok(output | prepared_flags(publication) | residency)
            }
            DescriptorOp::Publish {
                span,
                expected_ipa,
                access,
            } => {
                let expected = expected_ipa.raw() + (base - span.va);
                if descriptor & output_mask(level) != expected {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                match state {
                    El1PrivateLeafState::Prepared
                        if terminal_descriptor_permits_el0(descriptor | VALID, access) =>
                    {
                        Ok(descriptor | VALID)
                    }
                    El1PrivateLeafState::Resident
                        if terminal_descriptor_permits_el0(descriptor, access) =>
                    {
                        Ok(descriptor)
                    }
                    El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident => {
                        Err(DescriptorRefusal::PermissionDenied)
                    }
                    _ => Err(DescriptorRefusal::NotPrepared),
                }
            }
            DescriptorOp::Protect(edit) => {
                if !matches!(
                    state,
                    El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident
                ) {
                    return Err(DescriptorRefusal::NotPrivateAnonymous);
                }
                if el1_cow(descriptor) {
                    return Err(DescriptorRefusal::CowArmed);
                }
                if (edit.writable && descriptor & SW_EL1_MAY_WRITE == 0)
                    || (edit.executable && descriptor & SW_EL1_MAY_EXEC == 0)
                {
                    return Err(DescriptorRefusal::PermissionWidening);
                }
                let (ap, uxn) = if !(edit.readable || edit.writable || edit.executable) {
                    (AP_PRIV_RO, UXN)
                } else if edit.writable {
                    (AP_RW, if edit.executable { 0 } else { UXN })
                } else {
                    (AP_RO, if edit.executable { 0 } else { UXN })
                };
                Ok((descriptor & !AP_MASK & !UXN) | ap | uxn)
            }
            DescriptorOp::Retire(_) => match state {
                El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident => {
                    Ok((descriptor & !VALID) | SW_RETIRED)
                }
                _ => Err(DescriptorRefusal::NotPrivateAnonymous),
            },
            DescriptorOp::CowRepoint {
                access,
                va,
                old_ipa,
                new_ipa,
                ..
            } => {
                if descriptor & PA_MASK_4KIB != old_ipa.raw() + (base - va) {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                let output = new_ipa.raw() + (base - va);
                match access {
                    CowRepointAccess::Kernel => {
                        if descriptor & VALID == 0 || descriptor & (1 << 6) != 0 {
                            return Err(DescriptorRefusal::PermissionDenied);
                        }
                        return Ok(output | super::KERNEL_PAGE_FLAGS | NON_GLOBAL);
                    }
                    CowRepointAccess::User { writable_pages } => {
                        let repointed = (descriptor & !PA_MASK_4KIB) | output;
                        if descriptor & VALID == 0 {
                            // Retired/prepared backing maintenance must leave
                            // the page inaccessible until its later publication.
                            return Ok(repointed);
                        }
                        if descriptor & SW_EL1_PRIVATE == 0 {
                            let wants_write = writable_pages & (1 << ((base - va) / PT_PAGE)) != 0;
                            if wants_write && descriptor & AP_MASK == AP_PRIV_RO {
                                return Err(DescriptorRefusal::PermissionDenied);
                            }
                            return Ok(if wants_write {
                                (repointed & !AP_MASK) | AP_RW
                            } else {
                                repointed
                            });
                        }
                        // Tagged pages belong to EL1's permission authority;
                        // backend metadata must not override its recorded intent.
                    }
                    CowRepointAccess::RecordedPrivate => {}
                }
                if state != El1PrivateLeafState::Prepared
                    && (state != El1PrivateLeafState::Resident || !el1_cow(descriptor))
                {
                    return Err(DescriptorRefusal::NotCowArmed);
                }
                if descriptor & PA_MASK_4KIB != old_ipa.raw() + (base - va) {
                    return Err(DescriptorRefusal::WrongBacking);
                }
                let repointed = (descriptor & !PA_MASK_4KIB) | (new_ipa.raw() + (base - va));
                if state == El1PrivateLeafState::Prepared {
                    // The compound can include untouched pages. Moving their
                    // backing must not make them resident or widen access.
                    return Ok(repointed);
                }
                // Fork arming recorded the page's actual Linux write intent,
                // not just the allocation ceiling. Read-only and PROT_NONE
                // neighbors move with the compound without gaining access.
                let private = repointed & !SW_EL1_COW;
                Ok(
                    if descriptor & SW_EL1_MAY_WRITE != 0 && descriptor & AP_MASK != AP_PRIV_RO {
                        (private & !AP_MASK) | AP_RW
                    } else {
                        private
                    },
                )
            }
            // Terminal rules share the host editor's definition and are
            // applied in `visit_entry` before this per-op table.
            DescriptorOp::Terminal { .. } => Err(DescriptorRefusal::Malformed),
        }
    }
}

/// The L3 prepared-leaf encoding of the host grant publisher: Linux
/// permissions in AP/UXN, per-MM nG, EL1 private authority and its write /
/// execute ceilings; VALID clear until residency.
fn prepared_flags(publication: GuestLeafPublication) -> u64 {
    let mut flags = if publication.writable {
        USER_PAGE_FLAGS | NON_GLOBAL
    } else {
        (USER_PAGE_FLAGS & !AP_MASK) | AP_RO | NON_GLOBAL
    };
    flags |= SW_EL1_PRIVATE;
    if publication.writable {
        flags |= SW_EL1_MAY_WRITE;
    }
    if publication.executable {
        flags |= SW_EL1_MAY_EXEC;
    } else {
        flags |= UXN;
    }
    flags & !VALID
}

fn validate_op(op: &DescriptorOp) -> Result<(), DescriptorRefusal> {
    let span = op.span();
    if !span.is_well_formed() {
        return Err(DescriptorRefusal::BadRange);
    }
    // The EL1 COW copy window belongs to Carrick, not to any guest range:
    // only `copy_window::with_cow_copy_aliases` maps its leaves, and only
    // for the bounded copy. No host-described edit may name it.
    if copy_window::overlaps_cow_copy_window(span.va, span.len) {
        return Err(DescriptorRefusal::CarrickOwnedWindow);
    }
    let aligned = |raw: u64| raw != 0 && raw.is_multiple_of(PT_PAGE) && raw & !PA_MASK_4KIB == 0;
    let ok = match *op {
        DescriptorOp::Prepare {
            publication,
            resident,
            ..
        } => {
            aligned(publication.ipa)
                && publication.ipa.checked_add(publication.len).is_some()
                && resident.va.is_multiple_of(PT_PAGE)
                && resident.len.is_multiple_of(PT_PAGE)
                && span.contains_span(resident)
        }
        DescriptorOp::Publish { expected_ipa, .. } => {
            aligned(expected_ipa.raw()) && expected_ipa.raw().checked_add(span.len).is_some()
        }
        DescriptorOp::MapAlias { target_ipa, .. } => {
            aligned(target_ipa.raw())
                && target_ipa
                    .raw()
                    .checked_add(span.len)
                    .is_some_and(|end| end <= PA_MASK_4KIB + PT_PAGE)
        }
        DescriptorOp::Protect(_) | DescriptorOp::Retire(_) => true,
        DescriptorOp::Terminal { edit, .. } => {
            if !edit.reclaim_well_formed() {
                return Err(DescriptorRefusal::BadEncoding);
            }
            edit.excluded_ipa.checked_add(edit.excluded_len).is_some()
        }
        DescriptorOp::CowRepoint {
            access,
            old_ipa,
            new_ipa,
            ..
        } => {
            aligned(old_ipa.raw())
                && aligned(new_ipa.raw())
                && old_ipa != new_ipa
                && span.len <= 4 * PT_PAGE
                && access.covers(span.len)
                // The hardware copies pages in order. Overlap could overwrite
                // a source page before its turn, even with distinct starts.
                && old_ipa.raw().abs_diff(new_ipa.raw()) >= span.len
                && old_ipa
                    .raw()
                    .checked_add(span.len)
                    .is_some_and(|end| end <= PA_MASK_4KIB + PT_PAGE)
                && new_ipa
                    .raw()
                    .checked_add(span.len)
                    .is_some_and(|end| end <= PA_MASK_4KIB + PT_PAGE)
        }
    };
    if ok {
        Ok(())
    } else {
        Err(DescriptorRefusal::BadRange)
    }
}

fn roll_back<W: LiveDescriptorWords + ?Sized>(words: &W, journal: &[JournalEntry]) -> bool {
    for entry in journal.iter().rev() {
        if words.compare_exchange(entry.pa, entry.after, entry.before) != Ok(true) {
            return false;
        }
        if entry.bbm_len != 0 {
            words.invalidate_range(entry.bbm_va, entry.bbm_len);
        }
    }
    words.publish_barrier();
    true
}

/// Work a descriptor operation needs, from a read-only walk of the live graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorPlan {
    /// Unlinked table pages the operation will fill and link.
    pub table_grants: usize,
    /// Journaled live descriptor stores.
    pub live_stores: usize,
    /// Emptied tables a reclaiming operation will unlink (and grants it will
    /// consume and drop), at most its budget.
    pub reclaimed_tables: usize,
}

fn plan_validated<W>(
    words: &W,
    root: u64,
    op: DescriptorOp,
) -> Result<DescriptorPlan, DescriptorRefusal>
where
    W: LiveDescriptorWords + ?Sized,
{
    let span = op.span();
    let end = span.end().ok_or(DescriptorRefusal::BadRange)?;
    let mut no_journal = SliceJournal::new(&mut []);
    let mut plan = Executor {
        words,
        op,
        start: span.va,
        end,
        apply: false,
        grants: &[],
        grants_used: 0,
        journal: &mut no_journal,
        planned_live_stores: 0,
        root,
        reclaim_budget: op.reclaim_budget(),
        reclaimed_count: 0,
        reclaimed: ReclaimedTables::NONE,
    };
    plan.visit_live_table(root, 0, 0)?;
    Ok(DescriptorPlan {
        table_grants: plan.grants_used,
        live_stores: plan.planned_live_stores,
        reclaimed_tables: plan.reclaimed_count,
    })
}

/// Validate `op` against the live graph at `root` without storing, and
/// report the table grants and journal capacity it needs. The host uses this
/// to reserve exactly the grants a submission carries; EL1 re-plans against
/// the graph it actually edits, so a graph that changed in between refuses
/// rather than overrunning its grants.
pub fn plan_descriptor_op<W>(
    words: &W,
    root: SubstrateGpa,
    op: DescriptorOp,
) -> Result<DescriptorPlan, DescriptorRefusal>
where
    W: LiveDescriptorWords + ?Sized,
{
    validate_op(&op)?;
    let root = root.raw();
    if root == 0 || !root.is_multiple_of(PT_PAGE) {
        return Err(DescriptorRefusal::StaleRoot);
    }
    plan_validated(words, root, op)
}

/// Apply one descriptor operation to the live graph rooted at `root`.
///
/// The complete span, table-grant need and journal capacity are validated
/// by a read-only plan before the first live store; the same walk then
/// applies it. Guest-originated edits (first-touch commit, EL1-served
/// `mprotect`/`munmap`) and host submissions share this one implementation.
///
/// The caller holds the exact-MM editor for `root` and, after any outcome
/// with `flush_required` (or a rollback), invalidates the MM's ASID.
pub fn execute_descriptor_op<W, J>(
    words: &W,
    root: SubstrateGpa,
    op: DescriptorOp,
    tables: &TableGrants,
    journal: &mut J,
) -> DescriptorOutcome
where
    W: LiveDescriptorWords + ?Sized,
    J: DescriptorJournal + ?Sized,
{
    if let Err(refusal) = validate_op(&op) {
        return DescriptorOutcome::Refused(refusal);
    }
    let root = root.raw();
    if root == 0 || !root.is_multiple_of(PT_PAGE) {
        return DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot);
    }
    for &grant in tables.as_slice() {
        if grant == root
            || words.load(grant).is_err()
            || words.load(grant + PT_PAGE - 8).is_err()
            // A reclaiming op may drop a grant it split into, and reports it
            // freed: every grant must then be a primary spare table page.
            || (op.reclaim_budget() != 0 && !super::primary_spare_table(root, grant))
        {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadTableGrant);
        }
    }
    let plan = match plan_validated(words, root, op) {
        Ok(plan) => plan,
        Err(refusal) => return DescriptorOutcome::Refused(refusal),
    };
    let span = op.span();
    let end = span.va + span.len;
    let (grants_needed, live_stores) = (plan.table_grants, plan.live_stores);
    if grants_needed > tables.len() {
        return DescriptorOutcome::Refused(DescriptorRefusal::TablesExhausted);
    }
    if !journal.reserve(live_stores) {
        return DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity);
    }
    let mut apply = Executor {
        words,
        op,
        start: span.va,
        end,
        apply: true,
        grants: tables.as_slice(),
        grants_used: 0,
        journal: &mut *journal,
        planned_live_stores: 0,
        root,
        reclaim_budget: op.reclaim_budget(),
        reclaimed_count: 0,
        reclaimed: ReclaimedTables::NONE,
    };
    let result = apply.visit_live_table(root, 0, 0);
    let tables_linked = apply.grants_used;
    let reclaimed = apply.reclaimed;
    match result {
        Ok(_) => {
            let stored = journal.entries().len();
            DescriptorOutcome::Applied(DescriptorApplied {
                pages: span.len / PT_PAGE,
                resident: match op {
                    DescriptorOp::Prepare { resident, .. } => resident,
                    DescriptorOp::Publish { span, .. } => span,
                    _ => PageSpan::EMPTY,
                },
                tables_linked: u8::try_from(tables_linked).unwrap_or(u8::MAX),
                reclaimed,
                live_stores: u32::try_from(stored).unwrap_or(u32::MAX),
                flush_required: stored != 0,
            })
        }
        Err(refusal) => {
            let restored = roll_back(words, journal.entries());
            journal.clear();
            if restored {
                DescriptorOutcome::RolledBack(refusal)
            } else {
                DescriptorOutcome::Indeterminate(refusal)
            }
        }
    }
}

/// Apply one authenticated host submission. `root` is the root EL1 itself
/// authenticated for `txn.id.mm_key` from its published address space; a
/// submission naming any other root is refused before any store.
pub fn execute_descriptor_txn<W, J>(
    words: &W,
    root: SubstrateGpa,
    txn: &DescriptorTxn,
    journal: &mut J,
) -> DescriptorReceipt
where
    W: LiveDescriptorWords + ?Sized,
    J: DescriptorJournal + ?Sized,
{
    let outcome = if txn.root != root {
        DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot)
    } else {
        execute_descriptor_op(words, root, txn.op, &txn.tables, journal)
    };
    DescriptorReceipt {
        id: txn.id,
        digest: txn.digest(),
        outcome,
    }
}

/// EL1: claim, execute and answer the submission in `slot` for `mm_key`.
/// The caller holds `mm_key`'s exact editor, passes the root it
/// authenticated for that MM, and invalidates the ASID when the returned
/// receipt's outcome stored anything.
pub fn apply_submitted_descriptor_txn<W, J>(
    slot: &DescriptorTxnSlot,
    mm_key: u64,
    words: &W,
    root: SubstrateGpa,
    journal: &mut J,
) -> Option<DescriptorReceipt>
where
    W: LiveDescriptorWords + ?Sized,
    J: DescriptorJournal + ?Sized,
{
    let claimed = slot.claim_for_mm(mm_key)?;
    let outcome = match claimed.txn() {
        Ok(txn) => execute_descriptor_txn(words, root, txn, journal).outcome,
        Err(refusal) => DescriptorOutcome::Refused(refusal),
    };
    Some(claimed.complete(outcome))
}

/// One guest COW copy the host granted: the faulting page, the shared frame
/// it still maps, and the private replacement frame whose backing and
/// inventory are already live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowCopyGrant {
    pub mm_key: NonZeroU64,
    pub root: SubstrateGpa,
    pub va: u64,
    pub old_ipa: SubstrateGpa,
    pub new_ipa: SubstrateGpa,
    pub old_backing: BackingIdentity,
    pub new_backing: BackingIdentity,
}

/// Proof that one granted COW page was copied exactly, from the frame the
/// live leaf still maps into the granted replacement. Only
/// [`copy_granted_cow_page`] constructs it; the repoint it authorizes is
/// [`Self::repoint_op`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowCopyComplete {
    grant: CowCopyGrant,
    bytes: u64,
}

impl CowCopyComplete {
    #[must_use]
    pub fn grant(&self) -> CowCopyGrant {
        self.grant
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The only descriptor operation this copy authorizes.
    #[must_use]
    pub fn repoint_op(&self) -> DescriptorOp {
        DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            len: PT_PAGE,
            va: self.grant.va,
            old_ipa: self.grant.old_ipa,
            new_ipa: self.grant.new_ipa,
            backing: self.grant.new_backing,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowCopyError {
    /// The live leaf no longer is a COW-armed page mapping `old_ipa` (stale
    /// grant): nothing was copied.
    Refused(DescriptorRefusal),
    /// A window is not exactly one page.
    BadWindow,
}

/// Copy one granted COW page. The live graph at `grant.root` must still map
/// `grant.va` onto `grant.old_ipa` as a private prepared or COW-armed leaf
/// (validated by planning the repoint, without storing); then the 4096 bytes of
/// `source` (the old frame) copied into `destination` (the new frame). The
/// caller holds the exact-MM editor, so the leaf cannot change between the
/// check and the repoint that follows.
pub fn copy_granted_cow_page<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    grant: CowCopyGrant,
    source: &[u8],
    destination: &mut [u8],
) -> Result<CowCopyComplete, CowCopyError> {
    if source.len() != PT_PAGE as usize || destination.len() != PT_PAGE as usize {
        return Err(CowCopyError::BadWindow);
    }
    let op = DescriptorOp::CowRepoint {
        access: CowRepointAccess::RecordedPrivate,
        len: PT_PAGE,
        va: grant.va,
        old_ipa: grant.old_ipa,
        new_ipa: grant.new_ipa,
        backing: grant.new_backing,
    };
    let plan = plan_descriptor_op(words, grant.root, op).map_err(CowCopyError::Refused)?;
    if plan.table_grants != 0 {
        // A coarse COW block needs a split: the repoint must carry grants.
        return Err(CowCopyError::Refused(DescriptorRefusal::TablesExhausted));
    }
    destination.copy_from_slice(source);
    Ok(CowCopyComplete {
        grant,
        bytes: PT_PAGE,
    })
}

/// Whether a receipt's outcome changed live descriptors and therefore needs
/// the caller's ASID invalidation.
#[must_use]
pub fn outcome_requires_invalidation(outcome: &DescriptorOutcome) -> bool {
    match outcome {
        DescriptorOutcome::Applied(applied) => applied.flush_required,
        DescriptorOutcome::Refused(_) => false,
        DescriptorOutcome::RolledBack(_) | DescriptorOutcome::Indeterminate(_) => true,
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
                reclaimed: ReclaimedTables::NONE,
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
            DescriptorOp::MapAlias {
                access: AliasAccess::Deferred,
                span: PageSpan::new(0x5000, 2 * PT_PAGE),
                target_ipa: SubstrateGpa(0x7000),
                backing: backing(90),
            },
            DescriptorOp::MapAlias {
                access: AliasAccess::User {
                    writable: true,
                    executable: true,
                },
                span: PageSpan::new(0x5000, 2 * PT_PAGE),
                target_ipa: SubstrateGpa(0x7000),
                backing: backing(90),
            },
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
                access: CowRepointAccess::RecordedPrivate,
                len: PT_PAGE,
                va: 0x9000,
                old_ipa: SubstrateGpa(0xa000),
                new_ipa: SubstrateGpa(0xb000),
                backing: backing(90),
            },
            DescriptorOp::CowRepoint {
                access: CowRepointAccess::Kernel,
                len: PT_PAGE,
                va: 0x9000,
                old_ipa: SubstrateGpa(0xa000),
                new_ipa: SubstrateGpa(0xb000),
                backing: backing(90),
            },
            DescriptorOp::CowRepoint {
                access: CowRepointAccess::User {
                    writable_pages: 0b0101,
                },
                len: 4 * PT_PAGE,
                va: 0x9000,
                old_ipa: SubstrateGpa(0xa000),
                new_ipa: SubstrateGpa(0xe000),
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
    fn every_terminal_rule_round_trips_and_invalid_rule_words_are_refused() {
        use super::super::{PtOp, TerminalRule};
        let mut ops = alloc::vec![None];
        for exec in [false, true] {
            ops.extend([
                Some(PtOp::ReadOnly { exec }),
                Some(PtOp::ReadWrite { exec }),
                Some(PtOp::KernelReadOnly { exec }),
            ]);
        }
        ops.extend([
            Some(PtOp::Invalidate),
            Some(PtOp::Retire),
            Some(PtOp::ForkReadOnly),
        ]);
        let mut rules = alloc::vec![TerminalRule::BusFault];
        for op in ops {
            for bits in 0..8u8 {
                rules.push(TerminalRule::Pt {
                    op,
                    reset_retired: bits & 1 != 0,
                    deny_host_buffers: bits & 2 != 0,
                    fork_arm: bits & 4 != 0,
                });
            }
        }
        for rule in rules {
            for asid_scoped in [false, true] {
                let op = DescriptorOp::Terminal {
                    span: PageSpan::new(0x5000, 3 * PT_PAGE),
                    edit: TerminalEdit {
                        rule,
                        asid_scoped,
                        excluded_ipa: 0x0800_0000,
                        excluded_len: 0x0100_0000,
                        reclaim_budget: 0,
                    },
                };
                let (kind, payload) = op.encode();
                assert_eq!(
                    DescriptorOp::decode(kind, payload, None),
                    Some(op),
                    "{rule:?}"
                );
            }
        }
        // Reclaiming munmap retirement round-trips at every budget.
        for budget in 1..=MAX_RECLAIMED_TABLES as u8 {
            for asid_scoped in [false, true] {
                let mut edit =
                    TerminalEdit::unmap_reclaiming(asid_scoped, 0x0800_0000, 0x0100_0000);
                edit.reclaim_budget = budget;
                let op = DescriptorOp::Terminal {
                    span: PageSpan::new(0x5000, 3 * PT_PAGE),
                    edit,
                };
                let (kind, payload) = op.encode();
                assert_eq!(DescriptorOp::decode(kind, payload, None), Some(op));
                assert_eq!(op.reclaim_budget(), usize::from(budget));
            }
        }
        let decode = |word| {
            DescriptorOp::decode(
                DescriptorOp::KIND_TERMINAL,
                [0x5000, PT_PAGE, word, 0, 0, 0],
                None,
            )
        };
        // Unknown bits, an execute bit on an op without one, and composition
        // flags on a BUS-tail rule are malformed, not reinterpreted.
        let budget = |n: u64| n << TerminalEdit::RECLAIM_SHIFT;
        for word in [
            1 << 16,
            TerminalEdit::OP_INVALIDATE | TerminalEdit::EXEC,
            // Reclaim only follows plain munmap retirement, within the
            // receipt bound.
            TerminalEdit::OP_INVALIDATE | budget(1),
            TerminalEdit::OP_READ_WRITE | budget(1),
            TerminalEdit::OP_RETIRE | TerminalEdit::DENY_HOST_BUFFERS | budget(1),
            TerminalEdit::RULE_BUS_FAULT | budget(1),
            TerminalEdit::OP_RETIRE | budget(MAX_RECLAIMED_TABLES as u64 + 1),
            TerminalEdit::OP_NONE | TerminalEdit::EXEC,
            TerminalEdit::RULE_BUS_FAULT | TerminalEdit::FORK_ARM,
            TerminalEdit::RULE_BUS_FAULT | TerminalEdit::EXEC,
        ] {
            assert_eq!(decode(word), None, "{word:#x}");
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
            reclaimed: ReclaimedTables::NONE,
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
                access: CowRepointAccess::RecordedPrivate,
                len: PT_PAGE,
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

    mod executor {
        use super::super::*;
        use super::backing;
        use crate::aarch64::{AP_EL0_ACCESS, arm_existing_el1_fork_pages, indices};
        use core::cell::{Cell, RefCell};
        use std::vec;
        use std::vec::Vec;

        const ROOT: u64 = 0x8800_0000_0000;
        const PAGES: usize = 16;
        const VA: u64 = 0x4000_0000;
        const IPA: u64 = 0x009b_4000_0000;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Event {
            Unlinked(u64),
            Cas { pa: u64, before: u64, after: u64 },
            Barrier,
            Invalidate(u64, u64),
        }

        /// Host-memory live table arena that logs every store and can make
        /// the n-th forward compare-exchange observe a concurrent writer.
        struct TestWords {
            words: Vec<AtomicU64>,
            log: RefCell<Vec<Event>>,
            fail_cas_at: Cell<Option<usize>>,
            forward_cas: Cell<usize>,
        }

        impl TestWords {
            fn new() -> Self {
                Self {
                    words: (0..PAGES * 512).map(|_| AtomicU64::new(0)).collect(),
                    log: RefCell::new(Vec::new()),
                    fail_cas_at: Cell::new(None),
                    forward_cas: Cell::new(0),
                }
            }
            fn index(pa: u64) -> usize {
                ((pa - ROOT) / 8) as usize
            }
            fn get(&self, pa: u64) -> u64 {
                self.words[Self::index(pa)].load(Ordering::Relaxed)
            }
            fn set(&self, pa: u64, value: u64) {
                self.words[Self::index(pa)].store(value, Ordering::Relaxed);
            }
            fn image(&self) -> Vec<u64> {
                self.words
                    .iter()
                    .map(|w| w.load(Ordering::Relaxed))
                    .collect()
            }
            fn live_cas(&self) -> Vec<Event> {
                self.log
                    .borrow()
                    .iter()
                    .copied()
                    .filter(|e| matches!(e, Event::Cas { .. }))
                    .collect()
            }
        }

        impl LiveDescriptorWords for TestWords {
            fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
                if pa < ROOT || pa >= ROOT + (PAGES as u64) * PT_PAGE || !pa.is_multiple_of(8) {
                    return Err(DescriptorRefusal::TableOutsidePrimary);
                }
                Ok(self.get(pa))
            }
            fn compare_exchange(
                &self,
                pa: u64,
                current: u64,
                new: u64,
            ) -> Result<bool, DescriptorRefusal> {
                self.load(pa)?;
                let n = self.forward_cas.get();
                self.forward_cas.set(n + 1);
                if self.fail_cas_at.get() == Some(n) {
                    self.fail_cas_at.set(None);
                    return Ok(false);
                }
                let ok = self.words[Self::index(pa)]
                    .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                if ok {
                    self.log.borrow_mut().push(Event::Cas {
                        pa,
                        before: current,
                        after: new,
                    });
                }
                Ok(ok)
            }
            fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
                self.load(pa)?;
                self.set(pa, value);
                self.log.borrow_mut().push(Event::Unlinked(pa));
                Ok(())
            }
            fn publish_barrier(&self) {
                self.log.borrow_mut().push(Event::Barrier);
            }
            fn invalidate_range(&self, va: u64, len: u64) {
                self.log.borrow_mut().push(Event::Invalidate(va, len));
            }
        }

        fn page(n: u64) -> u64 {
            ROOT + n * PT_PAGE
        }

        fn table(n: u64) -> u64 {
            page(n) | TYPE_TABLE_OR_PAGE
        }

        /// L0 -> L1 -> L2 -> L3 for `VA`, down to `depth` linked levels.
        fn fixture(depth: usize) -> TestWords {
            let words = TestWords::new();
            let idx = indices(VA);
            if depth >= 1 {
                words.set(page(0) + idx[0] as u64 * 8, table(1));
            }
            if depth >= 2 {
                words.set(page(1) + idx[1] as u64 * 8, table(2));
            }
            if depth >= 3 {
                words.set(page(2) + idx[2] as u64 * 8, table(3));
            }
            words
        }

        fn leaf_pa(va: u64) -> u64 {
            let idx = indices(va);
            page(3) + idx[3] as u64 * 8
        }

        fn grants(pages: &[u64]) -> TableGrants {
            let pages: Vec<SubstrateGpa> = pages.iter().map(|&n| SubstrateGpa(page(n))).collect();
            TableGrants::new(&pages).unwrap()
        }

        fn prepare(len_pages: u64, resident: PageSpan, writable: bool) -> DescriptorOp {
            DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: VA,
                    ipa: IPA,
                    len: len_pages * PT_PAGE,
                    writable,
                    executable: false,
                },
                resident,
                backing: backing(40),
            }
        }

        fn run(words: &TestWords, op: DescriptorOp, tables: &TableGrants) -> DescriptorOutcome {
            let mut journal = InlineJournal::new();
            execute_descriptor_op(words, SubstrateGpa(ROOT), op, tables, &mut journal)
        }

        fn applied(outcome: DescriptorOutcome) -> DescriptorApplied {
            match outcome {
                DescriptorOutcome::Applied(applied) => applied,
                other => panic!("expected an applied outcome, got {other:?}"),
            }
        }

        fn nz(value: u64) -> NonZeroU64 {
            NonZeroU64::new(value).unwrap()
        }

        #[test]
        fn prepare_publishes_the_grant_and_exactly_the_resident_page() {
            let words = fixture(3);
            let resident = PageSpan::new(VA + PT_PAGE, PT_PAGE);
            let result = applied(run(&words, prepare(4, resident, true), &TableGrants::NONE));
            assert_eq!(result.resident, resident);
            assert_eq!(result.pages, 4);
            assert_eq!(result.live_stores, 4);
            for n in 0..4 {
                let d = words.get(leaf_pa(VA + n * PT_PAGE));
                assert_eq!(d & PA_MASK_4KIB, IPA + n * PT_PAGE);
                assert_ne!(d & NON_GLOBAL, 0);
                assert_ne!(d & UXN, 0);
                let expected = if n == 1 {
                    El1PrivateLeafState::Resident
                } else {
                    El1PrivateLeafState::Prepared
                };
                assert_eq!(el1_private_leaf_state(d), expected, "page {n}");
                assert!(terminal_descriptor_permits_el0(
                    d | VALID,
                    LeafAccess::Write
                ));
            }
            // A second prepare over the same span is refused whole.
            let image = words.image();
            assert_eq!(
                run(
                    &words,
                    prepare(4, PageSpan::EMPTY, true),
                    &TableGrants::NONE
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::Occupied)
            );
            assert_eq!(
                run(
                    &words,
                    DescriptorOp::Prepare {
                        publication: GuestLeafPublication {
                            va: VA + PT_PAGE,
                            ipa: IPA,
                            len: PT_PAGE,
                            writable: true,
                            executable: false,
                        },
                        resident: PageSpan::EMPTY,
                        backing: backing(50),
                    },
                    &TableGrants::NONE
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::AlreadyValid)
            );
            assert_eq!(words.image(), image);
        }

        #[test]
        fn prepare_builds_missing_hierarchy_from_grants_child_before_parent() {
            let words = fixture(1);
            let before = words.image();
            // Missing L2 and L3 need two grants; one is refused before any store.
            assert_eq!(
                run(
                    &words,
                    prepare(4, PageSpan::new(VA, PT_PAGE), true),
                    &grants(&[8])
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::TablesExhausted)
            );
            assert_eq!(words.image(), before);
            assert!(words.log.borrow().is_empty());

            let result = applied(run(
                &words,
                prepare(4, PageSpan::new(VA, PT_PAGE), true),
                &grants(&[8, 9, 10]),
            ));
            assert_eq!(result.tables_linked, 2);
            assert_eq!(
                result.live_stores, 1,
                "only the L1 link touches the live graph"
            );
            let idx = indices(VA);
            let l1_entry = page(1) + idx[1] as u64 * 8;
            assert_eq!(words.get(l1_entry), table(8));
            assert_eq!(words.get(page(8) + idx[2] as u64 * 8), table(9));
            let leaf = words.get(page(9) + idx[3] as u64 * 8);
            assert_eq!(el1_private_leaf_state(leaf), El1PrivateLeafState::Resident);
            // Every unlinked fill precedes the barrier, which precedes the link.
            let log = words.log.borrow();
            let barrier = log.iter().position(|e| *e == Event::Barrier).unwrap();
            let link = log
                .iter()
                .position(|e| matches!(e, Event::Cas { pa, .. } if *pa == l1_entry))
                .unwrap();
            assert!(barrier < link);
            assert!(
                log[..barrier]
                    .iter()
                    .all(|e| matches!(e, Event::Unlinked(_)))
            );
            assert_eq!(log.len(), barrier + 2, "nothing is stored after the link");
            // The unused third grant is untouched.
            assert!((0..512).all(|i| words.get(page(10) + i * 8) == 0));
        }

        #[test]
        fn tables_outside_the_primary_arena_refuse_before_any_store() {
            let words = fixture(2);
            let idx = indices(VA);
            // The L2 entry points into an extension arena EL1 cannot reach.
            words.set(
                page(2) + idx[2] as u64 * 8,
                0x9900_0000_0000 | TYPE_TABLE_OR_PAGE,
            );
            let before = words.image();
            assert_eq!(
                run(&words, prepare(2, PageSpan::EMPTY, true), &grants(&[8])),
                DescriptorOutcome::Refused(DescriptorRefusal::TableOutsidePrimary)
            );
            let foreign = TableGrants::new(&[SubstrateGpa(0x9900_0000_0000)]).unwrap();
            assert_eq!(
                run(&words, prepare(2, PageSpan::EMPTY, true), &foreign),
                DescriptorOutcome::Refused(DescriptorRefusal::BadTableGrant)
            );
            assert_eq!(
                run(&words, prepare(2, PageSpan::EMPTY, true), &grants(&[0])),
                DescriptorOutcome::Refused(DescriptorRefusal::BadTableGrant),
                "the root itself is never a grant"
            );
            assert_eq!(words.image(), before);
            assert!(words.live_cas().is_empty());
        }

        #[test]
        fn protect_serves_mixed_prepared_and_resident_ranges() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::new(VA, 2 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            let readonly = GuestPermissionEdit {
                va: VA,
                len: 4 * PT_PAGE,
                readable: true,
                writable: false,
                executable: false,
            };
            applied(run(
                &words,
                DescriptorOp::Protect(readonly),
                &TableGrants::NONE,
            ));
            for n in 0..4 {
                let d = words.get(leaf_pa(VA + n * PT_PAGE));
                assert_eq!(d & AP_MASK, AP_RO, "page {n}");
                assert_eq!(d & PA_MASK_4KIB, IPA + n * PT_PAGE);
                assert_eq!(d & VALID != 0, n < 2, "protection never changes residency");
                assert!(!terminal_descriptor_permits_el0(
                    d | VALID,
                    LeafAccess::Write
                ));
            }
            // The ceiling survives: RW is restorable, execute is widening.
            let rw = GuestPermissionEdit {
                writable: true,
                ..readonly
            };
            applied(run(&words, DescriptorOp::Protect(rw), &TableGrants::NONE));
            let before = words.image();
            assert_eq!(
                run(
                    &words,
                    DescriptorOp::Protect(GuestPermissionEdit {
                        executable: true,
                        ..rw
                    }),
                    &TableGrants::NONE
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::PermissionWidening)
            );
            // PROT_NONE denies EL0 and host buffers on both states.
            applied(run(
                &words,
                DescriptorOp::Protect(GuestPermissionEdit {
                    readable: false,
                    writable: false,
                    executable: false,
                    ..rw
                }),
                &TableGrants::NONE,
            ));
            for n in 0..4 {
                let d = words.get(leaf_pa(VA + n * PT_PAGE));
                assert!(!crate::aarch64::terminal_descriptor_permits_host_buffer(
                    d,
                    LeafAccess::Read
                ));
                assert_eq!(d & AP_EL0_ACCESS, 0);
            }
            let _ = before;
            // A COW-armed resident leaf belongs to the COW transaction.
            applied(run(&words, DescriptorOp::Protect(rw), &TableGrants::NONE));
            let byte_len = words.words.len() * 8;
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    byte_len,
                    VA,
                    PT_PAGE,
                )
            }
            .unwrap();
            let armed = words.image();
            assert_eq!(
                run(&words, DescriptorOp::Protect(readonly), &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::CowArmed)
            );
            assert_eq!(words.image(), armed);
        }

        fn resident_block(words: &TestWords, output: u64) -> u64 {
            let idx = indices(VA);
            let entry = page(2) + idx[2] as u64 * 8;
            let block = (output & PA_MASK_2MIB)
                | (crate::aarch64::USER_BLOCK_FLAGS & !AP_MASK)
                | AP_RW
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE
                | SW_EL1_MAY_WRITE;
            words.set(entry, block);
            entry
        }

        #[test]
        fn partial_valid_block_protect_splits_with_break_before_make() {
            let words = fixture(2);
            let entry = resident_block(&words, 0x009c_0000_0000);
            let block = words.get(entry);
            let target = VA + 5 * PT_PAGE;
            let edit = GuestPermissionEdit {
                va: target,
                len: PT_PAGE,
                readable: true,
                writable: false,
                executable: false,
            };
            assert_eq!(
                run(&words, DescriptorOp::Protect(edit), &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::TablesExhausted)
            );
            assert_eq!(words.get(entry), block);

            let result = applied(run(&words, DescriptorOp::Protect(edit), &grants(&[8])));
            assert_eq!(result.tables_linked, 1);
            assert_eq!(words.get(entry), table(8));
            for n in 0..512u64 {
                let d = words.get(page(8) + n * 8);
                assert_eq!(d & PA_MASK_4KIB, 0x009c_0000_0000 + n * PT_PAGE);
                assert!(terminal_descriptor_permits_el0(d, LeafAccess::Read));
                assert_eq!(
                    terminal_descriptor_permits_el0(d, LeafAccess::Write),
                    n != 5,
                    "only the edited page loses write"
                );
            }
            assert_eq!(
                words.live_cas(),
                vec![
                    Event::Cas {
                        pa: entry,
                        before: block,
                        after: 0
                    },
                    Event::Cas {
                        pa: entry,
                        before: 0,
                        after: table(8)
                    },
                ]
            );
            let log = words.log.borrow();
            let breaks = log
                .iter()
                .position(|e| matches!(e, Event::Cas { after: 0, .. }))
                .unwrap();
            assert_eq!(log[breaks + 1], Event::Invalidate(VA, 1 << 21));
        }

        #[test]
        fn partial_prepared_block_retire_splits_without_break_before_make() {
            let words = fixture(2);
            let entry = resident_block(&words, 0x009c_0000_0000);
            let prepared_block = words.get(entry) & !VALID;
            words.set(entry, prepared_block);
            let result = applied(run(
                &words,
                DescriptorOp::Retire(PageSpan::new(VA, 2 * PT_PAGE)),
                &grants(&[8]),
            ));
            assert_eq!(result.live_stores, 1);
            assert!(
                !words
                    .log
                    .borrow()
                    .iter()
                    .any(|e| matches!(e, Event::Invalidate(..))),
                "an invalid block has no translation to break"
            );
            for n in 0..512u64 {
                let d = words.get(page(8) + n * 8);
                assert_eq!(d & PA_MASK_4KIB, 0x009c_0000_0000 + n * PT_PAGE);
                let expected = if n < 2 {
                    El1PrivateLeafState::Retired
                } else {
                    El1PrivateLeafState::Prepared
                };
                assert_eq!(el1_private_leaf_state(d), expected, "page {n}");
            }
            // A complete block is edited in place without a grant.
            let words = fixture(2);
            let entry = resident_block(&words, 0x009c_0000_0000);
            let result = applied(run(
                &words,
                DescriptorOp::Retire(PageSpan::new(VA, 1 << 21)),
                &TableGrants::NONE,
            ));
            assert_eq!(result.tables_linked, 0);
            assert_eq!(
                el1_private_leaf_state(words.get(entry)),
                El1PrivateLeafState::Retired
            );
            assert_eq!(words.get(entry) & PA_MASK_2MIB, 0x009c_0000_0000);
        }

        #[test]
        fn rollback_after_publication_failure_restores_the_exact_preimage() {
            // Leaf stores: the third live store observes a concurrent writer.
            let words = fixture(3);
            let before = words.image();
            words.fail_cas_at.set(Some(2));
            assert_eq!(
                run(
                    &words,
                    prepare(4, PageSpan::new(VA, PT_PAGE), true),
                    &TableGrants::NONE
                ),
                DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
            );
            assert_eq!(words.image(), before);

            // Split: the table link fails after the block was broken.
            let words = fixture(2);
            let entry = resident_block(&words, 0x009c_0000_0000);
            let before = words.image();
            words.fail_cas_at.set(Some(1));
            let edit = GuestPermissionEdit {
                va: VA,
                len: PT_PAGE,
                readable: true,
                writable: false,
                executable: false,
            };
            let outcome = run(&words, DescriptorOp::Protect(edit), &grants(&[8]));
            assert_eq!(
                outcome,
                DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
            );
            assert!(outcome_requires_invalidation(&outcome));
            assert_eq!(words.get(entry), before[TestWords::index(entry)]);
            for (index, value) in words.image().iter().enumerate() {
                if index >= TestWords::index(page(8)) && index < TestWords::index(page(9)) {
                    continue; // the unlinked grant's contents are not state
                }
                assert_eq!(*value, before[index], "word {index}");
            }

            // A journal that cannot hold the planned stores refuses up front.
            let words = fixture(3);
            let before = words.image();
            let mut storage = [JournalEntry::default(); 2];
            let mut journal = SliceJournal::new(&mut storage);
            assert_eq!(
                execute_descriptor_op(
                    &words,
                    SubstrateGpa(ROOT),
                    prepare(4, PageSpan::EMPTY, true),
                    &TableGrants::NONE,
                    &mut journal,
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity)
            );
            assert_eq!(words.image(), before);
        }

        #[test]
        fn fork_arm_rolls_back_a_failed_split_and_arms_on_retry() {
            let words = fixture(2);
            let entry = resident_block(&words, 0x009c_0000_0000);
            let before = words.image();
            let op = DescriptorOp::Terminal {
                span: PageSpan::new(VA + 7 * PT_PAGE, PT_PAGE),
                edit: TerminalEdit::fork_arm(false, false, true, 0, 0),
            };
            // The link after break-before-make observes a concurrent writer.
            words.fail_cas_at.set(Some(1));
            assert_eq!(
                run(&words, op, &grants(&[8])),
                DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
            );
            assert_eq!(words.get(entry), before[TestWords::index(entry)]);
            let applied = applied(run(&words, op, &grants(&[8])));
            assert_eq!(applied.tables_linked, 1);
            let armed = words.get(page(8) + 7 * 8);
            assert!(el1_cow(armed));
            assert!(!terminal_descriptor_permits_el0(armed, LeafAccess::Write));
            assert!(terminal_descriptor_permits_el0(
                words.get(page(8) + 6 * 8),
                LeafAccess::Write
            ));
            // Arming an already-armed page is a no-op without a grant.
            assert_eq!(applied_stores(run(&words, op, &TableGrants::NONE)), 0);
        }

        fn applied_stores(outcome: DescriptorOutcome) -> u32 {
            applied(outcome).live_stores
        }

        #[test]
        fn stale_root_mm_and_owner_generation_cannot_mutate_the_graph() {
            let words = fixture(3);
            let before = words.image();
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(7),
                    generation: nz(1),
                },
                root: SubstrateGpa(ROOT + PT_PAGE),
                op: prepare(2, PageSpan::EMPTY, true),
                tables: TableGrants::NONE,
            };
            let mut journal = InlineJournal::new();
            let receipt = execute_descriptor_txn(&words, SubstrateGpa(ROOT), &txn, &mut journal);
            assert_eq!(
                receipt.outcome,
                DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot)
            );
            assert_eq!(words.image(), before);

            // Wrong MM: the slot never hands the submission to another MM.
            let slot = DescriptorTxnSlot::new();
            let txn = DescriptorTxn {
                root: SubstrateGpa(ROOT),
                ..txn
            };
            assert!(slot.submit(&txn));
            assert!(
                apply_submitted_descriptor_txn(&slot, 8, &words, SubstrateGpa(ROOT), &mut journal)
                    .is_none()
            );
            assert_eq!(words.image(), before);
            let receipt =
                apply_submitted_descriptor_txn(&slot, 7, &words, SubstrateGpa(ROOT), &mut journal)
                    .unwrap();
            let host_receipt = slot.take_receipt(txn.id).unwrap();
            assert_eq!(host_receipt, receipt);
            assert!(txn.verify_receipt(&host_receipt).is_ok());
            // A host whose inventory moved to a new owner generation cannot
            // consume the receipt of the older submission.
            let mut moved = txn;
            if let DescriptorOp::Prepare {
                ref mut backing, ..
            } = moved.op
            {
                backing.owner_generation = nz(99);
            }
            assert_eq!(
                moved.verify_receipt(&host_receipt),
                Err(ReceiptError::DigestMismatch)
            );
            // Publishing against a stale expected output is refused.
            let before = words.image();
            assert_eq!(
                run(
                    &words,
                    DescriptorOp::Publish {
                        span: PageSpan::new(VA, PT_PAGE),
                        expected_ipa: SubstrateGpa(IPA + 0x10_0000),
                        access: LeafAccess::Read,
                    },
                    &TableGrants::NONE
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking)
            );
            assert_eq!(words.image(), before);
        }

        #[test]
        fn host_copyout_publish_is_exact_and_permission_checked() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::EMPTY, true),
                &TableGrants::NONE,
            ));
            let publish = |va, access| DescriptorOp::Publish {
                span: PageSpan::new(va, PT_PAGE),
                expected_ipa: SubstrateGpa(IPA + (va - VA)),
                access,
            };
            let result = applied(run(
                &words,
                publish(VA + 2 * PT_PAGE, LeafAccess::Write),
                &TableGrants::NONE,
            ));
            assert_eq!(result.resident, PageSpan::new(VA + 2 * PT_PAGE, PT_PAGE));
            for n in 0..4 {
                let state = el1_private_leaf_state(words.get(leaf_pa(VA + n * PT_PAGE)));
                let expected = if n == 2 {
                    El1PrivateLeafState::Resident
                } else {
                    El1PrivateLeafState::Prepared
                };
                assert_eq!(state, expected, "page {n}");
            }
            // Already resident: no store.
            assert_eq!(
                applied(run(
                    &words,
                    publish(VA + 2 * PT_PAGE, LeafAccess::Read),
                    &TableGrants::NONE
                ))
                .live_stores,
                0
            );
            // Read-only prepared page refuses a write copyout.
            applied(run(
                &words,
                DescriptorOp::Protect(GuestPermissionEdit {
                    va: VA,
                    len: PT_PAGE,
                    readable: true,
                    writable: false,
                    executable: false,
                }),
                &TableGrants::NONE,
            ));
            assert_eq!(
                run(&words, publish(VA, LeafAccess::Write), &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied)
            );
            // A retired lease is not prepared backing.
            applied(run(
                &words,
                DescriptorOp::Retire(PageSpan::new(VA + 3 * PT_PAGE, PT_PAGE)),
                &TableGrants::NONE,
            ));
            assert_eq!(
                run(
                    &words,
                    publish(VA + 3 * PT_PAGE, LeafAccess::Read),
                    &TableGrants::NONE
                ),
                DescriptorOutcome::Refused(DescriptorRefusal::NotPrepared)
            );
        }

        #[test]
        fn alias_user_permissions_match_requested_access() {
            for writable in [false, true] {
                for executable in [false, true] {
                    let words = fixture(3);
                    applied(run(
                        &words,
                        DescriptorOp::MapAlias {
                            access: AliasAccess::User {
                                writable,
                                executable,
                            },
                            span: PageSpan::new(VA, PT_PAGE),
                            target_ipa: SubstrateGpa(IPA),
                            backing: backing(90),
                        },
                        &TableGrants::NONE,
                    ));
                    let leaf = words.get(leaf_pa(VA));
                    assert!(terminal_descriptor_permits_el0(leaf, LeafAccess::Read));
                    assert_eq!(
                        terminal_descriptor_permits_el0(leaf, LeafAccess::Write),
                        writable
                    );
                    assert_eq!(
                        terminal_descriptor_permits_el0(leaf, LeafAccess::Execute),
                        executable
                    );
                    assert_eq!(leaf & PA_MASK_4KIB, IPA);
                    assert_ne!(leaf & NON_GLOBAL, 0);
                }
            }
        }

        #[test]
        fn deferred_alias_retains_backing_without_granting_access() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::new(VA, 4 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            let destination = IPA + 0x8000;
            applied(run(
                &words,
                DescriptorOp::MapAlias {
                    access: AliasAccess::Deferred,
                    span: PageSpan::new(VA, 4 * PT_PAGE),
                    target_ipa: SubstrateGpa(destination),
                    backing: backing(90),
                },
                &TableGrants::NONE,
            ));
            for index in 0..4 {
                let leaf = words.get(leaf_pa(VA + index * PT_PAGE));
                assert_eq!(
                    leaf,
                    (destination + index * PT_PAGE)
                        | ((USER_PAGE_FLAGS & !AP_MASK & !VALID) | AP_RO | NON_GLOBAL)
                );
                assert!(!terminal_descriptor_permits_el0(leaf, LeafAccess::Read));
                assert!(!terminal_descriptor_permits_el0(leaf, LeafAccess::Write));
                assert!(!terminal_descriptor_permits_el0(leaf, LeafAccess::Execute));
            }
        }

        #[test]
        fn map_alias_replaces_outputs_without_private_tags_and_rolls_back() {
            let destination = IPA + 0x8000;
            for failure in core::iter::once(None).chain((0..8).map(Some)) {
                let words = fixture(3);
                applied(run(
                    &words,
                    prepare(4, PageSpan::new(VA, 4 * PT_PAGE), true),
                    &TableGrants::NONE,
                ));
                let before = words.image();
                words.log.borrow_mut().clear();
                words.forward_cas.set(0);
                words.fail_cas_at.set(failure);
                let result = run(
                    &words,
                    DescriptorOp::MapAlias {
                        access: AliasAccess::User {
                            writable: true,
                            executable: true,
                        },
                        span: PageSpan::new(VA, 4 * PT_PAGE),
                        target_ipa: SubstrateGpa(destination),
                        backing: backing(90),
                    },
                    &TableGrants::NONE,
                );
                if failure.is_some() {
                    assert!(
                        matches!(result, DescriptorOutcome::RolledBack(_)),
                        "{result:?}"
                    );
                    assert_eq!(words.image(), before);
                } else {
                    let receipt = applied(result);
                    assert_eq!(receipt.live_stores, 8);
                    let events = words.log.borrow();
                    for index in 0..4 {
                        let address = VA + index * PT_PAGE;
                        let pa = leaf_pa(address);
                        let cleared = events
                            .iter()
                            .position(|event| {
                                matches!(event,
                            Event::Cas { pa: at, after: 0, .. } if *at == pa)
                            })
                            .unwrap();
                        let invalidated = events
                            .iter()
                            .position(|event| *event == Event::Invalidate(address, PT_PAGE))
                            .unwrap();
                        let installed = events
                            .iter()
                            .position(|event| {
                                matches!(event,
                            Event::Cas { pa: at, before: 0, after } if *at == pa && *after != 0)
                            })
                            .unwrap();
                        assert!(cleared < invalidated && invalidated < installed);
                    }
                    for index in 0..4 {
                        assert_eq!(
                            words.get(leaf_pa(VA + index * PT_PAGE)),
                            (destination + index * PT_PAGE) | USER_PAGE_FLAGS | NON_GLOBAL
                        );
                    }
                }
            }
        }

        #[test]
        fn map_alias_builds_missing_tables_and_requires_aligned_block_outputs() {
            let empty = fixture(0);
            let created = applied(run(
                &empty,
                DescriptorOp::MapAlias {
                    access: AliasAccess::User {
                        writable: true,
                        executable: true,
                    },
                    span: PageSpan::new(VA, 4 * PT_PAGE),
                    target_ipa: SubstrateGpa(IPA),
                    backing: backing(90),
                },
                &grants(&[1, 2, 3]),
            ));
            assert_eq!(created.tables_linked, 3);
            for index in 0..4 {
                assert_eq!(
                    empty.get(leaf_pa(VA + index * PT_PAGE)) & PA_MASK_4KIB,
                    IPA + index * PT_PAGE
                );
            }
            for offset in [0, PT_PAGE] {
                let words = fixture(2);
                let block_pa = page(2) + indices(VA)[2] as u64 * 8;
                words.set(block_pa, IPA | super::super::super::USER_BLOCK_FLAGS);
                let target = IPA + 0x400000 + offset;
                let result = applied(run(
                    &words,
                    DescriptorOp::MapAlias {
                        access: AliasAccess::User {
                            writable: true,
                            executable: true,
                        },
                        span: PageSpan::new(VA, 0x200000),
                        target_ipa: SubstrateGpa(target),
                        backing: backing(90),
                    },
                    &grants(&[3]),
                ));
                if offset == 0 {
                    assert_eq!(result.tables_linked, 0);
                    assert_eq!(result.live_stores, 2);
                    assert_eq!(words.get(block_pa) & PA_MASK_2MIB, target);
                } else {
                    assert_eq!(result.tables_linked, 1);
                    for index in 0..512 {
                        assert_eq!(
                            words.get(leaf_pa(VA + index * PT_PAGE)) & PA_MASK_4KIB,
                            target + index * PT_PAGE
                        );
                    }
                }
            }
        }

        #[test]
        fn cow_repoint_commits_the_compound_under_one_journal() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::new(VA, 4 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    words.words.len() * 8,
                    VA,
                    4 * PT_PAGE,
                )
            }
            .unwrap();
            let destination = 0x009d_0000_0000;
            let op = DescriptorOp::CowRepoint {
                access: CowRepointAccess::RecordedPrivate,
                va: VA,
                len: 4 * PT_PAGE,
                old_ipa: SubstrateGpa(IPA),
                new_ipa: SubstrateGpa(destination),
                backing: backing(80),
            };
            applied(run(&words, op, &TableGrants::NONE));
            for index in 0..4 {
                let descriptor = words.get(leaf_pa(VA + index * PT_PAGE));
                assert_eq!(descriptor & PA_MASK_4KIB, destination + index * PT_PAGE);
                assert!(!el1_cow(descriptor));
            }
        }

        #[test]
        fn cow_backend_user_preserves_denied_and_invalid_neighbors() {
            let words = fixture(3);
            let attrs = [
                (USER_PAGE_FLAGS & !AP_MASK) | AP_RO | NON_GLOBAL | UXN,
                (USER_PAGE_FLAGS & !AP_MASK) | AP_RO | NON_GLOBAL | UXN,
                ((USER_PAGE_FLAGS & !AP_MASK) | AP_PRIV_RO | NON_GLOBAL | UXN) & !VALID,
                (USER_PAGE_FLAGS | NON_GLOBAL | UXN) & !VALID,
            ];
            for (index, flags) in attrs.iter().enumerate() {
                words.set(
                    leaf_pa(VA + index as u64 * PT_PAGE),
                    (IPA + index as u64 * PT_PAGE) | flags,
                );
            }
            let destination = 0x009d_0000_0000;
            applied(run(
                &words,
                DescriptorOp::CowRepoint {
                    access: CowRepointAccess::User {
                        writable_pages: 0b1001,
                    },
                    va: VA,
                    len: 4 * PT_PAGE,
                    old_ipa: SubstrateGpa(IPA),
                    new_ipa: SubstrateGpa(destination),
                    backing: backing(80),
                },
                &TableGrants::NONE,
            ));
            for (index, flags) in attrs.iter().enumerate() {
                let expected = if index == 0 {
                    (flags & !AP_MASK) | AP_RW
                } else {
                    *flags
                };
                assert_eq!(
                    words.get(leaf_pa(VA + index as u64 * PT_PAGE)),
                    (destination + index as u64 * PT_PAGE) | expected
                );
            }
        }

        #[test]
        fn cow_tagged_write_intent_is_not_overridden_by_legacy_mask() {
            let words = fixture(3);
            words.set(
                leaf_pa(VA),
                IPA | (USER_PAGE_FLAGS & !AP_MASK)
                    | AP_RO
                    | NON_GLOBAL
                    | SW_EL1_PRIVATE
                    | SW_EL1_COW
                    | SW_EL1_MAY_WRITE,
            );
            applied(run(
                &words,
                DescriptorOp::CowRepoint {
                    access: CowRepointAccess::User { writable_pages: 0 },
                    va: VA,
                    len: PT_PAGE,
                    old_ipa: SubstrateGpa(IPA),
                    new_ipa: SubstrateGpa(0x009d_0000_0000),
                    backing: backing(80),
                },
                &TableGrants::NONE,
            ));
            assert!(terminal_descriptor_permits_el0(
                words.get(leaf_pa(VA)),
                LeafAccess::Write
            ));
        }

        #[test]
        fn cow_kernel_repoint_never_grants_el0_access() {
            let words = fixture(3);
            words.set(
                leaf_pa(VA),
                IPA | super::super::super::KERNEL_PAGE_FLAGS | NON_GLOBAL | AP_PRIV_RO,
            );
            let destination = 0x009d_0000_0000;
            let op = DescriptorOp::CowRepoint {
                access: CowRepointAccess::Kernel,
                va: VA,
                len: PT_PAGE,
                old_ipa: SubstrateGpa(IPA),
                new_ipa: SubstrateGpa(destination),
                backing: backing(80),
            };
            applied(run(&words, op, &TableGrants::NONE));
            let leaf = words.get(leaf_pa(VA));
            assert_eq!(
                leaf,
                destination | super::super::super::KERNEL_PAGE_FLAGS | NON_GLOBAL
            );
            assert!(!terminal_descriptor_permits_el0(leaf, LeafAccess::Read));
            assert!(!terminal_descriptor_permits_el0(leaf, LeafAccess::Write));
            words.set(leaf_pa(VA), IPA | USER_PAGE_FLAGS | NON_GLOBAL);
            let before = words.image();
            assert_eq!(
                run(&words, op, &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied)
            );
            assert_eq!(words.image(), before);
        }

        #[test]
        fn cow_compound_preserves_readonly_prot_none_and_prepared_neighbors() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::new(VA, 3 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            for (index, readable) in [(1, true), (2, false)] {
                applied(run(
                    &words,
                    DescriptorOp::Protect(GuestPermissionEdit {
                        va: VA + index * PT_PAGE,
                        len: PT_PAGE,
                        readable,
                        writable: false,
                        executable: false,
                    }),
                    &TableGrants::NONE,
                ));
            }
            let before: Vec<_> = (0..4)
                .map(|i| words.get(leaf_pa(VA + i * PT_PAGE)))
                .collect();
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    words.words.len() * 8,
                    VA,
                    4 * PT_PAGE,
                )
            }
            .unwrap();
            let destination = 0x009d_0000_0000;
            applied(run(
                &words,
                DescriptorOp::CowRepoint {
                    access: CowRepointAccess::RecordedPrivate,
                    va: VA,
                    len: 4 * PT_PAGE,
                    old_ipa: SubstrateGpa(IPA),
                    new_ipa: SubstrateGpa(destination),
                    backing: backing(80),
                },
                &TableGrants::NONE,
            ));
            for index in 0..4 {
                let leaf = words.get(leaf_pa(VA + index * PT_PAGE));
                assert_eq!(leaf & PA_MASK_4KIB, destination + index * PT_PAGE);
                assert_eq!(
                    leaf & (VALID | AP_MASK | UXN),
                    before[index as usize] & (VALID | AP_MASK | UXN)
                );
                assert!(!el1_cow(leaf));
            }
            assert!(!terminal_descriptor_permits_el0(
                words.get(leaf_pa(VA + PT_PAGE)),
                LeafAccess::Write
            ));
            assert!(!terminal_descriptor_permits_el0(
                words.get(leaf_pa(VA + 2 * PT_PAGE)),
                LeafAccess::Read
            ));
            assert_eq!(
                el1_private_leaf_state(words.get(leaf_pa(VA + 3 * PT_PAGE))),
                El1PrivateLeafState::Prepared
            );
        }

        #[test]
        fn cow_compound_failure_restores_every_original_leaf() {
            for failed_store in 0..4 {
                let words = fixture(3);
                applied(run(
                    &words,
                    prepare(4, PageSpan::new(VA, 4 * PT_PAGE), true),
                    &TableGrants::NONE,
                ));
                unsafe {
                    arm_existing_el1_fork_pages(
                        words.words.as_ptr().cast_mut(),
                        ROOT,
                        words.words.len() * 8,
                        VA,
                        4 * PT_PAGE,
                    )
                }
                .unwrap();
                let before = words.image();
                words.forward_cas.set(0);
                words.fail_cas_at.set(Some(failed_store));
                let op = DescriptorOp::CowRepoint {
                    access: CowRepointAccess::RecordedPrivate,
                    va: VA,
                    len: 4 * PT_PAGE,
                    old_ipa: SubstrateGpa(IPA),
                    new_ipa: SubstrateGpa(0x009d_0000_0000),
                    backing: backing(80),
                };
                assert_eq!(
                    run(&words, op, &TableGrants::NONE),
                    DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
                    "store {failed_store}",
                );
                assert_eq!(words.image(), before, "store {failed_store}");
            }
        }

        #[test]
        fn cow_compound_refuses_overlapping_copy_extents() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(4, PageSpan::new(VA, 4 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    words.words.len() * 8,
                    VA,
                    4 * PT_PAGE,
                )
            }
            .unwrap();
            let before = words.image();
            for new_ipa in [IPA - PT_PAGE, IPA + PT_PAGE] {
                let op = DescriptorOp::CowRepoint {
                    access: CowRepointAccess::RecordedPrivate,
                    va: VA,
                    len: 4 * PT_PAGE,
                    old_ipa: SubstrateGpa(IPA),
                    new_ipa: SubstrateGpa(new_ipa),
                    backing: backing(80),
                };
                assert_eq!(
                    run(&words, op, &TableGrants::NONE),
                    DescriptorOutcome::Refused(DescriptorRefusal::BadRange),
                );
                assert_eq!(words.image(), before);
            }
        }

        #[test]
        fn cow_repoint_installs_the_private_copy_and_restores_write() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(2, PageSpan::new(VA, 2 * PT_PAGE), true),
                &TableGrants::NONE,
            ));
            let repoint = |old, new| DescriptorOp::CowRepoint {
                access: CowRepointAccess::RecordedPrivate,
                len: PT_PAGE,
                va: VA,
                old_ipa: SubstrateGpa(old),
                new_ipa: SubstrateGpa(new),
                backing: backing(80),
            };
            let copy = 0x009d_0000_0000;
            assert_eq!(
                run(&words, repoint(IPA, copy), &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::NotCowArmed)
            );
            let byte_len = words.words.len() * 8;
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    byte_len,
                    VA,
                    2 * PT_PAGE,
                )
            }
            .unwrap();
            assert_eq!(
                run(&words, repoint(IPA + PT_PAGE, copy), &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking)
            );
            let result = applied(run(&words, repoint(IPA, copy), &TableGrants::NONE));
            assert_eq!(result.live_stores, 1);
            let d = words.get(leaf_pa(VA));
            assert_eq!(d & PA_MASK_4KIB, copy);
            assert!(!el1_cow(d));
            assert!(terminal_descriptor_permits_el0(d, LeafAccess::Write));
            // The sibling stays shared and armed.
            assert!(el1_cow(words.get(leaf_pa(VA + PT_PAGE))));
            assert_eq!(
                words.get(leaf_pa(VA + PT_PAGE)) & PA_MASK_4KIB,
                IPA + PT_PAGE
            );
        }

        #[test]
        fn two_live_roots_with_identical_vas_edit_only_their_own_graph() {
            // Root A uses pages 0..=3; root B uses pages 4..=7 for the same VA.
            let words = fixture(3);
            let idx = indices(VA);
            words.set(page(4) + idx[0] as u64 * 8, table(5));
            words.set(page(5) + idx[1] as u64 * 8, table(6));
            words.set(page(6) + idx[2] as u64 * 8, table(7));
            let mut journal = InlineJournal::new();
            let outcome = execute_descriptor_op(
                &words,
                SubstrateGpa(page(4)),
                prepare(1, PageSpan::new(VA, PT_PAGE), true),
                &TableGrants::NONE,
                &mut journal,
            );
            applied(outcome);
            assert_eq!(words.get(leaf_pa(VA)), 0, "root A is untouched");
            let b_leaf = words.get(page(7) + idx[3] as u64 * 8);
            assert_eq!(
                el1_private_leaf_state(b_leaf),
                El1PrivateLeafState::Resident
            );
        }

        #[test]
        fn existing_leaf_wrappers_share_the_transaction_executor() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(2, PageSpan::EMPTY, true),
                &TableGrants::NONE,
            ));
            let byte_len = words.words.len() * 8;
            let ptr = words.words.as_ptr().cast_mut();
            assert_eq!(
                unsafe {
                    crate::aarch64::commit_existing_el1_prepared_page(
                        ptr,
                        ROOT,
                        byte_len,
                        VA,
                        IPA,
                        LeafAccess::Write,
                    )
                },
                Ok(crate::aarch64::GuestPreparedCommit::Committed)
            );
            // Mixed prepared/resident protection is guest-served.
            assert_eq!(
                unsafe {
                    crate::aarch64::protect_existing_el1_private_pages(
                        ptr,
                        ROOT,
                        byte_len,
                        GuestPermissionEdit {
                            va: VA,
                            len: 2 * PT_PAGE,
                            readable: true,
                            writable: false,
                            executable: false,
                        },
                    )
                },
                Ok(2)
            );
            assert_eq!(
                unsafe {
                    crate::aarch64::retire_existing_el1_private_pages(
                        ptr,
                        ROOT,
                        byte_len,
                        VA,
                        2 * PT_PAGE,
                    )
                },
                Ok(2)
            );
            assert_eq!(
                el1_private_leaf_state(words.get(leaf_pa(VA + PT_PAGE))),
                El1PrivateLeafState::Retired
            );
        }

        #[test]
        fn a_guest_cow_copy_is_exact_and_only_from_the_still_shared_frame() {
            let words = fixture(3);
            applied(run(
                &words,
                prepare(1, PageSpan::new(VA, PT_PAGE), true),
                &TableGrants::NONE,
            ));
            let byte_len = words.words.len() * 8;
            unsafe {
                arm_existing_el1_fork_pages(
                    words.words.as_ptr().cast_mut(),
                    ROOT,
                    byte_len,
                    VA,
                    PT_PAGE,
                )
            }
            .unwrap();
            let grant = CowCopyGrant {
                mm_key: nz(7),
                root: SubstrateGpa(ROOT),
                va: VA,
                old_ipa: SubstrateGpa(IPA),
                new_ipa: SubstrateGpa(0x009d_0000_0000),
                old_backing: backing(1),
                new_backing: backing(20),
            };
            let source: Vec<u8> = (0..PT_PAGE).map(|i| (i * 7 % 251) as u8).collect();
            let mut destination = vec![0xAA; PT_PAGE as usize];
            let before = words.image();
            // A stale grant (the leaf maps another frame) copies nothing.
            let stale = CowCopyGrant {
                old_ipa: SubstrateGpa(IPA + PT_PAGE),
                ..grant
            };
            assert_eq!(
                copy_granted_cow_page(&words, stale, &source, &mut destination),
                Err(CowCopyError::Refused(DescriptorRefusal::WrongBacking))
            );
            assert!(destination.iter().all(|&b| b == 0xAA));
            let copy = copy_granted_cow_page(&words, grant, &source, &mut destination).unwrap();
            assert_eq!(destination, source);
            assert_eq!(copy.bytes(), PT_PAGE);
            assert_eq!(words.image(), before, "copying stores no descriptor");
            // The copy authorizes exactly its repoint.
            let repointed = applied(run(&words, copy.repoint_op(), &TableGrants::NONE));
            assert_eq!(repointed.live_stores, 1);
            assert_eq!(words.get(leaf_pa(VA)) & PA_MASK_4KIB, 0x009d_0000_0000);
            // Once repointed, the same grant is stale.
            assert!(copy_granted_cow_page(&words, grant, &source, &mut destination).is_err());
        }

        /// L0 root (page 0) -> boot L1 (page 1) -> spare L2 (page 9) -> two
        /// spare L3 tables (pages 10, 11) for `VA` and `VA + 2 MiB`, each
        /// holding one valid untagged alias page at the start of its block.
        fn two_alias_blocks() -> TestWords {
            let words = TestWords::new();
            let idx = indices(VA);
            words.set(page(0) + idx[0] as u64 * 8, table(1));
            words.set(page(1) + idx[1] as u64 * 8, table(9));
            for (block, l3) in [(0u64, 10u64), (1, 11)] {
                words.set(page(9) + (idx[2] as u64 + block) * 8, table(l3));
                words.set(
                    page(l3),
                    (IPA + block * PT_PAGE) | USER_PAGE_FLAGS | NON_GLOBAL,
                );
            }
            words
        }

        fn unmap_reclaiming(va: u64, len: u64, budget: u8) -> DescriptorOp {
            let mut edit = TerminalEdit::unmap_reclaiming(true, 0, 0);
            edit.reclaim_budget = budget;
            DescriptorOp::Terminal {
                span: PageSpan::new(va, len),
                edit,
            }
        }

        #[test]
        fn reclaiming_unmap_unlinks_emptied_tables_with_break_before_make() {
            const TWO_MIB: u64 = 1 << 21;
            let words = two_alias_blocks();
            let op = unmap_reclaiming(VA, 2 * TWO_MIB, MAX_RECLAIMED_TABLES as u8);
            let plan = plan_descriptor_op(&words, SubstrateGpa(ROOT), op).unwrap();
            assert_eq!(plan.reclaimed_tables, 3, "two L3 tables and their L2");
            assert_eq!(plan.table_grants, 0);
            let result = applied(run(&words, op, &TableGrants::NONE));
            assert_eq!(result.reclaimed.as_slice(), &[page(10), page(11), page(9)]);
            assert_eq!(result.live_stores as usize, plan.live_stores);
            let idx = indices(VA);
            assert_eq!(
                words.get(page(1) + idx[1] as u64 * 8),
                0,
                "L1 entry unlinked"
            );
            // Each unlink is broken, published, then invalidated over the
            // whole span the entry covered, before anything later.
            let log = words.log.borrow().clone();
            let unlink = |entry: u64, before: u64, span_va: u64, span: u64| {
                let at = log
                    .iter()
                    .position(|e| {
                        *e == Event::Cas {
                            pa: entry,
                            before,
                            after: 0,
                        }
                    })
                    .expect("unlink store");
                assert_eq!(
                    &log[at + 1..at + 3],
                    &[Event::Barrier, Event::Invalidate(span_va, span)]
                );
            };
            unlink(page(9) + idx[2] as u64 * 8, table(10), VA, TWO_MIB);
            unlink(
                page(9) + (idx[2] as u64 + 1) * 8,
                table(11),
                VA + TWO_MIB,
                TWO_MIB,
            );
            unlink(
                page(1) + idx[1] as u64 * 8,
                table(9),
                VA & !((1 << 30) - 1),
                1 << 30,
            );

            // The boot L1 is never reclaimed, and a live neighbour keeps its
            // table: only the retired leaf changes.
            let words = two_alias_blocks();
            let result = applied(run(
                &words,
                unmap_reclaiming(VA + TWO_MIB, PT_PAGE, 4),
                &TableGrants::NONE,
            ));
            assert_eq!(result.reclaimed.as_slice(), &[page(11)]);
            assert_eq!(words.get(page(9) + idx[2] as u64 * 8), table(10));

            // Without a budget the same retirement reclaims nothing.
            let words = two_alias_blocks();
            let result = applied(run(
                &words,
                unmap_reclaiming(VA, 2 * TWO_MIB, 0),
                &TableGrants::NONE,
            ));
            assert!(result.reclaimed.is_empty());
            assert_eq!(words.get(page(1) + idx[1] as u64 * 8), table(9));
        }

        #[test]
        fn reclaim_beyond_the_budget_is_refused_before_any_store() {
            const TWO_MIB: u64 = 1 << 21;
            let words = two_alias_blocks();
            let before = words.image();
            let op = unmap_reclaiming(VA, 2 * TWO_MIB, 2);
            assert_eq!(
                plan_descriptor_op(&words, SubstrateGpa(ROOT), op),
                Err(DescriptorRefusal::ReclaimCapacity)
            );
            assert_eq!(
                run(&words, op, &TableGrants::NONE),
                DescriptorOutcome::Refused(DescriptorRefusal::ReclaimCapacity)
            );
            assert_eq!(words.image(), before);
            // A budget over the receipt bound, or reclaim after any rule but
            // plain retirement, is not an encodable edit.
            let mut edit = TerminalEdit::unmap_reclaiming(true, 0, 0);
            edit.reclaim_budget = MAX_RECLAIMED_TABLES as u8 + 1;
            let over = DescriptorOp::Terminal {
                span: PageSpan::new(VA, PT_PAGE),
                edit,
            };
            edit.reclaim_budget = 1;
            edit.rule = crate::aarch64::TerminalRule::pt(crate::aarch64::PtOp::Invalidate);
            let invalidate = DescriptorOp::Terminal {
                span: PageSpan::new(VA, PT_PAGE),
                edit,
            };
            for op in [over, invalidate] {
                assert_eq!(
                    run(&words, op, &TableGrants::NONE),
                    DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding)
                );
            }
            // Grants of a reclaiming op must be primary spare pages.
            assert_eq!(
                run(&words, unmap_reclaiming(VA, PT_PAGE, 1), &grants(&[2])),
                DescriptorOutcome::Refused(DescriptorRefusal::BadTableGrant)
            );
            assert_eq!(words.image(), before);
        }

        /// A contended store at any point of a reclaiming unmap, including
        /// between two unlinks and at the final L2 unlink, restores every
        /// retired leaf and every unlinked table link.
        #[test]
        fn contended_reclaim_restores_every_link() {
            const TWO_MIB: u64 = 1 << 21;
            let op = unmap_reclaiming(VA, 2 * TWO_MIB, MAX_RECLAIMED_TABLES as u8);
            let plan = plan_descriptor_op(&two_alias_blocks(), SubstrateGpa(ROOT), op).unwrap();
            assert_eq!(plan.live_stores, 5, "two retires and three unlinks");
            for fail_at in 0..plan.live_stores {
                let words = two_alias_blocks();
                let before = words.image();
                words.fail_cas_at.set(Some(fail_at));
                let outcome = run(&words, op, &TableGrants::NONE);
                assert_eq!(
                    outcome,
                    DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
                    "fail at {fail_at}"
                );
                assert!(outcome_requires_invalidation(&outcome));
                assert_eq!(words.image(), before, "fail at {fail_at}");
            }
        }

        #[test]
        fn receipts_name_only_distinct_spare_tables_within_the_budget() {
            const TWO_MIB: u64 = 1 << 21;
            let words = two_alias_blocks();
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(7),
                    generation: nz(1),
                },
                root: SubstrateGpa(ROOT),
                op: unmap_reclaiming(VA, 2 * TWO_MIB, 3),
                tables: grants(&[12]),
            };
            let mut journal = InlineJournal::new();
            let receipt = execute_descriptor_txn(&words, SubstrateGpa(ROOT), &txn, &mut journal);
            let verified = txn.verify_receipt(&receipt).expect("authentic");
            assert_eq!(verified.reclaimed_tables(), &[page(10), page(11), page(9)]);
            assert_eq!(verified.unused_table_grants(), &[page(12)]);

            let DescriptorOutcome::Applied(genuine) = receipt.outcome else {
                panic!("{receipt:?}");
            };
            let forged = |pages: &[u64]| DescriptorReceipt {
                outcome: DescriptorOutcome::Applied(DescriptorApplied {
                    reclaimed: ReclaimedTables::from_pages(pages).unwrap(),
                    ..genuine
                }),
                ..receipt
            };
            for pages in [
                // The root and boot tables are never freed.
                &[ROOT][..],
                &[page(1)],
                // Outside the arena below the root, and unaligned.
                &[ROOT - PT_PAGE],
                &[page(10) + 8],
                // A duplicate would free one page twice.
                &[page(10), page(10)],
                // More than the budget.
                &[page(10), page(11), page(9), page(13)],
                // An unused grant already returns as unused.
                &[page(12)],
            ] {
                assert_eq!(
                    txn.verify_receipt(&forged(pages)),
                    Err(ReceiptError::InconsistentReceipt),
                    "{pages:x?}"
                );
            }
            // Operations without a reclaim budget return no tables.
            let prepare = prepare_txn_at(ROOT);
            assert!(prepare.verify_receipt(&applied_receipt(&prepare)).is_ok());
            let mut with_reclaim = applied_receipt(&prepare);
            if let DescriptorOutcome::Applied(ref mut applied) = with_reclaim.outcome {
                applied.reclaimed = ReclaimedTables::from_pages(&[page(10)]).unwrap();
            }
            assert_eq!(
                prepare.verify_receipt(&with_reclaim),
                Err(ReceiptError::InconsistentReceipt)
            );
        }

        fn prepare_txn_at(root: u64) -> DescriptorTxn {
            DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(7),
                    generation: nz(2),
                },
                root: SubstrateGpa(root),
                op: prepare(4, PageSpan::new(VA, PT_PAGE), true),
                tables: TableGrants::NONE,
            }
        }

        fn applied_receipt(txn: &DescriptorTxn) -> DescriptorReceipt {
            DescriptorReceipt {
                id: txn.id,
                digest: txn.digest(),
                outcome: DescriptorOutcome::Applied(DescriptorApplied {
                    pages: 4,
                    resident: PageSpan::new(VA, PT_PAGE),
                    tables_linked: 0,
                    reclaimed: ReclaimedTables::NONE,
                    live_stores: 1,
                    flush_required: true,
                }),
            }
        }

        #[test]
        fn reclaimed_tables_cross_the_slot_and_an_oversized_list_is_indeterminate() {
            const TWO_MIB: u64 = 1 << 21;
            let words = two_alias_blocks();
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(7),
                    generation: nz(3),
                },
                root: SubstrateGpa(ROOT),
                op: unmap_reclaiming(VA, 2 * TWO_MIB, 3),
                tables: TableGrants::NONE,
            };
            let slot = DescriptorTxnSlot::new();
            assert!(slot.submit(&txn));
            let mut journal = InlineJournal::new();
            let published =
                apply_submitted_descriptor_txn(&slot, 7, &words, SubstrateGpa(ROOT), &mut journal)
                    .unwrap();
            let taken = slot.take_receipt(txn.id).unwrap();
            assert_eq!(taken, published);
            assert_eq!(
                txn.verify_receipt(&taken).unwrap().reclaimed_tables(),
                &[page(10), page(11), page(9)]
            );

            // A receipt whose list length exceeds the bound does not decode
            // as applied: which tables EL1 unlinked is unknown.
            assert!(slot.submit(&txn));
            let claimed = slot.claim_for_mm(7).unwrap();
            let _ = claimed.complete(published.outcome);
            slot.receipt_reclaimed_len
                .store(MAX_RECLAIMED_TABLES as u64 + 1, Ordering::Relaxed);
            assert_eq!(
                slot.take_receipt(txn.id).unwrap().outcome,
                DescriptorOutcome::Indeterminate(DescriptorRefusal::BadEncoding)
            );
        }
    }
}

#[cfg(test)]
mod carrick_owned_window_tests {
    use super::copy_window::{COW_COPY_WINDOW_BASE as WINDOW, COW_COPY_WINDOW_LEN};
    use super::*;

    fn backing() -> BackingIdentity {
        let one = NonZeroU64::MIN;
        BackingIdentity {
            frame_id: one,
            mapping_id: one,
            owner_generation: one,
            inventory_revision: one,
        }
    }

    fn ops(span: PageSpan) -> [DescriptorOp; 8] {
        let ipa = SubstrateGpa(0x40_0000_0000);
        [
            DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: span.va,
                    ipa: ipa.raw(),
                    len: span.len,
                    writable: true,
                    executable: false,
                },
                resident: span,
                backing: backing(),
            },
            DescriptorOp::Publish {
                span,
                expected_ipa: ipa,
                access: LeafAccess::Read,
            },
            DescriptorOp::Protect(GuestPermissionEdit {
                va: span.va,
                len: span.len,
                readable: true,
                writable: false,
                executable: false,
            }),
            DescriptorOp::Retire(span),
            DescriptorOp::CowRepoint {
                access: CowRepointAccess::Kernel,
                va: span.va,
                len: span.len,
                old_ipa: ipa,
                new_ipa: SubstrateGpa(ipa.raw() + 0x10_0000),
                backing: backing(),
            },
            DescriptorOp::MapAlias {
                access: AliasAccess::User {
                    writable: true,
                    executable: false,
                },
                span,
                target_ipa: ipa,
                backing: backing(),
            },
            DescriptorOp::Terminal {
                span,
                edit: TerminalEdit::fork_arm(true, false, true, 0, 0),
            },
            DescriptorOp::Terminal {
                span,
                edit: TerminalEdit::unmap_reclaiming(true, 0, 0),
            },
        ]
    }

    /// The copy window is Carrick-owned: no guest operation may name it,
    /// whatever the op, so a kernel-range fork arm or alias can never turn
    /// an idle copy slot into a mapping of the IPA its VA names.
    #[test]
    fn every_guest_op_naming_the_copy_window_is_refused() {
        for span in [
            PageSpan::new(WINDOW, COW_COPY_WINDOW_LEN),
            PageSpan::new(WINDOW + PT_PAGE, PT_PAGE),
            PageSpan::new(WINDOW - PT_PAGE, 2 * PT_PAGE),
            PageSpan::new(
                WINDOW - 4 * PT_PAGE,
                4 * PT_PAGE + COW_COPY_WINDOW_LEN + PT_PAGE,
            ),
        ] {
            for op in ops(span) {
                assert_eq!(
                    validate_op(&op),
                    Err(DescriptorRefusal::CarrickOwnedWindow),
                    "{op:?}"
                );
            }
        }
        for span in [
            PageSpan::new(WINDOW - 4 * PT_PAGE, 4 * PT_PAGE),
            PageSpan::new(WINDOW + COW_COPY_WINDOW_LEN, 4 * PT_PAGE),
        ] {
            for op in ops(span) {
                assert_ne!(
                    validate_op(&op),
                    Err(DescriptorRefusal::CarrickOwnedWindow),
                    "{op:?}"
                );
            }
        }
        assert_eq!(
            DescriptorRefusal::from_code(DescriptorRefusal::CarrickOwnedWindow as u32),
            Some(DescriptorRefusal::CarrickOwnedWindow)
        );
    }
}
