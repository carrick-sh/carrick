//! One original exact COW completion record, shared by ISA adapters.
use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
/// Bytes of one grant: the host COW compound.
pub const COW_GRANT_SIZE: u64 = 16 * 1024;
const PAGE: u64 = 4096;

/// Most split tables one grant carries: the first write into an armed
/// L1 block links one L2 and one L3 table.
pub const COW_GRANT_MAX_SPLIT_TABLES: usize = 2;

/// Unlinked stage-1 table pages the host (the only table allocator) reserved
/// with one grant, so the repoint of an armed block can split it (#2276).
/// The repoint links a prefix, in walk order; the host takes back the rest
/// when it settles the completion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CowSplitTables {
    pages: [u64; COW_GRANT_MAX_SPLIT_TABLES],
    len: u8,
}

impl CowSplitTables {
    pub const NONE: Self = Self {
        pages: [0; COW_GRANT_MAX_SPLIT_TABLES],
        len: 0,
    };

    /// Page-aligned, nonzero, distinct pages; at most
    /// [`COW_GRANT_MAX_SPLIT_TABLES`].
    #[must_use]
    pub fn new(pages: &[u64]) -> Option<Self> {
        if pages.len() > COW_GRANT_MAX_SPLIT_TABLES
            || pages
                .iter()
                .any(|&page| page == 0 || !page.is_multiple_of(PAGE))
            || (pages.len() == 2 && pages[0] == pages[1])
        {
            return None;
        }
        let mut tables = Self::NONE;
        tables.pages[..pages.len()].copy_from_slice(pages);
        tables.len = pages.len() as u8;
        Some(tables)
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

    /// The pages a repoint that linked `linked` of them left unlinked.
    #[must_use]
    pub fn unused_after(&self, linked: u8) -> &[u64] {
        &self.as_slice()[usize::from(linked).min(self.len())..]
    }
}

/// One ready grant as EL1 claimed it, or as the host published it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowGrant {
    pub slot: usize,
    /// The record's state word at publication, without the state bits.
    pub epoch: u64,
    pub mm_key: u64,
    /// 16 KiB-aligned IPA of the replacement compound.
    pub physical_ipa: u64,
    pub backing: BackingIdentity,
    /// Tables for splitting an armed block, or none.
    pub tables: CowSplitTables,
}

impl CowGrant {
    /// Whether this grant serves a repoint that must link `split_tables`
    /// tables. A page repoint takes only a table-less grant, so a block's
    /// tables are never spent on a page.
    #[must_use]
    pub fn serves(&self, split_tables: usize) -> bool {
        if split_tables == 0 {
            self.tables.is_empty()
        } else {
            self.tables.len() >= split_tables
        }
    }
}

/// Which owner operation licensed the physical replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum CowGrantPurpose {
    UserWrite = 0,
    RetiredBacking = 1,
    /// Malformed wire receipt; never accepted for publication or settlement.
    Invalid = 2,
}

/// One guest COW EL1 completed with a grant: `[span_va, span_va + span_len)`
/// moved from `old_ipa` (the span's first page) to `new_ipa`, both inside
/// their 16 KiB compounds at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowGrantCompletion {
    pub purpose: CowGrantPurpose,
    pub grant: CowGrant,
    pub span_va: u64,
    pub span_len: u64,
    pub old_ipa: u64,
    pub new_ipa: u64,
    /// The prefix of `grant.tables` the repoint linked into the live graph.
    pub tables_linked: u8,
}

impl CowGrantCompletion {
    /// Whether the completion describes a repoint inside one grant compound
    /// from one old compound at the same offset, page-granular and nonempty.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let offset = self.new_ipa.wrapping_sub(self.grant.physical_ipa);
        self.purpose != CowGrantPurpose::Invalid
            && self.span_len != 0
            && self.span_len.is_multiple_of(PAGE)
            && self.span_va.is_multiple_of(PAGE)
            && self.old_ipa.is_multiple_of(PAGE)
            && self.new_ipa >= self.grant.physical_ipa
            && offset
                .checked_add(self.span_len)
                .is_some_and(|end| end <= COW_GRANT_SIZE)
            && (self.old_ipa & (COW_GRANT_SIZE - 1)) == offset
            && self.span_va.checked_add(self.span_len).is_some()
            && usize::from(self.tables_linked) <= self.grant.tables.len()
    }

    /// The grant's tables the repoint did not link: the host's to take back.
    #[must_use]
    pub fn unused_tables(&self) -> &[u64] {
        self.grant.tables.unused_after(self.tables_linked)
    }
}

/// Why EL1 left a COW write fault to the host. Indexes
/// the grant venue's decline counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum CowDecline {
    /// No valid terminal: nothing mapped, or an invalid leaf or block.
    Unmapped = 0,
    /// A valid page that is not COW-armed (untagged backend leaf, or a
    /// private page `mprotect`ed read-only).
    NotCowArmed = 1,
    /// COW-armed but not EL1-private state.
    NotEl1Private = 2,
    /// COW-armed and private but Linux never granted write (a real
    /// protection fault).
    NoWriteIntent = 3,
    /// The table walk left the reachable primary arena.
    Unreachable = 4,
    /// No ready grant of this MM serves the run (none at all, or none
    /// carrying the tables an armed block's split needs).
    PoolEmpty = 5,
    /// Another EL1 editor held the MM, or a host pause closed its gate.
    EditorBusy = 6,
    /// The copy or the repoint refused (stale leaf, window absent, split
    /// needed); the grant went back to the pool untouched semantically.
    Refused = 7,
    /// An EL0-executable page: its fresh frame's instruction cache is the
    /// host's to make coherent, so the host resolves the COW.
    Executable = 8,
}

/// Number of [`CowDecline`] reasons.
pub const COW_DECLINE_REASONS: usize = 9;

/// Borrowed access to the existing exact-identity COW pool. No pool state or
/// custody is owned by this interface; the adapter retains the original owner.
pub trait CowGrantVenue {
    /// A ready grant of `mm_key` that [`CowGrant::serves`] `split_tables`.
    fn claim(&self, mm_key: u64, split_tables: usize) -> Option<CowGrant>;
    fn abandon(&self, grant: &CowGrant) -> bool;
    fn complete(&self, completion: &CowGrantCompletion) -> bool;
    fn note_declined(&self, reason: CowDecline);
}

/// Borrowing a service alias lease prevents scheduler-slot reuse until restore.
/// The adapter owns the exclusive lease and its execution-lane affinity.
pub trait ServiceCopyWindowLease {
    fn base(&self) -> u64;
}

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn cow_grant() {
        assert_eq!((size_of::<CowGrant>(), align_of::<CowGrant>()), (88, 8));
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |CowGrant {
                     slot: _,
                     epoch: _,
                     mm_key: _,
                     physical_ipa: _,
                     backing: _,
                     tables: _,
                 }: CowGrant| {};
        field!(CowGrant, slot, usize, 32, 8, 8);
        field!(CowGrant, epoch, u64, 40, 8, 8);
        field!(CowGrant, mm_key, u64, 48, 8, 8);
        field!(CowGrant, physical_ipa, u64, 56, 8, 8);
        field!(CowGrant, backing, BackingIdentity, 0, 32, 8);
        field!(CowGrant, tables, CowSplitTables, 64, 24, 8);
    }

    #[test]
    fn cow_grant_completion() {
        assert_eq!(
            (
                size_of::<CowGrantCompletion>(),
                align_of::<CowGrantCompletion>()
            ),
            (136, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |CowGrantCompletion {
                     purpose: _,
                     grant: _,
                     span_va: _,
                     span_len: _,
                     old_ipa: _,
                     new_ipa: _,
                     tables_linked: _,
                 }: CowGrantCompletion| {};
        field!(CowGrantCompletion, purpose, CowGrantPurpose, 0, 8, 8);
        field!(CowGrantCompletion, grant, CowGrant, 8, 88, 8);
        field!(CowGrantCompletion, span_va, u64, 96, 8, 8);
        field!(CowGrantCompletion, span_len, u64, 104, 8, 8);
        field!(CowGrantCompletion, old_ipa, u64, 112, 8, 8);
        field!(CowGrantCompletion, new_ipa, u64, 120, 8, 8);
        field!(CowGrantCompletion, tables_linked, u8, 128, 1, 1);
    }
}
