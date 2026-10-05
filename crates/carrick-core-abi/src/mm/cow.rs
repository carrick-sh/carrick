//! One original exact COW completion record, shared by ISA adapters.
use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
/// Bytes of one grant: the host COW compound.
pub const COW_GRANT_SIZE: u64 = 16 * 1024;
const PAGE: u64 = 4096;

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
    }
}

/// Why EL1 left a COW write fault to the host. Indexes
/// the grant venue's decline counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum CowDecline {
    /// No valid L3 page: nothing mapped, an invalid leaf, or a block terminal.
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
    /// No grant for this MM was ready.
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
    fn claim(&self, mm_key: u64) -> Option<CowGrant>;
    fn abandon(&self, grant: &CowGrant) -> bool;
    fn complete(&self, completion: &CowGrantCompletion) -> bool;
    fn note_declined(&self, reason: CowDecline);
}

/// Borrowing a service alias lease prevents scheduler-slot reuse until restore.
/// The adapter owns the exclusive lease and its execution-lane affinity.
pub trait ServiceCopyWindowLease {
    fn base(&self) -> u64;
}

