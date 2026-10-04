//! Runtime editor for the EL1 stage-1 identity page tables.
//!
//! At boot `memory::stage1_identity_page_tables` builds a coarse identity map
//! (1 GiB / 2 MiB blocks, with the first 2 MiB fine-grained to 4 KiB pages for
//! the null guard). To give guest `mprotect`/`PROT_NONE`/`munmap` real,
//! guest-visible semantics we must edit individual page descriptors at runtime:
//! split a covering block down to 4 KiB granularity, then flip validity / AP /
//! UXN on just the target pages. This module does that purely over the bytes of
//! the page-table region; HVF observes nothing until the caller copies the
//! edited bytes back to the region's host backing and runs the EL1 TLBI
//! maintenance trampoline (see `trap.rs`).
//!
//! 4 KiB translation granule, 40-bit IPA, AArch64 long-descriptor format.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub mod descriptor_txn;

/// Why the host could not build a guest descriptor transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestTxnPrepareError {
    /// The image is on the host-owned lane; edit it directly.
    NotGuestOwned,
    /// The image has no live primary arena to plan against.
    NotLive,
    /// EL1 would refuse the operation; nothing was reserved or submitted.
    Refused(descriptor_txn::DescriptorRefusal),
    /// Table grants could not be reserved.
    Manager(PageTableError),
}

/// Why a guest descriptor receipt did not settle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestTxnSettleError {
    Receipt(descriptor_txn::ReceiptError),
    Manager(PageTableError),
}

/// Which venue may store to an image's live, hardware-visible descriptor
/// words. `Guest` selects the lane on which guest EL1 is the only live
/// writer: host edits may stage and validate, but every store to live
/// backing is refused with [`PageTableError::GuestOwnsLiveDescriptors`] and
/// must instead be submitted as a [`descriptor_txn::DescriptorTxn`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LiveDescriptorOwner {
    #[default]
    Host,
    Guest,
}

/// Why a guest descriptor lane selection was refused (the MM stays on the
/// host-owned lane).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestLaneRefusal {
    /// The build's writer census does not admit the lane.
    Census,
    /// No live host resolver is bound, so EL1 and the host would not edit
    /// and read the same descriptors.
    NoLiveResolver,
    /// Host edits are staged but not synced to hardware.
    UnsyncedEdits,
    /// The operator hatch `CARRICK_EL1_DESCRIPTOR_LANE=0` keeps every MM on
    /// the host-owned lane.
    OperatorHatch,
}

/// Narrow substrate guest-physical address type for stage-1 table arena boundaries.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SubstrateGpa(pub u64);

impl SubstrateGpa {
    #[inline]
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl From<u64> for SubstrateGpa {
    #[inline]
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<SubstrateGpa> for u64 {
    #[inline]
    fn from(gpa: SubstrateGpa) -> Self {
        gpa.0
    }
}

/// Layout constraints and reserved memory bounds required for AArch64 page-table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTableLayoutConfig {
    /// Representative user VA used to detect whether initial descriptors carry nG.
    pub user_leaf_check_va: u64,
    /// Capacity in bytes for newly attached extension arenas.
    pub extension_arena_capacity: usize,
    /// Start of excluded / forbidden IPA range (e.g. GIC window).
    pub excluded_ipa_start: u64,
    /// Length in bytes of excluded / forbidden IPA range.
    pub excluded_ipa_len: u64,
}

impl PageTableLayoutConfig {
    #[must_use]
    pub const fn new(
        user_leaf_check_va: u64,
        extension_arena_capacity: usize,
        excluded_ipa_start: u64,
        excluded_ipa_len: u64,
    ) -> Self {
        Self {
            user_leaf_check_va,
            extension_arena_capacity,
            excluded_ipa_start,
            excluded_ipa_len,
        }
    }

    #[inline]
    #[must_use]
    pub const fn ipa_overlaps_excluded(&self, ipa: u64, len: u64) -> bool {
        if self.excluded_ipa_len == 0 || len == 0 {
            return false;
        }
        let Some(a_end) = ipa.checked_add(len) else {
            return true;
        };
        let Some(b_end) = self.excluded_ipa_start.checked_add(self.excluded_ipa_len) else {
            return true;
        };
        !(a_end <= self.excluded_ipa_start || b_end <= ipa)
    }
}

// Leaf attribute layout (must match `memory::stage1_identity_page_tables`).
const VALID: u64 = 1 << 0;
const TYPE_BITS: u64 = 0b11;
const TYPE_TABLE_OR_PAGE: u64 = 0b11; // L0..L2 table descriptor, or L3 page
const TYPE_BLOCK: u64 = 0b01; // L1/L2 block descriptor
const AP_MASK: u64 = 0b11 << 6; // AP[2:1]
const AP_RW: u64 = 0b01 << 6; // RW at EL0+EL1
const AP_RO: u64 = 0b11 << 6; // RO at EL0+EL1
// nG (not Global), bit 11. A forked HVPatch mm has its own stage-1 graph and
// ASID, so every private same-VA translation must set this bit. Otherwise the
// architecture is permitted to reuse one mm's global TLB entry in another mm
// regardless of ASID, defeating permission-fault COW isolation.
const NON_GLOBAL: u64 = 1 << 11;
// UXN (Unprivileged eXecute Never), bit 54: when set, EL0 instruction fetch
// from the page faults (instruction abort → SIGSEGV). USER_*_FLAGS leave it
// CLEAR (executable) because the boot image identity-maps code; guest `mmap`/
// `mprotect` set it per `PROT_EXEC` so a data page is non-executable (W^X / NX),
// matching Linux. PXN (bit 53, already in USER_*_FLAGS) keeps EL1 from fetching.
const UXN: u64 = 1 << 54;

// EL1 leaf layout (software bits 58:55, ignored by AArch64 hardware):
// 55: invalid = retired lease; valid private = fork COW.
// 56: private-anonymous grant authority, valid OR invalid. An invalid private
//     leaf with a retained output and bit 55 clear is prepared/owned, including
//     untouched bulk grants and host PROT_NONE leaves. No second prepared bit.
// 57: write ceiling, or current Linux write intent while valid COW is armed.
// 58: execute ceiling. These two bits have meaning only with bit 56 set.
// AP on a prepared leaf records host-buffer permission even while invalid;
// AP_PRIV_RO denies a host-forwarded PROT_NONE access. Retired leaves retain
// their output only for lease accounting, never access or permission authority.
const SW_RETIRED: u64 = 1 << 55;
/// Bit 55 is retirement only on invalid leaves. On valid EL1-private leaves
/// it marks fork COW, separating hardware write restriction from mprotect.
const SW_EL1_COW: u64 = SW_RETIRED;

fn el1_cow(descriptor: u64) -> bool {
    descriptor & (VALID | SW_EL1_PRIVATE | SW_EL1_COW) == (VALID | SW_EL1_PRIVATE | SW_EL1_COW)
}

/// A valid EL1-private leaf whose bit 55 is a fork COW arm, rather than the
/// retirement marker that bit represents on an invalid leaf.
pub fn terminal_descriptor_is_fork_cow(descriptor: u64) -> bool {
    el1_cow(descriptor)
}

/// An invalid terminal whose retained output belongs to a retired lease.
/// This applies to both EL1-private grants and older untagged host aliases.
pub fn terminal_descriptor_is_retired(descriptor: u64) -> bool {
    descriptor & VALID == 0 && descriptor & SW_RETIRED != 0
}

fn arm_private_cow(descriptor: u64) -> u64 {
    if descriptor & (VALID | SW_EL1_PRIVATE) != (VALID | SW_EL1_PRIVATE) || el1_cow(descriptor) {
        return descriptor;
    }
    // A previous EL1 mprotect may have kept the ceiling while revoking
    // current write access. Capture actual permission before lowering AP.
    (descriptor & !SW_EL1_MAY_WRITE)
        | SW_EL1_COW
        | if terminal_descriptor_permits_el0(descriptor, LeafAccess::Write) {
            SW_EL1_MAY_WRITE
        } else {
            0
        }
}
const SW_EL1_PRIVATE: u64 = 1 << 56;
/// EL1 write ceiling; on a COW-marked leaf, current Linux write permission.
const SW_EL1_MAY_WRITE: u64 = 1 << 57;
/// EL1 execute ceiling.
const SW_EL1_MAY_EXEC: u64 = 1 << 58;

/// The only EL1-private terminal states encoded by the software bits and
/// descriptor validity. This is the authority gate for prepared backing,
/// retirement, and host-buffer access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum El1PrivateLeafState {
    Unowned,
    Prepared,
    Resident,
    Retired,
    Malformed,
}

pub fn el1_private_leaf_state(descriptor: u64) -> El1PrivateLeafState {
    if descriptor & SW_EL1_PRIVATE == 0 {
        return El1PrivateLeafState::Unowned;
    }
    if descriptor & VALID != 0 {
        return El1PrivateLeafState::Resident;
    }
    if descriptor & SW_RETIRED != 0 {
        return El1PrivateLeafState::Retired;
    }
    if descriptor & PA_MASK_4KIB != 0 {
        El1PrivateLeafState::Prepared
    } else {
        El1PrivateLeafState::Malformed
    }
}

// PA field masks per level (identical to memory.rs).
const PA_MASK_1GIB: u64 = 0x0000_FFFF_C000_0000;
const PA_MASK_2MIB: u64 = 0x0000_FFFF_FFE0_0000;
const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;

/// Return the descriptor that terminates a serialized AArch64 stage-1 walk.
///
/// A live mapping can terminate at an L1/L2 block; indexing `walk[3]` is only
/// correct after an L3 split. Structural receipts use this helper so a coarse
/// live block is not misreported as an invalid page merely because the unused
/// later walk slots are zero.
pub fn terminal_descriptor(walk: [u64; 4]) -> u64 {
    terminal_entry(walk).1
}

/// The level (0..=3) at which a serialized AArch64 stage-1 walk terminates,
/// with the terminating descriptor: the first invalid descriptor, an L1/L2
/// block, or the L3 page. Post-mortem records use the level to say WHICH
/// table stopped the walk, which [`terminal_descriptor`] alone cannot.
pub fn terminal_entry(walk: [u64; 4]) -> (usize, u64) {
    for (level, descriptor) in walk.into_iter().enumerate() {
        if descriptor & VALID == 0 || level == 3 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            return (level, descriptor);
        }
    }
    (3, 0)
}

/// Whether `descriptor` is a valid (present) stage-1 descriptor.
pub const fn descriptor_is_valid(descriptor: u64) -> bool {
    descriptor & VALID != 0
}
const PA_MASK_TABLE: u64 = 0x0000_FFFF_FFFF_F000; // next-level table PA (bits 47:12)
// AF (Access Flag), bit 10. Carrick never uses hardware AF management, so a
// leaf with AF clear takes an access-flag fault on every touch.
const ACCESS_FLAG: u64 = 1 << 10;
// AP[1] (bit 6): EL0 may access the page at all; AP[2] (bit 7): read-only.
const AP_EL0_ACCESS: u64 = 1 << 6;
const AP_READ_ONLY: u64 = 1 << 7;

/// The direction of one EL0 access, as decoded from the fault syndrome.
/// The discriminants are the wire encoding of the
/// `hvpatch__stale__stage1__retry` probe's access argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LeafAccess {
    Read = 0,
    Write = 1,
    Execute = 2,
}

/// What a stage-1 data or instruction abort's fault status code (`DFSC` /
/// `IFSC`, ESR bits `[5:0]`) says the faulting walk found. The discriminants
/// are the wire encoding of the `hvpatch__stale__stage1__fault` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Stage1FaultKind {
    /// Translation fault (0b0001LL): the walk met an invalid descriptor.
    /// No TLB or walk cache holds a translation that faults this way.
    Translation = 0,
    /// Access flag fault (0b0010LL).
    AccessFlag = 1,
    /// Permission fault (0b0011LL): a valid translation, possibly a cached
    /// one, denied the access.
    Permission = 2,
}

impl Stage1FaultKind {
    /// Decode a stage-1 fault status code; `None` for anything else.
    pub const fn from_fault_status(status: u64) -> Option<Self> {
        match status & 0x3c {
            0x04 => Some(Self::Translation),
            0x08 => Some(Self::AccessFlag),
            0x0c => Some(Self::Permission),
            _ => None,
        }
    }

    /// Whether retrying a stale fault of this kind (the live leaf already
    /// permits the access) needs this MM's TLB entries invalidated first,
    /// given the consecutive stale faults at the same address so far
    /// (`consecutive >= 1`).
    ///
    /// A translation fault means the walk met an invalid descriptor, and no
    /// TLB or walk cache holds a translation that faults: the leaf became
    /// valid after the walk (a sibling's commit raced the fault), so the
    /// first retry needs no invalidation. Only a walk through a stale cached
    /// table pointer would fault again at the same address; the second
    /// consecutive stale fault there invalidates. A permission or
    /// access-flag fault came from a valid translation that may be cached,
    /// so it always invalidates.
    pub const fn stale_retry_needs_invalidation(self, consecutive: u32) -> bool {
        !matches!(self, Self::Translation) || consecutive > 1
    }
}

#[cfg(test)]
mod stage1_fault_kind_tests {
    use super::Stage1FaultKind;

    #[test]
    fn decodes_the_three_stage1_fault_status_classes_at_every_level() {
        for level in 0..4 {
            assert_eq!(
                Stage1FaultKind::from_fault_status(0x04 | level),
                Some(Stage1FaultKind::Translation)
            );
            assert_eq!(
                Stage1FaultKind::from_fault_status(0x08 | level),
                Some(Stage1FaultKind::AccessFlag)
            );
            assert_eq!(
                Stage1FaultKind::from_fault_status(0x0c | level),
                Some(Stage1FaultKind::Permission)
            );
        }
        // Address size, synchronous external abort, alignment: not stage-1
        // descriptor faults.
        for status in [0x00, 0x10, 0x21] {
            assert_eq!(Stage1FaultKind::from_fault_status(status), None);
        }
    }

    /// Contract `kernel.el1.task-load-entry` (no maintenance round trip a
    /// task load did not need): a sibling's commit racing a translation
    /// fault is retried without a TLB invalidation; a repeat at the same
    /// address, or any permission/access-flag fault, still invalidates.
    #[test]
    fn only_a_repeated_translation_fault_or_a_cached_translation_invalidates() {
        assert!(!Stage1FaultKind::Translation.stale_retry_needs_invalidation(1));
        assert!(Stage1FaultKind::Translation.stale_retry_needs_invalidation(2));
        for kind in [Stage1FaultKind::AccessFlag, Stage1FaultKind::Permission] {
            assert!(kind.stale_retry_needs_invalidation(1));
            assert!(kind.stale_retry_needs_invalidation(2));
        }
    }
}

/// Whether the hardware-visible terminal descriptor of a stage-1 walk lets EL0
/// perform `access` WITHOUT faulting: valid, access flag set, EL0-accessible,
/// writable for a write, and UXN clear for an instruction fetch. This is the
/// exact question a fault handler must ask when the software model no longer
/// names a pending edit for the page: a sibling thread's commit or a stale
/// TLB entry leaves a fault whose retry succeeds, while any other descriptor
/// state is a genuine fault to deliver.
pub fn terminal_descriptor_permits_el0(descriptor: u64, access: LeafAccess) -> bool {
    if descriptor & VALID == 0 || descriptor & ACCESS_FLAG == 0 || descriptor & AP_EL0_ACCESS == 0 {
        return false;
    }
    match access {
        LeafAccess::Read => true,
        LeafAccess::Write => descriptor & AP_READ_ONLY == 0,
        LeafAccess::Execute => descriptor & UXN == 0,
    }
}

/// Whether a terminal descriptor carries EL1's private-anonymous permission
/// authority. Host syscall-buffer paths use this bit to enforce permission
/// transitions served entirely in guest EL1 without consulting stale host VMA
/// mirrors.
#[inline]
pub fn terminal_descriptor_has_el1_private_authority(descriptor: u64) -> bool {
    el1_private_leaf_state(descriptor) != El1PrivateLeafState::Unowned
}

/// Whether a terminal descriptor carries EL1's private-anonymous write permission
/// intent, even if the leaf is temporarily armed read-only for fork COW.
#[inline]
pub fn terminal_descriptor_may_write(descriptor: u64) -> bool {
    descriptor & SW_EL1_MAY_WRITE != 0
}

/// Host buffer access for an EL1-owned leaf. COW writes are admitted only
/// while Linux write intent survives; the caller must privatize before copyout.
/// Non-EL1 mappings remain subject to the caller's ordinary permission checks.
pub fn terminal_descriptor_permits_host_buffer(descriptor: u64, access: LeafAccess) -> bool {
    // Invalid, non-retired leaves retain prepared backing and the current AP
    // permissions. Admission here is not residency publication. EL1-served
    // PROT_NONE remains VALID with AP_PRIV_RO; host-forwarded PROT_NONE is
    // invalid with AP_PRIV_RO (`set_prot_none_denying_host_buffers`), so the
    // AP check below denies both.
    match el1_private_leaf_state(descriptor) {
        El1PrivateLeafState::Unowned => true,
        El1PrivateLeafState::Prepared => {
            terminal_descriptor_permits_el0(descriptor | VALID, access)
        }
        El1PrivateLeafState::Resident => {
            (access == LeafAccess::Write
                && terminal_descriptor_permits_el0(descriptor, LeafAccess::Read)
                && el1_cow(descriptor)
                && terminal_descriptor_may_write(descriptor))
                || terminal_descriptor_permits_el0(descriptor, access)
        }
        El1PrivateLeafState::Retired | El1PrivateLeafState::Malformed => false,
    }
}

/// A terminal descriptor that names no output at all: an invalid leaf (or
/// missing table) that is not EL1-private and retains no backing. Inside a
/// delegated reservation root this is a never-touched page whose frame does
/// not exist yet; a host-invalidated leaf that keeps its output is not absent.
pub fn terminal_descriptor_is_absent(descriptor: u64) -> bool {
    descriptor & VALID == 0
        && el1_private_leaf_state(descriptor) == El1PrivateLeafState::Unowned
        && descriptor & PA_MASK_4KIB == 0
}

/// An EL1-private leaf that is invalid, not retired and still records its
/// granted output: bulk-prepared backing never touched by the guest, or a page
/// the host invalidated for `PROT_NONE` (which then carries kernel-only AP).
pub fn terminal_descriptor_is_prepared_private(descriptor: u64) -> bool {
    el1_private_leaf_state(descriptor) == El1PrivateLeafState::Prepared
}

/// Result of committing one host-owned, zero-filled prepared page in EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPreparedCommit {
    Committed,
    AlreadyResident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPreparedCommitError {
    BadAddress,
    MissingTable,
    TableOutsidePrimary,
    NotPrepared,
    WrongBacking,
    PermissionDenied,
    /// A failed commit could not restore its pre-image: editor exclusion
    /// was violated and the MM's table graph is indeterminate.
    RollbackFailed,
}

/// Validate an existing prepared L3 leaf without changing its output or
/// permission tags. The grant owner must have published stage 2 and its frame
/// inventory before the leaf became prepared. VALID is the residency truth.
/// The caller holds the exact-MM editor through the following ASID TLBI.
/// This is a one-page [`descriptor_txn::DescriptorOp::Publish`] through the
/// shared transaction executor, with no table grants.
///
/// # Safety
///
/// `words` names the writable primary table arena for `physical_base` (the
/// root) and `extra`, when present, every other arena of the graph; the
/// exact-MM editor excludes every other host or guest mutation of this graph.
pub unsafe fn commit_existing_el1_prepared_page(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    extra: Option<descriptor_txn::TableWindow>,
    va: u64,
    expected_ipa: u64,
    access: LeafAccess,
) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
    use descriptor_txn::{DescriptorOp, DescriptorOutcome, DescriptorRefusal, PageSpan};

    let maintenance = descriptor_txn::CallerInvalidatesAsid;
    let Ok(live) = (unsafe {
        descriptor_txn::PrimaryTableWords::new(words, physical_base, byte_len, &maintenance)
            .and_then(|live| match extra {
                Some(window) => live.with_window(window),
                None => Ok(live),
            })
    }) else {
        return Err(GuestPreparedCommitError::BadAddress);
    };
    let mut journal = descriptor_txn::InlineJournal::new();
    let outcome = descriptor_txn::execute_descriptor_op(
        &live,
        SubstrateGpa(physical_base),
        DescriptorOp::Publish {
            span: PageSpan::new(va, PT_PAGE),
            expected_ipa: SubstrateGpa(expected_ipa),
            access,
        },
        &descriptor_txn::TableGrants::NONE,
        &mut journal,
    );
    match outcome {
        DescriptorOutcome::Applied(applied) if applied.live_stores != 0 => {
            Ok(GuestPreparedCommit::Committed)
        }
        DescriptorOutcome::Applied(_) => Ok(GuestPreparedCommit::AlreadyResident),
        DescriptorOutcome::Indeterminate(_) => Err(GuestPreparedCommitError::RollbackFailed),
        DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
            Err(match refusal {
                DescriptorRefusal::BadRange | DescriptorRefusal::StaleRoot => {
                    GuestPreparedCommitError::BadAddress
                }
                DescriptorRefusal::TableOutsidePrimary => {
                    GuestPreparedCommitError::TableOutsidePrimary
                }
                DescriptorRefusal::MissingTable | DescriptorRefusal::TablesExhausted => {
                    GuestPreparedCommitError::MissingTable
                }
                DescriptorRefusal::WrongBacking => GuestPreparedCommitError::WrongBacking,
                DescriptorRefusal::PermissionDenied => GuestPreparedCommitError::PermissionDenied,
                _ => GuestPreparedCommitError::NotPrepared,
            })
        }
    }
}

/// Extend the guest permission ceiling after an authorized host protection edit.
/// Fork COW must not call this: its hardware restriction is not an mprotect.
fn private_permission_tags(descriptor: u64, writable: bool, executable: bool) -> u64 {
    if descriptor & SW_EL1_PRIVATE == 0 {
        return descriptor;
    }
    descriptor
        | if writable { SW_EL1_MAY_WRITE } else { 0 }
        | if executable { SW_EL1_MAY_EXEC } else { 0 }
}

/// Why a guest EL1 frame grant could not replace an already-provisioned span
/// of invalid L3 leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestLeafPublicationError {
    BadRange,
    TableOutsidePrimary,
    MissingTable,
    InvalidLeafShape,
    AlreadyValid,
    RetiredLeaf,
    Manager(PageTableError),
    RollbackFailed,
}

/// One exact semantic-to-physical leaf span and its Linux permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestLeafPublication {
    pub va: u64,
    pub ipa: u64,
    pub len: u64,
    pub writable: bool,
    pub executable: bool,
}

/// One resident private-anonymous permission transition owned by guest EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPermissionEdit {
    pub va: u64,
    pub len: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Why EL1 could not own a requested resident-anonymous protection edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPermissionEditError {
    BadRange,
    TableOutsidePrimary,
    MissingTable,
    NotPrivateAnonymous,
    PermissionWidening,
    Manager(PageTableError),
    RollbackFailed,
}

/// Why EL1 could not retire a requested resident private-anonymous range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRetirementError {
    BadRange,
    TableOutsidePrimary,
    MissingTable,
    NotPrivateAnonymous,
    /// A failed retirement could not restore its pre-image: editor
    /// exclusion was violated and the MM's table graph is indeterminate.
    RollbackFailed,
}

unsafe fn live_primary_descriptor(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    descriptor_pa: u64,
) -> Result<*mut core::sync::atomic::AtomicU64, GuestLeafPublicationError> {
    let offset = descriptor_pa
        .checked_sub(physical_base)
        .ok_or(GuestLeafPublicationError::TableOutsidePrimary)?;
    let offset =
        usize::try_from(offset).map_err(|_| GuestLeafPublicationError::TableOutsidePrimary)?;
    if !offset.is_multiple_of(core::mem::size_of::<u64>())
        || offset
            .checked_add(core::mem::size_of::<u64>())
            .is_none_or(|end| end > byte_len)
    {
        return Err(GuestLeafPublicationError::TableOutsidePrimary);
    }
    // SAFETY: the caller guarantees a live, aligned array covering byte_len;
    // the checked offset above stays within it.
    Ok(unsafe { words.add(offset / core::mem::size_of::<u64>()) })
}

#[cfg(test)]
unsafe fn existing_l3_descriptor(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    va: u64,
) -> Result<*mut core::sync::atomic::AtomicU64, GuestLeafPublicationError> {
    use core::sync::atomic::Ordering;

    let indexes = indices(va);
    let mut table = physical_base;
    for &index in &indexes[..3] {
        let descriptor_pa = table
            .checked_add((index * core::mem::size_of::<u64>()) as u64)
            .ok_or(GuestLeafPublicationError::TableOutsidePrimary)?;
        // SAFETY: forwarded from publish_existing_invalid_private_pages.
        let descriptor = unsafe {
            (*live_primary_descriptor(words, physical_base, byte_len, descriptor_pa)?)
                .load(Ordering::Acquire)
        };
        if descriptor & VALID == 0 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            return Err(GuestLeafPublicationError::MissingTable);
        }
        table = descriptor & PA_MASK_TABLE;
    }
    let leaf_pa = table
        .checked_add((indexes[3] * core::mem::size_of::<u64>()) as u64)
        .ok_or(GuestLeafPublicationError::TableOutsidePrimary)?;
    // SAFETY: forwarded from publish_existing_invalid_private_pages.
    unsafe { live_primary_descriptor(words, physical_base, byte_len, leaf_pa) }
}

#[derive(Clone, Copy)]
struct ExistingTerminalDescriptor {
    word: *mut core::sync::atomic::AtomicU64,
    semantic_base: u64,
    span: u64,
}

unsafe fn existing_terminal_descriptor(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    va: u64,
) -> Result<ExistingTerminalDescriptor, GuestLeafPublicationError> {
    use core::sync::atomic::Ordering;

    let indexes = indices(va);
    let mut table = physical_base;
    for (level, &index) in indexes.iter().enumerate() {
        let descriptor_pa = table
            .checked_add((index * core::mem::size_of::<u64>()) as u64)
            .ok_or(GuestLeafPublicationError::TableOutsidePrimary)?;
        // SAFETY: forwarded from protect_existing_el1_private_pages.
        let word =
            unsafe { live_primary_descriptor(words, physical_base, byte_len, descriptor_pa)? };
        let descriptor = unsafe { (*word).load(Ordering::Acquire) };
        let descriptor_type = descriptor & TYPE_BITS;
        match level {
            0 if descriptor & VALID != 0 && descriptor_type == TYPE_TABLE_OR_PAGE => {
                table = descriptor & PA_MASK_TABLE;
            }
            1 | 2 if descriptor & VALID != 0 && descriptor_type == TYPE_TABLE_OR_PAGE => {
                table = descriptor & PA_MASK_TABLE;
            }
            1 if descriptor_type == TYPE_BLOCK
                || (descriptor_type == 0
                    && el1_private_leaf_state(descriptor) != El1PrivateLeafState::Unowned) =>
            {
                return Ok(ExistingTerminalDescriptor {
                    word,
                    semantic_base: va & PA_MASK_1GIB,
                    span: 1 << 30,
                });
            }
            2 if descriptor_type == TYPE_BLOCK
                || (descriptor_type == 0
                    && el1_private_leaf_state(descriptor) != El1PrivateLeafState::Unowned) =>
            {
                return Ok(ExistingTerminalDescriptor {
                    word,
                    semantic_base: va & PA_MASK_2MIB,
                    span: 1 << 21,
                });
            }
            3 if descriptor_type == TYPE_TABLE_OR_PAGE
                || descriptor_type == (TYPE_TABLE_OR_PAGE & !VALID) =>
            {
                return Ok(ExistingTerminalDescriptor {
                    word,
                    semantic_base: va & PA_MASK_4KIB,
                    span: PT_PAGE,
                });
            }
            _ => return Err(GuestLeafPublicationError::MissingTable),
        }
    }
    Err(GuestLeafPublicationError::MissingTable)
}

/// Publish one exact linear IPA span into L3 leaves whose table hierarchy
/// already exists. The whole span is validated before the first descriptor is
/// exposed, so a late valid/retired/missing leaf cannot leave a partial map.
/// This path allocates no table pages and always emits per-MM `nG` leaves.
///
/// The caller performs the architectural `DSB`/`TLBI`/`DSB`/`ISB` sequence
/// after success and holds exclusive mutation authority for this table graph.
///
/// # Safety
///
/// `words` must be an aligned, writable, hardware-visible array of atomic
/// descriptor words covering `byte_len`. `physical_base` must name that same
/// primary page-table arena in every live table descriptor reachable here.
#[cfg(test)]
pub unsafe fn publish_existing_invalid_private_pages(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    publication: GuestLeafPublication,
) -> Result<usize, GuestLeafPublicationError> {
    use core::sync::atomic::Ordering;

    if words.is_null()
        || !(words as usize).is_multiple_of(core::mem::align_of::<core::sync::atomic::AtomicU64>())
        || !physical_base.is_multiple_of(PT_PAGE)
        || !publication.va.is_multiple_of(PT_PAGE)
        || !publication.ipa.is_multiple_of(PT_PAGE)
        || publication.len == 0
        || !publication.len.is_multiple_of(PT_PAGE)
        || publication.va.checked_add(publication.len).is_none()
        || publication.ipa.checked_add(publication.len).is_none()
    {
        return Err(GuestLeafPublicationError::BadRange);
    }
    let pages = usize::try_from(publication.len / PT_PAGE)
        .map_err(|_| GuestLeafPublicationError::BadRange)?;

    for page in 0..pages {
        let page_va = publication.va + page as u64 * PT_PAGE;
        // SAFETY: this function's caller owns the checked live descriptor
        // array, and the exact-MM editor excludes concurrent table mutation.
        let leaf = unsafe { existing_l3_descriptor(words, physical_base, byte_len, page_va)? };
        let descriptor = unsafe { (*leaf).load(Ordering::Acquire) };
        if descriptor & VALID != 0 {
            return Err(GuestLeafPublicationError::AlreadyValid);
        }
        if descriptor & SW_RETIRED != 0 {
            return Err(GuestLeafPublicationError::RetiredLeaf);
        }
        if descriptor != 0 && descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            return Err(GuestLeafPublicationError::InvalidLeafShape);
        }
    }

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
    }
    if !publication.executable {
        flags |= UXN;
    }
    for page in 0..pages {
        let page_va = publication.va + page as u64 * PT_PAGE;
        let page_ipa = publication.ipa + page as u64 * PT_PAGE;
        // SAFETY: the identical walk succeeded during the complete validation
        // pass while the caller's exact-MM editor remained held.
        let leaf = unsafe { existing_l3_descriptor(words, physical_base, byte_len, page_va)? };
        unsafe { (*leaf).store((page_ipa & PA_MASK_4KIB) | flags, Ordering::Release) };
    }
    Ok(pages)
}

/// Apply one permission transition to existing L1/L2 blocks or L3 leaves
/// carrying EL1's private-anonymous authority, prepared or resident (a
/// prepared leaf stays invalid; its AP/UXN govern its later commit and host
/// buffer access). The complete range, terminal coverage, and permission
/// ceiling are checked before the first store; COW-armed leaves report
/// `PermissionWidening`. This entry point carries no table grants, so a
/// partially covered block is refused; a host submission carrying grants
/// splits it (see [`descriptor_txn`]). A rolled-back edit restores every
/// word; the caller still invalidates the ASID only after success.
///
/// # Safety
///
/// `words` must be an aligned, writable, hardware-visible array of atomic
/// descriptor words covering `byte_len`. `physical_base` must name that same
/// primary page-table arena in every live table descriptor reachable here.
/// The caller holds exclusive mutation authority for this table graph and
/// performs the architectural `DSB`/`TLBI`/`DSB`/`ISB` sequence after success.
pub unsafe fn protect_existing_el1_private_pages(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    extra: Option<descriptor_txn::TableWindow>,
    edit: GuestPermissionEdit,
) -> Result<usize, GuestPermissionEditError> {
    use descriptor_txn::{DescriptorOp, DescriptorOutcome, DescriptorRefusal};

    let maintenance = descriptor_txn::CallerInvalidatesAsid;
    let Ok(live) = (unsafe {
        descriptor_txn::PrimaryTableWords::new(words, physical_base, byte_len, &maintenance)
            .and_then(|live| match extra {
                Some(window) => live.with_window(window),
                None => Ok(live),
            })
    }) else {
        return Err(GuestPermissionEditError::BadRange);
    };
    let mut journal = descriptor_txn::InlineJournal::new();
    match descriptor_txn::execute_descriptor_op(
        &live,
        SubstrateGpa(physical_base),
        DescriptorOp::Protect(edit),
        &descriptor_txn::TableGrants::NONE,
        &mut journal,
    ) {
        DescriptorOutcome::Applied(applied) => {
            usize::try_from(applied.pages).map_err(|_| GuestPermissionEditError::BadRange)
        }
        DescriptorOutcome::Indeterminate(_) => Err(GuestPermissionEditError::RollbackFailed),
        DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
            Err(match refusal {
                DescriptorRefusal::BadRange => GuestPermissionEditError::BadRange,
                DescriptorRefusal::TableOutsidePrimary => {
                    GuestPermissionEditError::TableOutsidePrimary
                }
                DescriptorRefusal::MissingTable => GuestPermissionEditError::MissingTable,
                DescriptorRefusal::PermissionWidening | DescriptorRefusal::CowArmed => {
                    GuestPermissionEditError::PermissionWidening
                }
                _ => GuestPermissionEditError::NotPrivateAnonymous,
            })
        }
    }
}

/// Retire existing L1/L2 blocks or L3 leaves carrying EL1's
/// private-anonymous authority. The complete range and every terminal are
/// checked before the first store. This entry point carries no table grants,
/// so a partial coarse block is refused rather than split on the syscall
/// path; a host submission carrying grants splits it (see [`descriptor_txn`]).
///
/// The output address and permission ceiling remain in each invalid retired
/// descriptor so the host's authenticated bulk-return path can reconcile its
/// frame inventory before the descriptor storage is reused. The caller owns
/// the exact-MM editor and performs the architectural TLB invalidation after
/// success.
///
/// # Safety
///
/// `words` must be an aligned, writable, hardware-visible array of atomic
/// descriptor words covering `byte_len`. `physical_base` must name that same
/// primary page-table arena in every live table descriptor reachable here.
/// The caller holds exclusive mutation authority for this table graph and
/// performs the architectural `DSB`/`TLBI`/`DSB`/`ISB` sequence after success.
pub unsafe fn retire_existing_el1_private_pages(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    extra: Option<descriptor_txn::TableWindow>,
    va: u64,
    len: u64,
) -> Result<usize, GuestRetirementError> {
    use descriptor_txn::{DescriptorOp, DescriptorOutcome, DescriptorRefusal, PageSpan};

    let maintenance = descriptor_txn::CallerInvalidatesAsid;
    let Ok(live) = (unsafe {
        descriptor_txn::PrimaryTableWords::new(words, physical_base, byte_len, &maintenance)
            .and_then(|live| match extra {
                Some(window) => live.with_window(window),
                None => Ok(live),
            })
    }) else {
        return Err(GuestRetirementError::BadRange);
    };
    let mut journal = descriptor_txn::InlineJournal::new();
    match descriptor_txn::execute_descriptor_op(
        &live,
        SubstrateGpa(physical_base),
        DescriptorOp::Retire(PageSpan::new(va, len)),
        &descriptor_txn::TableGrants::NONE,
        &mut journal,
    ) {
        DescriptorOutcome::Applied(applied) => {
            usize::try_from(applied.pages).map_err(|_| GuestRetirementError::BadRange)
        }
        DescriptorOutcome::Indeterminate(_) => Err(GuestRetirementError::RollbackFailed),
        DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
            Err(match refusal {
                DescriptorRefusal::BadRange => GuestRetirementError::BadRange,
                DescriptorRefusal::TableOutsidePrimary => GuestRetirementError::TableOutsidePrimary,
                DescriptorRefusal::MissingTable => GuestRetirementError::MissingTable,
                _ => GuestRetirementError::NotPrivateAnonymous,
            })
        }
    }
}

/// Why EL1 could not arm existing private leaves for fork COW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestCowError {
    BadAddress,
    NotMapped,
    TableOutsidePrimary,
    MissingTable,
    NotPrivateAnonymous,
    PermissionDenied,
}

/// Arm an existing resident private-anonymous range read-only for fork COW under EL1 authority.
///
/// # Safety
///
/// `words` must be an aligned, writable, hardware-visible array of atomic
/// descriptor words covering `byte_len`. `physical_base` must name that same
/// primary page-table arena in every live table descriptor reachable here.
/// The caller holds exclusive mutation authority for this table graph and
/// performs the architectural `DSB`/`TLBI`/`DSB`/`ISB` sequence after success.
pub unsafe fn arm_existing_el1_fork_pages(
    words: *mut core::sync::atomic::AtomicU64,
    physical_base: u64,
    byte_len: usize,
    va: u64,
    len: u64,
) -> Result<usize, GuestCowError> {
    use core::sync::atomic::Ordering;

    if words.is_null()
        || !(words as usize).is_multiple_of(core::mem::align_of::<core::sync::atomic::AtomicU64>())
        || !physical_base.is_multiple_of(PT_PAGE)
        || !va.is_multiple_of(PT_PAGE)
        || len == 0
        || !len.is_multiple_of(PT_PAGE)
        || va.checked_add(len).is_none()
    {
        return Err(GuestCowError::BadAddress);
    }
    let pages = usize::try_from(len / PT_PAGE).map_err(|_| GuestCowError::BadAddress)?;
    let terminal_for = |address| unsafe {
        existing_terminal_descriptor(words, physical_base, byte_len, address).map_err(|error| {
            match error {
                GuestLeafPublicationError::TableOutsidePrimary => {
                    GuestCowError::TableOutsidePrimary
                }
                GuestLeafPublicationError::MissingTable => GuestCowError::MissingTable,
                _ => GuestCowError::NotPrivateAnonymous,
            }
        })
    };

    let end = va + len;
    let mut current = va;
    while current < end {
        let terminal = terminal_for(current)?;
        let terminal_end = terminal
            .semantic_base
            .checked_add(terminal.span)
            .ok_or(GuestCowError::BadAddress)?;
        let descriptor = unsafe { (*terminal.word).load(Ordering::Acquire) };
        if descriptor & VALID != 0 && descriptor & SW_EL1_PRIVATE != 0 {
            let ap = if descriptor & AP_MASK == AP_PRIV_RO {
                AP_PRIV_RO
            } else {
                AP_RO
            };
            let updated = (arm_private_cow(descriptor) & !AP_MASK) | ap | NON_GLOBAL;
            unsafe { (*terminal.word).store(updated, Ordering::Release) };
        }
        current = terminal_end;
    }
    Ok(pages)
}

// User leaf flags (must match memory.rs USER_BLOCK_FLAGS / USER_PAGE_FLAGS).
const USER_BLOCK_FLAGS: u64 = (1u64 << 53) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01;
const USER_PAGE_FLAGS: u64 = USER_BLOCK_FLAGS | 0b10;
const KERNEL_BLOCK_FLAGS: u64 = (1u64 << 54) | (1 << 10) | (0b11 << 8) | 0b01;
const KERNEL_PAGE_FLAGS: u64 = KERNEL_BLOCK_FLAGS | 0b10;
const AP_PRIV_RO: u64 = 0b10 << 6;

const PT_PAGE: u64 = 0x1000; // stage-1 table page size (4 KiB granule)
// The boot image lays out eight tables in the first eight 4 KiB pages:
// L0, L1A, L1B, L2A, L2B, L3A (pages 0..5), then L1_rosetta, L2_rosetta
// (pages 6..7, the high-VA Rosetta alias). Runtime-allocated sub-tables come
// from the spare tail after them.
const SPARE_START_OFFSET: u64 = 8 * PT_PAGE;

/// The EL0 permission of a user alias leaf: Linux `PROT_WRITE` and
/// `PROT_EXEC` of the mapping that owns the range. Every alias publication
/// names both, so no mapping helper can make a page executable (or writable)
/// that its owner did not map that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserLeafAccess {
    pub writable: bool,
    pub executable: bool,
}

impl UserLeafAccess {
    /// Read/write, non-executable: anonymous data, the stack, `brk`.
    pub const READ_WRITE: Self = Self {
        writable: true,
        executable: false,
    };
    /// Read-only, non-executable.
    pub const READ_ONLY: Self = Self {
        writable: false,
        executable: false,
    };

    /// The access a Linux `PROT_*` word grants (`PROT_READ` is implied by a
    /// valid leaf; `PROT_NONE` is a separate invalidation, not an access).
    pub const fn from_linux_prot(prot: u64) -> Self {
        Self {
            writable: prot & 0x2 != 0,
            executable: prot & 0x4 != 0,
        }
    }

    /// `(block, page)` leaf flags carrying this access plus `scope` (nG).
    fn leaf_flags(self, scope: u64) -> (u64, u64) {
        let (mut block, mut page) = if self.writable {
            (USER_BLOCK_FLAGS, USER_PAGE_FLAGS)
        } else {
            (
                (USER_BLOCK_FLAGS & !AP_MASK) | AP_RO,
                (USER_PAGE_FLAGS & !AP_MASK) | AP_RO,
            )
        };
        if !self.executable {
            block |= UXN;
            page |= UXN;
        }
        (block | scope, page | scope)
    }
}

/// A protection change applied to a guest VA range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtOp {
    /// Clear the valid bit — any access faults (SEGV_MAPERR). The output
    /// address is retained and still names a frame this mm owns.
    Invalidate,
    /// `munmap`: clear the valid bit AND mark the retained output RETIRED
    /// (`SW_RETIRED`), so the table it sits in becomes reclaimable.
    Retire,
    /// Valid, AP=read-only. `exec` clears UXN (PROT_EXEC); else UXN set (NX).
    ReadOnly { exec: bool },
    /// Fork-COW read-only plus nG. Unlike an ordinary protection edit this must
    /// not treat an already-RO global descriptor as satisfied. Arming is a
    /// WRITE restriction only: the leaf's execute permission (UXN) is the
    /// guest's `PROT_EXEC` state and is preserved verbatim. Deriving it from
    /// the host mapping's perms made every private page in an RWX-backed
    /// arena executable in both parent and child after fork (`forkprotectexec`).
    ForkReadOnly,
    /// Valid, AP=read-write. `exec` clears UXN (PROT_EXEC); else UXN set (NX).
    ReadWrite { exec: bool },
    /// Valid, EL1 read-only and inaccessible to EL0 (AP=10).  Fork COW uses
    /// this for Carrick's identity/mailbox pages so PSTATE.PAN never turns the
    /// EL1 vector's own access into a false second fault.
    KernelReadOnly { exec: bool },
}

/// Build the leaf descriptor for `op` covering `base_pa` at `level`.
fn pt_desc_for(asid_scoped_leaves: bool, op: PtOp, base_pa: u64, level: usize) -> u64 {
    let (_, mask) = PageTableManager::level_span(level);
    // Block at L1/L2, page at L3 (type bit differs; USER_PAGE_FLAGS adds it).
    let kernel_only = matches!(op, PtOp::KernelReadOnly { .. });
    let flags = if level == 3 {
        if kernel_only {
            KERNEL_PAGE_FLAGS
        } else {
            USER_PAGE_FLAGS
        }
    } else if kernel_only {
        KERNEL_BLOCK_FLAGS
    } else {
        USER_BLOCK_FLAGS
    };
    let base = base_pa & mask;
    let scope = if asid_scoped_leaves { NON_GLOBAL } else { 0 };
    // UXN (bit 54) is set for a non-exec leaf; cleared for an exec one.
    // USER_*_FLAGS start UXN-clear (executable), so OR in UXN when !exec.
    let uxn = |exec: bool| if exec { 0 } else { UXN };
    match op {
        PtOp::Invalidate => base | (flags & !VALID) | scope,
        PtOp::Retire => base | (flags & !VALID) | scope | SW_RETIRED,
        PtOp::ReadWrite { exec } => base | flags | uxn(exec) | scope,
        PtOp::ReadOnly { exec } => base | (flags & !AP_MASK) | AP_RO | uxn(exec) | scope,
        // Fork restricts an existing output; it never constructs one.
        PtOp::ForkReadOnly => 0,
        PtOp::KernelReadOnly { exec } => base | (flags & !AP_MASK) | AP_PRIV_RO | uxn(exec) | scope,
    }
}

/// Does a leaf with `(valid, ap, uxn_set)` already satisfy `op`? Includes the
/// UXN (execute) bit so a re-protect that only flips PROT_EXEC still applies.
fn pt_satisfies(
    asid_scoped_leaves: bool,
    op: PtOp,
    valid: bool,
    ap: u64,
    uxn_set: bool,
    non_global: bool,
    retired: bool,
) -> bool {
    let scoped = !asid_scoped_leaves || non_global;
    match op {
        PtOp::Invalidate => !valid && scoped,
        PtOp::Retire => !valid && scoped && retired,
        PtOp::ReadWrite { exec } => valid && ap == AP_RW && uxn_set != exec && scoped,
        PtOp::ReadOnly { exec } => valid && ap == AP_RO && uxn_set != exec && scoped,
        PtOp::ForkReadOnly => (ap == AP_RO || ap == AP_PRIV_RO) && non_global,
        PtOp::KernelReadOnly { exec } => valid && ap == AP_PRIV_RO && uxn_set != exec && scoped,
    }
}

/// The descriptor `op` makes of one covering terminal at `level` whose
/// semantic block starts at `block_start`, or `None` when the terminal
/// already satisfies `op` (then its whole span is skipped, never split).
/// The host editor's `apply` and guest fork-arm transactions share this one
/// definition; callers check the GIC window for descriptors they store.
pub(crate) fn pt_terminal_edit(
    asid_scoped_leaves: bool,
    op: PtOp,
    desc: u64,
    level: usize,
    block_start: u64,
) -> Option<u64> {
    let empty = !PageTableManager::records_output(desc, level);
    let tagged = match op {
        PtOp::ReadWrite { exec } => private_permission_tags(desc & !SW_EL1_COW, true, exec),
        PtOp::ReadOnly { exec } | PtOp::KernelReadOnly { exec } => {
            private_permission_tags(desc & !SW_EL1_COW, false, exec)
        }
        PtOp::ForkReadOnly => arm_private_cow(desc),
        PtOp::Invalidate | PtOp::Retire => desc,
    };
    let already = tagged == desc
        && match op {
            // An EMPTY descriptor is already as invalid as it can be, and
            // nothing about it (nG, retirement) survives to a revalidation
            // — which rebuilds it from scratch. Writing anything into it
            // would turn "no output recorded" into a descriptor that a
            // later in-place edit or split treats as carrying one.
            PtOp::Invalidate | PtOp::Retire | PtOp::ForkReadOnly if empty => true,
            // A speculative EL1 grant leaf has no live EL0 write
            // permission to revoke at fork. Keep its current AP as
            // Linux intent until first touch publishes the page under
            // the backend's armed physical COW authority.
            PtOp::ForkReadOnly if terminal_descriptor_is_prepared_private(desc) => {
                desc & NON_GLOBAL != 0
            }
            _ => pt_satisfies(
                asid_scoped_leaves,
                op,
                desc & VALID != 0,
                desc & AP_MASK,
                desc & UXN != 0,
                desc & NON_GLOBAL != 0,
                desc & SW_RETIRED != 0,
            ),
        };
    if already {
        return None;
    }
    let new_desc = match op {
        PtOp::Invalidate | PtOp::Retire => {
            let scope = if asid_scoped_leaves { NON_GLOBAL } else { 0 };
            let retired = if matches!(op, PtOp::Retire) {
                SW_RETIRED
            } else {
                0
            };
            (desc & !VALID & !if el1_cow(desc) { SW_EL1_COW } else { 0 }) | scope | retired
        }
        PtOp::ReadOnly { .. }
        | PtOp::ForkReadOnly
        | PtOp::ReadWrite { .. }
        | PtOp::KernelReadOnly { .. }
            if !empty =>
        {
            let ap = match op {
                PtOp::ForkReadOnly if terminal_descriptor_is_prepared_private(desc) => {
                    desc & AP_MASK
                }
                PtOp::ForkReadOnly if desc & AP_MASK == AP_PRIV_RO => AP_PRIV_RO,
                PtOp::ReadOnly { .. } | PtOp::ForkReadOnly => AP_RO,
                PtOp::KernelReadOnly { .. } => AP_PRIV_RO,
                _ => AP_RW,
            };
            // Fork arming keeps the leaf's own execute permission;
            // every other edit sets it from the requested prot.
            let uxn = match op {
                PtOp::ForkReadOnly => desc & UXN,
                PtOp::ReadOnly { exec }
                | PtOp::ReadWrite { exec }
                | PtOp::KernelReadOnly { exec } => {
                    if exec {
                        0
                    } else {
                        UXN
                    }
                }
                PtOp::Invalidate | PtOp::Retire => unreachable!(),
            };
            let non_global = if asid_scoped_leaves || matches!(op, PtOp::ForkReadOnly) {
                NON_GLOBAL
            } else {
                0
            };
            let validity = if matches!(op, PtOp::ForkReadOnly) {
                desc & VALID
            } else {
                VALID
            };
            // A revalidated output is live again by definition;
            // retirement only survives an edit that keeps the
            // leaf invalid.
            let retired = if validity == 0 {
                desc & SW_RETIRED
            } else if matches!(op, PtOp::ForkReadOnly) {
                tagged & SW_EL1_COW
            } else {
                0
            };
            (tagged & !AP_MASK & !UXN & !SW_RETIRED) | ap | uxn | non_global | validity | retired
        }
        PtOp::ReadOnly { .. }
        | PtOp::ForkReadOnly
        | PtOp::ReadWrite { .. }
        | PtOp::KernelReadOnly { .. } => pt_desc_for(asid_scoped_leaves, op, block_start, level),
    };
    Some(new_desc)
}

/// One range rule that the host editor ([`PageTableManager::apply_rule`]) and
/// guest EL1 descriptor transactions ([`descriptor_txn::DescriptorOp::Terminal`])
/// both apply per covering terminal, so the two venues share one semantic
/// definition of every host-originated protection, retirement and tag edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRule {
    /// The [`PtOp`] terminal rule, composed per terminal as:
    /// `reset_retired` (a new mapping at a reused VA drops the predecessor's
    /// EL1-private retired leaf; a live private leaf there is refused), then
    /// `op` (none: leave the terminal as reset), then `deny_host_buffers` (a
    /// formerly resident EL1-private leaf that `op` invalidated records
    /// kernel-only AP so host buffer access is denied), then `fork_arm`
    /// (re-arm fork COW, recording write intent).
    Pt {
        op: Option<PtOp>,
        reset_retired: bool,
        deny_host_buffers: bool,
        fork_arm: bool,
        /// Before `op`, adopt a host-published EL0-writable 4 KiB leaf as
        /// EL1-private state (the tags EL1 needs to resolve its COW itself).
        /// Set only by fork arming of a guest-lane MM's compound-granule,
        /// non-kernel ranges; the host editor and the EL1 executor apply
        /// this one definition.
        adopt_private: bool,
    },
    /// Remove EL1-private authority from prepared (invalid) file BUS-tail
    /// leaves. A resident or malformed private leaf is refused.
    BusFault,
}

impl TerminalRule {
    /// The plain [`PtOp`] rule with no composition.
    #[must_use]
    pub const fn pt(op: PtOp) -> Self {
        Self::Pt {
            op: Some(op),
            reset_retired: false,
            deny_host_buffers: false,
            fork_arm: false,
            adopt_private: false,
        }
    }

    pub(crate) fn requires_private_pages(self) -> bool {
        matches!(
            self,
            Self::Pt {
                fork_arm: true,
                adopt_private: true,
                ..
            }
        )
    }

    /// Fork COW arming of a private range, optionally adopting host-published
    /// leaves as EL1-private so EL1 resolves their COW itself.
    #[must_use]
    pub const fn fork_arm(adopt_private: bool) -> Self {
        Self::Pt {
            op: Some(PtOp::ForkReadOnly),
            reset_retired: false,
            deny_host_buffers: false,
            fork_arm: false,
            adopt_private,
        }
    }
}

/// A terminal a [`TerminalRule`] refuses to edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRefusal {
    /// A new mapping would reuse a VA still holding a live private leaf.
    Occupied,
    /// A BUS tail over a resident private leaf.
    Resident,
    /// An EL1-private tag set with no valid encoding.
    Malformed,
}

/// The EL1-private tags a host-published leaf needs before fork arming so EL1
/// resolves its COW itself: a valid, EL0-writable 4 KiB leaf that no EL1 grant
/// produced gets `SW_EL1_PRIVATE` and the write (and execute) ceiling its
/// current permission implies. Only a writable leaf qualifies: an
/// already-restricted leaf carries no recoverable Linux write intent, so it
/// stays with the host. Blocks stay with the host (EL1 never splits).
fn adopt_host_leaf_as_el1_private(desc: u64, level: usize) -> u64 {
    if level != 3
        || desc & (VALID | SW_EL1_PRIVATE) != VALID
        || desc & TYPE_BITS != TYPE_TABLE_OR_PAGE
        || desc & AP_MASK != AP_RW
    {
        return desc;
    }
    desc | SW_EL1_PRIVATE | SW_EL1_MAY_WRITE | if desc & UXN == 0 { SW_EL1_MAY_EXEC } else { 0 }
}

/// Apply `rule` to one covering terminal. `Ok(None)`: the terminal already
/// satisfies the rule and its whole span is skipped without a split.
pub fn terminal_rule_edit(
    asid_scoped_leaves: bool,
    rule: TerminalRule,
    desc: u64,
    level: usize,
    block_start: u64,
) -> Result<Option<u64>, TerminalRefusal> {
    match rule {
        TerminalRule::BusFault => match el1_private_leaf_state(desc) {
            El1PrivateLeafState::Resident => Err(TerminalRefusal::Resident),
            El1PrivateLeafState::Malformed => Err(TerminalRefusal::Malformed),
            El1PrivateLeafState::Prepared => Ok(Some(
                desc & !(SW_EL1_PRIVATE | SW_EL1_MAY_WRITE | SW_EL1_MAY_EXEC),
            )),
            El1PrivateLeafState::Unowned | El1PrivateLeafState::Retired => Ok(None),
        },
        TerminalRule::Pt {
            op,
            reset_retired,
            deny_host_buffers,
            fork_arm,
            adopt_private,
        } => {
            let mut current = desc;
            if reset_retired {
                match el1_private_leaf_state(current) {
                    El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident => {
                        return Err(TerminalRefusal::Occupied);
                    }
                    El1PrivateLeafState::Malformed => return Err(TerminalRefusal::Malformed),
                    El1PrivateLeafState::Retired => current = 0,
                    El1PrivateLeafState::Unowned => {}
                }
            }
            if adopt_private {
                current = adopt_host_leaf_as_el1_private(current, level);
            }
            let was_resident = el1_private_leaf_state(current) == El1PrivateLeafState::Resident;
            if let Some(edited) = op.and_then(|op| {
                pt_terminal_edit(asid_scoped_leaves, op, current, level, block_start)
            }) {
                current = edited;
            }
            if deny_host_buffers
                && was_resident
                && el1_private_leaf_state(current) == El1PrivateLeafState::Prepared
                && current & AP_MASK != AP_PRIV_RO
            {
                current = (current & !AP_MASK) | AP_PRIV_RO;
            }
            // Imported private backing can arrive restricted. Its admitted
            // permission operation supplies the write intent before COW arming.
            if adopt_private && fork_arm {
                current = adopt_host_leaf_as_el1_private(current, level);
            }
            if fork_arm
                && let Some(armed) = pt_terminal_edit(
                    asid_scoped_leaves,
                    PtOp::ForkReadOnly,
                    current,
                    level,
                    block_start,
                )
            {
                current = armed;
            }
            Ok((current != desc).then_some(current))
        }
    }
}

/// Derive one child terminal when splitting an existing block. Invalid
/// prepared/retired outputs retain their tags without becoming accessible.
pub fn split_terminal_descriptor(
    descriptor: u64,
    level: usize,
    index: usize,
) -> Result<u64, PageTableError> {
    let (mask, child_mask, shift, page) = match level {
        1 => (PA_MASK_1GIB, PA_MASK_2MIB, 21, false),
        2 => (PA_MASK_2MIB, PA_MASK_4KIB, 12, true),
        _ => return Err(PageTableError::BadAddress),
    };
    if index >= 512 {
        return Err(PageTableError::BadAddress);
    }
    let output = descriptor & mask;
    if descriptor & VALID == 0 && output == 0 {
        return Ok(0);
    }
    let attrs = descriptor & !mask & !TYPE_BITS;
    let ty = if page { TYPE_TABLE_OR_PAGE } else { TYPE_BLOCK };
    let result = ((output + ((index as u64) << shift)) & child_mask) | attrs | ty;
    Ok(if descriptor & VALID == 0 {
        result & !VALID
    } else {
        result
    })
}

/// Whether a sub-table whose entries are descriptors at `level` may be
/// reclaimed at all: only L3 tables (under an L2 entry) and L2 tables (under
/// an L1 entry). L1 tables under the L0 root are never freed. The host
/// reclaim walk ([`PageTableManager::unmap_aliased`]) and the guest
/// executor's reclaiming Terminal op share this definition.
pub(crate) const fn sub_table_level_reclaimable(level: usize) -> bool {
    matches!(level, 2 | 3)
}

/// Whether the table page `pa` may be a runtime spare table of the MM whose
/// root (the first byte of its primary arena) is `root`: never one of the
/// primary arena's boot tables (null guard, kernel hole, Rosetta alias),
/// which must never be freed. A page of an extension arena is spare. Callers
/// bound the rest: the host by each arena's bump cursor, EL1 by the table
/// view it can reach.
pub(crate) fn spare_table(root: u64, pa: u64) -> bool {
    pa.is_multiple_of(PT_PAGE) && !(pa >= root && pa - root < SPARE_START_OFFSET)
}

/// Whether one entry of a sub-table at `level`, covering `entry_va`, records
/// nothing a rebuild could not reproduce, so freeing its table (and zeroing
/// the parent entry) loses no information. A table is reclaimable exactly
/// when it is spare and every one of its 512 entries satisfies this.
///
/// "VALID clear" is NOT that test. An invalid leaf that retains a
/// non-identity output is the normal shape of every armed-but-untouched
/// sparse-arena page, of every `PROT_NONE`/`MADV_DONTNEED` page whose frame
/// the mm still owns, and of every pending materialization receipt: the next
/// protection commit republishes exactly that output in place. Freeing such
/// a table and re-splitting the emptied parent later handed those pages
/// fabricated outputs (`cpython-concurrent_futures`' fork child validator:
/// "stage-1 VA 0x6008405000 resolves to IPA 0x5000, expected
/// 0x9c19205000"; the parent had been reading and writing IPA 0x5000
/// silently).
///
/// Reclaimable entries are: empty (no output), identity (a rebuild yields
/// the same address), or RETIRED by `munmap` (the lease is gone; the
/// retained address is only a reuse signal). The host editor and the guest
/// executor share this one definition.
/// The parts of `[va, end)` outside the Carrick-owned EL1 COW copy window,
/// or `None` when the range does not intersect it. Host range edits apply to
/// these parts only, so the window's idle leaves (and the L3 table holding
/// them) are exactly what [`PageTableManager::provision_cow_copy_window`]
/// left.
fn around_cow_copy_window(va: u64, end: u64) -> Option<[(u64, u64); 2]> {
    use descriptor_txn::copy_window::{COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN};
    if end <= va || !descriptor_txn::copy_window::overlaps_cow_copy_window(va, end - va) {
        return None;
    }
    let window_end = COW_COPY_WINDOW_BASE + COW_COPY_WINDOW_LEN;
    Some([
        (va, COW_COPY_WINDOW_BASE.max(va)),
        (window_end.min(end), end),
    ])
}

pub(crate) fn reclaimable_entry(desc: u64, level: usize, entry_va: u64) -> bool {
    if desc & VALID != 0 {
        return false;
    }
    // The idle EL1 COW copy leaves look like reclaimable identity leaves, but
    // their table is what lets EL1 map a copy without allocating.
    let (span, _) = PageTableManager::level_span(level);
    if descriptor_txn::copy_window::overlaps_cow_copy_window(entry_va, span) {
        return false;
    }
    if !PageTableManager::records_output(desc, level) || desc & SW_RETIRED != 0 {
        return true;
    }
    let (_, mask) = PageTableManager::level_span(level);
    desc & mask == entry_va & mask
}

/// The outcome of an edit applied to a page-table range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageTableApplyOutcome {
    /// Whether any descriptor in the page tables was changed.
    pub changed: bool,
    /// Whether any previously-VALID descriptor was modified, or a valid block
    /// was split/coalesced, requiring an architectural TLB invalidation.
    /// Validating a previously-invalid descriptor does NOT require a flush on
    /// AArch64 because invalid translations are never cached in the TLB.
    pub flush_required: bool,
}

impl PageTableApplyOutcome {
    #[must_use]
    pub const fn new(changed: bool, flush_required: bool) -> Self {
        Self {
            changed,
            flush_required,
        }
    }
}

impl core::ops::BitOr for PageTableApplyOutcome {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self {
            changed: self.changed | rhs.changed,
            flush_required: self.flush_required | rhs.flush_required,
        }
    }
}

impl core::ops::BitOrAssign for PageTableApplyOutcome {
    fn bitor_assign(&mut self, rhs: Self) {
        self.changed |= rhs.changed;
        self.flush_required |= rhs.flush_required;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableError {
    /// No spare table pages left to split a block.
    OutOfTables,
    /// A guest VA whose translation path leaves the page-table region, or an
    /// intermediate descriptor is unexpectedly unmapped.
    BadAddress,
    /// Extension arenas exist but no `TableArenaSource` is installed.
    MissingArenaSource,
    /// A conflicting `TableArenaSource` bound to another lease is already installed.
    ConflictingArenaSource,
    /// Host backing pointer for the page-table arena at base IPA was unresolved.
    UnresolvedArena(u64),
    /// An output address in the in-kernel GIC's guest-physical window
    /// (the caller-supplied excluded IPA interval): a stage-1 leaf there would
    /// give the guest MMIO access to the distributor or a redistributor.
    GicWindowOutput,
    /// Metadata allocation failed or was refused.
    MetadataAllocation,
    /// A host store to live descriptors on the lane where guest EL1 owns
    /// them. The edit must be submitted as a guest descriptor transaction.
    GuestOwnsLiveDescriptors,
    /// A single-leaf edit named the Carrick-owned EL1 COW copy window
    /// ([`descriptor_txn::copy_window::COW_COPY_WINDOW_BASE`]), whose leaves
    /// only provisioning and the bounded EL1 copy may write.
    CarrickOwnedWindow,
}

impl core::fmt::Display for PageTableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfTables => write!(f, "out of page tables"),
            Self::BadAddress => write!(f, "bad address"),
            Self::MissingArenaSource => write!(f, "missing arena source"),
            Self::ConflictingArenaSource => write!(f, "conflicting arena source"),
            Self::UnresolvedArena(base) => {
                write!(
                    f,
                    "unresolved stage-1 arena host backing at IPA {:#x}",
                    base
                )
            }
            Self::GicWindowOutput => write!(f, "output address in the in-kernel GIC window"),
            Self::MetadataAllocation => write!(f, "metadata allocation failed"),
            Self::GuestOwnsLiveDescriptors => {
                write!(f, "guest EL1 owns the live stage-1 descriptors")
            }
            Self::CarrickOwnedWindow => {
                write!(f, "edit names the Carrick-owned EL1 COW copy window")
            }
        }
    }
}

impl core::error::Error for PageTableError {}

/// Per-level table index for `va` (4 KiB granule, 40-bit IPA).
pub fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

/// Diagnostic: walk a raw stage-1 long-descriptor table image for `va`,
/// returning the descriptor read at each level `[L0, L1, L2, L3]`. A level not
/// reached (an earlier block descriptor terminated the walk, or a descriptor
/// was invalid, or the table PA fell outside the region) is left `0`. `bytes`
/// is the live page-table region, `base` the PA mapped at byte offset 0. Lets a
/// fault handler PROVE whether the leaf PTE is invalid IN MEMORY (a logic bug)
/// versus valid-in-memory but stale in the faulting vCPU's TLB (a coherence
/// bug) — the two have opposite fixes.
pub fn walk_descriptors(bytes: &[u8], base: u64, va: u64) -> [u64; 4] {
    let idx = indices(va);
    let mut out = [0u64; 4];
    let mut table_off: usize = 0; // L0 table at byte offset 0
    for level in 0..4 {
        let off = table_off + idx[level] * 8;
        if off + 8 > bytes.len() {
            break;
        }
        let mut desc = 0u64;
        for (i, b) in bytes[off..off + 8].iter().enumerate() {
            desc |= (*b as u64) << (i * 8);
        }
        out[level] = desc;
        if desc & VALID == 0 {
            break; // invalid descriptor: walk stops here
        }
        if level == 3 || desc & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            break; // L3 page, or an L1/L2 block descriptor: leaf reached
        }
        let child_pa = desc & PA_MASK_TABLE;
        let Some(child_off) = child_pa.checked_sub(base) else {
            break;
        };
        table_off = child_off as usize;
    }
    out
}

/// Diagnostic: the same walk as [`walk_descriptors`], reading the LIVE host
/// backing in place instead of a copy of it.
///
/// [`walk_descriptors`] needs an owned `&[u8]` of the whole region, so a caller
/// holding only a host pointer had to copy `LINUX_PAGE_TABLES_SIZE` (1.75 MiB)
/// to read four 8-byte descriptors. On the frame-COW fault path that copy is
/// per fault, which made a diagnostic probe the most expensive thing in the
/// handler. This reads the eight bytes it actually needs.
///
/// Descriptors are read as acquire loads, matching
/// [`PageTableManager::debug_walk_host`], so a walk concurrent with a sibling's
/// break-before-make publication observes a whole descriptor rather than a
/// torn one. Deliberately independent of any [`PageTableManager`]: the point of
/// a live walk is to compare hardware-visible bytes against the software model,
/// so it must not consult the model to find them.
///
/// # Safety
/// `host` must point at a live mapping of at least `len` bytes whose byte
/// offset 0 is the PA `base`, and must stay mapped for the call.
pub unsafe fn walk_descriptors_host(host: *const u8, len: usize, base: u64, va: u64) -> [u64; 4] {
    use core::sync::atomic::{AtomicU64, Ordering};

    let idx = indices(va);
    let mut out = [0u64; 4];
    let mut table_off: usize = 0; // L0 table at byte offset 0
    for level in 0..4 {
        let off = table_off + idx[level] * 8;
        if off + 8 > len {
            break;
        }
        // SAFETY: `off + 8 <= len` was just checked, every descriptor offset is
        // 8-byte aligned (table offsets are page-aligned, indices scale by 8),
        // and the caller guarantees the mapping covers `len` bytes.
        let desc = unsafe {
            let slot = host.add(off).cast::<AtomicU64>();
            (*slot).load(Ordering::Acquire)
        };
        out[level] = desc;
        if desc & VALID == 0 {
            break; // invalid descriptor: walk stops here
        }
        if level == 3 || desc & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            break; // L3 page, or an L1/L2 block descriptor: leaf reached
        }
        let child_pa = desc & PA_MASK_TABLE;
        let Some(child_off) = child_pa.checked_sub(base) else {
            break;
        };
        table_off = child_off as usize;
    }
    out
}

/// Reconstruct the spare-pool bump cursor from an existing table image: one
/// past the LAST non-zero spare page. The pristine boot image has an all-zero
/// spare tail (cursor = `SPARE_START_OFFSET`, the historical constant), but the
/// boot-time ELF read-only-span pass now allocates spare sub-tables BEFORE the
/// runtime manager is (lazily) built from the live backing — resetting the
/// cursor over those live tables would re-hand them out and corrupt the walk.
/// Taking one-past-the-LAST non-zero page (not the first all-zero page) also
/// treats any zeroed hole as used — safe (wasted at worst), never re-issued.
fn discover_next_free_spare(bytes: &[u8]) -> u64 {
    let spare = bytes.get(SPARE_START_OFFSET as usize..).unwrap_or_default();
    discover_spare_pages(spare.chunks_exact(PT_PAGE as usize))
}

fn discover_spare_pages<'a>(
    pages: impl DoubleEndedIterator<Item = &'a [u8]> + ExactSizeIterator,
) -> u64 {
    // Only the last occupied page determines the cursor. Keep zero holes
    // below it reserved, and compare whole pages so the zero tail uses the
    // platform's bulk comparison instead of a byte-at-a-time predicate.
    const ZERO_PAGE: [u8; PT_PAGE as usize] = [0; PT_PAGE as usize];
    pages
        .enumerate()
        .rev()
        .find(|(_, page)| *page != ZERO_PAGE)
        .map_or(SPARE_START_OFFSET, |(index, _)| {
            SPARE_START_OFFSET + (index as u64 + 1) * PT_PAGE
        })
}

/// Location of a descriptor within a possibly multi-arena page-table structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TableLocation {
    pub arena: usize,
    pub offset: usize,
}

impl TableLocation {
    #[inline]
    #[must_use]
    pub const fn new(arena: usize, offset: usize) -> Self {
        Self { arena, offset }
    }

    #[inline]
    #[must_use]
    pub const fn entry(self, index: usize) -> Self {
        Self {
            arena: self.arena,
            offset: self.offset + index * 8,
        }
    }
}

/// Typed identifier for a `TableArenaSource`, uniquely identified by its stage-1 root slot base.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TableArenaSourceId(pub SubstrateGpa);

impl TableArenaSourceId {
    #[inline]
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(SubstrateGpa(raw))
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0.0
    }
}

/// Provider of additional 2 MiB root slots when the primary stage-1 arena is exhausted.
pub trait TableArenaSource: core::fmt::Debug + Send + 'static {
    /// Return the typed identity of this arena source.
    fn id(&self) -> TableArenaSourceId;

    /// Allocate an additional 2 MiB root slot.
    fn take_arena(&mut self) -> Option<SubstrateGpa>;

    /// Return an unused root slot to the allocator.
    fn return_arena(&mut self, arena: SubstrateGpa);
}

/// Resolves the host backing pointer for a stage-1 table arena base address.
///
/// # Safety
/// Implementations must guarantee:
/// - If `host_ptr_for_range(base, len)` / `host_ptr_for_base(base)` returns `Some(ptr)`,
///   `ptr` points to valid, resident host memory of at least `len` bytes (or arena capacity),
///   aligned to at least 8 bytes.
/// - If `host_const_ptr_for_range(base, len)` / `host_const_ptr_for_base(base)` returns `Some(ptr)`,
///   `ptr` points to valid, resident host memory of at least `len` bytes (or arena capacity),
///   aligned to at least 8 bytes.
/// - The host memory must remain valid and resident for the duration of the access or be
///   protected by retained ownership/pins within the resolver.
pub unsafe trait HostArenaResolver {
    /// Return the writable host pointer for the arena at `base` covering at least `len` bytes.
    fn host_ptr_for_range(&self, base: u64, _len: usize) -> Option<*mut u8> {
        self.host_ptr_for_base(base)
    }

    /// Return the writable host pointer for the arena with guest-physical base `base`.
    fn host_ptr_for_base(&self, _base: u64) -> Option<*mut u8> {
        None
    }

    /// Return the readable host pointer for the arena at `base` covering at least `len` bytes.
    fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
        self.host_ptr_for_range(base, len).map(|p| p.cast_const())
    }

    /// Return the readable host pointer for the arena with guest-physical base `base`.
    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.host_ptr_for_base(base).map(|p| p.cast_const())
    }

    /// Record the populated prefix (high-water mark in bytes) for the arena at `base`.
    ///
    /// Pooled root slot handles track this so that on recycling, any host bytes an
    /// occupant wrote during its lifetime are guaranteed to be zero-filled before
    /// the slot is handed to the next occupant.
    fn record_populated_prefix(&self, _base: u64, _prefix: usize) {}

    /// Called by [`PageTableManager::sync_to_host`] immediately BEFORE it
    /// stores a descriptor that makes `[output, output + len)` executable at
    /// EL0 where the word it replaces did not (invalid, kernel-only, UXN, or a
    /// different output). This is the single host-lane point every
    /// user-executable leaf crosses on its way to hardware, so it is where
    /// the frame's instruction cache is made coherent with its contents, as
    /// arm64 Linux does in `set_pte_at` (`__sync_icache_dcache`): the frame
    /// may have held other code in an earlier life, and a guest that writes
    /// instructions into a fresh executable page owes no cache maintenance
    /// of its own. Required, with no default, so no resolver can skip it.
    /// An error aborts the publication before the descriptor is stored.
    fn publish_user_executable(&self, output: u64, len: u64) -> Result<(), PageTableError>;
}

/// The output page a terminal descriptor makes executable at EL0, if any: a
/// valid, EL0-accessible (`AP[1]`) L3 page (`0b11` in a non-table word) with
/// UXN clear. Blocks are deliberately not announced: the only EL0-executable
/// blocks are the boot image's static identity aperture, which every MM image
/// carries unchanged and the EL0 entry trampoline's `ic ialluis` makes
/// coherent; frames a process can recycle are always published page by page.
pub fn user_executable_output(descriptor: u64) -> Option<(u64, u64)> {
    (descriptor & VALID != 0
        && descriptor & TYPE_BITS == TYPE_TABLE_OR_PAGE
        && descriptor & AP_EL0_ACCESS != 0
        && descriptor & UXN == 0)
        .then_some((descriptor & PA_MASK_4KIB, PT_PAGE))
}

/// Whether storing `new` over the live word `old` newly makes an output range
/// executable at EL0, and which: an unchanged executable output (a permission
/// or attribute change on the same frame) publishes nothing new.
pub fn newly_user_executable(old: u64, new: u64) -> Option<(u64, u64)> {
    let published = user_executable_output(new)?;
    (user_executable_output(old) != Some(published)).then_some(published)
}

unsafe impl HostArenaResolver for (u64, *mut u8) {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        (self.0 == base).then_some(self.1)
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl HostArenaResolver for (u64, *const u8) {
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        (self.0 == base).then_some(self.1)
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        (self.0 == base).then_some(self.1)
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl<const N: usize> HostArenaResolver for [(u64, *mut u8); N] {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl<const N: usize> HostArenaResolver for &[(u64, *mut u8); N] {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl HostArenaResolver for &[(u64, *mut u8)] {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl<const N: usize> HostArenaResolver for [(u64, *const u8); N] {
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl<const N: usize> HostArenaResolver for &[(u64, *const u8); N] {
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl HostArenaResolver for &[(u64, *const u8)] {
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.iter().find_map(|&(b, p)| (b == base).then_some(p))
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ConstFnResolver<F>(F);

unsafe impl<F> HostArenaResolver for ConstFnResolver<F>
where
    F: Fn(u64) -> Option<*const u8>,
{
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        (self.0)(base)
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        (self.0)(base)
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

unsafe impl<F> HostArenaResolver for &ConstFnResolver<F>
where
    F: Fn(u64) -> Option<*const u8>,
{
    fn host_const_ptr_for_range(&self, base: u64, _len: usize) -> Option<*const u8> {
        (self.0)(base)
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        (self.0)(base)
    }

    /// A page-table-only resolver knows no guest frame to make coherent:
    /// refusing keeps executable publication on a frame-aware resolver.
    fn publish_user_executable(&self, output: u64, _len: u64) -> Result<(), PageTableError> {
        Err(PageTableError::UnresolvedArena(output))
    }
}

/// Wrap a closure as a `HostArenaResolver`.
///
/// # Safety
/// The provided closure `f` must return valid host pointers adhering to `HostArenaResolver`.
pub unsafe fn const_resolver<F: Fn(u64) -> Option<*const u8>>(f: F) -> ConstFnResolver<F> {
    ConstFnResolver(f)
}

unsafe impl HostArenaResolver for Arc<dyn HostArenaResolver + Send + Sync> {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        (**self).host_ptr_for_range(base, len)
    }

    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        (**self).host_ptr_for_base(base)
    }

    fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
        (**self).host_const_ptr_for_range(base, len)
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        (**self).host_const_ptr_for_base(base)
    }

    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        (**self).record_populated_prefix(base, prefix);
    }

    fn publish_user_executable(&self, output: u64, len: u64) -> Result<(), PageTableError> {
        (**self).publish_user_executable(output, len)
    }
}

unsafe impl HostArenaResolver for &Arc<dyn HostArenaResolver + Send + Sync> {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        (***self).host_ptr_for_range(base, len)
    }

    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        (***self).host_ptr_for_base(base)
    }

    fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
        (***self).host_const_ptr_for_range(base, len)
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        (***self).host_const_ptr_for_base(base)
    }

    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        (***self).record_populated_prefix(base, prefix);
    }

    fn publish_user_executable(&self, output: u64, len: u64) -> Result<(), PageTableError> {
        (***self).publish_user_executable(output, len)
    }
}

/// Storage kind for a stage-1 translation table arena.
#[derive(Debug)]
pub enum TableArenaStorage {
    /// Owned software buffer used for offline construction, boot images, and detached snapshots.
    Owned(Vec<u8>),
    /// Live hardware-visible backing. No software shadow bytes are stored; reads and
    /// observation query live host memory directly.
    Live,
}

/// The host's planning view of a guest-owned image: the descriptor words of
/// every arena, each resolved through the image's live host resolver. It
/// only loads; a guest-owned graph is stored to by EL1 alone.
struct ArenaTableWords<'a> {
    arenas: &'a [TableArena],
    resolver: &'a (dyn HostArenaResolver + Send + Sync),
}

impl descriptor_txn::LiveDescriptorWords for ArenaTableWords<'_> {
    fn load(&self, pa: u64) -> Result<u64, descriptor_txn::DescriptorRefusal> {
        use descriptor_txn::DescriptorRefusal;
        if !pa.is_multiple_of(8) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let arena = self
            .arenas
            .iter()
            .find(|arena| pa >= arena.base && pa - arena.base < arena.capacity as u64)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        let host = self
            .resolver
            .host_const_ptr_for_range(arena.base, arena.capacity)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        // SAFETY: the resolver maps the whole arena resident and aligned; the
        // offset is in bounds and 8-byte aligned.
        let word = unsafe {
            &*host
                .add((pa - arena.base) as usize)
                .cast::<core::sync::atomic::AtomicU64>()
        };
        Ok(word.load(core::sync::atomic::Ordering::Acquire))
    }

    fn compare_exchange(
        &self,
        _pa: u64,
        _current: u64,
        _new: u64,
    ) -> Result<bool, descriptor_txn::DescriptorRefusal> {
        Err(descriptor_txn::DescriptorRefusal::BadRange)
    }

    fn store_unlinked(
        &self,
        _pa: u64,
        _value: u64,
    ) -> Result<(), descriptor_txn::DescriptorRefusal> {
        Err(descriptor_txn::DescriptorRefusal::BadRange)
    }

    fn publish_barrier(&self) {}

    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

/// The host's STORING view of a guest-owned image, for the one case the
/// host may store to it: while it holds the MM's EL1 editor exclusion, so
/// no EL1 editor can store concurrently. Same multi-arena resolution as
/// [`ArenaTableWords`]; maintenance is the caller's.
struct ArenaLiveWords<'a, M: descriptor_txn::TableMaintenance + ?Sized> {
    arenas: &'a [TableArena],
    resolver: &'a (dyn HostArenaResolver + Send + Sync),
    maintenance: &'a M,
}

impl<M: descriptor_txn::TableMaintenance + ?Sized> ArenaLiveWords<'_, M> {
    fn word(
        &self,
        pa: u64,
    ) -> Result<&core::sync::atomic::AtomicU64, descriptor_txn::DescriptorRefusal> {
        use descriptor_txn::DescriptorRefusal;
        if !pa.is_multiple_of(8) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let arena = self
            .arenas
            .iter()
            .find(|arena| pa >= arena.base && pa - arena.base < arena.capacity as u64)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        let host = self
            .resolver
            .host_ptr_for_range(arena.base, arena.capacity)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        // SAFETY: the resolver maps the whole arena resident, aligned and
        // writable; the offset is in bounds and 8-byte aligned.
        Ok(unsafe {
            &*host
                .add((pa - arena.base) as usize)
                .cast::<core::sync::atomic::AtomicU64>()
        })
    }
}

impl<M: descriptor_txn::TableMaintenance + ?Sized> descriptor_txn::LiveDescriptorWords
    for ArenaLiveWords<'_, M>
{
    fn load(&self, pa: u64) -> Result<u64, descriptor_txn::DescriptorRefusal> {
        Ok(self.word(pa)?.load(core::sync::atomic::Ordering::Acquire))
    }

    fn compare_exchange(
        &self,
        pa: u64,
        current: u64,
        new: u64,
    ) -> Result<bool, descriptor_txn::DescriptorRefusal> {
        use core::sync::atomic::Ordering;
        Ok(self
            .word(pa)?
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), descriptor_txn::DescriptorRefusal> {
        self.word(pa)?
            .store(value, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn publish_barrier(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.maintenance.publish_barrier();
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        self.maintenance.invalidate_range(va, len);
    }
}

#[derive(Debug)]
pub struct TableArena {
    pub base: u64,
    pub storage: TableArenaStorage,
    pub next_free: u64,
    pub capacity: usize,
    // Empty allocation retained solely for a later owned snapshot. Live reads
    // never consult it; its length is zero whenever storage is Live.
    snapshot_scratch: Vec<u8>,
}

impl TableArena {
    fn make_live_storage(&mut self) {
        if let TableArenaStorage::Owned(mut bytes) =
            core::mem::replace(&mut self.storage, TableArenaStorage::Live)
        {
            bytes.clear();
            if bytes.capacity() >= self.snapshot_scratch.capacity() {
                self.snapshot_scratch = bytes;
            }
        }
    }

    fn prepare_owned_storage(&mut self) {
        if self.is_live() {
            self.storage = TableArenaStorage::Owned(core::mem::take(&mut self.snapshot_scratch));
        }
    }

    #[inline]
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.storage, TableArenaStorage::Live)
    }

    #[inline]
    #[must_use]
    pub fn allocated_span(&self) -> u64 {
        match self.storage {
            TableArenaStorage::Owned(ref bytes) => (bytes.len() as u64).max(self.next_free),
            TableArenaStorage::Live => self.next_free,
        }
    }

    /// Bytes that may contain a descriptor reached through a hardware-visible
    /// table pointer. A second exact-MM editor can grow a live primary arena
    /// after this manager cached its allocator cursor; the pointer is the
    /// authority for reading that table, while owned snapshots remain bounded
    /// by their populated prefix.
    #[inline]
    fn descriptor_span(&self) -> u64 {
        match self.storage {
            TableArenaStorage::Owned(_) => self.allocated_span(),
            TableArenaStorage::Live => self.capacity as u64,
        }
    }

    #[inline]
    #[must_use]
    pub fn current_pages(&self) -> usize {
        match self.storage {
            TableArenaStorage::Owned(ref bytes) => bytes.len() / PT_PAGE as usize,
            TableArenaStorage::Live => (self.next_free as usize) / PT_PAGE as usize,
        }
    }
}

impl Clone for TableArena {
    fn clone(&self) -> Self {
        let storage = match self.storage {
            TableArenaStorage::Owned(ref bytes) => {
                let mut new_bytes = Vec::with_capacity(self.capacity);
                let prefix_len = (self.next_free as usize).min(bytes.len());
                new_bytes.extend_from_slice(&bytes[..prefix_len]);
                TableArenaStorage::Owned(new_bytes)
            }
            TableArenaStorage::Live => TableArenaStorage::Live,
        };
        Self {
            snapshot_scratch: Vec::new(),
            base: self.base,
            storage,
            next_free: self.next_free,
            capacity: self.capacity,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.base = source.base;
        self.next_free = source.next_free;
        self.capacity = source.capacity;
        if matches!(source.storage, TableArenaStorage::Live) {
            self.make_live_storage();
        } else {
            self.prepare_owned_storage();
        }
        match (&mut self.storage, &source.storage) {
            (TableArenaStorage::Owned(my_bytes), TableArenaStorage::Owned(src_bytes)) => {
                my_bytes.clear();
                if my_bytes.capacity() < source.capacity {
                    my_bytes.reserve(source.capacity);
                }
                let prefix_len = (source.next_free as usize).min(src_bytes.len());
                my_bytes.extend_from_slice(&src_bytes[..prefix_len]);
            }
            (dest_storage, TableArenaStorage::Live) => {
                *dest_storage = TableArenaStorage::Live;
            }
            (dest_storage, TableArenaStorage::Owned(src_bytes)) => {
                let mut new_bytes = Vec::with_capacity(source.capacity);
                let prefix_len = (source.next_free as usize).min(src_bytes.len());
                new_bytes.extend_from_slice(&src_bytes[..prefix_len]);
                *dest_storage = TableArenaStorage::Owned(new_bytes);
            }
        }
    }
}

/// Mutable editor over stage-1 page-table descriptors.
///
/// For offline images, descriptors are owned in memory (`TableArenaStorage::Owned`).
/// For live address spaces, hardware-visible memory is the authoritative storage
/// (`TableArenaStorage::Live`), with uncommitted transaction writes overlaid in `staged`.
pub struct PageTableManager {
    pub arenas: Vec<TableArena>,
    layout: PageTableLayoutConfig,
    /// New or rebuilt terminal descriptors must carry nG. Derived from the
    /// canonical low user leaf so a rebased/cloned HVPatch table retains its
    /// ASID-scoped construction mode without a second out-of-band authority.
    asid_scoped_leaves: bool,
    /// PAs of spare sub-tables freed by coalescing, reused before bumping. Only
    /// populated while single-vCPU (coalesce is gated on that), so a reused page
    /// can never be referenced by a sibling's stale walk cache.
    free_tables: Vec<u64>,
    /// Whether more than one guest vCPU is currently live. Set per-edit by the
    /// engine from the process-wide live-vCPU count; gates coalescing (a
    /// break-before-make structural change that is unsafe without an all-vCPU
    /// TLB flush HVF can't give one vCPU).
    multi_vcpu: bool,
    /// Whether no hardware walker can currently reach this image. Replacing a
    /// valid table descriptor with a valid block is an architectural
    /// break-before-make transition. Carrick's live editor has one descriptor
    /// batch and one trailing TLBI, so only a detached fork image may compact
    /// tables until the live publisher grows a two-phase protocol.
    offline_private_image: bool,
    /// Whether THIS thread's stage-1 edits are exclusive (see
    /// `carrick_hal::stage1_exclusive`). Distinct from `multi_vcpu`, which asks
    /// whether EAGER coalescing is worth doing; this asks only whether freeing a
    /// table for REUSE is safe. Only the on-demand sweep in `alloc_table`
    /// consults it.
    stage1_exclusive: bool,
    /// Set when a teardown invalidated descriptors, so a sub-table MIGHT now be
    /// empty; cleared by the reclaim sweep. Without it the sweep re-walks the
    /// table graph on every allocation once the pool sits near its limit, which
    /// starves the vCPU badly enough to trip the sibling start gate.
    reclaim_pending: bool,
    /// Descriptors edited since the last sync, in write order, tagged
    /// `is_table_pointer`. The host sync replays them as aligned atomic stores,
    /// writing a table descriptor (which exposes a sub-table to the guest's
    /// hardware walker) only AFTER its child entries are visible — the
    /// break-before-make ordering that keeps a concurrent sibling walk safe
    /// without quiescing.
    dirty: Vec<(TableLocation, bool)>,
    /// Uncommitted writes overlaid during active transactions before sync_to_host.
    staged: hashbrown::HashMap<TableLocation, (u64, bool)>,
    /// Live host backing resolver for hardware-visible page table memory.
    resolver: Option<Arc<dyn HostArenaResolver + Send + Sync>>,
    /// Pre-images of every descriptor word written since [`Self::begin_undo`],
    /// in write order, with the scalar state to restore alongside them.
    undo: Option<UndoJournal>,
    /// Guest EL1's editor never allocates table pages: the host's owned copy
    /// cannot see EL1's allocations, and a fresh table can be all zero, so a
    /// content-discovered cursor would hand one page to both. EL1 publishes
    /// only into existing tables and hands the rest back to the host.
    table_allocation_forbidden: bool,
    /// The only venue allowed to store into this image's live backing.
    live_descriptor_owner: LiveDescriptorOwner,
}

impl core::fmt::Debug for PageTableManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageTableManager")
            .field("arenas", &self.arenas)
            .field("layout", &self.layout)
            .field("asid_scoped_leaves", &self.asid_scoped_leaves)
            .field("free_tables", &self.free_tables)
            .field("multi_vcpu", &self.multi_vcpu)
            .field("offline_private_image", &self.offline_private_image)
            .field("stage1_exclusive", &self.stage1_exclusive)
            .field("reclaim_pending", &self.reclaim_pending)
            .field("dirty", &self.dirty)
            .field("staged", &self.staged)
            .field("is_live", &self.is_live())
            .field("undo", &self.undo)
            .field("live_descriptor_owner", &self.live_descriptor_owner)
            .finish()
    }
}

/// Pre-transaction state captured by [`PageTableManager::begin_undo`].
#[derive(Clone, Debug, Default)]
struct UndoJournal {
    /// `(location, value before the write)`, in write order. Replayed in
    /// REVERSE so repeated writes to one location unwind to the oldest value.
    words: Vec<(TableLocation, u64)>,
    arena_next_frees: Vec<u64>,
    arenas_len: usize,
    free_tables: Vec<u64>,
    reclaim_pending: bool,
    /// Length of `dirty` when the journal opened, so a rollback can drop
    /// exactly the entries the failed transaction appended.
    dirty_len: usize,
    /// Whether any walker-visible descriptor word held a VALID descriptor
    /// when this transaction FIRST wrote it. Only the pre-transaction word
    /// matters: `sync_to_host` stores each dirty location's final shadow word,
    /// so a word that went valid and then invalid inside one transaction never
    /// reaches hardware as valid. Table pages being zeroed for reuse are
    /// excluded: they are unlinked, so no walk can cache them. A transaction
    /// that only turned invalid words valid needs publication ordering but no
    /// stage-1 TLB maintenance.
    replaced_valid: bool,
    /// Locations already journalled by this transaction, so only the first
    /// pre-image of each word decides `replaced_valid`.
    first_written: hashbrown::HashSet<(usize, usize)>,
    /// Pre-admitted storage for extension arena bases popped during rollback,
    /// ensuring rollback_undo performs zero heap allocations.
    returned_bases: Vec<u64>,
}

impl PageTableManager {
    /// Caller-supplied layout constraints retained by this image.
    pub fn layout(&self) -> PageTableLayoutConfig {
        self.layout
    }

    pub fn new(mut bytes: Vec<u8>, base: u64, layout: PageTableLayoutConfig) -> Self {
        let capacity = bytes.len();
        let next_free = discover_next_free_spare(&bytes).min(capacity as u64);
        bytes.truncate(next_free as usize);
        Self::from_occupied_prefix(bytes, capacity, base, layout)
    }

    /// Build the editor over a borrowed snapshot of a live table region of
    /// `live.len()` bytes (the primary capacity). Only the occupied prefix
    /// (through the last non-zero table page) is copied; the zero tail stays
    /// capacity that `alloc_table` grows into on demand.
    pub fn from_live_image(live: &[u8], base: u64, layout: PageTableLayoutConfig) -> Self {
        Self::from_image_prefix(live, live.len(), base, layout)
    }

    /// [`Self::from_live_image`] over `image`, the leading bytes of a primary
    /// arena of `capacity` bytes whose remainder is zero (an exec plan's
    /// occupied-prefix payload, see [`Self::into_occupied_bytes`]).
    pub fn from_image_prefix(
        image: &[u8],
        capacity: usize,
        base: u64,
        layout: PageTableLayoutConfig,
    ) -> Self {
        let next_free = discover_next_free_spare(image).min(capacity as u64) as usize;
        let next_free = next_free.min(image.len());
        let mut bytes = image[..next_free].to_vec();
        // `discover_next_free_spare` never reports below the spare start,
        // which a short image may not reach.
        let floor = (SPARE_START_OFFSET as usize).min(capacity);
        if bytes.len() < floor {
            bytes.resize(floor, 0);
        }
        Self::from_occupied_prefix(bytes, capacity, base, layout)
    }

    /// `prefix` holds every non-zero table page of a primary arena of
    /// `capacity` bytes; everything past it is zero.
    fn from_occupied_prefix(
        bytes: Vec<u8>,
        capacity: usize,
        base: u64,
        layout: PageTableLayoutConfig,
    ) -> Self {
        let next_free = bytes.len() as u64;
        let asid_scoped_leaves =
            terminal_descriptor(walk_descriptors(&bytes, base, layout.user_leaf_check_va))
                & NON_GLOBAL
                != 0;
        Self {
            arenas: vec![TableArena {
                snapshot_scratch: Vec::new(),
                base,
                storage: TableArenaStorage::Owned(bytes),
                next_free,
                capacity,
            }],
            layout,
            asid_scoped_leaves,
            free_tables: Vec::new(),
            multi_vcpu: false,
            offline_private_image: false,
            stage1_exclusive: false,
            reclaim_pending: false,
            dirty: Vec::new(),
            staged: hashbrown::HashMap::new(),
            resolver: None,
            undo: None,
            table_allocation_forbidden: false,
            live_descriptor_owner: LiveDescriptorOwner::Host,
        }
    }

    /// Create a live PageTableManager bound to hardware-visible memory via `resolver`.
    ///
    /// # Safety
    /// `resolver` must return valid, resident, 8-byte aligned host backing pointers.
    pub unsafe fn new_live(
        base: u64,
        layout: PageTableLayoutConfig,
        primary_capacity: usize,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
    ) -> Result<Self, PageTableError> {
        let host_ptr = resolver
            .host_const_ptr_for_range(base, primary_capacity)
            .ok_or(PageTableError::UnresolvedArena(base))?;
        let walk = unsafe {
            walk_descriptors_host(host_ptr, primary_capacity, base, layout.user_leaf_check_va)
        };
        let asid_scoped_leaves = terminal_descriptor(walk) & NON_GLOBAL != 0;
        // The live image may already contain sub-tables allocated after the
        // boot template was copied (for example by the ELF read-only-span
        // pass). Reconstruct the bump cursor from hardware-visible bytes;
        // resetting it to SPARE_START_OFFSET would hand an occupied table page
        // out again and let the next edit corrupt the active walk.
        let live_bytes = unsafe { core::slice::from_raw_parts(host_ptr, primary_capacity) };
        let next_free = discover_next_free_spare(live_bytes);
        Ok(Self {
            arenas: vec![TableArena {
                snapshot_scratch: Vec::new(),
                base,
                storage: TableArenaStorage::Live,
                next_free,
                capacity: primary_capacity,
            }],
            layout,
            asid_scoped_leaves,
            free_tables: Vec::new(),
            multi_vcpu: false,
            offline_private_image: false,
            stage1_exclusive: false,
            reclaim_pending: false,
            dirty: Vec::new(),
            staged: hashbrown::HashMap::new(),
            resolver: Some(resolver),
            undo: None,
            table_allocation_forbidden: false,
            live_descriptor_owner: LiveDescriptorOwner::Host,
        })
    }

    /// Refuse every table-page allocation (see `table_allocation_forbidden`).
    pub fn forbid_table_allocation(&mut self) {
        self.table_allocation_forbidden = true;
    }

    /// Select the venue that owns this image's live descriptor stores.
    pub fn set_live_descriptor_owner(&mut self, owner: LiveDescriptorOwner) {
        self.live_descriptor_owner = owner;
    }

    /// The venue that owns this image's live descriptor stores.
    pub fn live_descriptor_owner(&self) -> LiveDescriptorOwner {
        self.live_descriptor_owner
    }

    fn refuse_guest_owned_live_store(&self) -> Result<(), PageTableError> {
        if self.live_descriptor_owner == LiveDescriptorOwner::Guest {
            return Err(PageTableError::GuestOwnsLiveDescriptors);
        }
        Ok(())
    }

    /// Reserve `count` unlinked table pages for one guest descriptor
    /// transaction, from any arena of this image: freed pages first, then the
    /// spare tail of the primary arena, then the extension arenas, then new
    /// extension arenas taken from `source` exactly as the host editor grows
    /// (every arena is a slot of the table pool EL1 reaches, see
    /// `carrick_el1_abi::stage1_table_pool_window`). The host remains the only
    /// allocator of table-page identity; EL1 fills and links the pages it
    /// uses. Nothing is reserved on failure; an arena taken from `source`
    /// stays with the image for later tables.
    pub fn reserve_table_grants(
        &mut self,
        count: usize,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<descriptor_txn::TableGrants, PageTableError> {
        if count > descriptor_txn::MAX_TABLE_GRANTS {
            return Err(PageTableError::OutOfTables);
        }
        if self.table_allocation_forbidden || self.arenas.is_empty() {
            return Err(PageTableError::OutOfTables);
        }
        let mut pages = [SubstrateGpa(0); descriptor_txn::MAX_TABLE_GRANTS];
        let mut reserved = 0;
        for &pa in self.free_tables.iter().rev() {
            if reserved == count {
                break;
            }
            pages[reserved] = SubstrateGpa(pa);
            reserved += 1;
        }
        let from_free = reserved;
        // Bump cursors, committed only once every page is found.
        let mut cursors = [(usize::MAX, 0u64); descriptor_txn::MAX_TABLE_GRANTS];
        let mut used_cursors = 0;
        let mut index = 0;
        while reserved < count {
            if index == self.arenas.len() {
                let Some(gpa) = source.as_mut().and_then(|source| source.take_arena()) else {
                    return Err(PageTableError::OutOfTables);
                };
                if let Err(error) = self.adopt_extension_arena(gpa) {
                    if let Some(source) = source.as_mut() {
                        source.return_arena(gpa);
                    }
                    return Err(error);
                }
            }
            let wanted = (count - reserved) as u64;
            if index == 0 {
                let arena = &self.arenas[0];
                let available = (arena.capacity as u64).saturating_sub(arena.next_free) / PT_PAGE;
                self.skip_occupied_primary_candidates(wanted.min(available))?;
            }
            let arena = &self.arenas[index];
            let available = (arena.capacity as u64).saturating_sub(arena.next_free) / PT_PAGE;
            let take = wanted.min(available);
            for page in 0..take {
                pages[reserved] = SubstrateGpa(arena.base + arena.next_free + page * PT_PAGE);
                reserved += 1;
            }
            if take != 0 {
                cursors[used_cursors] = (index, arena.next_free + take * PT_PAGE);
                used_cursors += 1;
            }
            index += 1;
        }
        let grants =
            descriptor_txn::TableGrants::new(&pages[..count]).ok_or(PageTableError::BadAddress)?;
        for &(arena_index, bump_end) in &cursors[..used_cursors] {
            if let TableArenaStorage::Owned(ref mut bytes) = self.arenas[arena_index].storage {
                let needed = bump_end as usize;
                if bytes.len() < needed {
                    bytes
                        .try_reserve(needed - bytes.len())
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                    bytes.resize(needed, 0);
                }
            }
        }
        self.free_tables
            .retain(|pa| !pages[..from_free].contains(&SubstrateGpa(*pa)));
        for &(arena_index, bump_end) in &cursors[..used_cursors] {
            self.arenas[arena_index].next_free = bump_end;
        }
        Ok(grants)
    }

    /// Append the extension arena at `gpa` (just taken from the image's
    /// source) with nothing issued yet.
    fn adopt_extension_arena(&mut self, gpa: SubstrateGpa) -> Result<(), PageTableError> {
        let capacity = self.layout.extension_arena_capacity;
        let storage = match self.arenas[0].storage {
            TableArenaStorage::Owned(_) => {
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(capacity).is_err() {
                    return Err(PageTableError::MetadataAllocation);
                }
                TableArenaStorage::Owned(bytes)
            }
            TableArenaStorage::Live => TableArenaStorage::Live,
        };
        if self.arenas.try_reserve(1).is_err() {
            return Err(PageTableError::MetadataAllocation);
        }
        self.arenas.push(TableArena {
            snapshot_scratch: Vec::new(),
            base: gpa.0,
            storage,
            next_free: 0,
            capacity,
        });
        Ok(())
    }

    /// Build the guest descriptor transaction for `op` on this guest-owned
    /// live image: plan it against the live primary arena without storing,
    /// then reserve exactly the table grants it needs. The caller submits the
    /// result and later settles its receipt with
    /// [`Self::settle_guest_descriptor_receipt`] (or
    /// [`Self::abandon_guest_descriptor_txn`] if it is withdrawn unclaimed).
    /// Execute a prepared guest descriptor transaction with the host as the
    /// MM's editor: the same journaled executor and receipt EL1's drain
    /// uses ([`descriptor_txn::execute_descriptor_txn`]), on the live words
    /// of every arena. `maintenance` performs each break-before-make
    /// invalidation the executor asks for; the caller invalidates the ASID
    /// when [`descriptor_txn::outcome_requires_invalidation`] says so,
    /// BEFORE settling the receipt.
    ///
    /// # Safety
    ///
    /// The caller holds this MM's EL1 editor exclusion for the whole call:
    /// no EL1 editor can store to these tables concurrently. The one caller
    /// is `Stage1Authority::execute_guest_descriptor_txn_as_host`, which
    /// demands the exclusion witness.
    pub unsafe fn execute_guest_descriptor_txn_as_host<M>(
        &self,
        txn: &descriptor_txn::DescriptorTxn,
        maintenance: &M,
    ) -> Result<descriptor_txn::DescriptorReceipt, GuestTxnPrepareError>
    where
        M: descriptor_txn::TableMaintenance + ?Sized,
    {
        if self.live_descriptor_owner != LiveDescriptorOwner::Guest {
            return Err(GuestTxnPrepareError::NotGuestOwned);
        }
        if !self.arenas.first().is_some_and(TableArena::is_live) {
            return Err(GuestTxnPrepareError::NotLive);
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        let words = ArenaLiveWords {
            arenas: &self.arenas,
            resolver: resolver.as_ref(),
            maintenance,
        };
        let mut journal = descriptor_txn::InlineJournal::new();
        Ok(descriptor_txn::execute_descriptor_txn(
            &words,
            SubstrateGpa(self.base()),
            txn,
            &mut journal,
        ))
    }

    /// Apply the submission waiting in `slot` for `mm_key` with the host as
    /// the MM's editor, exactly as EL1's drain applies it
    /// ([`descriptor_txn::apply_submitted_descriptor_txn`]): claim, execute,
    /// `invalidate_asid` when the outcome requires it, publish the receipt
    /// for its owner to settle. `Ok(None)`: nothing waiting for `mm_key`.
    ///
    /// # Safety
    ///
    /// As [`Self::execute_guest_descriptor_txn_as_host`]: the caller holds
    /// this MM's EL1 editor exclusion for the whole call.
    pub unsafe fn apply_submitted_descriptor_txn_as_host<M>(
        &self,
        slot: &descriptor_txn::DescriptorTxnSlot,
        mm_key: u64,
        maintenance: &M,
        invalidate_asid: impl FnOnce(),
    ) -> Result<Option<descriptor_txn::DescriptorReceipt>, GuestTxnPrepareError>
    where
        M: descriptor_txn::TableMaintenance + ?Sized,
    {
        if self.live_descriptor_owner != LiveDescriptorOwner::Guest {
            return Err(GuestTxnPrepareError::NotGuestOwned);
        }
        if !self.arenas.first().is_some_and(TableArena::is_live) {
            return Err(GuestTxnPrepareError::NotLive);
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        let words = ArenaLiveWords {
            arenas: &self.arenas,
            resolver: resolver.as_ref(),
            maintenance,
        };
        let mut journal = descriptor_txn::InlineJournal::new();
        Ok(descriptor_txn::apply_submitted_descriptor_txn(
            slot,
            mm_key,
            &words,
            SubstrateGpa(self.base()),
            &mut journal,
            invalidate_asid,
        ))
    }

    pub fn prepare_guest_descriptor_txn(
        &mut self,
        id: descriptor_txn::DescriptorTxnId,
        op: descriptor_txn::DescriptorOp,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<descriptor_txn::DescriptorTxn, GuestTxnPrepareError> {
        if self.live_descriptor_owner != LiveDescriptorOwner::Guest {
            return Err(GuestTxnPrepareError::NotGuestOwned);
        }
        if !self.arenas.first().is_some_and(TableArena::is_live) {
            return Err(GuestTxnPrepareError::NotLive);
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        // Planning only loads, from whichever arena holds each table.
        let words = ArenaTableWords {
            arenas: &self.arenas,
            resolver: resolver.as_ref(),
        };
        let root = SubstrateGpa(self.base());
        let plan = descriptor_txn::plan_descriptor_op(&words, root, op)
            .map_err(GuestTxnPrepareError::Refused)?;
        // A reclaiming edit may return no more tables than planned (the plan
        // never exceeds the budget); the receipt is checked against this
        // narrowed budget.
        let op = match op {
            descriptor_txn::DescriptorOp::Terminal { span, mut edit } => {
                edit.reclaim_budget = edit
                    .reclaim_budget
                    .min(u8::try_from(plan.reclaimed_tables).unwrap_or(u8::MAX));
                descriptor_txn::DescriptorOp::Terminal { span, edit }
            }
            other => other,
        };
        let tables = self
            .reserve_table_grants(plan.table_grants, source)
            .map_err(GuestTxnPrepareError::Manager)?;
        Ok(descriptor_txn::DescriptorTxn {
            id,
            root,
            op,
            tables,
        })
    }

    /// The guest descriptor operation that arms `[va, va + len)` for fork COW
    /// exactly as [`Self::set_fork_readonly`] (or [`Self::set_kernel_readonly`]
    /// for a kernel-only range) would on this image.
    pub fn fork_arm_op(
        &self,
        va: u64,
        len: u64,
        kernel_only: bool,
        executable: bool,
        adopt_private: bool,
    ) -> descriptor_txn::DescriptorOp {
        self.terminal_op(
            va,
            len,
            descriptor_txn::TerminalEdit::fork_arm(
                kernel_only,
                executable,
                adopt_private,
                self.asid_scoped_leaves,
                self.layout.excluded_ipa_start,
                self.layout.excluded_ipa_len,
            )
            .rule,
        )
    }

    /// A guest transaction applying `rule` over `[va, va+len)` exactly as
    /// [`Self::apply_rule`] would on this image (same nG scoping and GIC
    /// output exclusion).
    pub fn terminal_op(
        &self,
        va: u64,
        len: u64,
        rule: TerminalRule,
    ) -> descriptor_txn::DescriptorOp {
        descriptor_txn::DescriptorOp::Terminal {
            span: descriptor_txn::PageSpan::new(va, len),
            edit: descriptor_txn::TerminalEdit {
                rule,
                asid_scoped: self.asid_scoped_leaves,
                excluded_ipa: self.layout.excluded_ipa_start,
                excluded_len: self.layout.excluded_ipa_len,
                reclaim_budget: 0,
            },
        }
    }

    /// The guest descriptor operation for [`Self::unmap_aliased`] on this
    /// image: munmap retirement followed by reclaim of every spare sub-table
    /// it empties. [`Self::prepare_guest_descriptor_txn`] narrows the reclaim
    /// budget to its plan; a span that would empty more than
    /// [`descriptor_txn::MAX_RECLAIMED_TABLES`] tables is refused there with
    /// [`descriptor_txn::DescriptorRefusal::ReclaimCapacity`] and must be
    /// submitted in pieces.
    pub fn unmap_aliased_op(&self, va: u64, len: u64) -> descriptor_txn::DescriptorOp {
        descriptor_txn::DescriptorOp::Terminal {
            span: descriptor_txn::PageSpan::new(va, len),
            edit: descriptor_txn::TerminalEdit::unmap_reclaiming(
                self.asid_scoped_leaves,
                self.layout.excluded_ipa_start,
                self.layout.excluded_ipa_len,
            ),
        }
    }

    /// Authenticate EL1's receipt for `txn` and return the table grants it
    /// did not consume and the emptied tables it unlinked. Grants of a
    /// refused or rolled-back transaction all return; after an
    /// unauthenticated or indeterminate receipt they stay reserved, because
    /// their linkage is unknown.
    ///
    /// Reclaimed tables return exactly once: each must be a table page this
    /// allocator issued from the primary arena's spare tail and does not
    /// already hold free. Otherwise the receipt is inconsistent with the
    /// allocator and nothing is returned.
    pub fn settle_guest_descriptor_receipt(
        &mut self,
        txn: &descriptor_txn::DescriptorTxn,
        receipt: &descriptor_txn::DescriptorReceipt,
    ) -> Result<descriptor_txn::VerifiedDescriptorReceipt, GuestTxnSettleError> {
        use descriptor_txn::{DescriptorOutcome, ReceiptError};
        match txn.verify_receipt(receipt) {
            Ok(verified) => {
                let reclaimed = verified.reclaimed_tables();
                // Verification kept them off the root's boot tables; the
                // allocator bounds them by what each arena issued.
                let root_is_primary = self
                    .arenas
                    .first()
                    .is_some_and(|arena| arena.base == txn.root.raw());
                if !root_is_primary
                    || reclaimed
                        .iter()
                        .any(|&pa| !self.is_spare_table(pa) || self.free_tables.contains(&pa))
                {
                    return Err(GuestTxnSettleError::Receipt(
                        ReceiptError::InconsistentReceipt,
                    ));
                }
                let unused = verified.unused_table_grants();
                self.free_tables
                    .try_reserve(unused.len() + reclaimed.len())
                    .map_err(|_| {
                        GuestTxnSettleError::Manager(PageTableError::MetadataAllocation)
                    })?;
                self.release_table_grants(unused)
                    .map_err(GuestTxnSettleError::Manager)?;
                // Verification proved them distinct and disjoint from the
                // unused grants; the check above, from the free list.
                self.free_tables.extend_from_slice(reclaimed);
                Ok(verified)
            }
            Err(
                error @ ReceiptError::NotApplied(
                    DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_),
                ),
            ) => {
                self.release_table_grants(txn.tables.as_slice())
                    .map_err(GuestTxnSettleError::Manager)?;
                Err(GuestTxnSettleError::Receipt(error))
            }
            Err(error) => Err(GuestTxnSettleError::Receipt(error)),
        }
    }

    /// Return every grant of a submission withdrawn before EL1 claimed it.
    pub fn abandon_guest_descriptor_txn(
        &mut self,
        txn: &descriptor_txn::DescriptorTxn,
    ) -> Result<(), PageTableError> {
        self.release_table_grants(txn.tables.as_slice())
    }

    /// Return table grants that a transaction did not link. The pages stay
    /// out of the bump range and are reused from the free list; they are
    /// re-zeroed at handout like every other freed table.
    pub fn release_table_grants(&mut self, pages: &[u64]) -> Result<(), PageTableError> {
        self.free_tables
            .try_reserve(pages.len())
            .map_err(|_| PageTableError::MetadataAllocation)?;
        for &pa in pages {
            if !self.free_tables.contains(&pa) {
                self.free_tables.push(pa);
            }
        }
        Ok(())
    }

    /// True if this manager is bound to live hardware-visible memory.
    pub fn is_live(&self) -> bool {
        self.arenas.first().is_some_and(|a| a.is_live())
    }

    /// Borrow the installed host arena resolver, if bound.
    pub fn resolver(&self) -> Option<&Arc<dyn HostArenaResolver + Send + Sync>> {
        self.resolver.as_ref()
    }

    /// Convert this manager to live backing authority. Discard descriptor contents
    /// while retaining empty allocation capacity for owned snapshot recycling.
    ///
    /// # Safety
    /// `resolver` must return valid, resident, 8-byte aligned host backing pointers.
    pub unsafe fn make_live(&mut self, resolver: Arc<dyn HostArenaResolver + Send + Sync>) {
        self.resolver = Some(resolver);
        for arena in &mut self.arenas {
            arena.make_live_storage();
        }
        self.staged.clear();
        self.dirty.clear();
        self.offline_private_image = false;
    }

    /// Whether host edits are staged or dirty but not yet synced to the
    /// live backing; making such a manager live would discard them.
    #[must_use]
    pub fn has_unsynced_edits(&self) -> bool {
        !self.staged.is_empty() || !self.dirty.is_empty()
    }

    /// Bind or update the host arena resolver for this live manager.
    ///
    /// # Safety
    /// `resolver` must uphold the safety contracts of `HostArenaResolver`.
    pub unsafe fn bind_resolver(&mut self, resolver: Arc<dyn HostArenaResolver + Send + Sync>) {
        self.resolver = Some(resolver);
    }

    /// Return the primary-arena prefix needed to contain every table page
    /// reachable from the live root.
    ///
    /// A second serialized editor can allocate and link a table page directly
    /// in hardware after this manager was constructed. Its cached bump cursor
    /// then predates that page. Walk the reachable table graph against each
    /// live arena's physical capacity so snapshots and later bump allocations
    /// do not truncate or reissue externally published hierarchy. The walk is
    /// bounded by the populated table graph (four levels), not the 1.75 MiB
    /// primary capacity.
    fn live_reachable_primary_prefix(&self) -> Result<u64, PageTableError> {
        if !self.arenas[0].is_live() {
            return Ok(self.arenas[0].next_free);
        }

        fn arena_span_for_discovery(arena: &TableArena) -> u64 {
            if arena.is_live() {
                arena.capacity as u64
            } else {
                arena.allocated_span()
            }
        }

        fn locate_child(
            manager: &PageTableManager,
            pa: u64,
        ) -> Result<TableLocation, PageTableError> {
            for (arena_index, arena) in manager.arenas.iter().enumerate() {
                let span = arena_span_for_discovery(arena);
                let Some(end) = arena.base.checked_add(span) else {
                    return Err(PageTableError::BadAddress);
                };
                let Some(child_end) = pa.checked_add(PT_PAGE) else {
                    return Err(PageTableError::BadAddress);
                };
                if pa >= arena.base && child_end <= end {
                    return Ok(TableLocation::new(arena_index, (pa - arena.base) as usize));
                }
            }
            Err(PageTableError::BadAddress)
        }

        fn visit(
            manager: &PageTableManager,
            table: TableLocation,
            level: usize,
            ancestors: &mut [Option<TableLocation>; 4],
            primary_prefix: &mut u64,
        ) -> Result<(), PageTableError> {
            if level >= 4 || ancestors[..level].contains(&Some(table)) {
                return Err(PageTableError::BadAddress);
            }
            let arena = manager
                .arenas
                .get(table.arena)
                .ok_or(PageTableError::BadAddress)?;
            let span = arena_span_for_discovery(arena);
            let table_end = (table.offset as u64)
                .checked_add(PT_PAGE)
                .ok_or(PageTableError::BadAddress)?;
            if !table.offset.is_multiple_of(PT_PAGE as usize) || table_end > span {
                return Err(PageTableError::BadAddress);
            }
            if table.arena == 0 {
                *primary_prefix = (*primary_prefix).max(table_end);
            }
            ancestors[level] = Some(table);
            if level < 3 {
                for index in 0..512usize {
                    let descriptor = manager.read_desc(table.entry(index))?;
                    if descriptor & VALID == 0 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
                        continue;
                    }
                    let child = locate_child(manager, descriptor & PA_MASK_TABLE)?;
                    visit(manager, child, level + 1, ancestors, primary_prefix)?;
                }
            }
            ancestors[level] = None;
            Ok(())
        }

        let mut primary_prefix = self.arenas[0].next_free;
        visit(
            self,
            TableLocation::new(0, 0),
            0,
            &mut [None; 4],
            &mut primary_prefix,
        )?;
        Ok(primary_prefix)
    }

    /// Snapshot this manager into `target`, reusing `target`'s existing buffers.
    ///
    /// Descriptors from live hardware backing are read atomically word-by-word with acquire ordering.
    pub fn snapshot_into(&self, target: &mut PageTableManager) -> Result<(), PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering};

        let live_primary_prefix = self.live_reachable_primary_prefix()?;

        target.layout = self.layout;
        target.asid_scoped_leaves = self.asid_scoped_leaves;
        target.free_tables.clear();
        target.free_tables.extend_from_slice(&self.free_tables);
        target.multi_vcpu = self.multi_vcpu;
        target.offline_private_image = self.offline_private_image;
        target.stage1_exclusive = self.stage1_exclusive;
        target.reclaim_pending = self.reclaim_pending;
        // An offline copy is never guest-owned (as `snapshot_image`), even
        // when the pooled target last belonged to a guest-owned MM.
        target.live_descriptor_owner = LiveDescriptorOwner::Host;
        target.dirty.clear();
        target.dirty.extend_from_slice(&self.dirty);
        target.undo = self.undo.clone();
        target.staged.clear();
        target.resolver = None;

        while target.arenas.len() > self.arenas.len() {
            target.arenas.pop();
        }
        while target.arenas.len() < self.arenas.len() {
            let i = target.arenas.len();
            let src = &self.arenas[i];
            let prefix_len = if i == 0 {
                live_primary_prefix
            } else {
                src.next_free
            };
            let mut bytes = Vec::with_capacity(src.capacity);
            bytes.resize(prefix_len as usize, 0);
            target.arenas.push(TableArena {
                snapshot_scratch: Vec::new(),
                base: src.base,
                storage: TableArenaStorage::Owned(bytes),
                next_free: prefix_len,
                capacity: src.capacity,
            });
        }

        for (i, src_arena) in self.arenas.iter().enumerate() {
            let target_arena = &mut target.arenas[i];
            target_arena.prepare_owned_storage();
            target_arena.base = src_arena.base;
            let prefix_len = if i == 0 {
                live_primary_prefix
            } else {
                src_arena.next_free
            };
            target_arena.next_free = prefix_len;
            target_arena.capacity = src_arena.capacity;

            let prefix_len = prefix_len as usize;
            match (&mut target_arena.storage, &src_arena.storage) {
                (TableArenaStorage::Owned(dst_bytes), TableArenaStorage::Owned(src_bytes)) => {
                    dst_bytes.clear();
                    if dst_bytes.capacity() < src_arena.capacity {
                        dst_bytes.reserve(src_arena.capacity);
                    }
                    let copy_len = prefix_len.min(src_bytes.len());
                    dst_bytes.extend_from_slice(&src_bytes[..copy_len]);
                    if dst_bytes.len() < prefix_len {
                        dst_bytes.resize(prefix_len, 0);
                    }
                }
                (TableArenaStorage::Owned(dst_bytes), TableArenaStorage::Live) => {
                    dst_bytes.clear();
                    if dst_bytes.capacity() < src_arena.capacity {
                        dst_bytes.reserve(src_arena.capacity);
                    }
                    dst_bytes.resize(prefix_len, 0);
                    let resolver = self
                        .resolver
                        .as_ref()
                        .ok_or(PageTableError::UnresolvedArena(src_arena.base))?;
                    let host = resolver
                        .host_const_ptr_for_range(src_arena.base, prefix_len)
                        .ok_or(PageTableError::UnresolvedArena(src_arena.base))?;
                    let words = prefix_len / 8;
                    for w in 0..words {
                        let slot = unsafe { host.add(w * 8).cast::<AtomicU64>() };
                        let desc = unsafe { (*slot).load(Ordering::Acquire) };
                        dst_bytes[w * 8..(w + 1) * 8].copy_from_slice(&desc.to_le_bytes());
                    }
                }
                (dest_storage, TableArenaStorage::Live) => {
                    let mut dst_bytes = Vec::with_capacity(src_arena.capacity);
                    dst_bytes.resize(prefix_len, 0);
                    let resolver = self
                        .resolver
                        .as_ref()
                        .ok_or(PageTableError::UnresolvedArena(src_arena.base))?;
                    let host = resolver
                        .host_const_ptr_for_range(src_arena.base, prefix_len)
                        .ok_or(PageTableError::UnresolvedArena(src_arena.base))?;
                    let words = prefix_len / 8;
                    for w in 0..words {
                        let slot = unsafe { host.add(w * 8).cast::<AtomicU64>() };
                        let desc = unsafe { (*slot).load(Ordering::Acquire) };
                        dst_bytes[w * 8..(w + 1) * 8].copy_from_slice(&desc.to_le_bytes());
                    }
                    *dest_storage = TableArenaStorage::Owned(dst_bytes);
                }
                (dest_storage, TableArenaStorage::Owned(src_bytes)) => {
                    let mut dst_bytes = Vec::with_capacity(src_arena.capacity);
                    let copy_len = prefix_len.min(src_bytes.len());
                    dst_bytes.extend_from_slice(&src_bytes[..copy_len]);
                    if dst_bytes.len() < prefix_len {
                        dst_bytes.resize(prefix_len, 0);
                    }
                    *dest_storage = TableArenaStorage::Owned(dst_bytes);
                }
            }

            if let TableArenaStorage::Owned(ref mut dst_bytes) = target_arena.storage {
                for (loc, (desc, _)) in &self.staged {
                    if loc.arena == i && loc.offset + 8 <= dst_bytes.len() {
                        dst_bytes[loc.offset..loc.offset + 8].copy_from_slice(&desc.to_le_bytes());
                    }
                }
            }
        }
        Ok(())
    }

    /// Snapshot this manager into a new owned PageTableManager image.
    pub fn snapshot_image(&self) -> Result<PageTableManager, PageTableError> {
        let mut target = PageTableManager {
            arenas: Vec::with_capacity(self.arenas.len()),
            layout: self.layout,
            asid_scoped_leaves: self.asid_scoped_leaves,
            free_tables: Vec::new(),
            multi_vcpu: self.multi_vcpu,
            offline_private_image: true,
            stage1_exclusive: true,
            reclaim_pending: self.reclaim_pending,
            dirty: Vec::new(),
            staged: hashbrown::HashMap::new(),
            resolver: None,
            undo: None,
            table_allocation_forbidden: false,
            // A snapshot is an offline image. Restoring it over a guest-owned
            // live authority is refused by that authority, not by the copy.
            live_descriptor_owner: LiveDescriptorOwner::Host,
        };
        self.snapshot_into(&mut target)?;
        Ok(target)
    }

    /// Guest-physical address of the L0 table represented by this image.
    ///
    /// A process-local table clone may be rebased away from the boot identity
    /// address. Callers that publish edits must use this address, not a fixed
    /// global page-table constant, to select the live backing.
    pub fn base(&self) -> u64 {
        self.arenas[0].base
    }

    /// Guest-physical base addresses of all extension arenas attached to this manager.
    pub fn extension_arena_bases(&self) -> Vec<u64> {
        self.arenas[1..].iter().map(|a| a.base).collect()
    }

    /// Sum of the populated table bytes (`next_free`) across all arenas.
    pub fn copied_bytes(&self) -> u64 {
        self.arenas.iter().map(|a| a.next_free).sum()
    }

    /// Pop all extension arenas. Returns the bases of the retired extension
    /// arenas so callers can unmap and retire them.
    pub fn retire_extension_arenas(&mut self) -> Vec<u64> {
        let mut bases = Vec::new();
        while self.arenas.len() > 1 {
            if let Some(arena) = self.arenas.pop() {
                bases.push(arena.base);
            }
        }
        bases
    }

    fn total_pages(&self) -> usize {
        self.arenas.iter().map(|a| a.current_pages()).sum()
    }

    fn loc_to_page_index(&self, loc: TableLocation) -> usize {
        let prior: usize = self.arenas[..loc.arena]
            .iter()
            .map(|a| a.current_pages())
            .sum();
        prior + loc.offset / PT_PAGE as usize
    }

    /// Relocate this complete stage-1 table image to `new_base` while
    /// preserving every leaf translation. Only table descriptors at levels
    /// L0-L2 contain addresses within the table backing; block/page leaves keep
    /// naming the same guest IPA and are intentionally left untouched.
    ///
    /// The caller must copy the returned image into its new backing before
    /// publishing the new TTBR. Rebased table descriptors are marked dirty so
    /// an already-copied backing can alternatively be fixed with
    /// [`Self::sync_to_host`] before publication.
    pub fn rebase(
        &mut self,
        new_base: u64,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<(), PageTableError> {
        if !new_base.is_multiple_of(PT_PAGE) {
            return Err(PageTableError::BadAddress);
        }
        let Some(last_byte) = new_base.checked_add(self.arenas[0].capacity as u64 - 1) else {
            return Err(PageTableError::BadAddress);
        };
        if last_byte & !(PA_MASK_TABLE | (PT_PAGE - 1)) != 0 {
            return Err(PageTableError::BadAddress);
        }

        if self.arenas.len() > 1 && source.is_none() {
            return Err(PageTableError::MissingArenaSource);
        }

        let mut new_bases = Vec::with_capacity(self.arenas.len());
        new_bases.push(new_base);
        for _ in 1..self.arenas.len() {
            let Some(gpa) = source.as_mut().and_then(|source| source.take_arena()) else {
                for &b in &new_bases[1..] {
                    if let Some(source) = source.as_mut() {
                        source.return_arena(SubstrateGpa(b));
                    }
                }
                return Err(PageTableError::OutOfTables);
            };
            new_bases.push(gpa.0);
        }

        let traverse = || -> Result<_, PageTableError> {
            let mut pending = vec![(TableLocation::new(0, 0), 0usize)];
            let mut visited = vec![false; self.total_pages()];
            let mut pointers = Vec::new();
            while let Some((table_loc, level)) = pending.pop() {
                if level > 3
                    || table_loc.offset % PT_PAGE as usize != 0
                    || table_loc.offset + PT_PAGE as usize
                        > self.arenas[table_loc.arena].allocated_span() as usize
                {
                    return Err(PageTableError::BadAddress);
                }
                let page = self.loc_to_page_index(table_loc);
                if visited[page] {
                    continue;
                }
                visited[page] = true;
                if level == 3 {
                    continue;
                }
                for index in 0..512usize {
                    let entry_loc = table_loc.entry(index);
                    let descriptor = self.read_desc(entry_loc)?;
                    if descriptor & VALID == 0 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
                        continue;
                    }
                    let child_pa = descriptor & PA_MASK_TABLE;
                    let child_loc = self.pa_to_loc(child_pa)?;
                    if !child_loc.offset.is_multiple_of(PT_PAGE as usize)
                        || child_loc.offset + PT_PAGE as usize
                            > self.arenas[child_loc.arena].allocated_span() as usize
                    {
                        return Err(PageTableError::BadAddress);
                    }
                    pointers.push((entry_loc, descriptor, child_loc));
                    pending.push((child_loc, level + 1));
                }
            }

            let mut rebased_free = Vec::with_capacity(self.free_tables.len());
            for &table_pa in &self.free_tables {
                let loc = self.pa_to_loc(table_pa)?;
                if !loc.offset.is_multiple_of(PT_PAGE as usize)
                    || loc.offset + PT_PAGE as usize
                        > self.arenas[loc.arena].allocated_span() as usize
                {
                    return Err(PageTableError::BadAddress);
                }
                rebased_free.push(new_bases[loc.arena] + loc.offset as u64);
            }
            Ok((pointers, rebased_free))
        };

        let (pointers, rebased_free) = match traverse() {
            Ok(res) => res,
            Err(err) => {
                for &b in &new_bases[1..] {
                    if let Some(source) = source.as_mut() {
                        source.return_arena(SubstrateGpa(b));
                    }
                }
                return Err(err);
            }
        };

        self.dirty.clear();
        for (entry_loc, descriptor, child_loc) in pointers {
            let child_pa = new_bases[child_loc.arena] + child_loc.offset as u64;
            self.write_table_desc(
                entry_loc,
                (descriptor & !PA_MASK_TABLE) | (child_pa & PA_MASK_TABLE),
            )?;
        }
        for (i, &base) in new_bases.iter().enumerate() {
            self.arenas[i].base = base;
        }
        self.free_tables = rebased_free;
        Ok(())
    }

    /// Tell the manager whether sibling vCPUs are live (set per-edit from the
    /// process-wide live-vCPU count). Gates coalescing.
    /// Record whether this thread's stage-1 edits are exclusive. Gates ONLY the
    /// last-resort reclaim sweep, never the eager paths — making exclusivity
    /// enable eager coalescing took `go-net_http` from 50 s to over 200 s,
    /// because a busy guest holds most of the pool legitimately and the scan
    /// then runs constantly while finding almost nothing.
    pub fn set_stage1_exclusive(&mut self, exclusive: bool) {
        self.stage1_exclusive = exclusive;
    }

    pub fn set_multi_vcpu(&mut self, multi: bool) {
        self.multi_vcpu = multi;
    }

    /// Declare this image an OFFLINE PRIVATE copy: sole owner, no hardware
    /// walker can reach it, so freeing a spare sub-table for reuse cannot race
    /// a stale cached walk.
    pub fn declare_offline_private_image(&mut self) {
        self.stage1_exclusive = true;
        self.offline_private_image = true;
    }

    /// Mark this image reachable by a hardware walker. Live table-to-block
    /// compaction stays disabled until the publisher can perform the required
    /// invalidate -> TLBI -> make -> TLBI sequence.
    pub fn declare_live_hardware_image(&mut self) {
        self.offline_private_image = false;
    }

    /// True iff `pa` is a runtime-allocated spare sub-table (never a boot table
    /// — the boot L0/L1/L2/L3 hold the null guard and kernel hole and must
    /// never be coalesced/freed).
    fn is_spare_table(&self, pa: u64) -> bool {
        if self.arenas.is_empty() {
            return false;
        }
        let primary = &self.arenas[0];
        if spare_table(primary.base, pa)
            && pa >= primary.base
            && pa < primary.base + primary.next_free
        {
            return true;
        }
        for arena in &self.arenas[1..] {
            if pa >= arena.base && pa < arena.base + arena.next_free {
                return true;
            }
        }
        false
    }

    /// Zero one unlinked spare table in the manager image. Live EL1 and host
    /// editors share the same backing, so callers also use this immediately
    /// before free-list reuse: zero-at-retirement alone is not a lasting fact.
    fn zero_unlinked_table(&mut self, pa: u64, publish_owned: bool) -> Result<(), PageTableError> {
        let loc = self.pa_to_loc(pa)?;
        let live = self.is_live();
        if let Some(journal) = self.undo.as_mut() {
            journal
                .words
                .try_reserve(512)
                .map_err(|_| PageTableError::MetadataAllocation)?;
        }
        if live {
            self.staged
                .try_reserve(512)
                .map_err(|_| PageTableError::MetadataAllocation)?;
        }
        if live || publish_owned {
            self.dirty
                .try_reserve(512)
                .map_err(|_| PageTableError::MetadataAllocation)?;
        }
        if self.undo.is_some() {
            for off in (loc.offset..loc.offset + PT_PAGE as usize).step_by(8) {
                self.note_undo_unlinked(TableLocation::new(loc.arena, off))?;
            }
        }
        let arena = &mut self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref mut bytes) => {
                for b in &mut bytes[loc.offset..loc.offset + PT_PAGE as usize] {
                    *b = 0;
                }
                if publish_owned {
                    for off in (loc.offset..loc.offset + PT_PAGE as usize).step_by(8) {
                        self.dirty.push((TableLocation::new(loc.arena, off), false));
                    }
                }
            }
            TableArenaStorage::Live => {
                for off in (loc.offset..loc.offset + PT_PAGE as usize).step_by(8) {
                    let word_loc = TableLocation::new(loc.arena, off);
                    self.staged.insert(word_loc, (0, false));
                    self.dirty.push((word_loc, false));
                }
            }
        }
        Ok(())
    }

    /// Zero a freed spare sub-table and return it to the reusable free list.
    fn free_table(&mut self, pa: u64) -> Result<(), PageTableError> {
        self.free_tables
            .try_reserve(1)
            .map_err(|_| PageTableError::MetadataAllocation)?;
        self.zero_unlinked_table(pa, false)?;
        self.free_tables.push(pa);
        Ok(())
    }

    /// Borrow the (possibly edited) table-region bytes of the primary arena.
    pub fn as_bytes(&self) -> &[u8] {
        match self.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes,
            TableArenaStorage::Live => &[],
        }
    }

    /// Consume the manager, returning the (possibly edited) table-region bytes of the primary arena.
    /// Used by the boot-time ELF read-only-span pass, which edits the pristine
    /// `stage1_identity_page_tables` image before it is mapped into the guest.
    pub fn into_bytes(self) -> Result<Vec<u8>, PageTableError> {
        let capacity = self.arenas[0].capacity;
        let mut bytes = self.into_occupied_bytes()?;
        if bytes.len() < capacity {
            bytes.resize(capacity, 0);
        }
        Ok(bytes)
    }

    /// The primary arena's occupied table prefix (through the bump cursor),
    /// without the zero capacity tail [`Self::into_bytes`] appends. For a
    /// consumer that installs the image into zeroed backing of the full
    /// capacity and rebuilds a manager with [`Self::from_live_image`].
    pub fn into_occupied_bytes(mut self) -> Result<Vec<u8>, PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering};

        let primary = self.arenas.remove(0);
        let mut bytes = match primary.storage {
            TableArenaStorage::Owned(bytes) => bytes,
            TableArenaStorage::Live => {
                let prefix_len = primary.next_free as usize;
                let mut bytes = vec![0; prefix_len];
                let resolver = self
                    .resolver
                    .as_ref()
                    .ok_or(PageTableError::UnresolvedArena(primary.base))?;
                let host = resolver
                    .host_const_ptr_for_range(primary.base, prefix_len)
                    .ok_or(PageTableError::UnresolvedArena(primary.base))?;
                let words = prefix_len / 8;
                for w in 0..words {
                    let slot = unsafe { host.add(w * 8).cast::<AtomicU64>() };
                    let desc = unsafe { (*slot).load(Ordering::Acquire) };
                    bytes[w * 8..(w + 1) * 8].copy_from_slice(&desc.to_le_bytes());
                }
                bytes
            }
        };
        bytes.truncate(primary.next_free as usize);
        Ok(bytes)
    }

    fn read_desc(&self, loc: TableLocation) -> Result<u64, PageTableError> {
        if let Some(&(desc, _)) = self.staged.get(&loc) {
            return Ok(desc);
        }
        let arena = &self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref bytes) => {
                if loc.offset + 8 <= bytes.len() {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&bytes[loc.offset..loc.offset + 8]);
                    Ok(u64::from_le_bytes(a))
                } else {
                    Ok(0)
                }
            }
            TableArenaStorage::Live => {
                let Some(ref resolver) = self.resolver else {
                    return Err(PageTableError::UnresolvedArena(arena.base));
                };
                let requested_len = loc
                    .offset
                    .checked_add(8)
                    .ok_or(PageTableError::BadAddress)?;
                let Some(host) = resolver.host_const_ptr_for_range(arena.base, requested_len)
                else {
                    return Err(PageTableError::UnresolvedArena(arena.base));
                };
                use core::sync::atomic::{AtomicU64, Ordering};
                unsafe {
                    let slot = host.add(loc.offset).cast::<AtomicU64>();
                    Ok((*slot).load(Ordering::Acquire))
                }
            }
        }
    }

    /// Write a leaf/child descriptor (a block, page, or sub-table entry that is
    /// not itself newly pointing the walker at a fresh table).
    fn write_desc(&mut self, loc: TableLocation, desc: u64) -> Result<(), PageTableError> {
        if let Some(journal) = self.undo.as_mut() {
            journal
                .words
                .try_reserve(1)
                .map_err(|_| PageTableError::MetadataAllocation)?;
            if !journal.first_written.contains(&(loc.arena, loc.offset)) {
                journal
                    .first_written
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
            }
        }
        let arena = &mut self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref mut bytes) => {
                if loc.offset + 8 > bytes.len() {
                    bytes
                        .try_reserve((loc.offset + 8) - bytes.len())
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                }
            }
            TableArenaStorage::Live => {
                if !self.staged.contains_key(&loc) {
                    self.staged
                        .try_reserve(1)
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                }
            }
        }
        self.dirty
            .try_reserve(1)
            .map_err(|_| PageTableError::MetadataAllocation)?;

        self.note_undo(loc)?;
        let arena = &mut self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref mut bytes) => {
                if loc.offset + 8 > bytes.len() {
                    bytes.resize(loc.offset + 8, 0);
                }
                bytes[loc.offset..loc.offset + 8].copy_from_slice(&desc.to_le_bytes());
            }
            TableArenaStorage::Live => {
                self.staged.insert(loc, (desc, false));
            }
        }
        self.dirty.push((loc, false));
        Ok(())
    }

    /// Record one walker-visible descriptor word's pre-image while a journal
    /// is open, noting whether it replaced a VALID descriptor.
    fn note_undo(&mut self, loc: TableLocation) -> Result<(), PageTableError> {
        if self.undo.is_some() {
            let previous = self.read_desc(loc)?;
            if let Some(journal) = self.undo.as_mut() {
                journal
                    .words
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
                if !journal.first_written.contains(&(loc.arena, loc.offset)) {
                    journal
                        .first_written
                        .try_reserve(1)
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                }
                journal.words.push((loc, previous));
                if journal.first_written.insert((loc.arena, loc.offset)) {
                    journal.replaced_valid |= previous & 1 != 0;
                }
            }
        }
        Ok(())
    }

    /// Record a pre-image for a word in an unlinked table page being zeroed
    /// for reuse. Rollback needs the word; TLB maintenance accounting does not,
    /// because nothing reachable from the live tree points at that page.
    fn note_undo_unlinked(&mut self, loc: TableLocation) -> Result<(), PageTableError> {
        if self.undo.is_some() {
            let previous = self.read_desc(loc)?;
            if let Some(journal) = self.undo.as_mut() {
                journal
                    .words
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
                journal.words.push((loc, previous));
            }
        }
        Ok(())
    }

    /// Write a table descriptor that exposes a (freshly populated) sub-table to
    /// the walker. Tagged so the host sync orders it AFTER the sub-table's
    /// entries are visible.
    fn write_table_desc(&mut self, loc: TableLocation, desc: u64) -> Result<(), PageTableError> {
        if let Some(journal) = self.undo.as_mut() {
            journal
                .words
                .try_reserve(1)
                .map_err(|_| PageTableError::MetadataAllocation)?;
            if !journal.first_written.contains(&(loc.arena, loc.offset)) {
                journal
                    .first_written
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
            }
        }
        let arena = &mut self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref mut bytes) => {
                if loc.offset + 8 > bytes.len() {
                    bytes
                        .try_reserve((loc.offset + 8) - bytes.len())
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                }
            }
            TableArenaStorage::Live => {
                if !self.staged.contains_key(&loc) {
                    self.staged
                        .try_reserve(1)
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                }
            }
        }
        self.dirty
            .try_reserve(1)
            .map_err(|_| PageTableError::MetadataAllocation)?;

        self.note_undo(loc)?;
        let arena = &mut self.arenas[loc.arena];
        match arena.storage {
            TableArenaStorage::Owned(ref mut bytes) => {
                if loc.offset + 8 > bytes.len() {
                    bytes.resize(loc.offset + 8, 0);
                }
                bytes[loc.offset..loc.offset + 8].copy_from_slice(&desc.to_le_bytes());
            }
            TableArenaStorage::Live => {
                self.staged.insert(loc, (desc, true));
            }
        }
        self.dirty.push((loc, true));
        Ok(())
    }

    /// Replay this edit's descriptor stores to the host page-table backing as
    /// aligned atomic 64-bit writes, with a release barrier before each
    /// table-pointer store so a concurrent sibling hardware walk never sees a
    /// table descriptor pointing at not-yet-visible child entries. Clears the
    /// dirty set.
    ///
    /// # Safety
    /// The resolver must return valid, writable mappings for the touched arenas.
    pub unsafe fn sync_to_host(
        &mut self,
        resolver: impl HostArenaResolver,
    ) -> Result<(), PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering, fence};
        if !self.dirty.is_empty() {
            self.refuse_guest_owned_live_store()?;
        }
        // An EL1 editor may have linked a table page after this live manager
        // cached its bump cursor. A host edit that reached and dirtied that page
        // has now authenticated it through the live table graph. Adopt the
        // complete table page before resolving/publishing the dirty words so
        // later snapshots and allocations cannot truncate or reissue it.
        for &(loc, _) in &self.dirty {
            let arena = self
                .arenas
                .get_mut(loc.arena)
                .ok_or(PageTableError::BadAddress)?;
            let touched = loc
                .offset
                .checked_add(core::mem::size_of::<u64>())
                .ok_or(PageTableError::BadAddress)?;
            if touched > arena.capacity {
                return Err(PageTableError::BadAddress);
            }
            if arena.is_live() {
                let table_end = touched
                    .checked_add(PT_PAGE as usize - 1)
                    .ok_or(PageTableError::BadAddress)?
                    / PT_PAGE as usize
                    * PT_PAGE as usize;
                arena.next_free = arena.next_free.max(table_end as u64);
            }
        }
        let mut inline_hosts = [None; 8];
        let mut overflow_hosts;
        let hosts = if self.arenas.len() <= inline_hosts.len() {
            &mut inline_hosts[..self.arenas.len()]
        } else {
            overflow_hosts = Vec::new();
            overflow_hosts
                .try_reserve_exact(self.arenas.len())
                .map_err(|_| PageTableError::MetadataAllocation)?;
            overflow_hosts.resize(self.arenas.len(), None);
            &mut overflow_hosts[..]
        };
        for (loc, _) in &self.dirty {
            if hosts[loc.arena].is_none() {
                let arena = &self.arenas[loc.arena];
                let span = (arena.allocated_span() as usize).min(arena.capacity);
                hosts[loc.arena] = Some(
                    resolver
                        .host_ptr_for_range(arena.base, span)
                        .ok_or(PageTableError::UnresolvedArena(arena.base))?,
                );
            }
        }
        let dirty = core::mem::take(&mut self.dirty);
        let publish = |loc: TableLocation, is_ptr: bool| -> Result<(), PageTableError> {
            let arena = &self.arenas[loc.arena];
            let (v, final_is_ptr) =
                if let Some(&(staged_desc, staged_is_ptr)) = self.staged.get(&loc) {
                    (staged_desc, staged_is_ptr)
                } else {
                    let value = match arena.storage {
                        TableArenaStorage::Owned(ref bytes) => {
                            let mut a = [0u8; 8];
                            a.copy_from_slice(&bytes[loc.offset..loc.offset + 8]);
                            u64::from_le_bytes(a)
                        }
                        TableArenaStorage::Live => self.read_desc(loc)?,
                    };
                    (value, is_ptr)
                };
            if final_is_ptr != is_ptr {
                return Ok(());
            }
            if final_is_ptr {
                fence(Ordering::SeqCst);
            }
            let host = hosts[loc.arena].ok_or(PageTableError::UnresolvedArena(arena.base))?;
            unsafe {
                let slot = host.add(loc.offset) as *mut AtomicU64;
                if !is_ptr
                    && let Some((output, len)) =
                        newly_user_executable((*slot).load(Ordering::SeqCst), v)
                {
                    resolver.publish_user_executable(output, len)?;
                }
                (*slot).store(v, Ordering::SeqCst);
            }
            Ok(())
        };
        // Publish terminal descriptors first. Newly created table pointers are
        // then replayed in reverse creation order, so an L3 table becomes
        // reachable before its L2 parent and that L2 table before its L1
        // parent. A sibling hardware walker can therefore observe either the
        // old invalid path or a completely initialized descendant path, never
        // a parent pointing at not-yet-published child contents.
        for &(loc, is_ptr) in &dirty {
            if !is_ptr {
                publish(loc, false)?;
            }
        }
        for &(loc, is_ptr) in dirty.iter().rev() {
            if is_ptr {
                publish(loc, true)?;
            }
        }
        fence(Ordering::SeqCst);
        self.staged.clear();
        for (i, host) in hosts.iter().enumerate() {
            if host.is_some() {
                resolver.record_populated_prefix(
                    self.arenas[i].base,
                    (self.arenas[i].next_free as usize).min(self.arenas[i].capacity),
                );
            }
        }
        Ok(())
    }

    fn preflight_live_private_publication(
        &self,
        publication: GuestLeafPublication,
    ) -> Result<usize, GuestLeafPublicationError> {
        if !publication.va.is_multiple_of(PT_PAGE)
            || !publication.ipa.is_multiple_of(PT_PAGE)
            || publication.len == 0
            || !publication.len.is_multiple_of(PT_PAGE)
            || publication.va.checked_add(publication.len).is_none()
            || publication.ipa.checked_add(publication.len).is_none()
        {
            return Err(GuestLeafPublicationError::BadRange);
        }
        if self
            .layout
            .ipa_overlaps_excluded(publication.ipa, publication.len)
        {
            return Err(GuestLeafPublicationError::Manager(
                PageTableError::GicWindowOutput,
            ));
        }
        let pages = usize::try_from(publication.len / PT_PAGE)
            .map_err(|_| GuestLeafPublicationError::BadRange)?;
        for page in 0..pages {
            let va = publication.va + page as u64 * PT_PAGE;
            let indexes = indices(va);
            let mut table = TableLocation::new(0, 0);
            #[allow(clippy::needless_range_loop)]
            for level in 0..4 {
                let entry = table.entry(indexes[level]);
                if entry.offset + core::mem::size_of::<u64>()
                    > self.arenas[entry.arena].descriptor_span() as usize
                {
                    return Err(GuestLeafPublicationError::Manager(
                        PageTableError::BadAddress,
                    ));
                }
                let descriptor = self
                    .read_desc(entry)
                    .map_err(GuestLeafPublicationError::Manager)?;
                if descriptor & VALID == 0 {
                    // This transaction carries a newly authenticated frame
                    // grant for the exact MM and semantic span. A retired
                    // descriptor records only the predecessor lease; the new
                    // mapping replaces that output and clears SW_RETIRED.
                    // Valid leaves remain an overwrite refusal below.
                    break;
                }
                if level == 3 {
                    return if descriptor & TYPE_BITS == TYPE_TABLE_OR_PAGE {
                        Err(GuestLeafPublicationError::AlreadyValid)
                    } else {
                        Err(GuestLeafPublicationError::InvalidLeafShape)
                    };
                }
                if descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
                    return if level == 0 {
                        Err(GuestLeafPublicationError::InvalidLeafShape)
                    } else {
                        Err(GuestLeafPublicationError::AlreadyValid)
                    };
                }
                table = self
                    .pa_to_loc(descriptor & PA_MASK_TABLE)
                    .map_err(GuestLeafPublicationError::Manager)?;
            }
        }
        Ok(pages)
    }

    /// Transactionally publish an authenticated private frame grant into this
    /// live stage-1 image, allocating a missing hierarchy from the manager's
    /// current table pool. The complete target range is checked before the
    /// first edit. Descriptor publication is child-before-parent, and every
    /// failed edit restores the journal to hardware-visible memory.
    ///
    /// This entry point deliberately has no extension-arena source: a guest
    /// cannot make a new arena walker-visible until its stage-2 backing is
    /// separately granted. Exhausting the current live pool therefore refuses
    /// the transaction whole with `Manager(OutOfTables)`.
    pub fn publish_live_private_pages_transaction(
        &mut self,
        publication: GuestLeafPublication,
    ) -> Result<usize, GuestLeafPublicationError> {
        if !self.is_live() {
            return Err(GuestLeafPublicationError::Manager(
                PageTableError::UnresolvedArena(self.base()),
            ));
        }
        let pages = self.preflight_live_private_publication(publication)?;
        let resolver =
            self.resolver
                .as_ref()
                .cloned()
                .ok_or(GuestLeafPublicationError::Manager(
                    PageTableError::UnresolvedArena(self.base()),
                ))?;
        self.begin_undo()
            .map_err(GuestLeafPublicationError::Manager)?;

        let edit = self.map_private_aliased(
            publication.va,
            publication.ipa,
            publication.len,
            UserLeafAccess {
                writable: publication.writable,
                executable: publication.executable,
            },
            None,
        );
        if let Err(error) = edit {
            if unsafe { self.rollback_undo(&resolver, None) }.is_err() {
                return Err(GuestLeafPublicationError::RollbackFailed);
            }
            return Err(GuestLeafPublicationError::Manager(error));
        }
        if let Err(error) = self.mark_guest_private_publication(publication) {
            if unsafe { self.rollback_undo(&resolver, None) }.is_err() {
                return Err(GuestLeafPublicationError::RollbackFailed);
            }
            return Err(error);
        }
        if let Err(error) = unsafe { self.sync_to_host(&resolver) } {
            if unsafe { self.rollback_undo(&resolver, None) }.is_err() {
                return Err(GuestLeafPublicationError::RollbackFailed);
            }
            return Err(GuestLeafPublicationError::Manager(error));
        }
        self.commit_undo();
        Ok(pages)
    }

    /// Publish bulk backing while exposing only the faulting Linux page.
    /// Speculative leaves retain their output IPA and private authority while
    /// remaining invalid. First-touch commits must preserve that authority so
    /// a fully touched range can subsequently change permissions in EL1.
    /// The caller holds exact-MM exclusion and flushes after this entire edit.
    pub fn publish_private_pages(
        &mut self,
        publication: GuestLeafPublication,
        fault_va: u64,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<(), GuestLeafPublicationError> {
        let end = publication
            .va
            .checked_add(publication.len)
            .ok_or(GuestLeafPublicationError::BadRange)?;
        let page = fault_va & !(PT_PAGE - 1);
        if publication.len == 0 || page < publication.va || page >= end {
            return Err(GuestLeafPublicationError::BadRange);
        }
        self.map_private_aliased(
            publication.va,
            publication.ipa,
            publication.len,
            UserLeafAccess {
                writable: publication.writable,
                executable: publication.executable,
            },
            source.as_deref_mut(),
        )
        .map_err(GuestLeafPublicationError::Manager)?;
        self.mark_guest_private_publication(publication)?;
        for (start, stop) in [(publication.va, page), (page + PT_PAGE, end)] {
            if start < stop {
                self.set_prot_none(start, (stop - start) as usize, source.as_deref_mut())
                    .map_err(GuestLeafPublicationError::Manager)?;
            }
        }
        Ok(())
    }

    fn mark_guest_private_publication(
        &mut self,
        publication: GuestLeafPublication,
    ) -> Result<(), GuestLeafPublicationError> {
        let end = publication
            .va
            .checked_add(publication.len)
            .ok_or(GuestLeafPublicationError::BadRange)?;
        let mut current = publication.va;
        while current < end {
            let (location, level) = self
                .leaf_offset(current, false, None)
                .map_err(GuestLeafPublicationError::Manager)?;
            let descriptor = self
                .read_desc(location)
                .map_err(GuestLeafPublicationError::Manager)?;
            let (span, mask) = Self::level_span(level);
            let semantic_base = current & mask;
            let semantic_end = semantic_base
                .checked_add(span)
                .ok_or(GuestLeafPublicationError::BadRange)?;
            if descriptor & VALID == 0 || semantic_base < publication.va || semantic_end > end {
                return Err(GuestLeafPublicationError::InvalidLeafShape);
            }
            let expected_output = publication
                .ipa
                .checked_add(semantic_base - publication.va)
                .ok_or(GuestLeafPublicationError::BadRange)?;
            if descriptor & mask != expected_output & mask {
                return Err(GuestLeafPublicationError::InvalidLeafShape);
            }
            let mut tagged = descriptor | SW_EL1_PRIVATE;
            if publication.writable {
                tagged |= SW_EL1_MAY_WRITE;
            }
            if publication.executable {
                tagged |= SW_EL1_MAY_EXEC;
            }
            self.write_desc(location, tagged)
                .map_err(GuestLeafPublicationError::Manager)?;
            current = semantic_end;
        }
        Ok(())
    }

    fn preflight_live_private_permission(
        &mut self,
        edit: GuestPermissionEdit,
    ) -> Result<PtOp, GuestPermissionEditError> {
        if !edit.va.is_multiple_of(PT_PAGE)
            || edit.len == 0
            || !edit.len.is_multiple_of(PT_PAGE)
            || edit.va.checked_add(edit.len).is_none()
        {
            return Err(GuestPermissionEditError::BadRange);
        }
        let end = edit.va + edit.len;
        let mut current = edit.va;
        while current < end {
            let (location, level) = self
                .leaf_offset(current, false, None)
                .map_err(GuestPermissionEditError::Manager)?;
            let descriptor = self
                .read_desc(location)
                .map_err(GuestPermissionEditError::Manager)?;
            if el1_private_leaf_state(descriptor) != El1PrivateLeafState::Resident {
                return Err(GuestPermissionEditError::NotPrivateAnonymous);
            }
            if el1_cow(descriptor)
                || (edit.writable && descriptor & SW_EL1_MAY_WRITE == 0)
                || (edit.executable && descriptor & SW_EL1_MAY_EXEC == 0)
            {
                return Err(GuestPermissionEditError::PermissionWidening);
            }
            let (span, mask) = Self::level_span(level);
            let next = (current & mask)
                .checked_add(span)
                .ok_or(GuestPermissionEditError::BadRange)?;
            current = next.min(end);
        }
        Ok(if !(edit.readable || edit.writable || edit.executable) {
            PtOp::KernelReadOnly { exec: false }
        } else if edit.writable {
            PtOp::ReadWrite {
                exec: edit.executable,
            }
        } else {
            PtOp::ReadOnly {
                exec: edit.executable,
            }
        })
    }

    /// Transactionally change permissions on a completely resident
    /// private-anonymous span previously published by guest EL1. The leaf's
    /// output address and software permission ceiling remain unchanged. COW
    /// leaves forward to the host, which owns shared-frame privatization.
    pub fn protect_live_private_pages_transaction(
        &mut self,
        edit: GuestPermissionEdit,
    ) -> Result<PageTableApplyOutcome, GuestPermissionEditError> {
        if !self.is_live() {
            return Err(GuestPermissionEditError::Manager(
                PageTableError::UnresolvedArena(self.base()),
            ));
        }
        let op = self.preflight_live_private_permission(edit)?;
        let resolver = self
            .resolver
            .as_ref()
            .cloned()
            .ok_or(GuestPermissionEditError::Manager(
                PageTableError::UnresolvedArena(self.base()),
            ))?;
        self.begin_undo()
            .map_err(GuestPermissionEditError::Manager)?;
        let len = usize::try_from(edit.len).map_err(|_| GuestPermissionEditError::BadRange)?;
        let outcome = match self.apply(edit.va, len, op, None) {
            Ok(outcome) => outcome,
            Err(error) => {
                if unsafe { self.rollback_undo(&resolver, None) }.is_err() {
                    return Err(GuestPermissionEditError::RollbackFailed);
                }
                return Err(GuestPermissionEditError::Manager(error));
            }
        };
        if let Err(error) = unsafe { self.sync_to_host(&resolver) } {
            if unsafe { self.rollback_undo(&resolver, None) }.is_err() {
                return Err(GuestPermissionEditError::RollbackFailed);
            }
            return Err(GuestPermissionEditError::Manager(error));
        }
        self.commit_undo();
        Ok(outcome)
    }

    /// Acquire a fresh journal without joining another caller's transaction.
    /// `false` leaves the already-open journal and all its edits untouched.
    /// The exclusive mutable manager borrow makes check and acquisition atomic.
    pub fn begin_fresh_undo(&mut self) -> Result<bool, PageTableError> {
        if self.undo.is_some() {
            return Ok(false);
        }
        self.begin_undo()?;
        Ok(true)
    }

    /// Open an undo journal covering every descriptor edit from here until
    /// [`Self::commit_undo`] or [`Self::rollback_undo`].
    pub fn begin_undo(&mut self) -> Result<(), PageTableError> {
        if self.undo.is_none() {
            let mut arena_next_frees = Vec::new();
            arena_next_frees
                .try_reserve_exact(self.arenas.len())
                .map_err(|_| PageTableError::MetadataAllocation)?;
            arena_next_frees.extend(self.arenas.iter().map(|a| a.next_free));

            let mut free_tables = Vec::new();
            free_tables
                .try_reserve_exact(self.free_tables.len())
                .map_err(|_| PageTableError::MetadataAllocation)?;
            free_tables.extend_from_slice(&self.free_tables);

            self.undo = Some(UndoJournal {
                words: Vec::new(),
                arena_next_frees,
                arenas_len: self.arenas.len(),
                free_tables,
                reclaim_pending: self.reclaim_pending,
                dirty_len: self.dirty.len(),
                replaced_valid: false,
                first_written: hashbrown::HashSet::new(),
                returned_bases: Vec::new(),
            });
        }
        Ok(())
    }

    /// Whether the open undo transaction has overwritten a walker-visible
    /// VALID descriptor. `false` while no journal is open.
    pub fn undo_replaced_valid_descriptor(&self) -> bool {
        self.undo
            .as_ref()
            .is_some_and(|journal| journal.replaced_valid)
    }

    /// Whether a journal is currently open.
    pub fn undo_is_open(&self) -> bool {
        self.undo.is_some()
    }

    /// Discard the journal: the transaction succeeded and its edits stand.
    pub fn commit_undo(&mut self) {
        self.undo = None;
    }

    /// Undo every edit since [`Self::begin_undo`] and publish the restored
    /// words to the live host backing.
    ///
    /// # Safety
    /// Resolver must return writable mappings for all touched arenas.
    pub unsafe fn rollback_undo(
        &mut self,
        resolver: impl HostArenaResolver,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<Vec<u64>, PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering, fence};

        let Some(ref journal) = self.undo else {
            return Ok(Vec::new());
        };
        // On the guest-owned lane `sync_to_host` refuses before its first
        // store, so no journaled word ever reached live backing: discard the
        // staged transaction without writing hardware memory.
        let publish_preimages = self.live_descriptor_owner == LiveDescriptorOwner::Host;

        // Pre-validate that all touched arenas resolve before modifying recoverable state.
        for &(loc, _) in journal.words.iter().filter(|_| publish_preimages) {
            if loc.arena < self.arenas.len() {
                let arena = &self.arenas[loc.arena];
                if resolver
                    .host_ptr_for_range(arena.base, loc.offset + 8)
                    .is_none()
                {
                    return Err(PageTableError::UnresolvedArena(arena.base));
                }
            }
        }

        // Resolution may be revoked after preflight. Keep the complete journal
        // and staged entries until every host write succeeds: a partial restore
        // must remain retryable and must not release newly attached arenas.
        for &(loc, previous) in journal.words.iter().rev() {
            let arena = &mut self.arenas[loc.arena];
            if !publish_preimages {
                if let TableArenaStorage::Owned(ref mut bytes) = arena.storage
                    && loc.offset + 8 <= bytes.len()
                {
                    bytes[loc.offset..loc.offset + 8].copy_from_slice(&previous.to_le_bytes());
                }
                continue;
            }
            let host = resolver
                .host_ptr_for_range(arena.base, loc.offset + 8)
                .ok_or(PageTableError::UnresolvedArena(arena.base))?;
            match arena.storage {
                TableArenaStorage::Owned(ref mut bytes) => {
                    if loc.offset + 8 <= bytes.len() {
                        bytes[loc.offset..loc.offset + 8].copy_from_slice(&previous.to_le_bytes());
                    }
                }
                TableArenaStorage::Live => {}
            }
            fence(Ordering::SeqCst);
            unsafe {
                let slot = host.add(loc.offset).cast::<AtomicU64>();
                (*slot).store(previous, Ordering::Release);
            }
        }
        fence(Ordering::SeqCst);
        let journal = match self.undo.take() {
            Some(journal) => journal,
            None => return Ok(Vec::new()),
        };
        for &(loc, _) in &journal.words {
            self.staged.remove(&loc);
        }
        for (i, &next_free) in journal.arena_next_frees.iter().enumerate() {
            if i < self.arenas.len() {
                self.arenas[i].next_free = next_free;
                if let TableArenaStorage::Owned(ref mut bytes) = self.arenas[i].storage {
                    bytes.truncate(next_free as usize);
                }
            }
        }
        self.free_tables = journal.free_tables;
        self.reclaim_pending = journal.reclaim_pending;
        self.dirty.truncate(journal.dirty_len);
        let mut popped = journal.returned_bases;
        popped.clear();
        while self.arenas.len() > journal.arenas_len {
            let Some(arena) = self.arenas.pop() else {
                break;
            };
            popped.push(arena.base);
            if let Some(source) = source.as_mut() {
                source.return_arena(SubstrateGpa(arena.base));
            }
        }
        Ok(popped)
    }

    /// Replace the live host backing with this manager's complete image across all arenas.
    ///
    /// # Safety
    /// `resolver` must return writable mappings for all attached arenas.
    pub unsafe fn restore_quiesced_snapshot_to_host(
        &self,
        resolver: impl HostArenaResolver,
    ) -> Result<(), PageTableError> {
        use core::sync::atomic::{Ordering, fence};

        self.refuse_guest_owned_live_store()?;
        // Resolve the complete destination set before publishing any bytes.
        // The caller's quiescence/ownership scope must keep these mappings valid
        // through the copy pass; a second fallible lookup could reintroduce a
        // partial restore. Scratch is linear in arenas, not descriptor words.
        let destinations = self
            .arenas
            .iter()
            .map(|arena| {
                let prefix_len = (arena.next_free as usize).min(arena.capacity);
                resolver
                    .host_ptr_for_range(arena.base, prefix_len)
                    .ok_or(PageTableError::UnresolvedArena(arena.base))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (arena, host) in self.arenas.iter().zip(destinations) {
            let prefix_len = (arena.next_free as usize).min(arena.capacity);
            match arena.storage {
                TableArenaStorage::Owned(ref bytes) => {
                    let copy_len = prefix_len.min(bytes.len());
                    // The whole image reaches hardware here, so every word
                    // that newly makes an output EL0-executable crosses the
                    // same instruction-cache authority as `sync_to_host`.
                    // Table words never carry AP[1], so they are never
                    // mistaken for an executable page.
                    for offset in (0..copy_len / 8).map(|word| word * 8) {
                        let mut new = [0u8; 8];
                        new.copy_from_slice(&bytes[offset..offset + 8]);
                        let new = u64::from_le_bytes(new);
                        if user_executable_output(new).is_none() {
                            continue;
                        }
                        let old =
                            unsafe { core::ptr::read_volatile(host.add(offset).cast::<u64>()) };
                        if let Some((output, len)) = newly_user_executable(old, new) {
                            resolver.publish_user_executable(output, len)?;
                        }
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), host, copy_len);
                    }
                    resolver.record_populated_prefix(arena.base, copy_len);
                }
                TableArenaStorage::Live => {
                    resolver.record_populated_prefix(arena.base, prefix_len);
                }
            }
        }
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Record the populated prefix across all arenas using `recorder`.
    pub fn record_populated_prefixes(&self, mut recorder: impl FnMut(u64, usize)) {
        for arena in &self.arenas {
            recorder(arena.base, (arena.next_free as usize).min(arena.capacity));
        }
    }

    /// Location of a PA known to live inside one of the page-table arenas.
    fn pa_to_loc(&self, pa: u64) -> Result<TableLocation, PageTableError> {
        for (i, arena) in self.arenas.iter().enumerate() {
            let end = arena.base + arena.descriptor_span();
            if pa >= arena.base && pa < end {
                return Ok(TableLocation::new(i, (pa - arena.base) as usize));
            }
        }
        Err(PageTableError::BadAddress)
    }

    /// Spare sub-table pool occupancy for diagnostics/tracing:
    /// `(in_use, free_list, capacity, arenas)` pages.
    pub fn pool_stats(&self) -> (u32, u32, u32, u32) {
        let primary_capacity = (self.arenas[0].capacity as u64 - SPARE_START_OFFSET) / PT_PAGE;
        let primary_bumped = (self.arenas[0].next_free - SPARE_START_OFFSET) / PT_PAGE;
        let ext_capacity: u64 = self.arenas[1..]
            .iter()
            .map(|a| a.capacity as u64 / PT_PAGE)
            .sum();
        let ext_bumped: u64 = self.arenas[1..].iter().map(|a| a.next_free / PT_PAGE).sum();
        let capacity = primary_capacity + ext_capacity;
        let bumped = primary_bumped + ext_bumped;
        let free = self.free_tables.len() as u64;
        let in_use = bumped.saturating_sub(free);
        (
            in_use as u32,
            free as u32,
            capacity as u32,
            self.arenas.len() as u32,
        )
    }

    /// Allocate one spare table page from the primary arena and return its base PA.
    /// Test helper for verifying table growth semantics.
    pub fn alloc_table_for_test(&mut self) -> Result<u64, PageTableError> {
        self.alloc_table(None)
    }

    /// Write one descriptor into the table at `pa` and mark it dirty for sync_to_host.
    /// Test helper for verifying table descriptor sync.
    /// Write one descriptor into the table at `pa` and mark it dirty for sync_to_host.
    /// Test helper for verifying table descriptor sync.
    pub fn write_desc_for_test(&mut self, pa: u64, desc: u64) -> Result<(), PageTableError> {
        let loc = self.pa_to_loc(pa)?;
        self.write_desc(loc, desc)?;
        Ok(())
    }

    /// Restore a pre-transaction image over `live` without losing what the
    /// live manager owns beyond its tables: every extension arena the live
    /// manager acquired after the image was taken is adopted as an empty arena
    /// (its tables are unreachable from the restored tree, and its stage-2
    /// backing stays published), so a rollback neither leaks pool slots nor
    /// leaves the process unable to grow.
    pub fn adopt_live_extension_state(&mut self, live: &Self) {
        for arena in live.arenas.iter().skip(1) {
            if self.arenas.iter().any(|mine| mine.base == arena.base) {
                continue;
            }
            let storage = match self.arenas[0].storage {
                TableArenaStorage::Owned(_) => {
                    let mut bytes = Vec::with_capacity(arena.capacity);
                    bytes.resize(PT_PAGE as usize, 0);
                    TableArenaStorage::Owned(bytes)
                }
                TableArenaStorage::Live => TableArenaStorage::Live,
            };
            self.arenas.push(TableArena {
                snapshot_scratch: Vec::new(),
                base: arena.base,
                storage,
                next_free: PT_PAGE,
                capacity: arena.capacity,
            });
        }
    }

    /// The three policy bits that decide whether an exhausted pool can recover:
    /// `(multi_vcpu, stage1_exclusive, reclaim_pending)`. `alloc_table`'s
    /// last-resort sweep runs only with `stage1_exclusive && reclaim_pending`,
    /// so an `OutOfTables` carrying `stage1_exclusive=false` was refused the
    /// sweep rather than genuinely out of reclaimable tables.
    #[must_use]
    pub fn coalesce_policy(&self) -> (bool, bool, bool) {
        (self.multi_vcpu, self.stage1_exclusive, self.reclaim_pending)
    }

    /// Read-only descriptor walk for `va`, returning `[L0, L1, L2, L3]` descriptors.
    pub fn try_debug_walk(&self, va: u64) -> Result<[u64; 4], PageTableError> {
        let idx = indices(va);
        let mut out = [0u64; 4];
        let mut table_loc = TableLocation::new(0, 0);
        #[allow(clippy::needless_range_loop)]
        for level in 0..4usize {
            let entry_loc = table_loc.entry(idx[level]);
            if entry_loc.offset + 8 > self.arenas[entry_loc.arena].descriptor_span() as usize {
                break;
            }
            let desc = self.read_desc(entry_loc)?;
            out[level] = desc;
            if level == 3 {
                break;
            }
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if !(valid && is_table) {
                break;
            }
            match self.pa_to_loc(desc & PA_MASK_TABLE) {
                Ok(loc) => table_loc = loc,
                Err(_) => break,
            }
        }
        Ok(out)
    }

    /// Read-only descriptor walk for `va`, for `carrick trace` diagnostics:
    /// returns `[L0, L1, L2, L3]` descriptors as the MANAGER sees them in its
    /// own `bytes` (not the host backing), stopping (rest 0) at the first
    /// non-table or out-of-range link. Lets a trace compare the manager's view
    /// across e.g. parent vs forked child.
    pub fn debug_walk(&self, va: u64) -> [u64; 4] {
        self.try_debug_walk(va).unwrap_or([0u64; 4])
    }

    /// Refresh the owned shadow table pages that a host edit of `[va, va+len)`
    /// can reach from the hardware-visible root.
    ///
    /// During the EL1 migration, guest code can allocate and populate a table
    /// below a host manager whose owned image predates that hierarchy. A host
    /// `munmap` must adopt the complete reached table pages before editing: a
    /// range-only leaf copy would lose live neighboring mappings when the
    /// owned image is published back to hardware. Work is bounded by the table
    /// pages covering the range, rather than by its Linux-page count.
    ///
    /// Live managers already read the hardware-visible backing directly and
    /// need no adoption.
    ///
    /// # Safety
    ///
    /// The caller must exclude every other stage-1 editor for this MM, and
    /// `resolver` must return readable backing for each reachable table arena.
    pub unsafe fn adopt_live_tables_for_range(
        &mut self,
        resolver: &impl HostArenaResolver,
        va: u64,
        len: usize,
    ) -> Result<(), PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering};

        if self.arenas.first().is_some_and(TableArena::is_live) || len == 0 {
            return Ok(());
        }
        if !va.is_multiple_of(PT_PAGE)
            || !self.dirty.is_empty()
            || !self.staged.is_empty()
            || self.undo.is_some()
        {
            return Err(PageTableError::BadAddress);
        }
        let rounded_len = (len as u64)
            .checked_add(PT_PAGE - 1)
            .map(|value| value & !(PT_PAGE - 1))
            .ok_or(PageTableError::BadAddress)?;
        let end = va
            .checked_add(rounded_len)
            .ok_or(PageTableError::BadAddress)?;
        let mut copied = Vec::<TableLocation>::new();
        copied
            .try_reserve(4)
            .map_err(|_| PageTableError::MetadataAllocation)?;

        let mut current = va;
        while current < end {
            let indexes = indices(current);
            let mut table = TableLocation::new(0, 0);
            let mut next = end;
            for (level, index) in indexes.into_iter().enumerate() {
                if !copied.contains(&table) {
                    if copied.len() == copied.capacity() {
                        copied
                            .try_reserve(1)
                            .map_err(|_| PageTableError::MetadataAllocation)?;
                    }
                    let (base, table_end) = {
                        let arena = self
                            .arenas
                            .get(table.arena)
                            .ok_or(PageTableError::BadAddress)?;
                        let table_end = table
                            .offset
                            .checked_add(PT_PAGE as usize)
                            .ok_or(PageTableError::BadAddress)?;
                        if !table.offset.is_multiple_of(PT_PAGE as usize)
                            || table_end > arena.capacity
                        {
                            return Err(PageTableError::BadAddress);
                        }
                        (arena.base, table_end)
                    };
                    let host = resolver
                        .host_const_ptr_for_range(base, table_end)
                        .ok_or(PageTableError::UnresolvedArena(base))?;
                    let arena = &mut self.arenas[table.arena];
                    let TableArenaStorage::Owned(ref mut bytes) = arena.storage else {
                        return Err(PageTableError::BadAddress);
                    };
                    if bytes.len() < table_end {
                        bytes
                            .try_reserve(table_end - bytes.len())
                            .map_err(|_| PageTableError::MetadataAllocation)?;
                        bytes.resize(table_end, 0);
                    }
                    for offset in (table.offset..table_end).step_by(8) {
                        let slot = unsafe { host.add(offset).cast::<AtomicU64>() };
                        let descriptor = unsafe { (*slot).load(Ordering::Acquire) };
                        bytes[offset..offset + 8].copy_from_slice(&descriptor.to_le_bytes());
                    }
                    arena.next_free = arena.next_free.max(table_end as u64);
                    let table_pa = base + table.offset as u64;
                    self.free_tables.retain(|pa| *pa != table_pa);
                    copied.push(table);
                }

                let entry = table.entry(index);
                let descriptor = self.read_desc(entry)?;
                if level == 3 {
                    next = (current & !((1_u64 << 21) - 1))
                        .checked_add(1_u64 << 21)
                        .ok_or(PageTableError::BadAddress)?;
                    break;
                }
                if descriptor & VALID == 0 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
                    let (span, mask) = Self::level_span(level);
                    next = (current & mask)
                        .checked_add(span)
                        .ok_or(PageTableError::BadAddress)?;
                    break;
                }
                let child_pa = descriptor & PA_MASK_TABLE;
                table = self
                    .arenas
                    .iter()
                    .enumerate()
                    .find_map(|(arena_index, arena)| {
                        let offset = child_pa.checked_sub(arena.base)?;
                        let child_end = offset.checked_add(PT_PAGE)?;
                        (offset.is_multiple_of(PT_PAGE) && child_end <= arena.capacity as u64)
                            .then_some(TableLocation::new(arena_index, offset as usize))
                    })
                    .ok_or(PageTableError::BadAddress)?;
            }
            current = next.min(end);
        }
        Ok(())
    }

    /// Read-only descriptor walk over the LIVE host backing that the hardware
    /// MMU walks, rather than this manager's shadow bytes. Descriptor loads are
    /// atomic acquire operations, matching [`Self::sync_to_host`]'s atomic
    /// release publication. This is diagnostic-only and lets `carrick trace`
    /// distinguish a correctly edited shadow from publication to the wrong
    /// backing.
    ///
    /// # Safety
    /// `resolver` must return readable mappings for all arenas walked.
    pub unsafe fn debug_walk_host(
        &self,
        resolver: impl HostArenaResolver,
        va: u64,
    ) -> Result<[u64; 4], PageTableError> {
        use core::sync::atomic::{AtomicU64, Ordering};

        let idx = indices(va);
        let mut out = [0_u64; 4];
        let mut current_base = self.arenas[0].base;
        let mut table_off = 0_usize;
        #[allow(clippy::needless_range_loop)]
        for level in 0..4_usize {
            let off = table_off + idx[level] * 8;
            let host = resolver
                .host_const_ptr_for_range(current_base, off + 8)
                .ok_or(PageTableError::UnresolvedArena(current_base))?;
            let desc = unsafe {
                let slot = host.add(off).cast::<AtomicU64>();
                (*slot).load(Ordering::Acquire)
            };
            out[level] = desc;
            if level == 3 {
                break;
            }
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if !(valid && is_table) {
                break;
            }
            let child_pa = desc & PA_MASK_TABLE;
            let live_child = self.arenas.iter().enumerate().find_map(|(arena, entry)| {
                let offset = child_pa.checked_sub(entry.base)?;
                let end = offset.checked_add(PT_PAGE)?;
                (offset.is_multiple_of(PT_PAGE) && end <= entry.capacity as u64)
                    .then_some(TableLocation::new(arena, offset as usize))
            });
            match live_child {
                Some(loc) => {
                    current_base = self.arenas[loc.arena].base;
                    table_off = loc.offset;
                }
                None => break,
            }
        }
        Ok(out)
    }

    /// [`Self::debug_walk_host`] for many pages: `visit` receives each page and
    /// its live walk, exactly as `debug_walk_host` would return it, but each
    /// table arena is resolved through `resolver` once for the whole call
    /// rather than once per level of every page.
    ///
    /// The per-page walk asked the resolver for the arena at every level, and
    /// a host resolver answers that with an index search over the VM's
    /// mappings; revalidating one 256-page EL1 grant cost ~1k such searches.
    /// The arena's host mapping cannot move while the caller holds the
    /// exclusion that makes the walk meaningful, so one resolution per arena
    /// is the same answer.
    ///
    /// # Safety
    /// As [`Self::debug_walk_host`], and the live tables and their host
    /// mappings must not change for the duration of the call.
    pub unsafe fn debug_walk_host_pages(
        &self,
        resolver: impl HostArenaResolver,
        pages: impl IntoIterator<Item = u64>,
        mut visit: impl FnMut(u64, Result<[u64; 4], PageTableError>),
    ) {
        use core::sync::atomic::{AtomicU64, Ordering};

        // (arena base, host pointer, bytes the pointer was resolved for)
        let mut resolved: Vec<(u64, *const u8, usize)> = Vec::new();
        let mut host_for = |base: u64, len: usize| -> Option<*const u8> {
            if let Some(&(_, host, covered)) = resolved.iter().find(|&&(arena, _, _)| arena == base)
                && len <= covered
            {
                return Some(host);
            }
            let covered = self
                .arenas
                .iter()
                .find(|entry| entry.base == base)
                .map_or(len, |entry| entry.capacity.max(len));
            let host = resolver.host_const_ptr_for_range(base, covered)?;
            resolved.retain(|&(arena, _, _)| arena != base);
            resolved.push((base, host, covered));
            Some(host)
        };
        for va in pages {
            let idx = indices(va);
            let mut out = [0_u64; 4];
            let mut current_base = self.arenas[0].base;
            let mut table_off = 0_usize;
            let mut result = Ok(());
            #[allow(clippy::needless_range_loop)]
            for level in 0..4_usize {
                let off = table_off + idx[level] * 8;
                let Some(host) = host_for(current_base, off + 8) else {
                    result = Err(PageTableError::UnresolvedArena(current_base));
                    break;
                };
                let desc = unsafe {
                    let slot = host.add(off).cast::<AtomicU64>();
                    (*slot).load(Ordering::Acquire)
                };
                out[level] = desc;
                if level == 3 {
                    break;
                }
                let valid = desc & VALID != 0;
                let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
                if !(valid && is_table) {
                    break;
                }
                let child_pa = desc & PA_MASK_TABLE;
                let live_child = self.arenas.iter().enumerate().find_map(|(arena, entry)| {
                    let offset = child_pa.checked_sub(entry.base)?;
                    let end = offset.checked_add(PT_PAGE)?;
                    (offset.is_multiple_of(PT_PAGE) && end <= entry.capacity as u64)
                        .then_some(TableLocation::new(arena, offset as usize))
                });
                match live_child {
                    Some(loc) => {
                        current_base = self.arenas[loc.arena].base;
                        table_off = loc.offset;
                    }
                    None => break,
                }
            }
            visit(va, result.map(|()| out));
        }
    }

    /// Translate a guest VA to its stage-1 output address, returning error on failed resolution.
    pub fn try_translate(&self, va: u64) -> Result<Option<u64>, PageTableError> {
        self.try_translate_with_invalid_leaf(va, false)
    }

    /// Resolve the output address retained in a block/page whose valid bit may have been cleared.
    pub fn try_translate_retained_output(&self, va: u64) -> Result<Option<u64>, PageTableError> {
        self.try_translate_with_invalid_leaf(va, true)
    }

    /// Translate a guest VA to its stage-1 output address (the IPA carrick handed
    /// `hv_vm_map`), walking this manager's live descriptors exactly as the MMU
    /// would. Returns `None` if any level is invalid/out-of-range. Handles L3
    /// pages and L1 (1 GiB) / L2 (2 MiB) block descriptors. The syscall memory
    /// path uses this to find where the GUEST actually reads/writes a high-VA
    /// alias — which the linear `start..end` region heuristic can mis-resolve
    /// when alias regions overlap (16 KiB host rounding) or are non-linearly
    /// aliased.
    pub fn translate(&self, va: u64) -> Option<u64> {
        self.try_translate(va).ok().flatten()
    }

    /// Resolve the output address retained in a block/page whose valid bit may
    /// have been cleared by `munmap`/`PROT_NONE` publication.
    ///
    /// The guest MMU must never use an invalid descriptor, so ordinary access
    /// routes through [`Self::translate`]. Backing maintenance is different: a
    /// reused anonymous VMA must scrub the exact physical page that the next
    /// protection commit will revalidate, including a private COW fragment.
    /// Clearing VALID deliberately preserves that output address; this typed
    /// lookup exposes it without making the descriptor guest-accessible.
    pub fn translate_retained_output(&self, va: u64) -> Option<u64> {
        self.try_translate_retained_output(va).ok().flatten()
    }

    fn try_translate_with_invalid_leaf(
        &self,
        va: u64,
        allow_invalid_leaf: bool,
    ) -> Result<Option<u64>, PageTableError> {
        let idx = indices(va);
        let mut table_loc = TableLocation::new(0, 0);
        #[allow(clippy::needless_range_loop)]
        for level in 0..4usize {
            let entry_loc = table_loc.entry(idx[level]);
            if entry_loc.offset + 8 > self.arenas[entry_loc.arena].descriptor_span() as usize {
                return Ok(None);
            }
            let desc = self.read_desc(entry_loc)?;
            if desc & VALID == 0 {
                if !allow_invalid_leaf {
                    return Ok(None);
                }
                return Ok(match level {
                    1 if desc & PA_MASK_1GIB != 0 => {
                        Some((desc & PA_MASK_1GIB) | (va & ((1u64 << 30) - 1)))
                    }
                    2 if desc & PA_MASK_2MIB != 0 => {
                        Some((desc & PA_MASK_2MIB) | (va & ((1u64 << 21) - 1)))
                    }
                    3 if desc & PA_MASK_4KIB != 0 => Some((desc & PA_MASK_4KIB) | (va & 0xFFF)),
                    _ => None,
                });
            }
            let is_table_or_page = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if level == 3 {
                // L3 leaf must be a page (TYPE_TABLE_OR_PAGE); 0b01 is invalid here.
                return Ok(is_table_or_page.then_some((desc & PA_MASK_4KIB) | (va & 0xFFF)));
            }
            if is_table_or_page {
                // Table descriptor: descend to the next level.
                table_loc = match self.pa_to_loc(desc & PA_MASK_TABLE) {
                    Ok(loc) => loc,
                    Err(_) => return Ok(None),
                };
            } else {
                // Block descriptor (TYPE_BLOCK) terminates the walk at L1/L2.
                return Ok(match level {
                    1 => Some((desc & PA_MASK_1GIB) | (va & ((1u64 << 30) - 1))),
                    2 => Some((desc & PA_MASK_2MIB) | (va & ((1u64 << 21) - 1))),
                    _ => None, // L0 block is not architecturally valid here
                });
            }
        }
        Ok(None)
    }

    /// The bump cursor of the live primary arena, re-established before
    /// `pages` pages are carved from it. A guest editor can grow the same
    /// live primary arena between host edits. Usually the cached cursor
    /// still points at pristine zero pages, so checking exactly the
    /// candidates is the whole cost. If any candidate is occupied,
    /// reconstruct the high-water mark once from the authoritative live
    /// image; never hand a guest-linked table page out again, whether to the
    /// host editor ([`Self::alloc_table`]) or as an EL1 table grant
    /// ([`Self::reserve_table_grants`]).
    fn skip_occupied_primary_candidates(&mut self, pages: u64) -> Result<(), PageTableError> {
        let arena = &self.arenas[0];
        let Some(candidate_end) = pages
            .checked_mul(PT_PAGE)
            .and_then(|len| arena.next_free.checked_add(len))
        else {
            return Ok(());
        };
        if pages == 0 || !arena.is_live() || candidate_end > arena.capacity as u64 {
            return Ok(());
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(PageTableError::UnresolvedArena(arena.base))?;
        let host = resolver
            .host_const_ptr_for_range(arena.base, candidate_end as usize)
            .ok_or(PageTableError::UnresolvedArena(arena.base))?;
        // SAFETY: the resolver maps `[base, candidate_end)` of the arena.
        let candidates = unsafe {
            core::slice::from_raw_parts(
                host.add(arena.next_free as usize),
                (candidate_end - arena.next_free) as usize,
            )
        };
        const ZERO_PAGE: [u8; PT_PAGE as usize] = [0; PT_PAGE as usize];
        if candidates
            .chunks_exact(PT_PAGE as usize)
            .all(|page| page == ZERO_PAGE)
        {
            return Ok(());
        }
        let host = resolver
            .host_const_ptr_for_range(arena.base, arena.capacity)
            .ok_or(PageTableError::UnresolvedArena(arena.base))?;
        // SAFETY: the resolver maps the whole primary arena.
        let image = unsafe { core::slice::from_raw_parts(host, arena.capacity) };
        let discovered = discover_next_free_spare(image);
        self.arenas[0].next_free = self.arenas[0].next_free.max(discovered);
        Ok(())
    }

    /// Carve a zeroed table page: reuse a coalesced one if available, else bump
    /// the spare tail of the primary arena or an extension arena, or allocate a
    /// new extension arena from the attached source.
    fn alloc_table(
        &mut self,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<u64, PageTableError> {
        if self.table_allocation_forbidden {
            return Err(PageTableError::OutOfTables);
        }
        if let Some(&pa) = self.free_tables.last() {
            // A guest EL1 editor can write the shared live backing after the
            // host cached this unlinked page as free. Re-establish the allocator
            // invariant at handout time so a partial new table cannot expose
            // descriptors from another VA or generation.
            self.zero_unlinked_table(pa, true)?;
            let popped = self.free_tables.pop();
            debug_assert_eq!(popped, Some(pa));
            return Ok(pa);
        }
        self.skip_occupied_primary_candidates(1)?;
        if self.arenas[0].next_free + PT_PAGE <= self.arenas[0].capacity as u64 {
            let off = self.arenas[0].next_free;
            let needed = (off + PT_PAGE) as usize;
            if let TableArenaStorage::Owned(ref mut bytes) = self.arenas[0].storage
                && bytes.len() < needed
            {
                bytes
                    .try_reserve(needed - bytes.len())
                    .map_err(|_| PageTableError::MetadataAllocation)?;
                bytes.resize(needed, 0);
            }
            self.arenas[0].next_free += PT_PAGE;
            return Ok(self.arenas[0].base + off);
        }
        for arena in &mut self.arenas[1..] {
            if arena.next_free + PT_PAGE <= arena.capacity as u64 {
                let off = arena.next_free;
                let needed = (off + PT_PAGE) as usize;
                if let TableArenaStorage::Owned(ref mut bytes) = arena.storage
                    && bytes.len() < needed
                {
                    bytes
                        .try_reserve(needed - bytes.len())
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                    bytes.resize(needed, 0);
                }
                arena.next_free += PT_PAGE;
                return Ok(arena.base + off);
            }
        }
        if self.reclaim_all_invalid_tables()?
            && let Some(&pa) = self.free_tables.last()
        {
            self.zero_unlinked_table(pa, true)?;
            let popped = self.free_tables.pop();
            debug_assert_eq!(popped, Some(pa));
            return Ok(pa);
        }
        if let Some(source) = source.as_mut()
            && let Some(gpa) = source.take_arena()
        {
            let base = gpa.0;
            let capacity = self.layout.extension_arena_capacity;
            let storage = match self.arenas[0].storage {
                TableArenaStorage::Owned(_) => {
                    let mut bytes = Vec::new();
                    if bytes.try_reserve_exact(capacity).is_err() {
                        source.return_arena(gpa);
                        return Err(PageTableError::MetadataAllocation);
                    }
                    bytes.resize(PT_PAGE as usize, 0);
                    TableArenaStorage::Owned(bytes)
                }
                TableArenaStorage::Live => TableArenaStorage::Live,
            };
            if self.arenas.try_reserve(1).is_err() {
                source.return_arena(gpa);
                return Err(PageTableError::MetadataAllocation);
            }
            if let Some(journal) = self.undo.as_mut() {
                let needed_capacity = self.arenas.len().saturating_sub(journal.arenas_len) + 1;
                if journal.returned_bases.capacity() < needed_capacity
                    && journal.returned_bases.try_reserve(needed_capacity).is_err()
                {
                    source.return_arena(gpa);
                    return Err(PageTableError::MetadataAllocation);
                }
            }
            let arena = TableArena {
                snapshot_scratch: Vec::new(),
                base,
                storage,
                next_free: PT_PAGE,
                capacity,
            };
            self.arenas.push(arena);
            return Ok(base);
        }
        Err(PageTableError::OutOfTables)
    }

    /// Split the block descriptor at `parent_loc` (a leaf at `level`, where
    /// level 1 = 1 GiB block, level 2 = 2 MiB block) into a finer sub-table,
    /// then rewrite the parent as a table descriptor pointing at it.
    fn split_block(
        &mut self,
        parent_loc: TableLocation,
        level: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<(), PageTableError> {
        let block = self.read_desc(parent_loc)?;
        let (parent_pa_mask, child_pa_mask, child_stride, child_is_page) = match level {
            1 => (PA_MASK_1GIB, PA_MASK_2MIB, 1u64 << 21, false),
            2 => (PA_MASK_2MIB, PA_MASK_4KIB, 1u64 << 12, true),
            _ => return Err(PageTableError::BadAddress),
        };
        let base_pa = block & parent_pa_mask;
        // Leaf attributes minus the PA and the type bits.
        let attrs = block & !parent_pa_mask & !TYPE_BITS;
        let child_type = if child_is_page {
            TYPE_TABLE_OR_PAGE
        } else {
            TYPE_BLOCK
        };
        let parent_valid = block & VALID != 0;
        let parent_empty = !parent_valid && base_pa == 0;

        let table_pa = self.alloc_table(source)?;
        let table_loc = self.pa_to_loc(table_pa)?;
        for i in 0..512u64 {
            let child_loc = table_loc.entry(i as usize);
            if parent_empty {
                self.write_desc(child_loc, 0)?;
                continue;
            }
            let child_pa = base_pa + i * child_stride;
            let mut desc = (child_pa & child_pa_mask) | attrs | child_type;
            if !parent_valid {
                desc &= !VALID;
            }
            self.write_desc(child_loc, desc)?;
        }
        self.write_table_desc(parent_loc, (table_pa & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE)?;
        Ok(())
    }

    /// Read the covering block/page without splitting or allocating tables.
    fn covering_terminal_offset(&self, va: u64) -> Result<(TableLocation, usize), PageTableError> {
        let idx = indices(va);
        let mut table_loc = TableLocation::new(0, 0);
        #[allow(clippy::needless_range_loop)]
        for level in 0..4usize {
            let entry_loc = table_loc.entry(idx[level]);
            if level == 3 {
                return Ok((entry_loc, 3));
            }
            let desc = self.read_desc(entry_loc)?;
            if desc & VALID == 0 || desc & TYPE_BITS != TYPE_TABLE_OR_PAGE {
                return Ok((entry_loc, level));
            }
            table_loc = self.pa_to_loc(desc & PA_MASK_TABLE)?;
        }
        Err(PageTableError::BadAddress)
    }

    /// Descend to the leaf descriptor for `va`. When `allocate`, split any
    /// covering block so the returned leaf is a 4 KiB page; otherwise stop at
    /// the first leaf (block or page) and report its level.
    fn leaf_offset(
        &mut self,
        va: u64,
        allocate: bool,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<(TableLocation, usize), PageTableError> {
        if !allocate {
            return self.covering_terminal_offset(va);
        }
        let idx = indices(va);
        let mut table_loc = TableLocation::new(0, 0);
        #[allow(clippy::needless_range_loop)]
        for level in 0..4usize {
            let entry_loc = table_loc.entry(idx[level]);
            if level == 3 {
                return Ok((entry_loc, 3));
            }
            let desc = self.read_desc(entry_loc)?;
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if is_table && valid {
                table_loc = self.pa_to_loc(desc & PA_MASK_TABLE)?;
                continue;
            }
            // A full-block first-touch/PROT_NONE edit clears VALID without
            // discarding the owned output. Fork may need to repoint only one
            // child alias inside that block. Split the retained block exactly
            // as a valid block, preserving its invalidity on every child leaf.
            // Empty and retired descriptors have no live output to repoint;
            // an invalidated table pointer is not a block output either.
            if !valid
                && (level == 0
                    || desc & (TYPE_TABLE_OR_PAGE & !VALID) != 0
                    || !Self::records_output(desc, level)
                    || desc & SW_RETIRED != 0)
            {
                return Err(PageTableError::BadAddress);
            }
            self.split_block(entry_loc, level, source.as_deref_mut())?;
            let desc2 = self.read_desc(entry_loc)?;
            table_loc = self.pa_to_loc(desc2 & PA_MASK_TABLE)?;
        }
        Err(PageTableError::BadAddress)
    }

    /// Next-level table PA if the entry at `loc` is a valid table descriptor.
    fn child_table_pa(&self, loc: TableLocation) -> Option<u64> {
        let d = self.read_desc(loc).ok()?;
        if d & VALID != 0 && d & TYPE_BITS == TYPE_TABLE_OR_PAGE {
            Some(d & PA_MASK_TABLE)
        } else {
            None
        }
    }

    /// If every one of a table's 512 entries is a valid leaf of `child_type`
    /// with contiguous PA (`child_pa_mask`/`child_stride`), a base aligned for
    /// the parent block, and IDENTICAL attributes — i.e. the table is exactly
    /// equivalent to one coarse block — return `(base_pa, attrs)` for that
    /// block. Otherwise `None` (don't coalesce). The strict equality and parent
    /// alignment are what make coalescing safe: the block we write maps
    /// precisely what the table did.
    fn uniform_block(
        &self,
        table_loc: TableLocation,
        child_pa_mask: u64,
        child_stride: u64,
        child_type: u64,
    ) -> Option<(u64, u64)> {
        let e0 = self.read_desc(table_loc).ok()?;
        if e0 & VALID == 0 || e0 & TYPE_BITS != child_type {
            return None;
        }
        let base_pa = e0 & child_pa_mask;
        let parent_span = child_stride.checked_mul(512)?;
        if !base_pa.is_multiple_of(parent_span) {
            return None;
        }
        let attrs = e0 & !child_pa_mask & !TYPE_BITS;
        for i in 0..512usize {
            let d = self.read_desc(table_loc.entry(i)).ok()?;
            if d & VALID == 0
                || d & TYPE_BITS != child_type
                || (d & child_pa_mask) != base_pa + (i as u64) * child_stride
                || (d & !child_pa_mask & !TYPE_BITS) != attrs
            {
                return None;
            }
        }
        Some((base_pa, attrs))
    }

    /// Collapse fully-uniform spare sub-tables covering `va` back into a single
    /// block, reclaiming the table page. L3→L2 (2 MiB) then L2→L1 (1 GiB).
    /// This is restricted to an offline private image: a live valid-table to
    /// valid-block replacement needs two-phase break-before-make publication,
    /// which the one-batch editor cannot express. Only spare tables are touched
    /// (the boot L2_A/L2_B/L3_A — null guard + kernel hole — are never uniform
    /// and never spare, so are doubly safe).
    fn try_coalesce(&mut self, va: u64) -> Result<bool, PageTableError> {
        if self.multi_vcpu || !self.offline_private_image {
            return Ok(false);
        }
        // The tables holding the idle EL1 COW copy leaves are never folded:
        // EL1 maps a copy into those leaves without allocating a table.
        let holds_window = |mask: u64, span: u64| {
            descriptor_txn::copy_window::overlaps_cow_copy_window(va & mask, span)
        };
        let mut coalesced = false;
        let idx = indices(va);
        let l0_entry = TableLocation::new(0, idx[0] * 8);
        let Some(l1_pa) = self.child_table_pa(l0_entry) else {
            return Ok(false);
        };
        let Ok(l1_loc) = self.pa_to_loc(l1_pa) else {
            return Ok(false);
        };
        let l1_entry = l1_loc.entry(idx[1]);

        // L3 -> L2: the L2 entry must point at a spare L3 table of uniform pages.
        if let Some(l2_pa) = self.child_table_pa(l1_entry)
            && let Ok(l2_loc) = self.pa_to_loc(l2_pa)
        {
            let l2_entry = l2_loc.entry(idx[2]);
            if !holds_window(PA_MASK_2MIB, 1 << 21)
                && let Some(l3_pa) = self.child_table_pa(l2_entry)
                && self.is_spare_table(l3_pa)
                && let Ok(l3_loc) = self.pa_to_loc(l3_pa)
                && let Some((base, attrs)) =
                    self.uniform_block(l3_loc, PA_MASK_4KIB, 1 << 12, TYPE_TABLE_OR_PAGE)
            {
                self.free_tables
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
                self.write_desc(l2_entry, (base & PA_MASK_2MIB) | attrs | TYPE_BLOCK)?;
                self.free_table(l3_pa)?;
                coalesced = true;
            }
        }

        // L2 -> L1: the L1 entry must point at a spare L2 table of uniform blocks.
        if !holds_window(PA_MASK_1GIB, 1 << 30)
            && let Some(l2_pa) = self.child_table_pa(l1_entry)
            && self.is_spare_table(l2_pa)
            && let Ok(l2_loc) = self.pa_to_loc(l2_pa)
            && let Some((base, attrs)) =
                self.uniform_block(l2_loc, PA_MASK_2MIB, 1 << 21, TYPE_BLOCK)
        {
            self.free_tables
                .try_reserve(1)
                .map_err(|_| PageTableError::MetadataAllocation)?;
            self.write_desc(l1_entry, (base & PA_MASK_1GIB) | attrs | TYPE_BLOCK)?;
            self.free_table(l2_pa)?;
            coalesced = true;
        }
        Ok(coalesced)
    }

    /// Block size in bytes mapped by a leaf at `level` (0=512 GiB, 1=1 GiB, 2=2 MiB,
    /// 3=4 KiB) and the matching PA mask.
    fn level_span(level: usize) -> (u64, u64) {
        match level {
            0 => (1 << 39, !((1 << 39) - 1)),
            1 => (1 << 30, PA_MASK_1GIB),
            2 => (1 << 21, PA_MASK_2MIB),
            _ => (1 << 12, PA_MASK_4KIB),
        }
    }

    /// Whether a terminal descriptor at `level` carries an output address at
    /// all. A descriptor whose output field is zero is EMPTY — never populated,
    /// or cleared by a table reclaim — and records nothing a protection edit
    /// may preserve; it must be rebuilt, never edited in place, and it must
    /// never seed children when its block is split.
    fn records_output(desc: u64, level: usize) -> bool {
        let (_, mask) = Self::level_span(level);
        desc & mask != 0
    }

    /// Apply `op` to `[va, va+len)` at the COARSEST granularity possible: edit a
    /// covering block descriptor in place when the whole block lies inside the
    /// range, and split one level finer only at an unaligned range edge. This
    /// keeps the stage-1 tables sparse — a 512 MiB `PROT_NONE` reservation costs
    /// one L1→L2 split + 256 L2-block edits (1 table), not 256 L3 tables. Skips
    /// granules already at the target protection (so RW-on-already-RW is free).
    pub fn apply(
        &mut self,
        va: u64,
        len: usize,
        op: PtOp,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply_rule(va, len, TerminalRule::pt(op), source)
    }

    /// Apply `rule` to every covering terminal of `[va, va+len)`: skip a
    /// terminal that already satisfies it, edit a covered one in place and
    /// split one the range bisects. Guest EL1 descriptor transactions apply
    /// the same `terminal_rule_edit`. A refused terminal fails the edit
    /// (the host editor keeps no journal; callers that need atomicity
    /// validate first, as `clear_retired_for_new_mapping` does).
    pub fn apply_rule(
        &mut self,
        va: u64,
        len: usize,
        rule: TerminalRule,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        // A teardown is the only thing that can empty a sub-table, so this is
        // where the reclaim sweep becomes worth re-running.
        if matches!(
            rule,
            TerminalRule::Pt {
                op: Some(PtOp::Invalidate | PtOp::Retire),
                ..
            }
        ) {
            self.reclaim_pending = true;
        }
        let end = va + (len as u64).div_ceil(PT_PAGE) * PT_PAGE;
        if let Some(parts) = around_cow_copy_window(va, end) {
            let mut outcome = PageTableApplyOutcome::default();
            for (start, stop) in parts {
                if start < stop {
                    outcome |= self.apply_rule(
                        start,
                        (stop - start) as usize,
                        rule,
                        source.as_deref_mut(),
                    )?;
                }
            }
            return Ok(outcome);
        }
        let mut cur = va;
        let mut changed = false;
        let mut flush_required = false;
        while cur < end {
            // The existing covering descriptor (block or page) for `cur`.
            let (off, level) = self.leaf_offset(cur, false, None)?;
            let (span, mask) = Self::level_span(level);
            let block_start = cur & mask;
            let block_end = block_start + span;
            let desc = self.read_desc(off)?;
            let edited =
                terminal_rule_edit(self.asid_scoped_leaves, rule, desc, level, block_start)
                    .map_err(|_| PageTableError::BadAddress)?;
            let split_private = level < 3 && desc != 0 && rule.requires_private_pages();
            if edited.is_none() && !split_private {
                // The covering block is ALREADY at the target — skip its whole
                // span with no split (this is what keeps RW-on-already-RW, and a
                // re-protect of an unchanged range, free).
                cur = block_end;
            } else if let Some(new_desc) =
                edited.filter(|_| !split_private && block_start >= va && block_end <= end)
            {
                // The whole covering block is inside the range and needs the
                // change: edit it in place at this level (no split).
                let previously_valid = desc & VALID != 0;
                // A valid leaf whose output lies in the in-kernel GIC's window
                // would expose the distributor or a redistributor as memory,
                // whether the output was rebuilt from the identity VA or kept.
                if new_desc & VALID != 0 && self.layout.ipa_overlaps_excluded(new_desc & mask, span)
                {
                    return Err(PageTableError::GicWindowOutput);
                }
                if new_desc != desc {
                    self.write_desc(off, new_desc)?;
                    changed = true;
                    if previously_valid {
                        flush_required = true;
                    }
                }
                cur = block_end;
            } else {
                // The range edge bisects a block that needs changing: split one
                // level finer and re-examine (a 4 KiB page is never bisected —
                // len is page aligned — so `level` here is always 1 or 2). The
                // split itself mutates the tables (parent → table pointer + a
                // new sub-table), so it must be synced even if the subsequent
                // in-range edits all happen to be no-ops.
                let block = self.read_desc(off)?;
                let parent_valid = block & VALID != 0;
                self.split_block(off, level, source.as_deref_mut())?;
                changed = true;
                if parent_valid {
                    flush_required = true;
                }
                // `cur` unchanged; loop re-reads the now-finer covering leaf.
            }
        }
        // Reclaim any sub-table the edit left fully uniform (single-vCPU only;
        // see try_coalesce). Walk one VA per 2 MiB block touched.
        let coalesces = matches!(
            rule,
            TerminalRule::Pt {
                reset_retired: false,
                ..
            }
        );
        if coalesces && changed && !self.multi_vcpu && self.offline_private_image {
            let mut block = va & !((1 << 21) - 1);
            while block < end {
                let idx = indices(block);
                let l0_entry = TableLocation::new(0, idx[0] * 8);
                let Some(l1_pa) = self.child_table_pa(l0_entry) else {
                    let next_l0 = (block & !((1 << 39) - 1)).saturating_add(1 << 39);
                    block = next_l0.max(block + (1 << 21));
                    continue;
                };
                let Ok(l1_loc) = self.pa_to_loc(l1_pa) else {
                    let next_l0 = (block & !((1 << 39) - 1)).saturating_add(1 << 39);
                    block = next_l0.max(block + (1 << 21));
                    continue;
                };
                let l1_entry = l1_loc.entry(idx[1]);
                let Some(_l2_pa) = self.child_table_pa(l1_entry) else {
                    let next_l1 = (block & !((1 << 30) - 1)).saturating_add(1 << 30);
                    block = next_l1.max(block + (1 << 21));
                    continue;
                };
                if self.try_coalesce(block)? {
                    flush_required = true;
                }
                block += 1 << 21;
            }
        }
        Ok(PageTableApplyOutcome {
            changed,
            flush_required,
        })
    }

    /// Mark `[va, va+len)` invalid (faults on any access → SEGV_MAPERR).
    pub fn set_prot_none(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        // A teardown is the only thing that can empty a sub-table, so this is
        // where the reclaim sweep becomes worth re-running.
        self.reclaim_pending = true;
        self.apply(va, len, PtOp::Invalidate, source)
    }

    /// Begin a newly admitted mapping at a reused VA. Retired terminals name
    /// only the predecessor's frame lease; neither their output nor their EL1
    /// permission tags may become authority for the successor. A live private
    /// terminal (including a prepared one) is not a vacant mapping slot.
    /// Refuse a new mapping over `[va, va+len)` while any terminal there is
    /// a live (prepared or resident) or malformed EL1-private leaf. Read-only:
    /// the journal-less host editor validates before a retired-leaf reset so
    /// a refusal leaves no partial edit.
    pub fn check_vacant_for_new_mapping(
        &mut self,
        va: u64,
        len: usize,
    ) -> Result<(), PageTableError> {
        let end = va
            .checked_add(len as u64)
            .ok_or(PageTableError::BadAddress)?;
        if len == 0 || !va.is_multiple_of(PT_PAGE) || !len.is_multiple_of(PT_PAGE as usize) {
            return Err(PageTableError::BadAddress);
        }
        let mut current = va;
        while current < end {
            let (location, level) = self.leaf_offset(current, false, None)?;
            let descriptor = self.read_desc(location)?;
            let (span, mask) = Self::level_span(level);
            if matches!(
                el1_private_leaf_state(descriptor),
                El1PrivateLeafState::Prepared
                    | El1PrivateLeafState::Resident
                    | El1PrivateLeafState::Malformed
            ) {
                return Err(PageTableError::BadAddress);
            }
            current = (current & mask)
                .checked_add(span)
                .ok_or(PageTableError::BadAddress)?;
        }
        Ok(())
    }

    pub fn clear_retired_for_new_mapping(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.check_vacant_for_new_mapping(va, len)?;
        // Validated above, so the shared rule refuses nothing here: only
        // EL1-private retired leaves change (other retired leaves keep their
        // retained output for same-VA reuse and file-fault classification).
        let outcome = self.apply_rule(
            va,
            len,
            TerminalRule::Pt {
                op: None,
                reset_retired: true,
                deny_host_buffers: false,
                fork_arm: false,
                adopt_private: false,
            },
            source,
        )?;
        Ok(PageTableApplyOutcome::new(outcome.changed, false))
    }

    /// Drop one invalid output which is retired or which the fork child did
    /// not inherit in its frame inventory. A retired block may be split, but
    /// must never be repointed into a new retired output. The child is offline;
    /// the parent and neighboring invalid leaves retain their descriptors.
    pub fn clear_inaccessible_invalid_fork_leaf(&mut self, va: u64) -> Result<(), PageTableError> {
        if !va.is_multiple_of(PT_PAGE) {
            return Err(PageTableError::BadAddress);
        }
        if descriptor_txn::copy_window::overlaps_cow_copy_window(va, PT_PAGE) {
            return Err(PageTableError::CarrickOwnedWindow);
        }
        loop {
            let (location, level) = self.leaf_offset(va, false, None)?;
            let descriptor = self.read_desc(location)?;
            if descriptor & VALID != 0
                || level == 0
                || !Self::records_output(descriptor, level)
                || (level < 3 && descriptor & (TYPE_TABLE_OR_PAGE & !VALID) != 0)
            {
                return Err(PageTableError::BadAddress);
            }
            if level == 3 {
                return self.write_desc(location, 0);
            }
            self.split_block(location, level, None)?;
        }
    }

    /// Clear an absent semantic VA span in an offline fork image. Unlike
    /// lease retirement, no output survives: the child's inventory separately
    /// retains every physical owner needed by its live aliases. Covering
    /// terminals are cleared whole; only boundary blocks need splitting.
    pub fn clear_offline_fork_range(&mut self, va: u64, len: usize) -> Result<(), PageTableError> {
        if self.is_live()
            || !self.offline_private_image
            || len == 0
            || !va.is_multiple_of(PT_PAGE)
            || !len.is_multiple_of(PT_PAGE as usize)
        {
            return Err(PageTableError::BadAddress);
        }
        let end = va
            .checked_add(len as u64)
            .ok_or(PageTableError::BadAddress)?;
        if descriptor_txn::copy_window::overlaps_cow_copy_window(va, len as u64) {
            return Err(PageTableError::CarrickOwnedWindow);
        }
        let mut current = va;
        while current < end {
            let (location, level) = self.leaf_offset(current, false, None)?;
            let descriptor = self.read_desc(location)?;
            let (span, mask) = Self::level_span(level);
            let start = current & mask;
            let next = start.checked_add(span).ok_or(PageTableError::BadAddress)?;
            if descriptor == 0 {
                current = next.min(end);
            } else if current == start && next <= end || level == 3 {
                self.write_desc(location, 0)?;
                current = next.min(end);
            } else {
                self.split_block(location, level, None)?;
            }
        }
        Ok(())
    }

    /// Live physical outputs within a semantic VMA. A reservation can contain
    /// pristine pages with retired predecessor outputs; those pages have no
    /// backing to protect or inherit. Walk covering terminals, not every page
    /// in an empty/block span.
    pub fn backed_terminal_spans(
        &self,
        va: u64,
        len: usize,
    ) -> Result<Vec<core::ops::Range<u64>>, PageTableError> {
        let end = va
            .checked_add(len as u64)
            .ok_or(PageTableError::BadAddress)?;
        let mut current = va;
        let mut spans: Vec<core::ops::Range<u64>> = Vec::new();
        while current < end {
            let (location, level) = self.covering_terminal_offset(current)?;
            let descriptor = self.read_desc(location)?;
            let (span, mask) = Self::level_span(level);
            let next = (current & mask)
                .checked_add(span)
                .ok_or(PageTableError::BadAddress)?
                .min(end);
            if el1_private_leaf_state(descriptor) == El1PrivateLeafState::Malformed {
                return Err(PageTableError::BadAddress);
            }
            if Self::records_output(descriptor, level)
                && !terminal_descriptor_is_retired(descriptor)
            {
                if let Some(last) = spans.last_mut()
                    && last.end == current
                {
                    last.end = next;
                } else {
                    spans.push(current..next);
                }
            }
            current = next;
        }
        Ok(spans)
    }

    /// Remove EL1-private authority from an invalid file BUS tail. The output
    /// remains recorded for the owning stage-2 lease, but no EL1 permission or
    /// prepared-backing decision may use it after the file fault is published.
    pub fn mark_bus_fault(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        if len == 0
            || !va.is_multiple_of(PT_PAGE)
            || !len.is_multiple_of(PT_PAGE as usize)
            || va.checked_add(len as u64).is_none()
        {
            return Err(PageTableError::BadAddress);
        }
        let outcome = self.apply_rule(va, len, TerminalRule::BusFault, source)?;
        // Prepared leaves are invalid: removing their tags needs no flush.
        Ok(PageTableApplyOutcome::new(outcome.changed, false))
    }

    /// Host-forwarded `mprotect(PROT_NONE)` over EL1-private leaves. The
    /// invalidation alone leaves the same shape as a bulk-prepared, untouched
    /// leaf (invalid, tagged, output retained, AP read-write), and host buffer
    /// access admits the latter. Record kernel-only AP in the invalid
    /// descriptor, which hardware ignores while VALID is clear, so the host
    /// buffer predicate denies it. Any later revalidation rebuilds AP.
    pub fn set_prot_none_denying_host_buffers(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        // Only leaves the guest could observe (VALID, EL1-private) are marked:
        // stale invalid leaves under a fresh PROT_NONE reservation stay as they
        // are, and publication rebuilds them when the range is granted again.
        self.reclaim_pending = true;
        self.apply_rule(
            va,
            len,
            TerminalRule::Pt {
                op: Some(PtOp::Invalidate),
                reset_retired: false,
                deny_host_buffers: true,
                fork_arm: false,
                adopt_private: false,
            },
            source,
        )
    }

    /// `munmap`: invalidate `[va, va+len)` (the freed range faults until
    /// reused) AND mark each leaf's retained output RETIRED. The output address
    /// stays readable through `translate_retained_output` — same-VA reuse
    /// consults it to tell a retired lease from a live one — but a table
    /// holding only retired/empty/identity leaves becomes reclaimable, unlike
    /// one whose invalid leaves (`set_prot_none`) still name frames this mm
    /// owns.
    pub fn invalidate(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.reclaim_pending = true;
        self.apply(va, len, PtOp::Retire, source)
    }

    /// `munmap` of a HIGH-VA alias: invalidate the range AND reclaim any spare
    /// L3/L2 sub-table the invalidation left entirely empty, returning it to the
    /// pool and clearing the parent entry. Unlike `invalidate` (which only faults
    /// the leaves and KEEPS the sub-table — correct for the low-VA arena, whose
    /// pages are reused in place), a high-VA alias is torn down completely, so
    /// its dedicated per-2-MiB L3 table (one per `mmap(MAP_SHARED, fd)`, which
    /// each takes its own 2 MiB alias block) must be freed — otherwise the
    /// 440-entry spare pool leaks one table per alias and a churning guest
    /// (CPython multiprocessing maps+unmaps 400+ SemLock/Pool shm files) hits
    /// OutOfTables. Caller must hold the alias region exclusively here (this is
    /// the munmap path, PMR-gated under multi-vCPU); reclaim is additionally
    /// gated single-vCPU/PMR inside (see `reclaim_invalid_tables`).
    pub fn unmap_aliased(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        let mut outcome = self.invalidate(va, len, source)?;
        let reclaimed = self.reclaim_invalid_tables(va, len)?;
        outcome.changed |= reclaimed;
        if reclaimed {
            outcome.flush_required = true;
        }
        Ok(outcome)
    }

    /// Free spare L3/L2 sub-tables in `[va, va+len)` that the caller just left
    /// ALL-INVALID, clearing the parent entry. The dual of `try_coalesce` (which
    /// flips a uniform-VALID table to a block): this reclaims an empty table.
    /// Single-vCPU/PMR only — a freed table must not be reused under a sibling's
    /// stale walk-cache (same break-before-make rule as coalesce). Returns
    /// whether anything was freed.
    fn reclaim_invalid_tables(&mut self, va: u64, len: usize) -> Result<bool, PageTableError> {
        self.reclaim_invalid_tables_counting(va, len)
            .map(|(freed, _)| freed)
    }

    fn reclaim_invalid_tables_counting(
        &mut self,
        va: u64,
        len: usize,
    ) -> Result<(bool, usize), PageTableError> {
        if self.multi_vcpu {
            return Ok((false, 0));
        }
        let end = va + (len as u64).div_ceil(PT_PAGE) * PT_PAGE;
        let mut block = va & !((1 << 21) - 1);
        let mut freed = false;
        let mut steps = 0;
        while block < end {
            steps += 1;
            let idx = indices(block);
            let l0_entry = TableLocation::new(0, idx[0] * 8);
            let Some(l1_pa) = self.child_table_pa(l0_entry) else {
                let next_l0 = (block & !((1 << 39) - 1)).saturating_add(1 << 39);
                block = next_l0.max(block + (1 << 21));
                continue;
            };
            let Ok(l1_loc) = self.pa_to_loc(l1_pa) else {
                let next_l0 = (block & !((1 << 39) - 1)).saturating_add(1 << 39);
                block = next_l0.max(block + (1 << 21));
                continue;
            };
            let l1_entry = l1_loc.entry(idx[1]);
            let Some(_l2_pa) = self.child_table_pa(l1_entry) else {
                let next_l1 = (block & !((1 << 30) - 1)).saturating_add(1 << 30);
                block = next_l1.max(block + (1 << 21));
                continue;
            };
            freed |= self.reclaim_invalid_block(block)?;
            block += 1 << 21;
        }
        Ok((freed, steps))
    }

    /// Walk the LIVE table structure and free every spare sub-table that is
    /// all-invalid, clearing the parent entry that pointed at it. The dual of
    /// `reclaim_invalid_tables`, but driven by the table graph rather than by a
    /// VA range, so a caller that has no range in hand (`alloc_table`) can still
    /// recover the pool.
    ///
    /// Bounded by the number of LIVE tables, not by the address space: at most
    /// `capacity` tables, each a 512-descriptor scan. That is trivial as a
    /// one-shot and unaffordable per edit, which is exactly why it lives here.
    ///
    /// EXCLUSIVITY IS REQUIRED. Freeing a table only makes it reusable, and
    /// handing a page back out while a sibling vCPU may hold a stale cached walk
    /// reaching it is the same break-before-make hazard that gates the eager
    /// paths. Under `stage1_exclusive` there is no such sibling. Returns whether
    /// anything was freed.
    fn reclaim_all_invalid_tables(&mut self) -> Result<bool, PageTableError> {
        if !self.stage1_exclusive || !self.reclaim_pending {
            return Ok(false);
        }
        let mut freed = false;
        for l0 in 0..512usize {
            let Some(l1_pa) = self.child_table_pa(TableLocation::new(0, l0 * 8)) else {
                continue;
            };
            let Ok(l1_loc) = self.pa_to_loc(l1_pa) else {
                continue;
            };
            for l1 in 0..512usize {
                let l1_entry = l1_loc.entry(l1);
                let Some(l2_pa) = self.child_table_pa(l1_entry) else {
                    continue;
                };
                let Ok(l2_loc) = self.pa_to_loc(l2_pa) else {
                    continue;
                };
                let l2_table_va = ((l0 as u64) << 39) | ((l1 as u64) << 30);
                for l2 in 0..512usize {
                    let l2_entry = l2_loc.entry(l2);
                    let l3_table_va = l2_table_va | ((l2 as u64) << 21);
                    if let Some(l3_pa) = self.child_table_pa(l2_entry)
                        && self.is_spare_table(l3_pa)
                        && let Ok(l3_loc) = self.pa_to_loc(l3_pa)
                        && self.table_reclaimable(l3_loc, l3_table_va, 3)
                    {
                        self.free_tables
                            .try_reserve(1)
                            .map_err(|_| PageTableError::MetadataAllocation)?;
                        self.write_desc(l2_entry, 0)?;
                        self.free_table(l3_pa)?;
                        freed = true;
                    }
                }
                if self.is_spare_table(l2_pa) && self.table_reclaimable(l2_loc, l2_table_va, 2) {
                    self.free_tables
                        .try_reserve(1)
                        .map_err(|_| PageTableError::MetadataAllocation)?;
                    self.write_desc(l1_entry, 0)?;
                    self.free_table(l2_pa)?;
                    freed = true;
                }
            }
        }
        // One sweep per teardown epoch. Re-walking with nothing newly
        // invalidated cannot find anything the last walk missed.
        self.reclaim_pending = false;
        Ok(freed)
    }

    fn reclaim_invalid_block(&mut self, va: u64) -> Result<bool, PageTableError> {
        let idx = indices(va);
        let l0_entry = TableLocation::new(0, idx[0] * 8);
        let Some(l1_pa) = self.child_table_pa(l0_entry) else {
            return Ok(false);
        };
        let Ok(l1_loc) = self.pa_to_loc(l1_pa) else {
            return Ok(false);
        };
        let l1_entry = l1_loc.entry(idx[1]);
        let mut freed = false;
        // L3 all-invalid -> free it, invalidate the L2 entry that pointed at it.
        if let Some(l2_pa) = self.child_table_pa(l1_entry)
            && let Ok(l2_loc) = self.pa_to_loc(l2_pa)
        {
            let l2_entry = l2_loc.entry(idx[2]);
            if let Some(l3_pa) = self.child_table_pa(l2_entry)
                && self.is_spare_table(l3_pa)
                && let Ok(l3_loc) = self.pa_to_loc(l3_pa)
                && self.table_reclaimable(l3_loc, va & !((1 << 21) - 1), 3)
            {
                self.free_tables
                    .try_reserve(1)
                    .map_err(|_| PageTableError::MetadataAllocation)?;
                self.write_desc(l2_entry, 0)?;
                self.free_table(l3_pa)?;
                freed = true;
            }
        }
        // L2 now all-invalid (the last alias in this 1 GiB went away) -> free it.
        if let Some(l2_pa) = self.child_table_pa(l1_entry)
            && self.is_spare_table(l2_pa)
            && let Ok(l2_loc) = self.pa_to_loc(l2_pa)
            && self.table_reclaimable(l2_loc, va & !((1 << 30) - 1), 2)
        {
            self.free_tables
                .try_reserve(1)
                .map_err(|_| PageTableError::MetadataAllocation)?;
            self.write_desc(l1_entry, 0)?;
            self.free_table(l2_pa)?;
            freed = true;
        }
        Ok(freed)
    }

    /// Whether the table at `table_loc`, whose entries are terminal
    /// descriptors at `level` covering `[table_va, table_va + 512 * span)`,
    /// records nothing a rebuild could not reproduce: every entry satisfies
    /// the shared [`reclaimable_entry`] (see there for why "VALID clear" is
    /// not the test).
    fn table_reclaimable(&self, table_loc: TableLocation, table_va: u64, level: usize) -> bool {
        debug_assert!(sub_table_level_reclaimable(level));
        let (span, _) = Self::level_span(level);
        (0..512usize).all(|i| {
            self.read_desc(table_loc.entry(i))
                .is_ok_and(|desc| reclaimable_entry(desc, level, table_va + (i as u64) * span))
        })
    }

    /// Mark `[va, va+len)` valid read-only (AP=RO). `exec` clears UXN
    /// (executable, PROT_EXEC); otherwise UXN is set (non-executable / NX).
    pub fn set_readonly(
        &mut self,
        va: u64,
        len: usize,
        exec: bool,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply(va, len, PtOp::ReadOnly { exec }, source)
    }

    /// [`Self::set_fork_readonly`], first adopting host-published writable
    /// 4 KiB leaves as EL1-private so EL1 can resolve their COW itself (a
    /// guest-lane MM's compound-granule, non-kernel ranges only).
    pub fn set_fork_readonly_adopting(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply_rule(va, len, TerminalRule::fork_arm(true), source)
    }

    /// Arm a private fork range read-only and make the descriptor ASID-scoped.
    /// The output address and all unrelated attributes are preserved, including
    /// for non-identity aliases and already-read-only mappings.
    pub fn set_fork_readonly(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply(va, len, PtOp::ForkReadOnly, source)
    }

    /// Make the two EL1 COW copy-alias leaves exactly what
    /// [`descriptor_txn::copy_window::with_cow_copy_aliases`] requires: table
    /// descriptors down to L3, and each leaf invalid, EL1-only (AP=00),
    /// kernel-attributed and recording its own VA as output, with this
    /// image's nG scoping. This is the one writer of those leaves outside the
    /// bounded EL1 copy; every constructor of a live HVPatch MM image (boot,
    /// exec rebuild, fork child) calls it on the offline image before
    /// publication. Other range edits step around the window and never
    /// coalesce or reclaim its table, so the shape then persists. Returns
    /// whether any descriptor changed.
    pub fn provision_cow_copy_window(
        &mut self,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        use descriptor_txn::copy_window::{COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN};
        let scope = if self.asid_scoped_leaves {
            NON_GLOBAL
        } else {
            0
        };
        let mut changed = false;
        for va in (COW_COPY_WINDOW_BASE..COW_COPY_WINDOW_BASE + COW_COPY_WINDOW_LEN)
            .step_by(PT_PAGE as usize)
        {
            let (location, level) = self.leaf_offset(va, true, source.as_deref_mut())?;
            if level != 3 {
                return Err(PageTableError::BadAddress);
            }
            let idle = (va & PA_MASK_4KIB) | (KERNEL_PAGE_FLAGS & !VALID) | scope;
            if self.read_desc(location)? != idle {
                self.write_desc(location, idle)?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Whether both EL1 COW copy-alias leaves have the idle shape
    /// [`descriptor_txn::copy_window::with_cow_copy_aliases`] requires:
    /// table descriptors down to L3, each leaf invalid, AP=00 and recording
    /// its own VA. The post-condition of [`Self::provision_cow_copy_window`].
    #[must_use]
    pub fn cow_copy_window_is_idle(&self) -> bool {
        use descriptor_txn::copy_window::{COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN};
        (COW_COPY_WINDOW_BASE..COW_COPY_WINDOW_BASE + COW_COPY_WINDOW_LEN)
            .step_by(PT_PAGE as usize)
            .all(|va| {
                self.try_debug_walk(va).is_ok_and(|walk| {
                    walk[..3]
                        .iter()
                        .all(|descriptor| descriptor & TYPE_BITS == TYPE_TABLE_OR_PAGE)
                        && walk[3] & (VALID | AP_MASK) == 0
                        && walk[3] & PA_MASK_4KIB == va
                })
            })
    }

    /// Mark a Carrick-owned EL1 range read-only without granting EL0 access.
    /// The AP=10 distinction is architectural under PAN and must survive the
    /// fork-arm split of the kernel-only 2 MiB boot block.
    pub fn set_kernel_readonly(
        &mut self,
        va: u64,
        len: usize,
        exec: bool,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply(va, len, PtOp::KernelReadOnly { exec }, source)
    }

    /// Restore `[va, va+len)` to a valid RW user page (identity-mapped). `exec`
    /// clears UXN (executable, PROT_EXEC); otherwise UXN is set (NX).
    pub fn set_rw(
        &mut self,
        va: u64,
        len: usize,
        exec: bool,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply(va, len, PtOp::ReadWrite { exec }, source)
    }

    /// Build a fresh VA→IPA translation for `[va, va+len)` for EL0, creating
    /// any missing L1/L2/L3 sub-tables. This is the dynamic counterpart of the
    /// boot Rosetta alias: it maps high guest VAs (which can't be
    /// identity-mapped — HVF's IPA is only 40 bits) down to a low IPA the caller
    /// has `hv_vm_map`'d. Uses 2 MiB blocks when `va`/`ipa`/`len` are 2 MiB
    /// aligned, else 4 KiB pages. Always Ok(true).
    ///
    /// `access` is the mapping's EL0 permission, both bits named by the
    /// caller from the Linux protection that owns the range: a non-writable
    /// leaf is built AP=RO while PRESERVING the IPA output address (a guest
    /// store to a SHM_RDONLY shmat alias raises a stage-1 permission abort,
    /// SIGSEGV, matching Linux; set_readonly/apply on an empty leaf would
    /// rebuild it from the VA), and a non-executable leaf sets UXN. There is
    /// no executable default.
    pub fn map_aliased(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        access: UserLeafAccess,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        let scope = if self.asid_scoped_leaves {
            NON_GLOBAL
        } else {
            0
        };
        let (block_flags, page_flags) = access.leaf_flags(scope);
        self.map_aliased_with_flags(va, ipa, len, block_flags, page_flags, source)
    }

    /// Build a per-mm VA→IPA translation whose TLB entries are ASID-scoped.
    ///
    /// HVPatch uses this for private demand-materialized mmap extents. Their
    /// output lives in a VM-global IPA arena, but the semantic translation is
    /// owned by exactly one mm and must therefore carry nG from its first
    /// publication. Shared aliases keep using [`Self::map_aliased`]. New
    /// leaves are always ASID-scoped (`nG`) and carry exactly `access`.
    pub fn map_private_aliased(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        access: UserLeafAccess,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        let (block_flags, page_flags) = access.leaf_flags(NON_GLOBAL);
        self.map_aliased_with_flags(va, ipa, len, block_flags, page_flags, source)
    }

    /// Repoint an EL1-only Carrick control-page range while preserving the
    /// kernel-hole execution regime: AP=00, UXN=1, PXN=0. Using the ordinary
    /// user alias flags here sets PXN and makes the entry trampoline/vector
    /// page unexecutable at EL1 under FEAT_PAN3.
    pub fn map_kernel_aliased(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const KERNEL_ATTRS: u64 = (1u64 << 54) | NON_GLOBAL | (1 << 10) | (0b11 << 8);
        self.map_aliased_with_flags(
            va,
            ipa,
            len,
            KERNEL_ATTRS | TYPE_BLOCK,
            KERNEL_ATTRS | TYPE_TABLE_OR_PAGE,
            source,
        )
    }

    /// Map Carrick-owned EL1 data at `[va, va + len)`: AP=00 (EL1 read/write,
    /// no EL0 access), never executable at either level. The stage-1 table
    /// pool view (`carrick_el1_abi::stage1_table_pool_window`) is mapped this way.
    pub fn map_kernel_data_aliased(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const KERNEL_DATA_ATTRS: u64 =
            (1u64 << 54) | (1u64 << 53) | NON_GLOBAL | (1 << 10) | (0b11 << 8);
        self.map_aliased_with_flags(
            va,
            ipa,
            len,
            KERNEL_DATA_ATTRS | TYPE_BLOCK,
            KERNEL_DATA_ATTRS | TYPE_TABLE_OR_PAGE,
            source,
        )
    }

    /// Repoint existing 4 KiB leaves to a new linear IPA while preserving every
    /// non-address attribute: validity, AP, AF, shareability, PXN and UXN.  Frame
    /// COW uses this before selectively granting write to the semantic pages
    /// which are currently writable.  That matters when one 16 KiB host
    /// compound straddles a `brk`, `mprotect`, or partial-unmap boundary.
    pub fn repoint_preserving_attributes(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const FOUR_KIB: u64 = 1 << 12;
        if va & (FOUR_KIB - 1) != ipa & (FOUR_KIB - 1) {
            return Err(PageTableError::BadAddress);
        }
        if descriptor_txn::copy_window::overlaps_cow_copy_window(va, len) {
            return Err(PageTableError::CarrickOwnedWindow);
        }
        if self.layout.ipa_overlaps_excluded(ipa, len) {
            return Err(PageTableError::GicWindowOutput);
        }
        let pages = len.div_ceil(FOUR_KIB);
        let mut changed = false;
        for index in 0..pages {
            let page_va = (va & !(FOUR_KIB - 1)) + index * FOUR_KIB;
            let page_ipa = (ipa & !(FOUR_KIB - 1)) + index * FOUR_KIB;
            let (loc, level) = self.leaf_offset(page_va, true, source.as_deref_mut())?;
            if level != 3 {
                return Err(PageTableError::BadAddress);
            }
            let descriptor = self.read_desc(loc)?;
            let replacement = (descriptor & !PA_MASK_4KIB) | (page_ipa & PA_MASK_4KIB);
            if replacement != descriptor {
                self.write_desc(loc, replacement)?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Grant EL0/EL1 write access without changing validity or execute policy.
    /// The caller has already established that these exact semantic pages are
    /// writable; preserving UXN/PXN avoids reintroducing execute permission on
    /// a page whose post-fork `mprotect` state differs from its boot mapping.
    /// Clear the EL1 fork-COW arm of every valid EL1-private leaf in
    /// `[va, va + len)`, preserving everything else. A host-lane frame COW
    /// that made the span private calls this after its repoint: the arm is
    /// EL1's authority to copy on the guest lane, so a stale one would let
    /// EL1 copy a span the host already resolved (and disarmed) once the MM
    /// moves to the guest lane. Returns whether a descriptor changed.
    pub fn clear_el1_cow_arm(
        &mut self,
        va: u64,
        len: usize,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const FOUR_KIB: u64 = 1 << 12;
        if descriptor_txn::copy_window::overlaps_cow_copy_window(va, len as u64) {
            return Err(PageTableError::CarrickOwnedWindow);
        }
        let pages = (len as u64).div_ceil(FOUR_KIB);
        let mut changed = false;
        for index in 0..pages {
            let page_va = (va & !(FOUR_KIB - 1)) + index * FOUR_KIB;
            let (loc, level) = self.leaf_offset(page_va, true, source.as_deref_mut())?;
            if level != 3 {
                return Err(PageTableError::BadAddress);
            }
            let descriptor = self.read_desc(loc)?;
            if !el1_cow(descriptor) {
                continue;
            }
            self.write_desc(loc, descriptor & !SW_EL1_COW)?;
            changed = true;
        }
        Ok(changed)
    }

    pub fn set_writable_preserving_attributes(
        &mut self,
        va: u64,
        len: usize,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const FOUR_KIB: u64 = 1 << 12;
        if descriptor_txn::copy_window::overlaps_cow_copy_window(va, len as u64) {
            return Err(PageTableError::CarrickOwnedWindow);
        }
        let pages = (len as u64).div_ceil(FOUR_KIB);
        let mut changed = false;
        for index in 0..pages {
            let page_va = (va & !(FOUR_KIB - 1)) + index * FOUR_KIB;
            let (loc, level) = self.leaf_offset(page_va, true, source.as_deref_mut())?;
            if level != 3 {
                return Err(PageTableError::BadAddress);
            }
            let descriptor = self.read_desc(loc)?;
            if descriptor & VALID == 0 {
                continue;
            }
            let replacement = (descriptor & !AP_MASK) | AP_RW;
            if replacement != descriptor {
                self.write_desc(loc, replacement)?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Spare pages still available to `alloc_table`: the free list plus the
    /// untouched bump tail across all arenas.
    pub fn spare_tables_available(&self) -> u64 {
        let mut tail = 0u64;
        for arena in &self.arenas {
            tail += (arena.capacity as u64).saturating_sub(arena.next_free) / PT_PAGE;
        }
        self.free_tables.len() as u64 + tail
    }

    /// Count the naturally aligned `gran` spans that `[start, end)` touches.
    fn spans_touched(start: u64, end: u64, gran: u64) -> u64 {
        if end <= start {
            return 0;
        }
        let first = start & !(gran - 1);
        let last = (end - 1) & !(gran - 1);
        (last - first) / gran + 1
    }

    /// Build a VA→IPA alias translation using the COARSEST leaf the geometry
    /// admits at every step: 1 GiB L1 blocks, then 2 MiB L2 blocks, then 4 KiB
    /// L3 pages only at the edges.
    ///
    /// `mmap` establishes a VMA; it must not do work proportional to the
    /// mapping's size. A block leaf maps a naturally aligned VA span onto an
    /// equally aligned output, so it is expressible exactly when the VA and the
    /// IPA are *congruent* modulo the block size — congruence, not either
    /// address's own alignment, is what decides whether coarse leaves are
    /// usable. (Masking an unaligned output into a block descriptor would
    /// silently map the wrong bytes, so the choice is made per step and never
    /// forced.)
    ///
    /// The build is also all-or-nothing. Running out of spare tables partway
    /// used to leave a half-built mapping that the guest re-faults on forever —
    /// an apparent hang rather than an error — so the table budget is checked
    /// UP FRONT and an unsatisfiable build is refused whole, which the callers
    /// lower to a guest `ENOMEM` the way Linux does.
    fn map_aliased_with_flags(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        block_flags: u64,
        page_flags: u64,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<bool, PageTableError> {
        const ONE_GIB: u64 = 1 << 30;
        const TWO_MIB: u64 = 1 << 21;
        const L1_SPAN: u64 = 1 << 39;
        if len == 0 {
            return Ok(false);
        }
        if self.layout.ipa_overlaps_excluded(ipa, len) {
            return Err(PageTableError::GicWindowOutput);
        }
        let end = va.checked_add(len).ok_or(PageTableError::BadAddress)?;
        if let Some(parts) = around_cow_copy_window(va, end) {
            let mut mapped = false;
            for (start, stop) in parts {
                if start < stop {
                    mapped |= self.map_aliased_with_flags(
                        start,
                        ipa + (start - va),
                        stop - start,
                        block_flags,
                        page_flags,
                        source.as_deref_mut(),
                    )?;
                }
            }
            return Ok(mapped);
        }

        // Upper-bound the new tables this build can need, so an unsatisfiable
        // one is refused before a single descriptor is written. Coarse leaves
        // need no table at their own level, so only the levels ABOVE the leaf
        // count. When VA and IPA are incongruent mod 2 MiB no block leaf is
        // expressible anywhere and the build is page-granular throughout —
        // which is what makes the budget check load-bearing rather than
        // theoretical.
        let congruent = (va & (TWO_MIB - 1)) == (ipa & (TWO_MIB - 1));
        let l1_tables = Self::spans_touched(va, end, L1_SPAN);
        let l2_tables = Self::spans_touched(va, end, ONE_GIB);
        let l3_tables = if congruent {
            // Only the two unaligned edges fall to pages.
            Self::spans_touched(va, end, TWO_MIB).min(2)
        } else {
            Self::spans_touched(va, end, TWO_MIB)
        };
        let needed = l1_tables + l2_tables + l3_tables;
        if needed > self.spare_tables_available() {
            // The budget is checked UP FRONT (see above), so this path returns
            // before `alloc_table` is ever called and its last-resort sweep
            // would never run. Take the same one-shot reclaim here, then re-ask.
            self.reclaim_all_invalid_tables()?;
            if source.is_none() && needed > self.spare_tables_available() {
                return Err(PageTableError::OutOfTables);
            }
        }

        let mut cursor = va;
        while cursor < end {
            let out = ipa + (cursor - va);
            let remaining = end - cursor;
            let level = if cursor.is_multiple_of(ONE_GIB)
                && out.is_multiple_of(ONE_GIB)
                && remaining >= ONE_GIB
            {
                1
            } else if cursor.is_multiple_of(TWO_MIB)
                && out.is_multiple_of(TWO_MIB)
                && remaining >= TWO_MIB
            {
                2
            } else {
                3
            };
            let (span, mask) = Self::level_span(level);
            let flags = if level == 3 { page_flags } else { block_flags };
            let table_loc = self.descend_creating(cursor, level, source.as_deref_mut())?;
            let idx = indices(cursor);
            self.write_desc(table_loc.entry(idx[level]), (out & mask) | flags)?;
            cursor += span;
        }
        Ok(true)
    }

    /// Descend from L0 to the table at `target_level` (1, 2, or 3), allocating
    /// any missing intermediate table from the spare pool. Returns the table's
    /// location. Errors if an existing block sits on the path (never the case
    /// for the high alias space).
    fn descend_creating(
        &mut self,
        va: u64,
        target_level: usize,
        mut source: Option<&mut dyn TableArenaSource>,
    ) -> Result<TableLocation, PageTableError> {
        let idx = indices(va);
        let mut table_loc = TableLocation::new(0, 0); // L0 at byte offset 0 in arena 0
        #[allow(clippy::needless_range_loop)]
        for level in 0..target_level {
            let entry_loc = table_loc.entry(idx[level]);
            let desc = self.read_desc(entry_loc)?;
            let valid = desc & VALID != 0;
            let is_table = desc & TYPE_BITS == TYPE_TABLE_OR_PAGE;
            if valid && is_table {
                table_loc = self.pa_to_loc(desc & PA_MASK_TABLE)?;
                continue;
            }
            if valid {
                // A valid BLOCK leaf covering this VA. Split it into a finer
                // sub-table (preserving its mapping + validity) so we can
                // descend and install a sub-range — e.g. a finer mapping inside
                // a 2 MiB block an earlier alias mapping created (the case a
                // forked child hits when it maps inside a block its parent's
                // cloned tables already established). Mirrors `leaf_offset`.
                self.split_block(entry_loc, level, source.as_deref_mut())?;
                let desc2 = self.read_desc(entry_loc)?;
                table_loc = self.pa_to_loc(desc2 & PA_MASK_TABLE)?;
                continue;
            }
            let pa = self.alloc_table(source.as_deref_mut())?;
            table_loc = self.pa_to_loc(pa)?;
            self.write_table_desc(entry_loc, (pa & PA_MASK_TABLE) | TYPE_TABLE_OR_PAGE)?;
        }
        Ok(table_loc)
    }

    /// True iff the leaf for `va` (block or page) is valid. Test/diagnostic.
    #[cfg(test)]
    pub fn is_valid(&mut self, va: u64) -> bool {
        match self.leaf_offset(va, false, None) {
            Ok((loc, _)) => self.read_desc(loc).map(|d| d & VALID != 0).unwrap_or(false),
            Err(_) => false,
        }
    }

    /// AP[2:1] of the leaf for `va`. Test/diagnostic.
    #[cfg(test)]
    pub fn ap_bits(&mut self, va: u64) -> u64 {
        match self.leaf_offset(va, false, None) {
            Ok((loc, _)) => self.read_desc(loc).map(|d| d & AP_MASK).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// `unmap_aliased` returning exact traversal steps for algorithmic verification.
    #[cfg(test)]
    pub fn unmap_aliased_counting(
        &mut self,
        va: u64,
        len: usize,
        source: Option<&mut dyn TableArenaSource>,
    ) -> Result<(PageTableApplyOutcome, usize), PageTableError> {
        let mut outcome = self.invalidate(va, len, source)?;
        let (reclaimed, steps) = self.reclaim_invalid_tables_counting(va, len)?;
        outcome.changed |= reclaimed;
        if reclaimed {
            outcome.flush_required = true;
        }
        Ok((outcome, steps))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    /// Page-table arenas for a VM-free test whose images carry executable
    /// leaves: a raw `(base, host)` set refuses executable publication in
    /// production, so a test that publishes them says so explicitly.
    struct TestArenas<'a>(&'a [(u64, *mut u8)]);

    unsafe impl HostArenaResolver for TestArenas<'_> {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            self.0.iter().find_map(|&(b, p)| (b == base).then_some(p))
        }

        fn publish_user_executable(&self, _output: u64, _len: u64) -> Result<(), PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    /// The executable leaves these fixtures were written against; the
    /// production callers name their mapping's own access.
    const RWX: UserLeafAccess = UserLeafAccess {
        writable: true,
        executable: true,
    };
    const RX: UserLeafAccess = UserLeafAccess {
        writable: false,
        executable: true,
    };
    use alloc::boxed::Box;
    use alloc::vec;
    use carrick_mem::memory::{
        LINUX_ALIAS_IPA_BASE, LINUX_GIC_DISTRIBUTOR_BASE, LINUX_GIC_REDISTRIBUTOR_BASE,
        LINUX_GIC_WINDOW_BASE, LINUX_GIC_WINDOW_SIZE, LINUX_HEAP_BASE, LINUX_HEAP_SIZE,
        LINUX_HIGH_VA_THRESHOLD, LINUX_HVPATCH_GLOBAL_FRAME_BASE, LINUX_MMAP_BASE,
        LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE,
        LINUX_PRIVATE_OVERLAY_BASE, LINUX_SHARED_FILE_BASE, mmap_arena_size,
        stage1_hvpatch_page_tables, stage1_identity_page_tables,
    };

    mod rollback_revocation {
        use super::*;
        use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        struct Revocable {
            words: Box<[AtomicU64]>,
            calls: AtomicUsize,
        }
        // Backing remains resident and aligned for the whole test; only lookup availability changes.
        unsafe impl HostArenaResolver for &Revocable {
            fn host_ptr_for_range(&self, _: u64, len: usize) -> Option<*mut u8> {
                assert!(len <= self.words.len() * 8);
                (self.calls.fetch_add(1, Ordering::SeqCst) == 0)
                    .then_some(self.words.as_ptr().cast_mut().cast())
            }
            fn publish_user_executable(
                &self,
                _output: u64,
                _len: u64,
            ) -> Result<(), PageTableError> {
                // VM-free test backing: no instruction cache to maintain.
                Ok(())
            }
        }
        #[test]
        fn rollback_must_not_discard_journal_after_resolution_is_revoked() {
            let base = 0x100000;
            let mut manager = PageTableManager::new(
                vec![0; 524288],
                base,
                PageTableLayoutConfig::new(0, 524288, 0, 0),
            );
            manager.begin_undo().unwrap();
            manager.write_desc_for_test(base, 0x1234).unwrap();
            let backing = Revocable {
                words: (0..65536).map(|_| AtomicU64::new(0)).collect(),
                calls: AtomicUsize::new(0),
            };
            backing.words[0].store(0x1234, Ordering::SeqCst);
            let result = unsafe { manager.rollback_undo(&backing, None) };
            assert!(
                result.is_err() && manager.undo_is_open(),
                "rollback acknowledged success or discarded journal after resolution revocation: result={result:?}, journal={}, host={:#x}",
                manager.undo_is_open(),
                backing.words[0].load(Ordering::SeqCst)
            );
        }

        struct CutoffBacking {
            words: Box<[AtomicU64]>,
            calls: AtomicUsize,
            allowed: AtomicUsize,
        }
        unsafe impl HostArenaResolver for &CutoffBacking {
            fn host_ptr_for_range(&self, _: u64, len: usize) -> Option<*mut u8> {
                assert!(len <= self.words.len() * 8);
                (self.calls.fetch_add(1, Ordering::SeqCst) < self.allowed.load(Ordering::SeqCst))
                    .then_some(self.words.as_ptr().cast_mut().cast())
            }
            fn publish_user_executable(
                &self,
                _output: u64,
                _len: u64,
            ) -> Result<(), PageTableError> {
                // VM-free test backing: no instruction cache to maintain.
                Ok(())
            }
        }
        #[test]
        fn partial_rollback_retains_a_retryable_journal() {
            let base = 0x100000;
            let mut manager = PageTableManager::new(
                vec![0; 524288],
                base,
                PageTableLayoutConfig::new(0, 524288, 0, 0),
            );
            manager.begin_undo().unwrap();
            manager.write_desc_for_test(base, 0x1234).unwrap();
            manager.write_desc_for_test(base + 8, 0x5678).unwrap();
            let backing = CutoffBacking {
                words: (0..65536).map(|_| AtomicU64::new(0)).collect(),
                calls: AtomicUsize::new(0),
                allowed: AtomicUsize::new(3),
            };
            backing.words[0].store(0x1234, Ordering::SeqCst);
            backing.words[1].store(0x5678, Ordering::SeqCst);
            assert!(unsafe { manager.rollback_undo(&backing, None) }.is_err());
            assert!(manager.undo_is_open());
            assert_eq!(backing.words[0].load(Ordering::SeqCst), 0x1234);
            assert_eq!(backing.words[1].load(Ordering::SeqCst), 0);
            backing.allowed.store(usize::MAX, Ordering::SeqCst);
            assert!(unsafe { manager.rollback_undo(&backing, None) }.is_ok());
            assert!(!manager.undo_is_open());
            assert_eq!(backing.words[0].load(Ordering::SeqCst), 0);
            assert_eq!(backing.words[1].load(Ordering::SeqCst), 0);
        }
    }

    mod snapshot_allocations {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;
        std::thread_local! {
            pub(super) static LARGE: Cell<Option<u64>> = const { Cell::new(None) };
            pub(super) static OP_COUNT: Cell<Option<u64>> = const { Cell::new(None) };
            pub(super) static ALLOCATED_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
            pub(super) static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
            pub(super) static REFUSED_ALLOCS: Cell<usize> = const { Cell::new(0) };
        }
        struct CountingAllocator;
        #[global_allocator]
        static ALLOCATOR: CountingAllocator = CountingAllocator;
        fn check_and_record(size: usize) -> bool {
            if size >= super::LINUX_PAGE_TABLES_SIZE as usize {
                let _ = LARGE.try_with(|count| {
                    if let Some(n) = count.get() {
                        count.set(Some(n.checked_add(1).unwrap()));
                    }
                });
            }
            let _ = OP_COUNT.try_with(|count| {
                if let Some(n) = count.get() {
                    count.set(Some(n.checked_add(1).unwrap()));
                }
            });
            let _ = ALLOCATED_BYTES.try_with(|bytes| {
                if let Some(b) = bytes.get() {
                    bytes.set(Some(b.saturating_add(size)));
                }
            });
            let should_fail = FAIL_AFTER
                .try_with(|limit_cell| {
                    if let Some(limit) = limit_cell.get() {
                        if limit == 0 {
                            let _ = REFUSED_ALLOCS.try_with(|refused| {
                                refused.set(refused.get().saturating_add(1));
                            });
                            true
                        } else {
                            limit_cell.set(Some(limit - 1));
                            false
                        }
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            !should_fail
        }
        // SAFETY: forwards each allocation unchanged; const TLS does not allocate.
        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                if !check_and_record(layout.size()) {
                    return core::ptr::null_mut();
                }
                unsafe { System.alloc(layout) }
            }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                if !check_and_record(layout.size()) {
                    return core::ptr::null_mut();
                }
                unsafe { System.alloc_zeroed(layout) }
            }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                if !check_and_record(size) {
                    return core::ptr::null_mut();
                }
                unsafe { System.realloc(ptr, layout, size) }
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) }
            }
        }
    }

    #[test]
    fn recycled_live_images_do_not_reallocate_snapshot_buffers() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        let mut source = hvpatch_manager();
        unsafe {
            source
                .restore_quiesced_snapshot_to_host(&*resolver)
                .unwrap();
            source.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        let mut recycled = source.snapshot_image().unwrap();
        let mut results = Vec::new();
        for scale in [1, 8, 32, 128] {
            snapshot_allocations::LARGE.with(|n| n.set(Some(0)));
            for _ in 0..scale {
                unsafe {
                    recycled.make_live(
                        Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
                    );
                }
                source.snapshot_into(&mut recycled).unwrap();
            }
            let allocations = snapshot_allocations::LARGE
                .with(|n| n.replace(None))
                .unwrap();
            std::eprintln!("scale={scale} large_snapshot_allocations={allocations}");
            results.push((scale, allocations));
        }
        for (scale, allocations) in results {
            assert_eq!(
                allocations, 0,
                "warmed live image reuse allocated arena buffers at scale {scale}"
            );
        }
    }

    /// A manager built over a live table region copies the occupied table
    /// prefix, never the whole primary capacity: the exec and first-edit
    /// paths build one per process, and the region is 1.75 MiB of mostly zero
    /// pages. The capacity stays the region's, so later tables still fit.
    #[test]
    fn manager_from_live_image_copies_only_occupied_tables() {
        let live = hvpatch_manager().into_bytes().unwrap();
        assert_eq!(live.len(), LINUX_PAGE_TABLES_SIZE as usize);
        let reference = PageTableManager::new(live.clone(), LINUX_PAGE_TABLES_BASE, test_layout());
        let occupied = reference.copied_bytes() as usize;
        assert!(
            occupied < live.len() / 4,
            "fixture must be mostly spare capacity"
        );
        snapshot_allocations::LARGE.with(|n| n.set(Some(0)));
        snapshot_allocations::ALLOCATED_BYTES.with(|n| n.set(Some(0)));
        let mut built =
            PageTableManager::from_live_image(&live, LINUX_PAGE_TABLES_BASE, test_layout());
        let large = snapshot_allocations::LARGE
            .with(|n| n.replace(None))
            .unwrap();
        let bytes = snapshot_allocations::ALLOCATED_BYTES
            .with(|n| n.replace(None))
            .unwrap();
        std::eprintln!(
            "from_live_image occupied={occupied} capacity={} allocated={bytes} large={large}",
            live.len()
        );
        assert_eq!(large, 0, "copied the whole primary capacity");
        assert!(
            bytes <= occupied + 4096,
            "allocated {bytes} bytes for {occupied} occupied table bytes"
        );
        assert_eq!(built.copied_bytes(), reference.copied_bytes());
        for va in [
            LINUX_NULL_GUARD_END,
            LINUX_PAGE_TABLES_BASE,
            LINUX_MMAP_BASE,
        ] {
            assert_eq!(built.debug_walk(va), reference.debug_walk(va));
        }
        assert_eq!(built.pool_stats(), reference.pool_stats());
        // Capacity is the live region's: a new table still allocates.
        built
            .set_rw(LINUX_MMAP_BASE + 0x40_0000_0000, 0x1000, false, None)
            .expect("a table beyond the copied prefix allocates");
    }

    /// A manager built from the occupied prefix alone (the exec plan's
    /// payload, with an explicit capacity) must be indistinguishable from the
    /// one built over the full zero-padded image: same walks, same
    /// allocations (spare cursor), same reclaim, same final bytes, including
    /// after the owned storage grows past the prefix.
    #[test]
    fn prefix_built_manager_matches_the_full_image_manager() {
        let full = hvpatch_manager().into_bytes().unwrap();
        let capacity = full.len();
        let mut reference =
            PageTableManager::new(full.clone(), LINUX_PAGE_TABLES_BASE, test_layout());
        let prefix = hvpatch_manager().into_occupied_bytes().unwrap();
        assert!(prefix.len() < capacity / 4);
        let mut built = PageTableManager::from_image_prefix(
            &prefix,
            capacity,
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        assert_eq!(built.copied_bytes(), reference.copied_bytes());
        assert_eq!(built.pool_stats(), reference.pool_stats());
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let base = LINUX_MMAP_BASE + 0x40_0000_0000;
        for step in 0..48u64 {
            let va = base + step * TWO_MIB;
            let a = reference.set_rw(va + 0x1000, 0x1000, false, None);
            let b = built.set_rw(va + 0x1000, 0x1000, false, None);
            assert_eq!(a.is_ok(), b.is_ok(), "step {step}");
            assert_eq!(
                built.debug_walk(va + 0x1000),
                reference.debug_walk(va + 0x1000)
            );
            assert_eq!(built.pool_stats(), reference.pool_stats(), "step {step}");
            assert_eq!(
                built.copied_bytes(),
                reference.copied_bytes(),
                "step {step}"
            );
            if step % 3 == 2 {
                let prev = base + (step - 1) * TWO_MIB;
                let a = reference.unmap_aliased(prev + 0x1000, 0x1000, None);
                let b = built.unmap_aliased(prev + 0x1000, 0x1000, None);
                assert_eq!(a.is_ok(), b.is_ok(), "unmap step {step}");
                assert_eq!(built.pool_stats(), reference.pool_stats(), "step {step}");
            }
        }
        assert!(
            built.copied_bytes() as usize > prefix.len(),
            "storage must have grown past the prefix"
        );
        assert_eq!(built.into_bytes().unwrap(), reference.into_bytes().unwrap());
    }

    #[derive(Debug)]
    struct NonAllocTestArenaSource {
        id: TableArenaSourceId,
        available: Vec<SubstrateGpa>,
        returned: Vec<SubstrateGpa>,
    }

    impl TableArenaSource for NonAllocTestArenaSource {
        fn id(&self) -> TableArenaSourceId {
            self.id
        }
        fn take_arena(&mut self) -> Option<SubstrateGpa> {
            self.available.pop()
        }
        fn return_arena(&mut self, base: SubstrateGpa) {
            self.returned.push(base);
        }
    }

    #[test]
    fn test_metadata_refusal_witness_rollback_allocations() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        for scale in [1, 8, 32, 128] {
            let mut mgr = hvpatch_manager();
            mgr.set_rw(
                LINUX_MMAP_BASE + 512 * TWO_MIB + 0x1000,
                0x1000,
                false,
                None,
            )
            .expect("pre-create L2 table");
            mgr.layout.extension_arena_capacity = PT_PAGE as usize;
            exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);

            let ext_bases: Vec<SubstrateGpa> = (0..scale)
                .map(|i| SubstrateGpa(0x80_0000_0000 + (i as u64) * 0x20_0000))
                .collect();
            let mut host_arenas: Vec<Vec<u8>> = (0..scale + 1)
                .map(|_| vec![0u8; LINUX_PAGE_TABLES_SIZE as usize])
                .collect();
            let mut resolver: Vec<(u64, *mut u8)> = Vec::with_capacity(scale + 1);
            resolver.push((LINUX_PAGE_TABLES_BASE, host_arenas[0].as_mut_ptr()));
            for (i, base) in ext_bases.iter().enumerate() {
                resolver.push((base.0, host_arenas[i + 1].as_mut_ptr()));
            }

            let mut source = NonAllocTestArenaSource {
                id: TableArenaSourceId(SubstrateGpa(LINUX_PAGE_TABLES_BASE)),
                available: ext_bases.clone(),
                returned: Vec::with_capacity(scale),
            };

            // Publish setup before measuring this transaction, so the budget
            // is independent of historical dirty entries from pool exhaustion.
            unsafe { mgr.sync_to_host(resolver.as_slice()).unwrap() };
            let initial_walk = mgr.debug_walk(LINUX_MMAP_BASE);
            let initial_trans = mgr.translate(LINUX_MMAP_BASE);
            let initial_arenas_len = mgr.arenas.len();
            let initial_dirty_len = mgr.dirty.len();
            let initial_free_len = mgr.free_tables.len();

            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            snapshot_allocations::ALLOCATED_BYTES.with(|c| c.set(Some(0)));
            mgr.begin_undo().unwrap();

            let mut edit_va = LINUX_MMAP_BASE + 513 * TWO_MIB;
            for _ in 0..scale {
                mgr.set_rw(edit_va + 0x1000, 0x1000, false, Some(&mut source))
                    .expect("mapping succeeds");
                edit_va += TWO_MIB;
            }
            let admission_allocations = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();
            let admission_bytes = snapshot_allocations::ALLOCATED_BYTES
                .with(|c| c.replace(None))
                .unwrap();

            assert_eq!(
                mgr.arenas.len(),
                initial_arenas_len + scale,
                "scale={scale}: expected to attach {scale} extension arenas"
            );
            assert_eq!(
                source.available.len(),
                0,
                "scale={scale}: source available slots must be exhausted"
            );

            // Each new L3 table writes 512 leaves, one parent link, and the
            // selected leaf once more. This fixture pre-creates the L2 table
            // and has exhausted reusable tables: no reclamation or staged
            // (Live-storage) hash map contributes to this Owned-storage arm.
            let writes = scale * (PT_PAGE as usize / core::mem::size_of::<u64>() + 2);
            let journal = mgr.undo.as_ref().unwrap();
            assert!(journal.words.len() <= writes);
            assert!(journal.first_written.len() <= writes);
            assert!(mgr.dirty.len() <= initial_dirty_len + writes);
            assert!(mgr.staged.is_empty());
            assert!(mgr.free_tables.is_empty());

            // A doubling Vec needs at most log2(next_power_of_two(n)) + 2
            // allocations and requests fewer than 4*max(n, 4)*sizeof(T)
            // bytes in total, including a non-power-of-two initial capacity.
            fn vector_budget<T>(elements: usize) -> (u64, usize) {
                let slots = elements.max(4);
                (
                    u64::from(slots.next_power_of_two().ilog2()) + 2,
                    4 * slots * core::mem::size_of::<T>(),
                )
            }
            let vectors = [
                vector_budget::<TableArena>(initial_arenas_len + scale),
                vector_budget::<u64>(scale), // returned_bases
                vector_budget::<(TableLocation, u64)>(writes),
                vector_budget::<(TableLocation, bool)>(initial_dirty_len + writes),
            ];
            // hashbrown doubles power-of-two buckets at a maximum 7/8
            // occupancy. Sum of bucket counts across growth is <2*final.
            // Include each control byte and SIMD-group/alignment padding.
            let buckets = (writes * 8).div_ceil(7).next_power_of_two().max(4);
            let hash_allocations = u64::from(buckets.ilog2()) + 1;
            let hash_bytes = 2 * buckets * (core::mem::size_of::<(usize, usize)>() + 1)
                + hash_allocations as usize * (16 + core::mem::align_of::<(usize, usize)>() - 1);
            // One exact allocation per 4 KiB extent; at most two exact
            // snapshots when opening the journal (arena cursors/free list).
            let max_allocs = scale as u64
                + 2
                + hash_allocations
                + vectors.iter().map(|budget| budget.0).sum::<u64>();
            let max_bytes = scale * PT_PAGE as usize
                + (initial_arenas_len + initial_free_len) * core::mem::size_of::<u64>()
                + hash_bytes
                + vectors.iter().map(|budget| budget.1).sum::<usize>();
            assert!(
                admission_allocations <= max_allocs,
                "scale={scale}: admission allocations {admission_allocations} exceeded justified bound {max_allocs}"
            );
            assert!(
                admission_bytes <= max_bytes,
                "scale={scale}: admission bytes {admission_bytes} exceeded justified bound {max_bytes}"
            );

            // Scope allocation count around rollback_undo only.
            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            snapshot_allocations::ALLOCATED_BYTES.with(|c| c.set(Some(0)));
            let popped = unsafe { mgr.rollback_undo(resolver.as_slice(), Some(&mut source)) }
                .expect("rollback must succeed");
            let rollback_allocations = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();
            let rollback_bytes = snapshot_allocations::ALLOCATED_BYTES
                .with(|c| c.replace(None))
                .unwrap();

            std::eprintln!(
                "scale={scale} admission_allocations={admission_allocations} admission_bytes={admission_bytes} max_allocs={max_allocs} max_bytes={max_bytes} rollback_allocations={rollback_allocations} rollback_bytes={rollback_bytes} popped_len={}",
                popped.len()
            );

            // Capture state after rollback
            assert_eq!(
                mgr.arenas.len(),
                initial_arenas_len,
                "scale={scale}: arenas restored to initial"
            );
            assert_eq!(
                source.returned.len(),
                scale,
                "scale={scale}: all attached arenas returned to source"
            );
            assert_eq!(
                mgr.debug_walk(LINUX_MMAP_BASE),
                initial_walk,
                "scale={scale}: initial descriptor walk preserved"
            );
            assert_eq!(
                mgr.translate(LINUX_MMAP_BASE),
                initial_trans,
                "scale={scale}: translation preserved"
            );

            // Structural invariant requirement: rollback must perform zero allocations and zero bytes.
            assert_eq!(
                rollback_allocations, 0,
                "scale={scale}: rollback allocated heap memory ({rollback_allocations} allocs)"
            );
            assert_eq!(
                rollback_bytes, 0,
                "scale={scale}: rollback allocated heap bytes ({rollback_bytes} bytes)"
            );
        }
    }

    #[test]
    fn test_metadata_refusal_at_begin_undo() {
        let mut mgr = hvpatch_manager();
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(0)));
        let res = mgr.begin_undo();
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
        assert_eq!(res, Err(PageTableError::MetadataAllocation));
        assert!(!mgr.undo_is_open());

        // Subsequent begin_undo and edit succeed cleanly
        assert!(mgr.begin_undo().is_ok());
        assert!(mgr.undo_is_open());
        mgr.set_readonly(LINUX_HEAP_BASE, 0x1000, false, None)
            .unwrap();
        mgr.commit_undo();
        assert!(!mgr.undo_is_open());
    }

    #[test]
    fn test_metadata_refusal_sweep_during_transaction_mutations_and_recovery() {
        let mut measure_mgr = hvpatch_manager();
        measure_mgr.begin_undo().unwrap();
        snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
        measure_mgr
            .set_rw(LINUX_MMAP_BASE + 0x1000, 0x4000, false, None)
            .unwrap();
        let total_alloc_attempts = snapshot_allocations::OP_COUNT
            .with(|c| c.replace(None))
            .unwrap();
        assert!(total_alloc_attempts > 0);

        for fail_point in 0..total_alloc_attempts as usize {
            let mut mgr = hvpatch_manager();
            let initial_walk = mgr.debug_walk(LINUX_MMAP_BASE);
            let mut host = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let resolver = [(mgr.base(), host.as_mut_ptr())];

            mgr.begin_undo().unwrap();

            snapshot_allocations::REFUSED_ALLOCS.with(|c| c.set(0));
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(fail_point)));
            let edit_res = mgr.set_rw(LINUX_MMAP_BASE + 0x1000, 0x4000, false, None);
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            let refused = snapshot_allocations::REFUSED_ALLOCS.with(|c| c.get());

            assert!(refused > 0, "fail_point={fail_point}: must trigger refusal");
            assert_eq!(edit_res, Err(PageTableError::MetadataAllocation));
            assert!(mgr.undo_is_open());

            // Rollback must succeed without allocating
            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            unsafe { mgr.rollback_undo(&resolver[..], None).unwrap() };
            let rollback_allocs = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();
            assert_eq!(rollback_allocs, 0, "rollback must not allocate");
            assert!(!mgr.undo_is_open());
            assert_eq!(mgr.debug_walk(LINUX_MMAP_BASE), initial_walk);

            // Verify a fresh transaction succeeds following the previous failure/rollback on this SAME manager
            mgr.begin_undo().unwrap();
            mgr.set_readonly(LINUX_HEAP_BASE, 0x1000, false, None)
                .unwrap();
            unsafe { mgr.rollback_undo(&resolver[..], None).unwrap() };
            assert!(!mgr.undo_is_open());
        }

        // Boundary control: total_alloc_attempts succeeds without refusal
        {
            let mut mgr = hvpatch_manager();
            let mut host = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let resolver = [(mgr.base(), host.as_mut_ptr())];
            mgr.begin_undo().unwrap();
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(total_alloc_attempts as usize)));
            let edit_res = mgr.set_rw(LINUX_MMAP_BASE + 0x1000, 0x4000, false, None);
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            assert!(
                edit_res.is_ok(),
                "boundary control must succeed without refusal"
            );
            unsafe { mgr.rollback_undo(&resolver[..], None).unwrap() };
        }
    }

    #[test]
    fn test_metadata_refusal_during_extension_arena_attach_returns_grant_exactly_once() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let va = LINUX_MMAP_BASE + 600 * TWO_MIB + 0x1000;
        let ext_base = SubstrateGpa(0xb0_0000_0000);

        // Measure exact allocation attempts when attaching an extension arena
        let total_alloc_attempts = {
            let mut measure_mgr = hvpatch_manager();
            exhaust_spare_pool(&mut measure_mgr, LINUX_MMAP_BASE);
            let mut measure_source = NonAllocTestArenaSource {
                id: TableArenaSourceId(ext_base),
                available: vec![ext_base],
                returned: Vec::with_capacity(1),
            };
            measure_mgr.begin_undo().unwrap();
            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            measure_mgr
                .set_rw(va, 0x1000, false, Some(&mut measure_source))
                .unwrap();
            snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap()
        };
        assert!(total_alloc_attempts > 0);

        for fail_point in 0..total_alloc_attempts as usize {
            let mut mgr = hvpatch_manager();
            exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);

            let mut source = NonAllocTestArenaSource {
                id: TableArenaSourceId(ext_base),
                available: vec![ext_base],
                returned: Vec::with_capacity(1),
            };

            let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let full_resolver = [
                (mgr.base(), host_arena0.as_mut_ptr()),
                (ext_base.0, host_arena1.as_mut_ptr()),
            ];

            mgr.begin_undo().unwrap();

            snapshot_allocations::REFUSED_ALLOCS.with(|c| c.set(0));
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(fail_point)));
            let edit_res = mgr.set_rw(va, 0x1000, false, Some(&mut source));
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            let refused = snapshot_allocations::REFUSED_ALLOCS.with(|c| c.get());

            assert!(refused > 0, "fail_point={fail_point}: must trigger refusal");
            assert_eq!(edit_res, Err(PageTableError::MetadataAllocation));
            assert!(mgr.undo_is_open());

            // Rollback must succeed without allocating and return any attached arenas to source exactly once
            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            let _ = unsafe { mgr.rollback_undo(&full_resolver[..], Some(&mut source)) }
                .expect("rollback must succeed");
            let rollback_allocs = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();
            assert_eq!(rollback_allocs, 0, "rollback must not allocate");
            assert!(!mgr.undo_is_open());
            assert_eq!(
                source.returned.as_slice(),
                &[ext_base],
                "fail_point={fail_point}: arena must be returned to source exactly once"
            );
            assert_eq!(mgr.arenas.len(), 1);

            // Verify subsequent retry on this SAME manager with new source succeeds
            let mut retry_source = NonAllocTestArenaSource {
                id: TableArenaSourceId(ext_base),
                available: vec![ext_base],
                returned: Vec::with_capacity(1),
            };
            mgr.begin_undo().unwrap();
            mgr.set_rw(va, 0x1000, false, Some(&mut retry_source))
                .unwrap();
            assert_eq!(mgr.arenas.len(), 2);
            assert_eq!(retry_source.available.len(), 0);
            unsafe {
                mgr.rollback_undo(&full_resolver[..], Some(&mut retry_source))
                    .unwrap()
            };
            assert_eq!(mgr.arenas.len(), 1);
            assert_eq!(retry_source.returned.as_slice(), &[ext_base]);
        }

        // Boundary control: total_alloc_attempts attaches arena cleanly without refusal
        {
            let mut mgr = hvpatch_manager();
            exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
            let mut source = NonAllocTestArenaSource {
                id: TableArenaSourceId(ext_base),
                available: vec![ext_base],
                returned: Vec::with_capacity(1),
            };
            let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
            let full_resolver = [
                (mgr.base(), host_arena0.as_mut_ptr()),
                (ext_base.0, host_arena1.as_mut_ptr()),
            ];
            mgr.begin_undo().unwrap();
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(total_alloc_attempts as usize)));
            let edit_res = mgr.set_rw(va, 0x1000, false, Some(&mut source));
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            assert!(
                edit_res.is_ok(),
                "boundary control must attach arena without refusal"
            );
            unsafe {
                mgr.rollback_undo(&full_resolver[..], Some(&mut source))
                    .unwrap()
            };
        }
    }

    #[test]
    fn test_metadata_refusal_sync_to_host_overflow_scratch() {
        // Build a manager with 9 arenas (>8 inline resolvers in sync_to_host)
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = hvpatch_manager();
        mgr.set_rw(
            LINUX_MMAP_BASE + 512 * TWO_MIB + 0x1000,
            0x1000,
            false,
            None,
        )
        .expect("pre-create L2 table");
        mgr.layout.extension_arena_capacity = PT_PAGE as usize;
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);

        const SCALE: usize = 9;
        let ext_bases: Vec<SubstrateGpa> = (0..SCALE)
            .map(|i| SubstrateGpa(0x80_0000_0000 + (i as u64) * 0x20_0000))
            .collect();
        let mut host_arenas: Vec<Vec<u8>> = (0..SCALE + 1)
            .map(|_| vec![0u8; LINUX_PAGE_TABLES_SIZE as usize])
            .collect();
        let mut resolver: Vec<(u64, *mut u8)> = Vec::with_capacity(SCALE + 1);
        resolver.push((LINUX_PAGE_TABLES_BASE, host_arenas[0].as_mut_ptr()));
        for (i, base) in ext_bases.iter().enumerate() {
            resolver.push((base.0, host_arenas[i + 1].as_mut_ptr()));
        }

        let mut source = NonAllocTestArenaSource {
            id: TableArenaSourceId(SubstrateGpa(LINUX_PAGE_TABLES_BASE)),
            available: ext_bases.clone(),
            returned: Vec::with_capacity(SCALE),
        };

        let mut edit_va = LINUX_MMAP_BASE + 513 * TWO_MIB;
        for _ in 0..SCALE {
            mgr.set_rw(edit_va + 0x1000, 0x1000, false, Some(&mut source))
                .unwrap();
            edit_va += TWO_MIB;
        }
        assert_eq!(mgr.arenas.len(), SCALE + 1);
        assert!(!mgr.dirty.is_empty());
        let dirty_count_before = mgr.dirty.len();

        // Fail allocation during sync_to_host (when allocating the >8 resolved vector)
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(0)));
        let sync_err = unsafe { mgr.sync_to_host(resolver.as_slice()) };
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));

        assert_eq!(sync_err, Err(PageTableError::MetadataAllocation));
        assert_eq!(
            mgr.dirty.len(),
            dirty_count_before,
            "dirty list must be preserved when sync_to_host fails"
        );

        // Retrying sync_to_host without refusal succeeds and drains dirty entries
        unsafe { mgr.sync_to_host(resolver.as_slice()).unwrap() };
        assert!(
            mgr.dirty.is_empty(),
            "dirty list drained on successful sync"
        );
    }

    #[test]
    fn director_coalesce_refusal_preserves_linked_table() {
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_prot_none(block, 0x1000, None).unwrap();
        mgr.set_rw(block, 1 << 21, true, None).unwrap();
        let original = mgr.translate(block);
        assert!(original.is_some());
        mgr.declare_offline_private_image();
        mgr.dirty = Vec::new();
        mgr.free_tables.reserve(2);
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(0)));
        let coalesced = mgr.try_coalesce(block);
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
        assert_eq!(coalesced, Err(PageTableError::MetadataAllocation));
        assert_eq!(
            mgr.translate(block),
            original,
            "failed parent write must not free its still-linked child"
        );
    }

    #[test]
    fn test_coalesce_free_tables_refusal_preserves_state() {
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_prot_none(block, 0x1000, None).unwrap();
        mgr.set_rw(block, 1 << 21, true, None).unwrap();
        let original = mgr.translate(block);
        assert!(original.is_some());
        mgr.declare_offline_private_image();
        mgr.dirty.reserve(10);
        mgr.free_tables = Vec::new();
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(0)));
        let coalesced = mgr.try_coalesce(block);
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
        assert_eq!(coalesced, Err(PageTableError::MetadataAllocation));
        assert_eq!(
            mgr.translate(block),
            original,
            "failed free_table bookkeeping must not modify parent or free child"
        );
    }

    #[test]
    fn test_reclaim_refusal_preserves_linked_tables() {
        let mut mgr = manager();
        mgr.set_multi_vcpu(true);
        mgr.set_stage1_exclusive(true);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_prot_none(block, 1 << 21, None)
            .expect("tear the block down");
        assert!(mgr.free_tables.is_empty());

        mgr.free_tables = Vec::new();
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(0)));
        let sweep_res = mgr.reclaim_all_invalid_tables();
        snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
        assert_eq!(sweep_res, Err(PageTableError::MetadataAllocation));
        assert!(mgr.free_tables.is_empty());

        assert!(mgr.reclaim_all_invalid_tables().unwrap());
        assert!(!mgr.free_tables.is_empty());
    }

    fn create_live_fixture() -> (PageTableManager, Arc<MockLiveResolver>) {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        unsafe {
            mgr.restore_quiesced_snapshot_to_host(&*resolver).unwrap();
            mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }

        // Establish initial mappings in live backing
        mgr.begin_undo().unwrap();
        mgr.set_readonly(LINUX_HEAP_BASE, 0x4000, false, None)
            .unwrap();
        mgr.set_rw(LINUX_MMAP_BASE, 0x4000, false, None).unwrap();
        unsafe { mgr.sync_to_host(&*resolver).unwrap() };
        mgr.commit_undo();
        (mgr, resolver)
    }

    #[test]
    fn metadata_refusal_contract() {
        let (mut mgr, resolver) = create_live_fixture();

        let initial_trans_heap = mgr.translate(LINUX_HEAP_BASE);
        let initial_trans_mmap = mgr.translate(LINUX_MMAP_BASE);
        let initial_walk_heap = mgr.debug_walk(LINUX_HEAP_BASE);
        let initial_walk_mmap = mgr.debug_walk(LINUX_MMAP_BASE);
        assert!(initial_trans_heap.is_some());
        assert!(initial_trans_mmap.is_some());

        // Count total allocation attempts specifically within the multi-step transaction body
        let (mut test_mgr, _test_resolver) = create_live_fixture();
        test_mgr.begin_undo().unwrap();
        snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
        test_mgr
            .set_rw(LINUX_HEAP_BASE, 0x4000, false, None)
            .unwrap();
        test_mgr
            .set_prot_none(LINUX_MMAP_BASE, 0x2000, None)
            .unwrap();
        test_mgr
            .set_rw(LINUX_MMAP_BASE + 0x2000, 0x2000, false, None)
            .unwrap();
        // Repeated write covering prior staged/dirty entries
        test_mgr
            .set_readonly(LINUX_HEAP_BASE, 0x2000, false, None)
            .unwrap();
        let total_alloc_attempts = snapshot_allocations::OP_COUNT
            .with(|c| c.replace(None))
            .unwrap();
        assert!(
            total_alloc_attempts > 0,
            "transaction must perform measurable allocations to sweep"
        );

        // Sweep actual allocation attempt population across the transaction
        for fail_point in 0..total_alloc_attempts as usize {
            let (mut trial_mgr, trial_resolver) = create_live_fixture();
            trial_mgr.begin_undo().unwrap();

            snapshot_allocations::REFUSED_ALLOCS.with(|c| c.set(0));
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(fail_point)));
            let res = (|| -> Result<(), PageTableError> {
                trial_mgr.set_rw(LINUX_HEAP_BASE, 0x4000, false, None)?;
                trial_mgr.set_prot_none(LINUX_MMAP_BASE, 0x2000, None)?;
                trial_mgr.set_rw(LINUX_MMAP_BASE + 0x2000, 0x2000, false, None)?;
                trial_mgr.set_readonly(LINUX_HEAP_BASE, 0x2000, false, None)?;
                Ok(())
            })();
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            let refused = snapshot_allocations::REFUSED_ALLOCS.with(|c| c.get());

            assert!(refused > 0, "fail_point={fail_point}: must trigger refusal");
            assert_eq!(
                res,
                Err(PageTableError::MetadataAllocation),
                "fail_point={fail_point}: expected MetadataAllocation error"
            );
            assert!(trial_mgr.undo_is_open());

            // Rollback must succeed with 0 allocations
            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            unsafe { trial_mgr.rollback_undo(&*trial_resolver, None).unwrap() };
            let rollback_allocs = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();
            assert_eq!(
                rollback_allocs, 0,
                "fail_point={fail_point}: rollback under refusal must perform zero allocations"
            );
            assert!(!trial_mgr.undo_is_open());

            // Descriptor bytes and translations must match exact pre-image
            assert_eq!(
                trial_mgr.translate(LINUX_HEAP_BASE),
                initial_trans_heap,
                "fail_point={fail_point}: heap translation restored"
            );
            assert_eq!(
                trial_mgr.translate(LINUX_MMAP_BASE),
                initial_trans_mmap,
                "fail_point={fail_point}: mmap translation restored"
            );
            assert_eq!(
                trial_mgr.debug_walk(LINUX_HEAP_BASE),
                initial_walk_heap,
                "fail_point={fail_point}: heap descriptor walk restored"
            );
            assert_eq!(
                trial_mgr.debug_walk(LINUX_MMAP_BASE),
                initial_walk_mmap,
                "fail_point={fail_point}: mmap descriptor walk restored"
            );

            // Exercise recovery and subsequent transaction on the SAME trial manager
            trial_mgr.begin_undo().unwrap();
            trial_mgr
                .set_rw(LINUX_HEAP_BASE, 0x2000, false, None)
                .unwrap();
            unsafe { trial_mgr.sync_to_host(&*trial_resolver).unwrap() };
            trial_mgr.commit_undo();
            assert!(!trial_mgr.undo_is_open());
        }

        // Boundary control: total_alloc_attempts without refusal succeeds to completion
        {
            let (mut trial_mgr, trial_resolver) = create_live_fixture();
            trial_mgr.begin_undo().unwrap();
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(Some(total_alloc_attempts as usize)));
            let res = (|| -> Result<(), PageTableError> {
                trial_mgr.set_rw(LINUX_HEAP_BASE, 0x4000, false, None)?;
                trial_mgr.set_prot_none(LINUX_MMAP_BASE, 0x2000, None)?;
                trial_mgr.set_rw(LINUX_MMAP_BASE + 0x2000, 0x2000, false, None)?;
                trial_mgr.set_readonly(LINUX_HEAP_BASE, 0x2000, false, None)?;
                Ok(())
            })();
            snapshot_allocations::FAIL_AFTER.with(|c| c.set(None));
            assert!(res.is_ok(), "boundary control must succeed without refusal");
            unsafe { trial_mgr.sync_to_host(&*trial_resolver).unwrap() };
            trial_mgr.commit_undo();
            assert!(!trial_mgr.undo_is_open());
        }

        // Subsequent live transaction without refusal succeeds and updates live backing
        mgr.begin_undo().unwrap();
        mgr.set_rw(LINUX_HEAP_BASE, 0x4000, false, None).unwrap();
        mgr.set_prot_none(LINUX_MMAP_BASE, 0x2000, None).unwrap();
        unsafe { mgr.sync_to_host(&*resolver).unwrap() };
        mgr.commit_undo();
        assert!(!mgr.undo_is_open());
        assert_eq!(mgr.translate(LINUX_MMAP_BASE), None);
    }

    #[test]
    fn test_rollback_zero_allocations_repeated_cycles() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        const SCALE: usize = 8;
        let ext_bases: Vec<SubstrateGpa> = (0..SCALE)
            .map(|i| SubstrateGpa(0x80_0000_0000 + (i as u64) * 0x20_0000))
            .collect();
        let mut host_arenas: Vec<Vec<u8>> = (0..SCALE + 1)
            .map(|_| vec![0u8; LINUX_PAGE_TABLES_SIZE as usize])
            .collect();
        let mut resolver: Vec<(u64, *mut u8)> = Vec::with_capacity(SCALE + 1);
        resolver.push((LINUX_PAGE_TABLES_BASE, host_arenas[0].as_mut_ptr()));
        for (i, base) in ext_bases.iter().enumerate() {
            resolver.push((base.0, host_arenas[i + 1].as_mut_ptr()));
        }

        let mut mgr = hvpatch_manager();
        mgr.set_rw(
            LINUX_MMAP_BASE + 512 * TWO_MIB + 0x1000,
            0x1000,
            false,
            None,
        )
        .expect("pre-create L2 table");
        mgr.layout.extension_arena_capacity = PT_PAGE as usize;
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);

        for cycle in 0..5 {
            let mut source = NonAllocTestArenaSource {
                id: TableArenaSourceId(SubstrateGpa(LINUX_PAGE_TABLES_BASE)),
                available: ext_bases.clone(),
                returned: Vec::with_capacity(SCALE),
            };

            mgr.begin_undo().unwrap();

            let mut edit_va = LINUX_MMAP_BASE + 513 * TWO_MIB;
            for _ in 0..SCALE {
                mgr.set_rw(edit_va + 0x1000, 0x1000, false, Some(&mut source))
                    .unwrap();
                edit_va += TWO_MIB;
            }
            assert_eq!(mgr.arenas.len(), 1 + SCALE);

            snapshot_allocations::OP_COUNT.with(|c| c.set(Some(0)));
            let popped = unsafe { mgr.rollback_undo(resolver.as_slice(), Some(&mut source)) }
                .expect("rollback must succeed");
            let rollback_allocs = snapshot_allocations::OP_COUNT
                .with(|c| c.replace(None))
                .unwrap();

            assert_eq!(
                rollback_allocs, 0,
                "cycle {cycle}: rollback must perform 0 allocations"
            );
            assert_eq!(popped.len(), SCALE);
            assert_eq!(source.returned.len(), SCALE);
            assert_eq!(mgr.arenas.len(), 1);
            assert!(!mgr.undo_is_open());
        }
    }

    fn test_layout() -> PageTableLayoutConfig {
        PageTableLayoutConfig {
            user_leaf_check_va: LINUX_NULL_GUARD_END,
            extension_arena_capacity: LINUX_PAGE_TABLES_SIZE as usize,
            excluded_ipa_start: LINUX_GIC_WINDOW_BASE,
            excluded_ipa_len: LINUX_GIC_WINDOW_SIZE,
        }
    }

    fn manager() -> PageTableManager {
        let mut bytes = stage1_identity_page_tables();
        bytes.resize(0x40000, 0);
        PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout())
    }

    fn hvpatch_manager() -> PageTableManager {
        let mut mgr = PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        mgr.set_prot_none(LINUX_MMAP_BASE, mmap_arena_size() as usize, None)
            .expect("reserve sparse arena");
        mgr
    }

    /// Live host backing for one manager plus a log of every executable
    /// publication its stores announced, with the live leaf word observed at
    /// the moment of each announcement.
    struct ExecLog {
        base: u64,
        host: Vec<u8>,
        va: u64,
        calls: std::cell::RefCell<Vec<(u64, u64, u64)>>,
        refuse: bool,
    }

    unsafe impl HostArenaResolver for &ExecLog {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (base == self.base).then_some(self.host.as_ptr().cast_mut())
        }

        fn publish_user_executable(&self, output: u64, len: u64) -> Result<(), PageTableError> {
            // The live leaf at `va` as the hardware would see it right now.
            let walk = unsafe {
                walk_descriptors_host(self.host.as_ptr(), self.host.len(), self.base, self.va)
            };
            self.calls.borrow_mut().push((output, len, walk[3]));
            if self.refuse {
                return Err(PageTableError::UnresolvedArena(output));
            }
            Ok(())
        }
    }

    fn exec_log(mgr: &PageTableManager, va: u64) -> ExecLog {
        let mut log = ExecLog {
            base: mgr.base(),
            host: vec![0; LINUX_PAGE_TABLES_SIZE as usize],
            va,
            calls: std::cell::RefCell::new(Vec::new()),
            refuse: false,
        };
        let host = log.host.as_mut_ptr();
        unsafe { mgr.restore_quiesced_snapshot_to_host(TestArenas(&[(mgr.base(), host)])) }
            .expect("seed live backing");
        log
    }

    /// Work budget of the instruction-cache funnel: a data-only publication
    /// announces nothing; making a page EL0-executable announces exactly its
    /// output once, BEFORE the live store; a permission change that keeps
    /// the executable output announces nothing; adding EXEC to a resident
    /// data page (mprotect) and moving the leaf to a new frame each announce
    /// once.
    #[test]
    fn executable_publication_is_announced_once_before_the_store() {
        let mut mgr = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        let log = exec_log(&mgr, va);
        let sync = |mgr: &mut PageTableManager| unsafe { mgr.sync_to_host(&log) }.expect("sync");

        // Alias installation publishes data access first; the vCPU loop's
        // protect_range subsequently adds EXEC to this non-identity output.
        let alias_output = LINUX_MMAP_BASE + 0x80_0000;
        mgr.map_aliased(va, alias_output, 0x1000, UserLeafAccess::READ_WRITE, None)
            .unwrap();
        sync(&mut mgr);
        assert!(log.calls.borrow().is_empty(), "data-only page announced");

        mgr.set_rw(va, 0x1000, true, None).unwrap();
        sync(&mut mgr);
        let output = mgr.translate(va).unwrap();
        assert_eq!(output, alias_output, "EXEC must preserve the alias output");
        {
            let calls = log.calls.borrow();
            assert_eq!(calls.len(), 1, "{calls:x?}");
            assert_eq!((calls[0].0, calls[0].1), (output, 0x1000));
            assert_ne!(
                calls[0].2 & UXN,
                0,
                "announced after the executable leaf was already live"
            );
        }

        mgr.set_readonly(va, 0x1000, true, None).unwrap();
        sync(&mut mgr);
        mgr.set_rw(va, 0x1000, true, None).unwrap();
        sync(&mut mgr);
        assert_eq!(
            log.calls.borrow().len(),
            1,
            "same executable output re-announced"
        );

        mgr.set_readonly(va, 0x1000, false, None).unwrap();
        sync(&mut mgr);
        mgr.set_rw(va, 0x1000, true, None).unwrap();
        sync(&mut mgr);
        assert_eq!(log.calls.borrow().len(), 2, "mprotect adding EXEC");

        mgr.repoint_preserving_attributes(va, output + 0x10_0000, 0x1000, None)
            .unwrap();
        sync(&mut mgr);
        let calls = log.calls.borrow();
        assert_eq!(calls.len(), 3, "a new frame under an executable leaf");
        assert_eq!(calls[2].0, output + 0x10_0000);
    }

    /// Blocks are never announced: the static identity aperture that every
    /// image carries would otherwise cost an invalidation of up to 1 GiB per
    /// fork or exec. Only an L3 page is an executable publication.
    #[test]
    fn executable_blocks_are_not_announced_pages_are() {
        const BLOCK: u64 = (1 << 10) | (0b01 << 6) | 0b01;
        assert_eq!(user_executable_output(0x4000_0000 | BLOCK), None);
        assert_eq!(user_executable_output(0x4020_0000 | BLOCK), None);
        assert_eq!(
            user_executable_output(0x4020_1000 | BLOCK | 0b10),
            Some((0x4020_1000, 0x1000))
        );
        assert_eq!(
            user_executable_output(0x4020_1000 | BLOCK | 0b10 | UXN),
            None
        );
        assert_eq!(
            user_executable_output((0x4020_1000 | BLOCK | 0b10) & !AP_EL0_ACCESS),
            None,
            "a kernel-only page"
        );
    }

    /// A refused announcement refuses the publication: the executable leaf
    /// never reaches the live backing.
    #[test]
    fn a_refused_executable_publication_stores_nothing() {
        let mut mgr = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        let mut log = exec_log(&mgr, va);
        log.refuse = true;
        mgr.set_rw(va, 0x1000, true, None).unwrap();
        assert!(unsafe { mgr.sync_to_host(&log) }.is_err());
        let live =
            unsafe { walk_descriptors_host(log.host.as_ptr(), log.host.len(), log.base, va) };
        assert_eq!(
            live[3] & VALID,
            0,
            "refused executable leaf reached hardware"
        );
    }

    /// A whole-image publication (fork child, exec, rollback) announces each
    /// newly executable output once, and none when the live words already
    /// hold the same image.
    #[test]
    fn whole_image_publication_announces_new_executable_outputs_once() {
        let mut mgr = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        let log = exec_log(&mgr, va);
        let before = log.calls.borrow().len();
        mgr.set_rw(va, 0x3000, true, None).unwrap();
        mgr.set_rw(va + 0x3000, 0x1000, false, None).unwrap();
        unsafe { mgr.restore_quiesced_snapshot_to_host(&log) }.unwrap();
        assert_eq!(
            log.calls.borrow().len() - before,
            3,
            "three executable pages"
        );
        unsafe { mgr.restore_quiesced_snapshot_to_host(&log) }.unwrap();
        assert_eq!(
            log.calls.borrow().len() - before,
            3,
            "an identical image re-announced"
        );
    }

    /// Source audit: every function that stores a descriptor into live host
    /// backing is one the instruction-cache funnel covers or one that cannot
    /// newly make a page executable. A new live-store path must be added here
    /// with its reason, after it calls `publish_user_executable`.
    #[test]
    fn every_live_descriptor_store_is_covered_by_the_executable_funnel() {
        let source = include_str!("aarch64.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        // (function, why it is covered)
        let allowed = [
            ("sync_to_host", "announces before each store"),
            (
                "restore_quiesced_snapshot_to_host",
                "announces before the copy",
            ),
            ("rollback_undo", "restores words that were already live"),
            (
                "arm_existing_el1_fork_pages",
                "write-protects only; output and UXN kept",
            ),
            ("publish_existing_invalid_private_pages", "test-only"),
        ];
        let mut function = "";
        for line in production.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed
                .strip_prefix("pub unsafe fn ")
                .or_else(|| trimmed.strip_prefix("pub fn "))
                .or_else(|| trimmed.strip_prefix("unsafe fn "))
                .or_else(|| trimmed.strip_prefix("fn "))
                .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
                .or_else(|| trimmed.strip_prefix("pub(crate) unsafe fn "))
            {
                function = rest.split(['(', '<']).next().unwrap_or("");
            }
            let stores_live = (trimmed.contains(").store(") && !trimmed.starts_with("//"))
                || trimmed.contains("copy_nonoverlapping(bytes.as_ptr(), host");
            if stores_live {
                assert!(
                    allowed.iter().any(|(name, _)| *name == function),
                    "`{function}` stores live descriptors outside the executable funnel: {trimmed}"
                );
            }
        }
    }

    fn exhaust_spare_pool(mgr: &mut PageTableManager, keep_out: u64) {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut block = keep_out + 64 * TWO_MIB;
        loop {
            let (_, free, _, _) = mgr.pool_stats();
            let spare = mgr.spare_tables_available();
            if spare == 0 && free == 0 {
                break;
            }
            if mgr.set_rw(block + 0x1000, 0x1000, false, None).is_err() {
                break;
            }
            block += TWO_MIB;
        }
    }

    #[derive(Debug)]
    struct TestArenaSource {
        id: TableArenaSourceId,
        available: std::sync::Arc<std::sync::Mutex<Vec<SubstrateGpa>>>,
        returned: std::sync::Arc<std::sync::Mutex<Vec<SubstrateGpa>>>,
    }

    impl TableArenaSource for TestArenaSource {
        fn id(&self) -> TableArenaSourceId {
            self.id
        }
        fn take_arena(&mut self) -> Option<SubstrateGpa> {
            self.available.lock().unwrap().pop()
        }
        fn return_arena(&mut self, base: SubstrateGpa) {
            self.returned.lock().unwrap().push(base);
        }
    }

    #[test]
    fn spare_cursor_discovery_stops_at_the_last_used_page() {
        use core::cell::Cell;
        let mut pages = vec![0; 440 * super::PT_PAGE as usize];
        *pages.last_mut().unwrap() = 0x80;
        let visited = Cell::new(0);
        let cursor = super::discover_spare_pages(
            pages.chunks_exact(super::PT_PAGE as usize).inspect(|_| {
                visited.set(visited.get() + 1);
            }),
        );
        assert_eq!(cursor, super::SPARE_START_OFFSET + pages.len() as u64);
        assert_eq!(visited.get(), 1, "only the final occupied page is needed");
    }

    #[test]
    fn spare_cursor_discovery_preserves_holes_and_every_byte_position() {
        let page = super::PT_PAGE as usize;
        let start = super::SPARE_START_OFFSET as usize;
        let mut image = vec![0; start + 4 * page + 17];
        image[start + 4 * page + 16] = 1;
        assert_eq!(super::discover_next_free_spare(&image), start as u64);
        for byte in 0..page {
            image[start + 2 * page + byte] = 0x80;
            assert_eq!(
                super::discover_next_free_spare(&image),
                (start + 3 * page) as u64
            );
            image[start + 2 * page + byte] = 0;
        }
        image[start] = 1;
        image[start + 3 * page] = 1;
        assert_eq!(
            super::discover_next_free_spare(&image),
            (start + 4 * page) as u64
        );
        for len in [0, 1, start - 1, start] {
            let manager = super::PageTableManager::new(vec![0; len], 0x10000, test_layout());
            assert_eq!(manager.copied_bytes(), len as u64);
        }
    }

    #[test]
    fn terminal_descriptor_permission_tracks_valid_af_ap_and_uxn() {
        let pa = 0x0000_0001_2345_6000_u64;
        let rw_nx = pa | super::USER_PAGE_FLAGS | super::UXN | super::NON_GLOBAL;
        let rw_exec = pa | super::USER_PAGE_FLAGS | super::NON_GLOBAL;
        let ro_nx = (rw_nx & !super::AP_MASK) | super::AP_RO;
        let kernel_only = (rw_nx & !super::AP_MASK) | super::AP_PRIV_RO;

        assert!(terminal_descriptor_permits_el0(rw_nx, LeafAccess::Read));
        assert!(terminal_descriptor_permits_el0(rw_nx, LeafAccess::Write));
        assert!(!terminal_descriptor_permits_el0(rw_nx, LeafAccess::Execute));
        assert!(terminal_descriptor_permits_el0(
            rw_exec,
            LeafAccess::Execute
        ));
        assert!(terminal_descriptor_permits_el0(ro_nx, LeafAccess::Read));
        assert!(!terminal_descriptor_permits_el0(ro_nx, LeafAccess::Write));
        for access in [LeafAccess::Read, LeafAccess::Write, LeafAccess::Execute] {
            assert!(!terminal_descriptor_permits_el0(kernel_only, access));
            assert!(!terminal_descriptor_permits_el0(
                rw_exec & !super::VALID,
                access
            ));
            assert!(!terminal_descriptor_permits_el0(
                rw_exec & !super::ACCESS_FLAG,
                access
            ));
            assert!(!terminal_descriptor_permits_el0(0, access));
        }
    }

    /// `kernel.mm.image-page-permissions`: an alias leaf carries exactly the
    /// access its caller names. A mapping without `PROT_EXEC` sets UXN; no
    /// alias helper has an executable default.
    #[test]
    fn alias_leaves_carry_exactly_the_named_access() {
        let mut pt = manager();
        let cases = [
            (UserLeafAccess::READ_WRITE, AP_RW | UXN),
            (UserLeafAccess::READ_ONLY, AP_RO | UXN),
            (RWX, AP_RW),
            (RX, AP_RO),
            (UserLeafAccess::from_linux_prot(0x1 | 0x4), AP_RO),
            (UserLeafAccess::from_linux_prot(0x1 | 0x2), AP_RW | UXN),
        ];
        for (index, (access, expected)) in cases.into_iter().enumerate() {
            let shared = LINUX_MMAP_BASE + (index as u64) * 0x20_0000;
            let private = shared + 0x10_0000;
            let ipa = LINUX_ALIAS_IPA_BASE + (index as u64) * 0x20_0000;
            pt.map_aliased(shared, ipa, 0x1000, access, None)
                .expect("shared alias");
            pt.map_private_aliased(private, ipa + 0x10_0000, 0x1000, access, None)
                .expect("private alias");
            for va in [shared, private] {
                let leaf = terminal_descriptor(pt.debug_walk(va));
                assert_eq!(leaf & (AP_MASK | UXN), expected, "{access:?} at {va:#x}");
            }
        }
    }

    #[test]
    fn stage1_publication_refuses_outputs_in_the_gic_window() {
        let mut pt = manager();
        assert_eq!(
            pt.map_aliased(
                LINUX_MMAP_BASE,
                LINUX_GIC_REDISTRIBUTOR_BASE,
                0x4000,
                RWX,
                None
            ),
            Err(PageTableError::GicWindowOutput)
        );
        assert_eq!(
            pt.map_private_aliased(
                LINUX_MMAP_BASE,
                LINUX_GIC_WINDOW_BASE - 0x2000,
                0x4000,
                RWX,
                None
            ),
            Err(PageTableError::GicWindowOutput)
        );
        pt.map_aliased(LINUX_MMAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RWX, None)
            .expect("an ordinary alias");
        assert_eq!(
            pt.repoint_preserving_attributes(LINUX_MMAP_BASE, LINUX_GIC_WINDOW_BASE, 0x4000, None),
            Err(PageTableError::GicWindowOutput)
        );
        assert_eq!(pt.translate(LINUX_MMAP_BASE), Some(LINUX_ALIAS_IPA_BASE));
        let applied = pt.apply(
            LINUX_GIC_WINDOW_BASE,
            0x4000,
            PtOp::ReadWrite { exec: false },
            None,
        );
        assert!(
            applied.is_err(),
            "apply published the GIC window: {applied:?}"
        );
        assert_eq!(pt.translate(LINUX_GIC_WINDOW_BASE), None);
    }

    #[test]
    fn boot_stage1_images_leave_the_gic_window_untranslated() {
        for bytes in [stage1_identity_page_tables(), stage1_hvpatch_page_tables()] {
            let pt = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
            for va in [
                LINUX_GIC_DISTRIBUTOR_BASE,
                LINUX_GIC_REDISTRIBUTOR_BASE,
                LINUX_GIC_WINDOW_BASE + LINUX_GIC_WINDOW_SIZE - 0x1000,
            ] {
                assert_eq!(pt.translate(va), None, "{va:#x}");
            }
            assert_eq!(
                pt.translate(LINUX_GIC_WINDOW_BASE - 0x1000),
                Some(LINUX_GIC_WINDOW_BASE - 0x1000),
                "the block below keeps its identity user mapping"
            );
        }
    }

    #[test]
    fn undo_journal_rollback_matches_a_cloned_snapshot() {
        type Edit = Box<dyn Fn(&mut PageTableManager)>;
        let edits: Vec<Edit> = vec![
            Box::new(|m: &mut PageTableManager| {
                m.set_readonly(LINUX_HEAP_BASE, 0x4000, false, None).ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.set_rw(LINUX_HEAP_BASE, 0x2000, false, None).ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.map_private_aliased(LINUX_MMAP_BASE, LINUX_ALIAS_IPA_BASE, 0x8000, RX, None)
                    .ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.set_prot_none(LINUX_MMAP_BASE, 0x4000, None).ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.repoint_preserving_attributes(
                    LINUX_MMAP_BASE,
                    LINUX_ALIAS_IPA_BASE + 0x10000,
                    0x4000,
                    None,
                )
                .ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.unmap_aliased(LINUX_MMAP_BASE, 0x8000, None).ok();
            }),
            Box::new(|m: &mut PageTableManager| {
                m.invalidate(LINUX_HEAP_BASE, 0x4000, None).ok();
            }),
        ];

        for length in 1..=edits.len() {
            let mut journalled = manager();
            journalled.set_multi_vcpu(false);
            journalled.set_stage1_exclusive(true);
            journalled
                .set_readonly(LINUX_HEAP_BASE, 0x8000, false, None)
                .ok();
            journalled
                .map_private_aliased(LINUX_MMAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RX, None)
                .ok();

            let oracle = journalled.snapshot_image().expect("snapshot oracle");
            journalled.begin_undo().unwrap();
            assert!(journalled.undo_is_open());
            for edit in edits.iter().take(length) {
                edit(&mut journalled);
            }
            let mut host = journalled.as_bytes().to_vec();
            unsafe {
                journalled
                    .rollback_undo((journalled.base(), host.as_mut_ptr()), None)
                    .unwrap();
            };

            assert!(
                !journalled.undo_is_open(),
                "rollback must close the journal"
            );
            assert_eq!(
                journalled.as_bytes(),
                oracle.as_bytes(),
                "prefix of {length} edit(s): journalled rollback diverged from the cloned image"
            );
            assert_eq!(
                journalled.pool_stats(),
                oracle.pool_stats(),
                "prefix of {length} edit(s): spare-table pool state diverged"
            );
            assert_eq!(
                journalled.coalesce_policy(),
                oracle.coalesce_policy(),
                "prefix of {length} edit(s): coalesce policy state diverged"
            );
            assert_eq!(
                &host[..oracle.as_bytes().len()],
                oracle.as_bytes(),
                "prefix of {length} edit(s): host backing was not restored to the pre-image"
            );
        }
    }

    #[test]
    fn undo_journal_reports_replaced_valid_only_for_pre_transaction_words() {
        let mut fresh = manager();
        fresh.set_multi_vcpu(false);
        fresh.set_stage1_exclusive(true);
        fresh
            .invalidate(LINUX_MMAP_BASE, 0x4000, None)
            .expect("carve hole");
        for page in 0..4 {
            assert_eq!(fresh.translate(LINUX_MMAP_BASE + page * 0x1000), None);
        }
        assert!(!fresh.undo_replaced_valid_descriptor(), "closed journal");
        fresh.begin_undo().unwrap();
        fresh
            .map_private_aliased(LINUX_MMAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RX, None)
            .expect("map fresh hole");
        fresh
            .set_prot_none(LINUX_MMAP_BASE, 0x4000, None)
            .expect("make inaccessible");
        assert!(
            !fresh.undo_replaced_valid_descriptor(),
            "valid words written and unwritten inside one transaction are not replacements"
        );
        fresh.commit_undo();

        let mut replacing = manager();
        replacing.set_multi_vcpu(false);
        replacing.set_stage1_exclusive(true);
        replacing
            .map_private_aliased(LINUX_MMAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RX, None)
            .expect("map before the transaction");
        replacing.begin_undo().unwrap();
        replacing
            .set_prot_none(LINUX_MMAP_BASE, 0x4000, None)
            .expect("replace a live valid word");
        assert!(
            replacing.undo_replaced_valid_descriptor(),
            "overwriting a pre-transaction VALID word needs maintenance"
        );
        replacing.commit_undo();
        assert!(
            !replacing.undo_replaced_valid_descriptor(),
            "commit closes the journal"
        );
    }

    #[test]
    fn undo_journal_commit_keeps_the_transaction() {
        let mut mgr = manager();
        mgr.begin_undo().unwrap();
        mgr.set_readonly(LINUX_HEAP_BASE, 0x4000, false, None)
            .expect("protect heap");
        let after = mgr.snapshot_image().expect("snapshot after");
        mgr.commit_undo();
        assert!(!mgr.undo_is_open());
        assert_eq!(mgr.as_bytes(), after.as_bytes());
    }

    #[test]
    fn hvpatch_editor_preserves_non_global_across_protect_alias_repoint_and_coalesce() {
        let mut mgr = PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        mgr.declare_offline_private_image();
        let leaf = |manager: &PageTableManager, va| terminal_descriptor(manager.debug_walk(va));
        let text = 0x0040_0000_u64;

        mgr.set_readonly(text, 0x1000, true, None)
            .expect("protect text");
        assert_ne!(leaf(&mgr, text) & NON_GLOBAL, 0);
        mgr.set_rw(text, 0x1000, true, None).expect("restore text");
        let restored = mgr.debug_walk(text);
        assert_ne!(terminal_descriptor(restored) & NON_GLOBAL, 0);
        assert_ne!(
            restored[2] & TYPE_BITS,
            TYPE_TABLE_OR_PAGE,
            "uniform HVPatch leaves should coalesce back to an nG block"
        );

        let shared_va = LINUX_SHARED_FILE_BASE;
        let shared_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        mgr.map_aliased(shared_va, shared_ipa, 0x4000, RWX, None)
            .expect("publish physically shared per-mm alias");
        assert_ne!(
            leaf(&mgr, shared_va) & NON_GLOBAL,
            0,
            "physical sharing must not make a semantic per-mm translation global"
        );

        let private_va = LINUX_PRIVATE_OVERLAY_BASE;
        let first_private_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
        mgr.map_private_aliased(private_va, first_private_ipa, 0x4000, RWX, None)
            .expect("publish private alias");
        let replacement_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x60_0000;
        mgr.repoint_preserving_attributes(private_va, replacement_ipa, 0x4000, None)
            .expect("repoint private alias");
        assert_ne!(leaf(&mgr, private_va) & NON_GLOBAL, 0);

        let mut compatibility = manager();
        compatibility
            .map_aliased(shared_va, shared_ipa, 0x4000, RWX, None)
            .expect("publish compatibility alias");
        assert_eq!(
            leaf(&compatibility, shared_va) & NON_GLOBAL,
            0,
            "HVPatch ASID scope must not blanket-change compatibility editors"
        );

        mgr.unmap_aliased(carrick_mem::memory::LINUX_NULL_GUARD_END, 0x1000, None)
            .expect("remove the low detection leaf");
        let mut reconstructed = PageTableManager::new(
            mgr.into_bytes().unwrap(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        reconstructed
            .map_aliased(shared_va, shared_ipa, 0x4000, RWX, None)
            .expect("publish alias after reconstructing the editor");
        assert_ne!(
            leaf(&reconstructed, shared_va) & NON_GLOBAL,
            0,
            "HVPatch mode must not depend on one mutable user leaf"
        );
    }

    #[test]
    fn host_walk_matches_the_copying_walk() {
        let mut mgr = manager();
        let va = LINUX_HEAP_BASE;
        mgr.map_private_aliased(va, LINUX_ALIAS_IPA_BASE, 0x4000, RWX, None)
            .expect("map a private alias to force a full four-level walk");
        let bytes = mgr.as_bytes().to_vec();
        let base = mgr.base();

        for probe in [va, va + 0x1000, LINUX_MMAP_BASE, LINUX_SHARED_FILE_BASE] {
            let copied = walk_descriptors(&bytes, base, probe);
            let live = unsafe { walk_descriptors_host(bytes.as_ptr(), bytes.len(), base, probe) };
            assert_eq!(copied, live, "walk diverged at VA {probe:#x}");
        }

        let short = 8;
        let copied = walk_descriptors(&bytes[..short], base, va);
        let live = unsafe { walk_descriptors_host(bytes.as_ptr(), short, base, va) };
        assert_eq!(copied, live, "bounded walks diverged");
    }

    #[test]
    fn snapshot_into_reproduces_snapshot_and_keeps_the_buffer() {
        let mut source = manager();
        source
            .map_private_aliased(LINUX_HEAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RWX, None)
            .expect("split a block so the source has allocator state to carry");

        let mut recycled = manager();
        let capacity_before = recycled.arenas[0].capacity;
        let buf_cap_before = match recycled.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes.capacity(),
            TableArenaStorage::Live => 0,
        };
        source.snapshot_into(&mut recycled).expect("snapshot_into");

        let fresh = source.snapshot_image().expect("snapshot_image");
        assert_eq!(recycled.as_bytes(), fresh.as_bytes());
        assert_eq!(recycled.base(), fresh.base());
        assert_eq!(recycled.pool_stats(), fresh.pool_stats());
        assert_eq!(recycled.arenas[0].capacity, capacity_before);
        let buf_cap_after = match recycled.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes.capacity(),
            TableArenaStorage::Live => 0,
        };
        assert!(
            buf_cap_after >= buf_cap_before,
            "both managers cover the same region, so no reallocation is needed"
        );
    }

    #[test]
    fn snapshot_copies_only_populated_prefix_and_preserves_capacity() {
        let mut source = manager();
        source
            .map_private_aliased(LINUX_HEAP_BASE, LINUX_ALIAS_IPA_BASE, 0x4000, RWX, None)
            .expect("split a block so the source has allocator state to carry");

        let populated = source.copied_bytes();
        assert!(
            populated < source.arenas[0].capacity as u64,
            "source should only be partially populated: populated={populated} vs cap={}",
            source.arenas[0].capacity
        );
        let src_len = match source.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes.len(),
            TableArenaStorage::Live => 0,
        };
        assert_eq!(src_len, populated as usize);

        assert!(
            source
                .pa_to_loc(source.base() + populated - PT_PAGE)
                .is_ok()
        );
        assert_eq!(
            source.pa_to_loc(source.base() + populated).unwrap_err(),
            PageTableError::BadAddress
        );

        let cloned = source.snapshot_image().expect("snapshot_image");
        assert_eq!(cloned.copied_bytes(), populated);
        let cloned_len = match cloned.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes.len(),
            TableArenaStorage::Live => 0,
        };
        assert_eq!(cloned_len, populated as usize);
        assert_eq!(cloned.arenas[0].capacity, source.arenas[0].capacity);
        let cloned_cap = match cloned.arenas[0].storage {
            TableArenaStorage::Owned(ref bytes) => bytes.capacity(),
            TableArenaStorage::Live => 0,
        };
        assert!(
            cloned_cap >= source.arenas[0].capacity,
            "cloned arena must preserve full allocation capacity"
        );
        assert_eq!(
            cloned.pa_to_loc(cloned.base() + populated).unwrap_err(),
            PageTableError::BadAddress,
            "clone must also fail closed beyond populated prefix"
        );
    }

    #[test]
    fn indices_decompose_va() {
        let i = indices(LINUX_MMAP_BASE);
        assert_eq!(i[0], 0);
        assert_eq!(i[1], (LINUX_MMAP_BASE >> 30 & 0x1ff) as usize);
    }

    #[test]
    fn terminal_descriptor_selects_block_page_and_invalid_leaf() {
        let table = VALID | TYPE_TABLE_OR_PAGE;
        let block = VALID | TYPE_BLOCK | 0x2000_0000;
        let page = VALID | TYPE_TABLE_OR_PAGE | 0x1234_5000;
        let invalid = 0x4567_8000;

        assert_eq!(terminal_descriptor([table, block, 0, 0]), block);
        assert_eq!(terminal_descriptor([table, table, table, page]), page);
        assert_eq!(terminal_descriptor([table, table, table, invalid]), invalid);
    }

    #[test]
    fn terminal_entry_names_the_level_that_stopped_the_walk() {
        let table = VALID | TYPE_TABLE_OR_PAGE;
        let block = VALID | TYPE_BLOCK | 0x2000_0000;
        let page = VALID | TYPE_TABLE_OR_PAGE | 0x1234_5000;

        assert_eq!(terminal_entry([0, 0, 0, 0]), (0, 0));
        assert_eq!(terminal_entry([table, 0, 0, 0]), (1, 0));
        assert_eq!(terminal_entry([table, block, 0, 0]), (1, block));
        assert_eq!(terminal_entry([table, table, 0x4000, 0]), (2, 0x4000));
        assert_eq!(terminal_entry([table, table, table, page]), (3, page));
        assert!(descriptor_is_valid(page));
        assert!(!descriptor_is_valid(0x4000));
    }

    #[test]
    fn rosetta_alias_vas_avoid_boot_identity_l0_slots() {
        assert_eq!(indices(LINUX_HIGH_VA_THRESHOLD - 1)[0], 1);
        let elf_va = 0xffff_ffff_ffff_4000u64 & 0x0000_FFFF_FFFF_FFFF;
        assert!(
            indices(elf_va)[0] >= 2,
            "ELF alias collides with identity L0[0..1]"
        );
        let arena_va = 240u64 * (1 << 40);
        assert!(
            indices(arena_va)[0] >= 2,
            "arena alias collides with identity L0[0..1]"
        );
    }

    #[test]
    fn user_block_flags_match_boot_image() {
        let bytes = stage1_identity_page_tables();
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[0x2000..0x2008]);
        let desc = u64::from_le_bytes(a);
        assert_eq!(desc & !PA_MASK_1GIB, USER_BLOCK_FLAGS);
    }

    #[test]
    fn set_prot_none_splits_block_and_invalidates_only_target() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x10_0000;
        assert!(mgr.is_valid(va), "arena starts mapped");
        mgr.set_prot_none(va, 0x1000, None)
            .expect("split + invalidate");
        assert!(!mgr.is_valid(va), "target page now faults");
        assert!(mgr.is_valid(va + 0x1000), "next page stays mapped");
        assert!(
            mgr.is_valid(va.wrapping_sub(0x1000)),
            "prev page stays mapped"
        );
    }

    #[test]
    fn repoint_untouched_fork_alias_splits_retained_invalid_block() {
        let mut mgr = PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        mgr.declare_offline_private_image();
        let va = LINUX_PRIVATE_OVERLAY_BASE + 0x20_0000;
        let old_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
        let new_ipa = old_ipa + 0x20_0000;
        mgr.map_private_aliased(va, old_ipa, 0x20_0000, RWX, None)
            .expect("map aligned private block");
        mgr.set_prot_none(va, 0x20_0000, None)
            .expect("arm untouched block for first touch");
        assert_eq!(
            mgr.translate_retained_output(va + 0x77_000),
            Some(old_ipa + 0x77_000)
        );
        assert_eq!(mgr.debug_walk(va + 0x77_000)[2] & VALID, 0);

        mgr.repoint_preserving_attributes(va + 0x77_000, new_ipa + 0x77_000, 0x4000, None)
            .expect("repoint child alias in retained invalid block");

        assert_eq!(mgr.translate(va + 0x77_000), None);
        assert_eq!(
            mgr.translate_retained_output(va + 0x77_000),
            Some(new_ipa + 0x77_000)
        );
        assert_eq!(
            mgr.translate_retained_output(va + 0x76_000),
            Some(old_ipa + 0x76_000),
            "neighbor retains its inherited output"
        );
        assert_eq!(mgr.translate(va + 0x76_000), None);
        mgr.set_rw(va + 0x77_000, 0x4000, false, None)
            .expect("child first touch revalidates only its private alias");
        assert_eq!(mgr.translate(va + 0x77_000), Some(new_ipa + 0x77_000));
        assert_eq!(mgr.translate(va + 0x76_000), None);
    }

    #[test]
    fn repoint_prepared_el1_invalid_block_splits_without_losing_grant_tags() {
        let mut mgr = PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        mgr.declare_offline_private_image();
        let va = LINUX_PRIVATE_OVERLAY_BASE + 0x20_0000;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
        mgr.map_private_aliased(va, ipa, 0x20_0000, RWX, None)
            .expect("seed a block grant");
        mgr.mark_guest_private_publication(GuestLeafPublication {
            va,
            ipa,
            len: 0x20_0000,
            writable: true,
            executable: false,
        })
        .expect("tag the block grant");
        mgr.set_prot_none(va, 0x20_0000, None)
            .expect("leave the grant prepared");
        let child_va = va + 0x3c_000;
        assert_eq!(
            el1_private_leaf_state(terminal_descriptor(mgr.debug_walk(child_va))),
            El1PrivateLeafState::Prepared
        );
        let child_ipa = ipa + 0x40_0000 + 0x7c_000;
        mgr.repoint_preserving_attributes(child_va, child_ipa, 0x4000, None)
            .expect("repoint an untouched child alias within the block");
        assert_eq!(mgr.translate(child_va), None);
        assert_eq!(mgr.translate_retained_output(child_va), Some(child_ipa));
        assert_eq!(
            el1_private_leaf_state(terminal_descriptor(mgr.debug_walk(child_va))),
            El1PrivateLeafState::Prepared
        );
        assert_eq!(
            mgr.translate_retained_output(child_va - 0x1000),
            Some(ipa + 0x3b_000)
        );

        let retired_va = va + 0x20_0000;
        let retired_ipa = ipa + 0x80_0000;
        mgr.map_private_aliased(retired_va, retired_ipa, 0x20_0000, RWX, None)
            .expect("seed the next block grant");
        mgr.mark_guest_private_publication(GuestLeafPublication {
            va: retired_va,
            ipa: retired_ipa,
            len: 0x20_0000,
            writable: true,
            executable: false,
        })
        .expect("tag the next block grant");
        mgr.invalidate(retired_va, 0x20_0000, None)
            .expect("retire the entire block lease");
        let stale = retired_va + 0x3c_000;
        assert!(terminal_descriptor_is_retired(terminal_descriptor(
            mgr.debug_walk(stale)
        )));
        mgr.clear_inaccessible_invalid_fork_leaf(stale)
            .expect("split a retired EL1 block and clear just the stale alias");
        assert_eq!(mgr.translate_retained_output(stale), None);
        assert_eq!(
            mgr.translate_retained_output(stale - PT_PAGE),
            Some(retired_ipa + 0x3b_000)
        );
        assert!(terminal_descriptor_is_retired(terminal_descriptor(
            mgr.debug_walk(stale - PT_PAGE)
        )));
    }

    #[test]
    fn set_readonly_then_rw_round_trips() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_readonly(va, 0x1000, true, None).expect("ro");
        assert_eq!(mgr.ap_bits(va), AP_RO);
        assert!(mgr.is_valid(va));
        mgr.set_rw(va, 0x1000, true, None).expect("rw");
        assert_eq!(mgr.ap_bits(va), AP_RW);
        assert!(mgr.is_valid(va));
    }

    #[test]
    fn fork_readonly_marks_the_per_mm_leaf_non_global() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x24_0000;
        assert_eq!(mgr.debug_walk(va)[3] & (1 << 11), 0);

        mgr.set_fork_readonly(va, 0x1000, None)
            .expect("arm fork COW");

        let leaf = mgr.debug_walk(va)[3];
        assert_eq!(leaf & AP_MASK, AP_RO);
        assert_ne!(leaf & (1 << 11), 0, "per-mm fork leaf must use its ASID");
    }

    #[test]
    fn fork_readonly_preserves_each_leaf_execute_permission() {
        let mut mgr = manager();
        let nx = LINUX_MMAP_BASE + 0x2c_0000;
        let x = LINUX_MMAP_BASE + 0x2c_1000;
        mgr.set_rw(nx, 0x1000, false, None).expect("rw nx");
        mgr.set_rw(x, 0x1000, true, None).expect("rw exec");
        assert_ne!(mgr.debug_walk(nx)[3] & UXN, 0);
        assert_eq!(mgr.debug_walk(x)[3] & UXN, 0);

        mgr.set_fork_readonly(nx, 0x2000, None)
            .expect("arm fork COW");

        for va in [nx, x] {
            let leaf = mgr.debug_walk(va)[3];
            assert_eq!(leaf & AP_MASK, AP_RO, "fork arm must remove write");
            assert_ne!(leaf & NON_GLOBAL, 0);
        }
        assert_ne!(
            mgr.debug_walk(nx)[3] & UXN,
            0,
            "fork arm must not grant execute to an NX leaf"
        );
        assert_eq!(
            mgr.debug_walk(x)[3] & UXN,
            0,
            "fork arm must not revoke execute from an executable leaf"
        );
        assert!(
            !mgr.set_fork_readonly(nx, 0x2000, None)
                .expect("re-arm")
                .changed,
            "an armed leaf is satisfied whatever its execute bit"
        );
    }

    #[test]
    fn fork_readonly_preserves_prot_none_and_later_write_keeps_non_global() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x28_0000;
        mgr.set_prot_none(va, 0x1000, None).expect("PROT_NONE");
        assert!(!mgr.is_valid(va));

        mgr.set_fork_readonly(va, 0x1000, None)
            .expect("arm invalid fork leaf");
        assert!(!mgr.is_valid(va), "fork arming must not grant access");
        assert_ne!(mgr.debug_walk(va)[3] & NON_GLOBAL, 0);

        mgr.set_rw(va, 0x1000, false, None).expect("mprotect write");
        assert!(mgr.is_valid(va));
        assert_ne!(
            mgr.debug_walk(va)[3] & NON_GLOBAL,
            0,
            "mprotect must preserve the fork leaf's ASID scoping"
        );
    }

    #[test]
    fn kernel_cow_arm_and_alias_preserve_el1_only_access() {
        let mut mgr = manager();
        let va = carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE;
        mgr.set_kernel_readonly(va, 0x4000, false, None)
            .expect("arm kernel COW");
        assert_eq!(mgr.ap_bits(va), AP_PRIV_RO);

        let private_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        mgr.map_kernel_aliased(va, private_ipa, 0x4000, None)
            .expect("publish kernel COW");
        assert_eq!(mgr.ap_bits(va), 0, "EL1 is writable and EL0 remains denied");
        assert_ne!(mgr.debug_walk(va)[3] & NON_GLOBAL, 0);
        assert_eq!(mgr.translate(va), Some(private_ipa));
    }

    #[test]
    fn compound_cow_repoint_preserves_mixed_semantic_permissions() {
        let mut mgr = manager();
        let va = LINUX_HEAP_BASE + 0x40_0000;
        let new_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        mgr.set_readonly(va, 0x4000, false, None)
            .expect("arm compound read-only");
        mgr.set_prot_none(va + 0x2000, 0x1000, None)
            .expect("semantic hole inside compound");
        let before = [
            mgr.debug_walk(va)[3],
            mgr.debug_walk(va + 0x1000)[3],
            mgr.debug_walk(va + 0x2000)[3],
            mgr.debug_walk(va + 0x3000)[3],
        ];

        mgr.repoint_preserving_attributes(va, new_ipa, 0x4000, None)
            .expect("repoint physical compound");
        mgr.set_writable_preserving_attributes(va, 0x1000, None)
            .expect("faulting semantic page becomes writable");

        for index in 0..4_u64 {
            let leaf = mgr.debug_walk(va + index * 0x1000)[3];
            assert_eq!(
                leaf & PA_MASK_4KIB,
                new_ipa + index * 0x1000,
                "every leaf follows the copied compound"
            );
            assert_eq!(
                leaf & !(PA_MASK_4KIB | AP_MASK),
                before[index as usize] & !(PA_MASK_4KIB | AP_MASK),
                "repoint/write grant preserves validity and execute attributes"
            );
        }
        assert_eq!(mgr.ap_bits(va), AP_RW);
        assert_eq!(mgr.ap_bits(va + 0x1000), AP_RO);
        assert!(!mgr.is_valid(va + 0x2000));
        assert_eq!(mgr.ap_bits(va + 0x3000), AP_RO);
    }

    #[test]
    fn prot_none_then_rw_remaps() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x30_0000;
        mgr.set_prot_none(va, 0x2000, None).expect("none");
        assert!(!mgr.is_valid(va));
        assert!(!mgr.is_valid(va + 0x1000));
        mgr.set_rw(va, 0x2000, true, None).expect("rw");
        assert!(mgr.is_valid(va));
        assert!(mgr.is_valid(va + 0x1000));
    }

    #[test]
    fn private_overlay_protection_preserves_backing_and_identity_restore_repoints() {
        let mut mgr = manager();
        let va = LINUX_SHARED_FILE_BASE + 0x4000;
        let overlay = LINUX_PRIVATE_OVERLAY_BASE + 0x8000;
        mgr.map_aliased(va, overlay, 0x1000, RWX, None)
            .expect("private overlay");
        mgr.set_readonly(va, 0x1000, false, None)
            .expect("protect overlay readonly");
        assert_eq!(mgr.translate(va), Some(overlay));

        mgr.invalidate(va, 0x1000, None).expect("unmap overlay");
        mgr.map_aliased(va, va, 0x1000, RWX, None)
            .expect("restore shared identity");
        mgr.set_rw(va, 0x1000, false, None)
            .expect("protect restored shared mapping");
        assert_eq!(
            mgr.translate(va),
            Some(va),
            "protect_range must not resurrect the stale private-overlay IPA"
        );
    }

    #[test]
    fn unmap_aliased_reclaims_only_the_freed_l3_table() {
        let mut mgr = manager();
        let va1 = 0x100_0020_0000u64;
        let va2 = va1 + (1 << 21);
        mgr.map_aliased(va1, 0x80_0000, 0x1000, RWX, None)
            .expect("alias 1");
        mgr.map_aliased(va2, 0xA0_0000, 0x1000, RWX, None)
            .expect("alias 2");
        assert!(
            mgr.is_valid(va1) && mgr.is_valid(va2),
            "both aliases mapped"
        );
        let (two, _, _, _) = mgr.pool_stats();

        let changed = mgr.unmap_aliased(va1, 0x1000, None).expect("unmap alias 1");
        assert!(changed.changed, "unmap edited the tables");
        let (one, _, _, _) = mgr.pool_stats();
        assert_eq!(
            one,
            two - 1,
            "freed exactly the va1 L3 table; the shared L2/L1 + va2's L3 stay"
        );
        assert!(!mgr.is_valid(va1), "va1 faults after unmap");
        assert!(mgr.is_valid(va2), "sibling alias va2 still mapped");
    }

    #[test]
    fn map_aliased_large_unaligned_len_does_not_exhaust_table_pool() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE;
        let bulk = 128 * (1u64 << 20);
        let len = bulk + 0x4000;
        let ok = mgr
            .map_aliased(va, ipa, len, RWX, None)
            .expect("large unaligned alias must not exhaust the table pool");
        assert!(ok);
        assert!(mgr.is_valid(va), "first block of the bulk is mapped");
        assert!(
            mgr.is_valid(va + bulk - 0x1000),
            "last page of the bulk is mapped"
        );
        assert!(
            mgr.is_valid(va + bulk),
            "first tail page (past the 2 MiB-aligned bulk) is mapped"
        );
        assert!(mgr.is_valid(va + len - 0x1000), "last tail page is mapped");
        assert!(
            !mgr.is_valid(va + len),
            "one page past the mapping is NOT mapped"
        );
    }

    #[test]
    fn translate_resolves_aliased_va_to_ipa_with_page_offset() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE;
        let len = 0x1_0000;
        mgr.map_aliased(va, ipa, len, RWX, None).expect("map");
        assert_eq!(mgr.translate(va), Some(ipa));
        assert_eq!(mgr.translate(va + 0xabc), Some(ipa + 0xabc));
        assert_eq!(mgr.translate(va + 0x3000 + 0x10), Some(ipa + 0x3000 + 0x10));
        assert_eq!(mgr.translate(va + len), None);
    }

    #[test]
    fn readonly_does_not_coalesce_an_unaligned_physical_alias() {
        let mut mgr = manager();
        let va = 0x1_0000;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x1_4000;
        let len = 0xc1_0000;
        let probe = 0x80_e280;

        mgr.map_aliased(va, ipa, len, RWX, None).expect("map image");
        let expected = ipa + (probe - va);
        assert_eq!(mgr.translate(probe), Some(expected));

        mgr.set_readonly(0x5a_0000, 0x5d_4000, false, None)
            .expect("apply ELF rodata protection");
        assert_eq!(
            mgr.translate(probe),
            Some(expected),
            "read-only coalescing must preserve a non-block-aligned IPA delta"
        );
    }

    #[test]
    fn retained_output_resolves_invalidated_private_alias_without_revalidating_it() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;
        mgr.map_aliased(va, ipa, 0x4000, RWX, None).expect("map");
        mgr.invalidate(va, 0x4000, None).expect("invalidate");

        assert_eq!(mgr.translate(va + 0x123), None);
        assert_eq!(mgr.translate_retained_output(va + 0x123), Some(ipa + 0x123));
        assert_eq!(mgr.debug_walk(va)[3] & VALID, 0);
    }

    #[test]
    fn multi_gib_alias_maps_with_coarse_leaves_and_a_tiny_table_budget() {
        const ONE_GIB: u64 = 1 << 30;
        let mut mgr = manager();
        let (before, _, capacity, _) = mgr.pool_stats();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE;
        let len = 2 * ONE_GIB + 4 * 0x1000;
        mgr.map_aliased(va, ipa, len, RWX, None)
            .expect("a 2 GiB + 16 KiB alias must map");
        let (after, _, _, _) = mgr.pool_stats();
        assert!(
            after.saturating_sub(before) <= 8,
            "coarse leaves must keep the table budget O(1): used {} of {capacity}",
            after.saturating_sub(before)
        );
        assert_eq!(mgr.translate(va), Some(ipa));
        assert_eq!(
            mgr.translate(va + ONE_GIB + 0x1234),
            Some(ipa + ONE_GIB + 0x1234)
        );
        assert_eq!(mgr.translate(va + 2 * ONE_GIB), Some(ipa + 2 * ONE_GIB));
        assert_eq!(mgr.translate(va + len - 1), Some(ipa + len - 1));
    }

    #[test]
    fn a_gib_aligned_alias_span_uses_l1_block_leaves() {
        const ONE_GIB: u64 = 1 << 30;
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE;
        mgr.map_aliased(va, ipa, ONE_GIB, RWX, None)
            .expect("a 1 GiB alias must map");
        let walk = mgr.debug_walk(va);
        assert_ne!(walk[1] & VALID, 0, "L1 leaf must be valid");
        assert_eq!(
            walk[1] & TYPE_BITS,
            TYPE_BLOCK,
            "a 1 GiB-aligned span must terminate in an L1 block leaf"
        );
        assert_eq!(walk[2], 0, "a 1 GiB block has no L2 table beneath it");
        assert_eq!(mgr.translate(va + ONE_GIB - 1), Some(ipa + ONE_GIB - 1));
    }

    #[test]
    fn an_unsatisfiable_alias_build_writes_nothing() {
        const FOUR_KIB: u64 = 1 << 12;
        const ONE_GIB: u64 = 1 << 30;
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE + FOUR_KIB;
        let before = mgr.pool_stats();
        assert_eq!(
            mgr.map_aliased(va, ipa, ONE_GIB, RWX, None),
            Err(PageTableError::OutOfTables)
        );
        assert_eq!(
            mgr.pool_stats(),
            before,
            "a refused build must consume no spare tables"
        );
        assert_eq!(
            mgr.translate(va),
            None,
            "a refused build must leave no live translation"
        );
        assert_eq!(mgr.translate(va + ONE_GIB / 2), None);
    }

    #[test]
    fn retained_output_resolves_invalidated_aligned_alias_block() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD + 2 * TWO_MIB;
        let ipa = LINUX_ALIAS_IPA_BASE + 4 * TWO_MIB;
        mgr.map_aliased(va, ipa, TWO_MIB, RX, None)
            .expect("map aligned block");
        mgr.invalidate(va, TWO_MIB as usize, None)
            .expect("invalidate aligned block");

        let probe = va + 0x12_345;
        assert_eq!(mgr.translate(probe), None);
        assert_eq!(
            mgr.translate_retained_output(probe),
            Some(ipa + (probe - va)),
            "an invalidated L2 alias must retain its exact non-identity output"
        );
        assert_eq!(terminal_descriptor(mgr.debug_walk(probe)) & VALID, 0);
    }

    #[test]
    fn sparse_arena_materializes_only_exact_private_extent() {
        let mut mgr = manager();
        mgr.set_prot_none(LINUX_MMAP_BASE, mmap_arena_size() as usize, None)
            .expect("reserve sparse arena");

        let va = LINUX_MMAP_BASE + 0x41_000;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x81_000;
        let len = 0x23_000;
        mgr.map_private_aliased(va, ipa, len, RX, None)
            .expect("install exact private output");
        assert_ne!(
            terminal_descriptor(mgr.debug_walk(va)) & NON_GLOBAL,
            0,
            "a per-mm sparse output must be ASID scoped before publication"
        );
        mgr.set_prot_none(va, len as usize, None)
            .expect("keep new output inaccessible until VMA commit");

        assert_eq!(mgr.translate(va), None);
        assert_eq!(mgr.translate_retained_output(va), Some(ipa));
        assert_eq!(
            mgr.translate_retained_output(va + len - 1),
            Some(ipa + len - 1)
        );
        assert_eq!(
            mgr.translate_retained_output(va - 1),
            None,
            "the uncommitted arena prefix must remain physically absent"
        );
        assert_eq!(
            mgr.translate_retained_output(va + len),
            None,
            "the uncommitted arena suffix must remain physically absent"
        );

        mgr.set_rw(va, len as usize, false, None)
            .expect("publish exact VMA writable");
        assert_eq!(mgr.translate(va + 0x12_345), Some(ipa + 0x12_345));
        assert_eq!(mgr.translate(va - 1), None);
        assert_eq!(mgr.translate(va + len), None);
    }

    #[test]
    fn translate_picks_the_live_region_for_adjacent_aliases() {
        let mut mgr = manager();
        let a_va = LINUX_HIGH_VA_THRESHOLD;
        let a_ipa = LINUX_ALIAS_IPA_BASE;
        let a_len = 0xa2000;
        let b_va = a_va + a_len;
        let b_ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;
        let b_len = 0x2_2000;
        mgr.map_aliased(a_va, a_ipa, a_len, RWX, None)
            .expect("map A");
        mgr.map_aliased(b_va, b_ipa, b_len, RWX, None)
            .expect("map B");
        assert_eq!(mgr.translate(b_va + 0x1000), Some(b_ipa + 0x1000));
        assert_eq!(
            mgr.translate(a_va + a_len - 0x1000),
            Some(a_ipa + a_len - 0x1000)
        );
    }

    #[test]
    fn sub_16k_high_va_alias_does_not_perturb_neighbor_l3_entry() {
        let mut mgr = manager();
        let a_va = LINUX_HIGH_VA_THRESHOLD;
        let a_ipa = LINUX_ALIAS_IPA_BASE;
        let a_len = 0x3000;
        let b_va = a_va + a_len;
        let b_ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;

        mgr.map_aliased(b_va, b_ipa, 0x1000, RWX, None)
            .expect("map neighbor B first");
        let b_before = mgr.debug_walk(b_va)[3];
        assert_eq!(mgr.translate(b_va), Some(b_ipa));

        mgr.map_aliased(a_va, a_ipa, a_len, RWX, None)
            .expect("map sub-16 KiB A");

        assert_eq!(
            mgr.translate(a_va + a_len - 0x1000),
            Some(a_ipa + a_len - 0x1000)
        );
        assert_eq!(mgr.translate(b_va), Some(b_ipa));
        assert_eq!(
            mgr.debug_walk(b_va)[3],
            b_before,
            "neighbor B's L3 descriptor must not be overwritten by A's HVF-rounded length"
        );
    }

    #[test]
    fn clone_preserves_bump_cursor_so_fork_child_does_not_realloc_live_tables() {
        let mut parent = manager();
        parent
            .set_prot_none(LINUX_MMAP_BASE + 0x10_0000, 0x1000, None)
            .unwrap();
        parent
            .set_prot_none(LINUX_MMAP_BASE + 0x4080_0000, 0x1000, None)
            .unwrap();
        let (parent_in_use, _, _, _) = parent.pool_stats();
        assert!(parent_in_use >= 2, "two splits allocated >=2 tables");

        let mut child = parent.snapshot_image().expect("snapshot child");
        assert_eq!(child.pool_stats(), parent.pool_stats(), "cursor preserved");
        assert!(!child.is_valid(LINUX_MMAP_BASE + 0x10_0000));
        assert!(child.is_valid(LINUX_MMAP_BASE + 0x10_0000 + 0x1000));

        child
            .set_prot_none(LINUX_MMAP_BASE + 0x8080_0000, 0x1000, None)
            .unwrap();
        let (child_in_use, _, _, _) = child.pool_stats();
        assert!(child_in_use > parent_in_use, "fresh table, no re-handout");
        assert!(child.is_valid(LINUX_MMAP_BASE + 0x10_0000 + 0x1000));
    }

    #[test]
    fn exhausting_spare_tables_errors() {
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        assert_eq!(
            mgr.set_prot_none(LINUX_MMAP_BASE + 0x10_0000, 0x1000, None),
            Err(PageTableError::OutOfTables),
        );
    }

    #[test]
    fn set_rw_on_default_rw_block_does_not_split() {
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        assert_eq!(
            mgr.set_rw(LINUX_MMAP_BASE + 0x10_0000, 0x4000, false, None),
            Ok(PageTableApplyOutcome::default())
        );
    }

    #[test]
    fn full_block_restore_coalesces_and_reclaims_table() {
        let mut mgr = manager();
        mgr.declare_offline_private_image();
        let block = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        let after_split = mgr.arenas[0].next_free;
        assert!(
            after_split > SPARE_START_OFFSET,
            "split consumed spare pages"
        );
        mgr.set_rw(block, 1 << 21, true, None).expect("restore");
        assert!(mgr.is_valid(block));
        assert!(
            !mgr.free_tables.is_empty(),
            "coalesce reclaimed a sub-table"
        );
    }

    #[test]
    fn live_block_restore_keeps_table_until_break_before_make_is_available() {
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        assert_eq!(
            mgr.debug_walk(block)[2] & TYPE_BITS,
            TYPE_TABLE_OR_PAGE,
            "the partial edit creates an L3 table"
        );

        mgr.set_rw(block, 1 << 21, true, None).expect("restore");
        assert_eq!(
            mgr.debug_walk(block)[2] & TYPE_BITS,
            TYPE_TABLE_OR_PAGE,
            "a live editor must retain the table until it has a two-phase BBM publisher"
        );
        assert!(mgr.free_tables.is_empty(), "the live table remains owned");
    }

    #[test]
    fn large_aligned_prot_none_is_coarse_not_dense() {
        let mut mgr = manager();
        assert_eq!(
            LINUX_MMAP_BASE % (1 << 30),
            0,
            "arena base is 1 GiB-aligned"
        );
        let before = mgr.arenas[0].next_free;
        mgr.set_prot_none(LINUX_MMAP_BASE, 512 << 20, None)
            .expect("coarse prot_none");
        let pages_used = (mgr.arenas[0].next_free - before) / 0x1000;
        assert_eq!(
            pages_used, 1,
            "512 MiB PROT_NONE used {pages_used} tables, want 1"
        );
        assert!(!mgr.is_valid(LINUX_MMAP_BASE));
        assert!(!mgr.is_valid(LINUX_MMAP_BASE + (512 << 20) - 0x1000));
        assert!(mgr.is_valid(LINUX_MMAP_BASE + (512 << 20)));
    }

    #[test]
    fn rw_commit_into_prot_none_block_keeps_neighbors_invalid() {
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE;
        mgr.set_prot_none(block, 1 << 21, None)
            .expect("reserve PROT_NONE");
        assert!(!mgr.is_valid(block));
        assert!(!mgr.is_valid(block + 0x1000));
        mgr.set_rw(block + 0x10000, 0x1000, true, None)
            .expect("RW commit");
        assert!(mgr.is_valid(block + 0x10000), "committed page is RW");
        assert_eq!(mgr.ap_bits(block + 0x10000), AP_RW);
        assert!(!mgr.is_valid(block), "neighbor page 0 stays invalid");
        assert!(
            !mgr.is_valid(block + 0x1000),
            "neighbor page 1 stays invalid"
        );
        assert!(
            !mgr.is_valid(block + 0x1ff000),
            "last page of the 2 MiB block stays invalid"
        );
    }

    #[test]
    fn full_1gib_prot_none_edits_block_with_no_split() {
        let mut bytes = stage1_identity_page_tables();
        bytes.truncate(6 * 0x1000);
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        assert_eq!(
            mgr.set_prot_none(LINUX_MMAP_BASE, 1 << 30, None),
            Ok(PageTableApplyOutcome {
                changed: true,
                flush_required: true
            })
        );
        assert!(!mgr.is_valid(LINUX_MMAP_BASE));
        assert!(!mgr.is_valid(LINUX_MMAP_BASE + (1 << 30) - 0x1000));
    }

    #[test]
    fn last_resort_sweep_reclaims_an_emptied_subtable() {
        let mut mgr = manager();
        mgr.set_multi_vcpu(true);
        mgr.set_stage1_exclusive(true);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_prot_none(block, 1 << 21, None)
            .expect("tear the block down");
        assert!(
            mgr.free_tables.is_empty(),
            "eager reclaim must NOT have run for a multi-vCPU guest"
        );
        assert!(
            mgr.reclaim_all_invalid_tables().unwrap(),
            "sweep should free the L3"
        );
        assert!(!mgr.free_tables.is_empty(), "the emptied table came back");
    }

    #[test]
    fn last_resort_sweep_declines_without_exclusivity() {
        let mut mgr = manager();
        mgr.set_multi_vcpu(true);
        mgr.set_stage1_exclusive(false);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_prot_none(block, 1 << 21, None)
            .expect("tear the block down");
        assert!(!mgr.reclaim_all_invalid_tables().unwrap());
        assert!(mgr.free_tables.is_empty(), "nothing may be reclaimed");
    }

    #[test]
    fn last_resort_sweep_runs_once_per_teardown() {
        let mut mgr = manager();
        mgr.set_multi_vcpu(true);
        mgr.set_stage1_exclusive(true);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_prot_none(block, 1 << 21, None)
            .expect("tear the block down");
        assert!(
            mgr.reclaim_all_invalid_tables().unwrap(),
            "first sweep does the work"
        );
        assert!(
            !mgr.reclaim_all_invalid_tables().unwrap(),
            "a second sweep with no new teardown must decline"
        );
        let other = LINUX_MMAP_BASE + 0x80_0000;
        mgr.set_prot_none(other, 0x1000, None).expect("split");
        mgr.set_prot_none(other, 1 << 21, None)
            .expect("tear the block down");
        assert!(
            mgr.reclaim_all_invalid_tables().unwrap(),
            "new teardown re-arms"
        );
    }

    #[test]
    fn offline_fork_copy_sweeps_where_the_inherited_marker_refused() {
        let mut parent = manager();
        parent.set_multi_vcpu(true);
        parent.set_stage1_exclusive(false);

        let mut block = LINUX_MMAP_BASE;
        let mut exhausted = false;
        for _ in 0..1024 {
            match parent.set_prot_none(block, 0x1000, None) {
                Ok(_) => {}
                Err(PageTableError::OutOfTables) => {
                    exhausted = true;
                    break;
                }
                Err(other) => panic!("unexpected split failure: {other:?}"),
            }
            parent
                .set_prot_none(block, 1 << 21, None)
                .expect("tear the block down");
            block += 1 << 21;
        }
        assert!(exhausted, "the churn must exhaust the spare pool");
        let (in_use, free, capacity, _) = parent.pool_stats();
        assert_eq!(free, 0, "a refused sweep reclaims nothing");
        assert_eq!(in_use, capacity, "the pool is at its limit");
        assert_eq!(
            parent.coalesce_policy(),
            (true, false, true),
            "and it is refused with a teardown still pending"
        );

        let mut inherited = parent.snapshot_image().expect("snapshot inherited");
        assert_eq!(
            inherited.set_prot_none(block, 0x1000, None),
            Err(PageTableError::OutOfTables),
            "the inherited marker keeps refusing the sweep"
        );

        let mut offline = parent.snapshot_image().expect("snapshot offline");
        offline.declare_offline_private_image();
        assert_eq!(
            offline.set_prot_none(block, 0x1000, None),
            Ok(PageTableApplyOutcome {
                changed: true,
                flush_required: true
            }),
            "an offline private copy may sweep and recover the pool"
        );
        assert_eq!(
            offline.pool_stats().2,
            capacity,
            "recovery reuses the pool, it does not grow it"
        );
    }

    #[test]
    fn multi_vcpu_does_not_coalesce() {
        let mut mgr = manager();
        mgr.declare_offline_private_image();
        mgr.set_multi_vcpu(true);
        let block = LINUX_MMAP_BASE + 0x60_0000;
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_rw(block, 1 << 21, true, None).expect("restore");
        assert!(mgr.is_valid(block));
        assert!(
            mgr.free_tables.is_empty(),
            "multi-vCPU must NOT coalesce/reclaim"
        );
        mgr.set_multi_vcpu(false);
        mgr.set_prot_none(block, 0x1000, None).expect("split");
        mgr.set_rw(block, 1 << 21, true, None).expect("restore");
        assert!(
            !mgr.free_tables.is_empty(),
            "single-vCPU coalesces/reclaims"
        );
    }

    #[test]
    fn partial_protection_does_not_coalesce() {
        let mut mgr = manager();
        let block = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_readonly(block, 0x1000, true, None)
            .expect("ro one page");
        mgr.set_rw(block, 1 << 21, true, None).expect("rw the rest");
        let mut mgr2 = manager();
        mgr2.set_readonly(block, 0x1000, true, None)
            .expect("ro one page");
        mgr2.set_rw(block + 0x1000, 0x1000, true, None)
            .expect("rw next page");
        assert_eq!(mgr2.ap_bits(block), AP_RO, "mixed block keeps RO page");
        assert_eq!(mgr2.ap_bits(block + 0x1000), AP_RW);
        assert!(mgr2.free_tables.is_empty(), "mixed block must not coalesce");
    }

    #[test]
    fn as_bytes_into_bytes_round_trip() {
        let mut mgr = manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        mgr.set_prot_none(va, 0x1000, None).unwrap();
        let bytes = mgr.into_bytes().unwrap();
        let mut mgr2 = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        assert!(!mgr2.is_valid(va), "edit survived round-trip through bytes");
    }

    #[test]
    fn quiesced_snapshot_restore_replaces_every_live_table_byte() {
        let snapshot = manager();
        let mut live = vec![0xa5; snapshot.arenas[0].capacity];

        unsafe {
            snapshot
                .restore_quiesced_snapshot_to_host(TestArenas(&[(
                    snapshot.base(),
                    live.as_mut_ptr(),
                )]))
                .unwrap()
        };

        assert_eq!(&live[..snapshot.as_bytes().len()], snapshot.as_bytes());
        assert!(
            live[snapshot.as_bytes().len()..].iter().all(|&b| b == 0xa5),
            "unpopulated tail should be untouched"
        );
    }

    #[test]
    fn rebase_moves_every_table_pointer_without_changing_leaf_translations() {
        let mut mgr = manager();
        let invalid_va = LINUX_MMAP_BASE + 0x10_0000;
        let alias_va = LINUX_HIGH_VA_THRESHOLD + 0x20_0000;
        let alias_ipa = LINUX_ALIAS_IPA_BASE + 0x40_0000;
        mgr.set_prot_none(invalid_va, 0x1000, None).expect("split");
        mgr.map_aliased(alias_va, alias_ipa, 0x3000, RX, None)
            .expect("alias");
        let identity_va = LINUX_HEAP_BASE + 0x1234;
        let before_identity = mgr.translate(identity_va);
        let before_alias = mgr.translate(alias_va + 0x234);
        let old_base = mgr.base();
        let new_base = 0xa0_0000_0000;

        mgr.rebase(new_base, None).expect("rebase cloned tables");

        assert_eq!(mgr.base(), new_base);
        assert_eq!(mgr.translate(identity_va), before_identity);
        assert_eq!(mgr.translate(alias_va + 0x234), before_alias);
        assert!(!mgr.is_valid(invalid_va));
        assert!(mgr.dirty.iter().any(|(_, is_pointer)| *is_pointer));
        for level in 0..3 {
            for descriptor in walk_descriptors(mgr.as_bytes(), new_base, alias_va)
                .into_iter()
                .take(level + 1)
            {
                if descriptor & VALID != 0 && descriptor & TYPE_BITS == TYPE_TABLE_OR_PAGE {
                    let pa = descriptor & PA_MASK_TABLE;
                    assert!(
                        (new_base..new_base + mgr.as_bytes().len() as u64).contains(&pa),
                        "level {level} table pointer 0x{pa:x} stayed under old base 0x{old_base:x}"
                    );
                }
            }
        }
    }

    #[test]
    fn new_rediscovers_bump_cursor_over_boot_edited_tables() {
        let mut boot = manager();
        boot.set_multi_vcpu(true);
        let ro_va = 0x40_0000;
        boot.set_readonly(ro_va, 0x2000, true, None)
            .expect("boot RO span");
        let (used, _, _, _) = boot.pool_stats();
        assert!(used >= 1, "boot edit allocated spare table(s)");

        let mut rebuilt = PageTableManager::new(
            boot.into_bytes().unwrap(),
            LINUX_PAGE_TABLES_BASE,
            test_layout(),
        );
        let (rebuilt_used, _, _, _) = rebuilt.pool_stats();
        assert_eq!(rebuilt_used, used, "cursor re-discovered, not reset");
        assert_eq!(rebuilt.ap_bits(ro_va), AP_RO);
        assert_eq!(rebuilt.ap_bits(ro_va + 0x2000), AP_RW, "past the span");
        rebuilt
            .set_prot_none(LINUX_MMAP_BASE + 0x10_0000, 0x1000, None)
            .expect("fresh split");
        let (after, _, _, _) = rebuilt.pool_stats();
        assert!(after > rebuilt_used, "fresh table allocated");
        assert_eq!(rebuilt.ap_bits(ro_va), AP_RO, "boot edit survives");
    }

    #[test]
    fn stage1_heap_starts_invalid_and_preserves_neighbors() {
        for (image_name, bytes, expect_ng) in [
            ("compatibility", stage1_identity_page_tables(), false),
            ("hvpatch", stage1_hvpatch_page_tables(), true),
        ] {
            let walk_leaf =
                |va| terminal_descriptor(walk_descriptors(&bytes, LINUX_PAGE_TABLES_BASE, va));

            let heap_base_leaf = walk_leaf(LINUX_HEAP_BASE);
            assert_eq!(
                heap_base_leaf & VALID,
                0,
                "{image_name}: heap base {:#x} must start invalid",
                LINUX_HEAP_BASE
            );

            let last_heap_page = LINUX_HEAP_BASE + LINUX_HEAP_SIZE - 0x1000;
            let last_heap_leaf = walk_leaf(last_heap_page);
            assert_eq!(
                last_heap_leaf & VALID,
                0,
                "{image_name}: last heap page {:#x} must start invalid",
                last_heap_page
            );

            let past_heap = LINUX_HEAP_BASE + LINUX_HEAP_SIZE;
            let past_heap_leaf = walk_leaf(past_heap);
            assert_ne!(
                past_heap_leaf & VALID,
                0,
                "{image_name}: past heap {:#x} must be valid",
                past_heap
            );
            if expect_ng {
                assert_ne!(
                    past_heap_leaf & NON_GLOBAL,
                    0,
                    "{image_name}: past heap {:#x} must be nG",
                    past_heap
                );
            }

            // The shared aperture is sealed PROT_NONE in a fresh image
            // (`kernel.mm.carrier-window-isolation`): invalid, output kept.
            let aperture_leaf = walk_leaf(LINUX_SHARED_FILE_BASE);
            assert_eq!(
                aperture_leaf & VALID,
                0,
                "{image_name}: shared aperture must start invalid"
            );
            assert_ne!(
                aperture_leaf, 0,
                "{image_name}: shared aperture keeps its output"
            );
            for (name, va) in [("user text", 0x0040_0000), ("mmap", LINUX_MMAP_BASE)] {
                let leaf = walk_leaf(va);
                assert_ne!(
                    leaf & VALID,
                    0,
                    "{image_name}: {name} at {va:#x} must be valid"
                );
                if expect_ng {
                    assert_ne!(
                        leaf & NON_GLOBAL,
                        0,
                        "{image_name}: {name} at {va:#x} must be nG"
                    );
                } else {
                    assert_eq!(
                        leaf & NON_GLOBAL,
                        0,
                        "{image_name}: {name} at {va:#x} must be global"
                    );
                }
            }
        }

        let hvpatch_bytes = stage1_hvpatch_page_tables();
        let mut mgr = PageTableManager::new(hvpatch_bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        mgr.set_multi_vcpu(true);

        mgr.set_rw(LINUX_HEAP_BASE, 0x1000, false, None)
            .expect("grow heap page to RW");
        let bytes_after_grow = mgr.into_bytes().unwrap();
        let walk_grow = |va| {
            terminal_descriptor(walk_descriptors(
                &bytes_after_grow,
                LINUX_PAGE_TABLES_BASE,
                va,
            ))
        };

        let grown_leaf = walk_grow(LINUX_HEAP_BASE);
        assert_ne!(grown_leaf & VALID, 0, "grown heap page must be valid");
        assert_eq!(
            grown_leaf & AP_MASK,
            AP_RW,
            "grown heap page must be writable (RW)"
        );
        assert_ne!(
            grown_leaf & NON_GLOBAL,
            0,
            "grown heap page must be nG (ASID-scoped)"
        );

        let next_heap_leaf = walk_grow(LINUX_HEAP_BASE + 0x1000);
        assert_eq!(
            next_heap_leaf & VALID,
            0,
            "next heap page must remain invalid"
        );

        let mut mgr2 =
            PageTableManager::new(bytes_after_grow, LINUX_PAGE_TABLES_BASE, test_layout());
        mgr2.set_multi_vcpu(true);
        mgr2.set_prot_none(LINUX_HEAP_BASE, 0x1000, None)
            .expect("shrink heap page to PROT_NONE");
        let bytes_after_shrink = mgr2.into_bytes().unwrap();
        let walk_shrink = |va| {
            terminal_descriptor(walk_descriptors(
                &bytes_after_shrink,
                LINUX_PAGE_TABLES_BASE,
                va,
            ))
        };

        let shrunk_leaf = walk_shrink(LINUX_HEAP_BASE);
        assert_eq!(
            shrunk_leaf & VALID,
            0,
            "shrunk heap page must return to invalid"
        );
    }

    #[test]
    fn reclaim_sweep_keeps_tables_whose_invalid_leaves_retain_live_outputs() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = hvpatch_manager();
        mgr.declare_offline_private_image();
        let va = LINUX_MMAP_BASE + 8 * TWO_MIB;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x1234_5000;
        let probe = va + 0x5000;
        mgr.map_private_aliased(va, ipa, TWO_MIB - 0x1000, RWX, None)
            .expect("publish sparse extent");
        mgr.set_prot_none(va, (TWO_MIB - 0x1000) as usize, None)
            .expect("arm first touch");
        assert_eq!(mgr.translate_retained_output(probe), Some(ipa + 0x5000));

        exhaust_spare_pool(&mut mgr, va);
        let reclaimed = mgr.reclaim_all_invalid_tables().unwrap();
        assert_eq!(
            mgr.translate_retained_output(probe),
            Some(ipa + 0x5000),
            "sweep (freed={reclaimed}) must keep a table whose invalid leaves still \
             retain live outputs"
        );
        mgr.set_rw(probe, 0x1000, false, None)
            .expect("commit resident page");
        assert_eq!(mgr.translate(probe), Some(ipa + 0x5000));
    }

    #[test]
    fn munmap_retires_leaves_so_the_reclaim_sweep_can_free_their_table() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = hvpatch_manager();
        mgr.declare_offline_private_image();
        let va = LINUX_MMAP_BASE + 8 * TWO_MIB;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x1234_5000;
        mgr.map_private_aliased(va, ipa, TWO_MIB - 0x1000, RWX, None)
            .expect("publish sparse extent");
        let (in_use_before, _, _, _) = mgr.pool_stats();
        mgr.invalidate(va, (TWO_MIB - 0x1000) as usize, None)
            .expect("munmap");
        assert_eq!(
            mgr.translate_retained_output(va + 0x5000),
            Some(ipa + 0x5000),
            "munmap keeps the retained output until the table is reclaimed"
        );
        assert!(
            mgr.reclaim_all_invalid_tables().unwrap(),
            "the retired table is reclaimable"
        );
        let (in_use_after, _, _, _) = mgr.pool_stats();
        assert_eq!(in_use_after, in_use_before - 2);
        assert_eq!(mgr.translate_retained_output(va + 0x5000), None);

        mgr.set_prot_none(va + 0x1000, 0x1000, None)
            .expect("bisect empty entry");
        assert_eq!(mgr.translate_retained_output(va + 0x5000), None);
        mgr.set_rw(va + 0x5000, 0x1000, false, None)
            .expect("revalidate");
        assert_ne!(mgr.translate(va + 0x5000), Some(0x5000));
    }

    #[test]
    fn empty_descriptors_never_mint_an_output_address() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = hvpatch_manager();
        let block = LINUX_MMAP_BASE + 40 * TWO_MIB;
        let probe = block + 0x5000;
        mgr.map_private_aliased(
            block,
            LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x7000,
            0x1000,
            RWX,
            None,
        )
        .expect("publish one page");
        assert_eq!(
            terminal_descriptor(mgr.debug_walk(probe)),
            0,
            "neighbour starts empty"
        );
        mgr.set_prot_none(block, TWO_MIB as usize, None)
            .expect("PROT_NONE the block");
        assert_eq!(
            terminal_descriptor(mgr.debug_walk(probe)),
            0,
            "invalidating an empty descriptor keeps it empty"
        );
        assert_eq!(mgr.translate_retained_output(probe), None);
        mgr.set_rw(probe, 0x1000, false, None).expect("revalidate");
        assert_ne!(
            mgr.translate(probe),
            Some(0),
            "revalidating an empty leaf must not publish output address 0"
        );
    }

    #[test]
    fn invalid_to_valid_leaf_edit_reports_flush_not_required() {
        let mut mgr = hvpatch_manager();
        let block = LINUX_MMAP_BASE + 20 * (2 * 1024 * 1024);
        let page0 = block;
        let page1 = block + 0x1000;

        mgr.set_prot_none(block, 2 * 1024 * 1024, None)
            .expect("set block to prot_none");
        assert!(!mgr.is_valid(page0));
        assert!(!mgr.is_valid(page1));

        let outcome_validating = mgr
            .set_rw(page0, 0x1000, false, None)
            .expect("validate invalid leaf to rw");
        assert!(outcome_validating.changed, "leaf changed to valid");
        assert!(
            !outcome_validating.flush_required,
            "validating an invalid leaf must report flush_required=false"
        );
        assert!(mgr.is_valid(page0));

        let outcome_perm_change = mgr
            .set_readonly(page0, 0x1000, false, None)
            .expect("change valid leaf AP to ro");
        assert!(outcome_perm_change.changed, "leaf changed to ro");
        assert!(
            outcome_perm_change.flush_required,
            "changing a valid leaf's AP must report flush_required=true"
        );

        let outcome_both = mgr
            .set_rw(page0, 0x2000, false, None)
            .expect("edit touching both invalid and valid leaves");
        assert!(outcome_both.changed);
        assert!(
            outcome_both.flush_required,
            "an edit touching both invalid and valid leaves must report flush_required=true"
        );
    }

    #[test]
    fn stage1_arena_exhaustion_fails_without_growth() {
        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let next_block = LINUX_MMAP_BASE + 600 * TWO_MIB;
        let err = mgr
            .set_rw(next_block + 0x1000, 0x1000, false, None)
            .unwrap_err();
        assert_eq!(err, PageTableError::OutOfTables);
    }

    #[test]
    fn adopting_live_extension_state_keeps_source_and_arenas() {
        use std::sync::{Arc, Mutex};

        let mut live = hvpatch_manager();
        exhaust_spare_pool(&mut live, LINUX_MMAP_BASE);
        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::new(Mutex::new(vec![ext_base])),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let image = live.snapshot_image().expect("snapshot live");

        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let va = LINUX_MMAP_BASE + 600 * TWO_MIB + 0x1000;
        live.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("grows into the extension arena");
        assert_eq!(live.arenas.len(), 2);

        let mut restored = image;
        restored.adopt_live_extension_state(&live);
        assert_eq!(restored.arenas.len(), 2);
        assert_eq!(restored.arenas[1].base, ext_base.0);
        assert_eq!(
            restored.arenas[1].next_free, PT_PAGE,
            "adopted arena starts empty"
        );
        assert_eq!(
            restored.translate(va),
            None,
            "pre-image tree does not see the live edit"
        );
        restored
            .set_rw(va, 0x1000, false, Some(&mut source))
            .expect("restored manager allocates");
        assert_eq!(restored.arenas.len(), 2);
    }

    #[test]
    fn growable_stage1_arena_exhaustion_uses_extension_source() {
        use std::sync::{Arc, Mutex};

        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let next_block = LINUX_MMAP_BASE + 600 * TWO_MIB;
        let va = next_block + 0x1000;
        assert_eq!(
            mgr.set_rw(va, 0x1000, false, None).unwrap_err(),
            PageTableError::OutOfTables
        );

        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let available = Arc::new(Mutex::new(vec![ext_base]));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        mgr.begin_undo().unwrap();
        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("mapping succeeds by allocating extension arena");
        assert_eq!(mgr.pool_stats().3, 2, "pool reports 2 arenas during tx");
        assert_eq!(
            mgr.translate(va),
            Some(va),
            "page in extension arena translated"
        );
        assert!(available.lock().unwrap().is_empty(), "source arena taken");

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let resolver = [
            (mgr.base(), host_arena0.as_mut_ptr()),
            (ext_base.0, host_arena1.as_mut_ptr()),
        ];
        unsafe { mgr.rollback_undo(&resolver[..], Some(&mut source)).unwrap() };
        assert_eq!(mgr.pool_stats().3, 1, "pool reports 1 arena after rollback");
        assert_eq!(
            returned.lock().unwrap().as_slice(),
            &[ext_base],
            "rolled back arena returned to source"
        );

        available.lock().unwrap().push(ext_base);
        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("mapping succeeds with extension arena");
        assert_eq!(mgr.pool_stats().3, 2, "pool reports 2 arenas");
        assert_eq!(
            mgr.translate(va),
            Some(va),
            "page in extension arena translated"
        );

        unsafe { mgr.sync_to_host(&resolver[..]).unwrap() };
        assert_ne!(
            host_arena0,
            vec![0u8; LINUX_PAGE_TABLES_SIZE as usize],
            "host arena 0 written"
        );
        assert_ne!(
            host_arena1,
            vec![0u8; LINUX_PAGE_TABLES_SIZE as usize],
            "host arena 1 written"
        );
    }

    #[test]
    fn sync_to_host_resolves_each_arena_once() {
        use core::cell::Cell;

        let mut mgr = hvpatch_manager();
        mgr.set_rw(LINUX_MMAP_BASE + 0x1000, 64 * 0x1000, true, None)
            .unwrap();
        assert_eq!(mgr.arenas.len(), 1);
        assert!(mgr.dirty.len() > 64);
        let mut host = vec![0u64; LINUX_PAGE_TABLES_SIZE as usize / 8];
        let ptr = host.as_mut_ptr().cast::<u8>();
        let calls = Cell::new(0);
        let expected: Vec<_> = mgr
            .dirty
            .iter()
            .map(|(loc, _)| {
                let word = mgr.read_desc(*loc).unwrap();
                (loc.offset / 8, word)
            })
            .collect();
        struct CountingResolver<'a> {
            calls: &'a Cell<usize>,
            ptr: *mut u8,
        }
        unsafe impl HostArenaResolver for CountingResolver<'_> {
            fn host_ptr_for_base(&self, _base: u64) -> Option<*mut u8> {
                self.calls.set(self.calls.get() + 1);
                Some(self.ptr)
            }
            fn publish_user_executable(
                &self,
                _output: u64,
                _len: u64,
            ) -> Result<(), PageTableError> {
                // VM-free test backing: no instruction cache to maintain.
                Ok(())
            }
        }
        unsafe {
            mgr.sync_to_host(CountingResolver { calls: &calls, ptr })
                .unwrap();
        }
        for (offset, word) in expected {
            assert_eq!(host[offset], word);
        }
        assert!(mgr.dirty.is_empty());
        assert_eq!(
            calls.get(),
            1,
            "resolve backing once per arena, not per descriptor"
        );
    }

    #[test]
    fn sync_to_host_errors_on_unresolved_arena() {
        use std::sync::{Arc, Mutex};

        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let next_block = LINUX_MMAP_BASE + 600 * TWO_MIB;
        let va = next_block + 0x1000;

        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let available = Arc::new(Mutex::new(vec![ext_base]));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("mapping succeeds with extension arena");
        assert_eq!(mgr.pool_stats().3, 2, "pool reports 2 arenas");

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let resolver = [(mgr.base(), host_arena0.as_mut_ptr())];
        let dirty_len = mgr.dirty.len();
        let res = unsafe { mgr.sync_to_host(&resolver[..]) };
        assert_eq!(res, Err(PageTableError::UnresolvedArena(ext_base.0)));
        assert!(
            host_arena0.iter().all(|&byte| byte == 0),
            "failed preflight must not publish descriptors"
        );
        assert_eq!(
            mgr.dirty.len(),
            dirty_len,
            "failed preflight preserves the edit for retry"
        );
        let mut host_arena1 = vec![0u64; LINUX_PAGE_TABLES_SIZE as usize / 8];
        let resolver = [
            (mgr.base(), host_arena0.as_mut_ptr()),
            (ext_base.0, host_arena1.as_mut_ptr().cast()),
        ];
        unsafe { mgr.sync_to_host(&resolver[..]).unwrap() };
        assert!(mgr.dirty.is_empty());
    }

    #[test]
    fn rollback_undo_returns_arena_when_resolver_missing_extension() {
        use std::sync::{Arc, Mutex};

        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let next_block = LINUX_MMAP_BASE + 600 * TWO_MIB;
        let va = next_block + 0x1000;

        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let available = Arc::new(Mutex::new(vec![ext_base]));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        mgr.begin_undo().unwrap();
        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("mapping succeeds with extension arena");
        assert_eq!(mgr.pool_stats().3, 2, "pool reports 2 arenas");

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        // Partial resolver missing extension arena must fail closed and preserve journal
        let partial_resolver = [(mgr.base(), host_arena0.as_mut_ptr())];
        let rollback_err = unsafe { mgr.rollback_undo(&partial_resolver[..], Some(&mut source)) };
        assert_eq!(
            rollback_err,
            Err(PageTableError::UnresolvedArena(ext_base.0)),
            "rollback_undo with missing extension arena must fail closed"
        );
        assert!(
            mgr.undo_is_open(),
            "journal must be preserved on rollback failure"
        );
        assert!(
            returned.lock().unwrap().is_empty(),
            "no arenas returned on failure"
        );
        assert_eq!(mgr.pool_stats().3, 2, "arenas preserved on failure");

        // Full resolver succeeds and pops extension arena
        let full_resolver = [
            (mgr.base(), host_arena0.as_mut_ptr()),
            (ext_base.0, host_arena1.as_mut_ptr()),
        ];
        let popped = unsafe {
            mgr.rollback_undo(&full_resolver[..], Some(&mut source))
                .unwrap()
        };
        assert_eq!(popped, vec![ext_base.0]);
        assert_eq!(returned.lock().unwrap().as_slice(), &[ext_base]);
        assert_eq!(mgr.pool_stats().3, 1, "pool reports 1 arena after rollback");
    }

    /// Contract `kernel.el1.grant-commit-revalidation`: revalidating an EL1
    /// grant's committed pages reads the live tables through the host
    /// resolver once per table arena, not once per page and level. The
    /// per-page walk resolved the arena at every level of every page (four
    /// index searches per page; a 256-page grant cost ~1k lookups), which the
    /// 2026-10-01 A/B measured at ~4% of carrier CPU on cpython and Node.
    #[test]
    fn debug_walk_host_pages_resolves_each_arena_once_however_many_pages() {
        let mut mgr = hvpatch_manager();
        const PAGES: u64 = 256;
        let va = LINUX_MMAP_BASE + 0x20_0000;
        mgr.set_rw(va, (PAGES * 0x1000) as usize, false, None)
            .expect("map the grant window");
        let mut host = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let full = [(mgr.base(), host.as_mut_ptr())];
        unsafe {
            mgr.restore_quiesced_snapshot_to_host(TestArenas(&full))
                .unwrap()
        };
        let lookups = core::cell::Cell::new(0_usize);
        let base = mgr.base();
        let host_ptr = host.as_ptr();
        let resolver = unsafe {
            crate::aarch64::const_resolver(|arena: u64| -> Option<*const u8> {
                lookups.set(lookups.get() + 1);
                (arena == base).then_some(host_ptr)
            })
        };
        let mut seen = 0_u64;
        unsafe {
            mgr.debug_walk_host_pages(
                resolver,
                (0..PAGES).map(|i| va + i * 0x1000),
                |page, walk| {
                    assert_eq!(walk, Ok(mgr.debug_walk(page)), "page 0x{page:x}");
                    seen += 1;
                },
            );
        }
        assert_eq!(seen, PAGES);
        assert_eq!(lookups.get(), 1, "one resolution of the one table arena");
    }

    /// The batched walk is the per-page walk: same descriptors at every
    /// level, including pages that cross into another L3 table and pages
    /// whose walk stops at an invalid upper level.
    /// A sole-owner COW write reuses the frame in place by granting write on
    /// the fork-armed leaf. The grant changes AP only: an executable page
    /// stays executable (mprotectexec `exec_mmap_fetch_allowed`) and a
    /// non-executable one stays NX, exactly as the copy path's repoint does.
    #[test]
    fn a_fork_armed_leaf_granted_write_in_place_keeps_its_execute_permission() {
        for exec in [true, false] {
            let mut mgr = hvpatch_manager();
            let va = LINUX_MMAP_BASE + 0x4000;
            mgr.set_rw(va, 0x4000, exec, None)
                .expect("map the private compound");
            mgr.set_fork_readonly(va, 0x4000, None).expect("fork arm");
            let armed = mgr.debug_walk(va)[3];
            assert_eq!(armed & AP_MASK, AP_RO, "exec={exec}: armed read-only");
            assert_eq!(armed & UXN == 0, exec, "exec={exec}: arming keeps UXN");
            mgr.set_writable_preserving_attributes(va, 0x4000, None)
                .expect("grant write in place");
            for page in (va..va + 0x4000).step_by(0x1000) {
                let leaf = mgr.debug_walk(page)[3];
                assert_eq!(leaf & AP_MASK, AP_RW, "exec={exec} page {page:#x}");
                assert_eq!(
                    leaf & UXN == 0,
                    exec,
                    "exec={exec} page {page:#x}: UXN changed"
                );
            }
        }
    }

    #[test]
    fn debug_walk_host_pages_matches_the_per_page_walk() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut mgr = hvpatch_manager();
        let boundary = LINUX_MMAP_BASE + 3 * TWO_MIB;
        mgr.set_rw(boundary - 0x4000, 0x8000, false, None)
            .expect("map across an L3 boundary");
        let mut host = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let full = [(mgr.base(), host.as_mut_ptr())];
        unsafe {
            mgr.restore_quiesced_snapshot_to_host(TestArenas(&full))
                .unwrap()
        };
        let base = mgr.base();
        let host_ptr = host.as_ptr();
        let resolver = || unsafe {
            crate::aarch64::const_resolver(move |arena: u64| -> Option<*const u8> {
                (arena == base).then_some(host_ptr)
            })
        };
        let pages = [
            boundary - 0x4000,
            boundary - 0x1000,
            boundary,
            boundary + 0x3000,
            boundary + 0x10_0000,
            LINUX_MMAP_BASE + 40 * TWO_MIB,
            0x1000,
        ];
        let mut batched = Vec::new();
        unsafe {
            mgr.debug_walk_host_pages(resolver(), pages, |page, walk| batched.push((page, walk)));
        }
        let single: Vec<_> = pages
            .iter()
            .map(|&page| (page, unsafe { mgr.debug_walk_host(resolver(), page) }))
            .collect();
        assert_eq!(batched, single);
    }

    #[test]
    fn debug_walk_host_errors_on_unresolved_arena() {
        use std::sync::{Arc, Mutex};

        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let next_block = LINUX_MMAP_BASE + 600 * TWO_MIB;
        let va = next_block + 0x1000;

        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let available = Arc::new(Mutex::new(vec![ext_base]));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("mapping succeeds with extension arena");

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let full_resolver = [
            (mgr.base(), host_arena0.as_mut_ptr()),
            (ext_base.0, host_arena1.as_mut_ptr()),
        ];
        unsafe {
            mgr.restore_quiesced_snapshot_to_host(TestArenas(&full_resolver[..]))
                .unwrap();
        };

        let partial_resolver = unsafe {
            crate::aarch64::const_resolver(|base: u64| -> Option<*const u8> {
                if base == mgr.base() {
                    Some(host_arena0.as_ptr())
                } else {
                    None
                }
            })
        };
        let res = unsafe { mgr.debug_walk_host(partial_resolver, va) };
        assert_eq!(res, Err(PageTableError::UnresolvedArena(ext_base.0)));

        let good_resolver = unsafe {
            crate::aarch64::const_resolver(|base: u64| -> Option<*const u8> {
                if base == mgr.base() {
                    Some(host_arena0.as_ptr())
                } else if base == ext_base.0 {
                    Some(host_arena1.as_ptr())
                } else {
                    None
                }
            })
        };
        let walk = unsafe { mgr.debug_walk_host(good_resolver, va).unwrap() };
        assert_eq!(walk, mgr.debug_walk(va));
    }

    #[test]
    fn clone_with_extension_arenas_requires_child_source_for_rebase() {
        use std::sync::{Arc, Mutex};

        let mut parent = hvpatch_manager();
        exhaust_spare_pool(&mut parent, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let ext1_base = SubstrateGpa(0xb0_0000_0000);
        let ext2_base = SubstrateGpa(0xc0_0000_0000);

        let parent_available = Arc::new(Mutex::new(vec![ext2_base, ext1_base]));
        let parent_returned = Arc::new(Mutex::new(Vec::new()));
        let mut parent_source = TestArenaSource {
            id: TableArenaSourceId(ext1_base),
            available: Arc::clone(&parent_available),
            returned: Arc::clone(&parent_returned),
        };

        let va1 = LINUX_MMAP_BASE + 600 * TWO_MIB + 0x1000;
        parent
            .set_rw(va1, 0x1000, false, Some(&mut parent_source))
            .expect("allocates first extension arena");
        assert_eq!(parent.pool_stats().3, 2, "parent has 2 arenas");

        let mut child2 = parent.snapshot_image().expect("snapshot child2");
        let child_root = 0x50_0000_0000;
        assert_eq!(
            child2.rebase(child_root, None).unwrap_err(),
            PageTableError::MissingArenaSource,
            "rebase without source fails with MissingArenaSource"
        );

        parent.arenas.push(TableArena {
            snapshot_scratch: Vec::new(),
            base: ext2_base.0,
            storage: TableArenaStorage::Owned(vec![0u8; SPARE_START_OFFSET as usize]),
            next_free: SPARE_START_OFFSET,
            capacity: LINUX_PAGE_TABLES_SIZE as usize,
        });
        assert_eq!(parent.pool_stats().3, 3, "parent has 3 arenas");

        let mut child = parent.snapshot_image().expect("snapshot child");

        assert_eq!(
            child.rebase(child_root, None).unwrap_err(),
            PageTableError::MissingArenaSource,
            "rebasing 3-arena manager without source returns MissingArenaSource"
        );

        let child_ext1 = SubstrateGpa(0xd0_0000_0000);
        let child_ext2 = SubstrateGpa(0xe0_0000_0000);
        let child_available = Arc::new(Mutex::new(vec![child_ext2, child_ext1]));
        let child_returned = Arc::new(Mutex::new(Vec::new()));
        let mut child_source = TestArenaSource {
            id: TableArenaSourceId(child_ext1),
            available: Arc::clone(&child_available),
            returned: Arc::clone(&child_returned),
        };

        let parent_avail_count_before = parent_available.lock().unwrap().len();

        child
            .rebase(child_root, Some(&mut child_source))
            .expect("rebase succeeds with child source");

        assert_eq!(
            child_available.lock().unwrap().len(),
            0,
            "child took two fresh slots from child source"
        );
        assert_eq!(
            parent_available.lock().unwrap().len(),
            parent_avail_count_before,
            "parent source was untouched by child rebase"
        );
        assert_eq!(child.pool_stats().3, 3, "child preserves 3 arenas");
        assert_eq!(child.base(), child_root, "child rebased root");
        assert_eq!(child.arenas[1].base, child_ext1.0, "child rebased arena 1");
        assert_eq!(child.arenas[2].base, child_ext2.0, "child rebased arena 2");
    }

    #[test]
    fn large_vma_unmap_work_is_hierarchically_bounded_empty_and_populated_islands() {
        let mut mgr = hvpatch_manager();
        let size_16t = 16u64 << 40;
        let base = LINUX_HIGH_VA_THRESHOLD;

        let (outcome, steps_empty) = mgr
            .unmap_aliased_counting(base, size_16t as usize, None)
            .expect("unmap empty 16 TiB");
        assert!(!outcome.changed);
        assert_eq!(
            steps_empty, 32,
            "empty 16 TiB traverses exactly 32 L0 slots"
        );

        let island_offsets = [
            0,
            (size_16t / 2 / (2 * 1024 * 1024)) * (2 * 1024 * 1024),
            size_16t - 2 * 1024 * 1024,
        ];
        let ipa_base = 0x80_0000;
        for (i, &offset) in island_offsets.iter().enumerate() {
            let va = base + offset;
            let ipa = ipa_base + (i as u64) * 0x20_0000;
            mgr.map_aliased(va, ipa, 2 * 1024 * 1024, RWX, None)
                .expect("map island");
            assert!(mgr.is_valid(va), "island at {va:#x} must be valid");
        }

        let (outcome_populated, steps_populated) = mgr
            .unmap_aliased_counting(base, size_16t as usize, None)
            .expect("unmap populated 16 TiB");
        assert!(
            outcome_populated.changed,
            "populated islands must be reclaimed"
        );

        for &offset in &island_offsets {
            let va = base + offset;
            assert!(!mgr.is_valid(va), "island at {va:#x} must be invalidated");
        }

        assert!(
            steps_populated < 5000,
            "16 TiB reclaim steps must be hierarchically bounded: {steps_populated} < 5000 (old linear sweep = 8,388,608)"
        );
    }

    #[test]
    fn test_el1_stack_walk_after_rebase() {
        let bytes = stage1_hvpatch_page_tables();
        let mut mgr = PageTableManager::new(bytes, LINUX_PAGE_TABLES_BASE, test_layout());
        let stack_va = 0x2d04213ee0;
        let leaf_before = terminal_descriptor(mgr.debug_walk(stack_va));

        let child_root = 0x9a_0000_0000;
        mgr.rebase(child_root, None).expect("rebase");
        let leaf_after = terminal_descriptor(mgr.debug_walk(stack_va));
        assert_eq!(leaf_before & VALID, 1);
        assert_eq!(leaf_after & VALID, 1);
        assert_eq!(leaf_after & AP_MASK, leaf_before & AP_MASK);
    }

    struct MockLiveResolver {
        arenas: std::sync::Mutex<hashbrown::HashMap<u64, Vec<u8>>>,
        populated: std::sync::Mutex<hashbrown::HashMap<u64, usize>>,
    }

    impl MockLiveResolver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                arenas: std::sync::Mutex::new(hashbrown::HashMap::new()),
                populated: std::sync::Mutex::new(hashbrown::HashMap::new()),
            })
        }

        fn register_arena(&self, base: u64, size: usize) {
            let mut arenas = self.arenas.lock().unwrap();
            arenas.insert(base, vec![0u8; size]);
        }

        fn write_word(&self, base: u64, offset: usize, value: u64) {
            let mut arenas = self.arenas.lock().unwrap();
            let buf = arenas.get_mut(&base).expect("arena must exist");
            buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        fn read_word(&self, base: u64, offset: usize) -> u64 {
            let arenas = self.arenas.lock().unwrap();
            let buf = arenas.get(&base).expect("arena must exist");
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[offset..offset + 8]);
            u64::from_le_bytes(bytes)
        }
    }

    unsafe impl HostArenaResolver for MockLiveResolver {
        fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
            let mut arenas = self.arenas.lock().unwrap();
            let buf = arenas.get_mut(&base)?;
            if len > buf.len() {
                return None;
            }
            Some(buf.as_mut_ptr())
        }

        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            self.host_ptr_for_range(base, 0)
        }

        fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
            let arenas = self.arenas.lock().unwrap();
            let buf = arenas.get(&base)?;
            if len > buf.len() {
                return None;
            }
            Some(buf.as_ptr())
        }

        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            self.host_const_ptr_for_range(base, 0)
        }

        fn record_populated_prefix(&self, base: u64, prefix_len: usize) {
            self.populated.lock().unwrap().insert(base, prefix_len);
        }
        fn publish_user_executable(&self, _output: u64, _len: u64) -> Result<(), PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    unsafe impl HostArenaResolver for &MockLiveResolver {
        fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
            (*self).host_ptr_for_range(base, len)
        }

        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (*self).host_ptr_for_base(base)
        }

        fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
            (*self).host_const_ptr_for_range(base, len)
        }

        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            (*self).host_const_ptr_for_base(base)
        }

        fn record_populated_prefix(&self, base: u64, prefix_len: usize) {
            (*self).record_populated_prefix(base, prefix_len);
        }
        fn publish_user_executable(&self, _output: u64, _len: u64) -> Result<(), PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    #[test]
    fn owned_host_image_reuse_clears_live_descriptors_written_by_an_el1_editor() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;

        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let retired = LINUX_MMAP_BASE + 2 * TWO_MIB;
        let target = LINUX_MMAP_BASE + 3 * TWO_MIB;
        let sentinel = LINUX_MMAP_BASE + 4 * TWO_MIB;
        let old_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let target_ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
        let mut host = hvpatch_manager();
        host.map_private_aliased(retired, old_ipa, 0x4000, RWX, None)
            .expect("map table that will retire");
        host.map_private_aliased(sentinel, old_ipa + TWO_MIB, 0x1000, RWX, None)
            .expect("keep the shared L2 table live");
        let reclaimed_l3 = host.debug_walk(retired)[2] & PA_MASK_TABLE;
        let stale_leaf = terminal_descriptor(host.debug_walk(retired));
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
        }

        host.unmap_aliased(retired, 0x4000, None)
            .expect("retire and reclaim the old L3");
        unsafe { host.sync_to_host(&*resolver).expect("publish retirement") };
        assert_eq!(
            host.free_tables.last().copied(),
            Some(reclaimed_l3),
            "the retired L3 must be next for reuse"
        );

        // EL1 and the host deliberately share the live table backing. Model a
        // guest editor writing after the host cached this page as free. A later
        // partial host publication must not expose that stale descriptor at an
        // untouched neighbour.
        let reclaimed_offset =
            usize::try_from(reclaimed_l3 - LINUX_PAGE_TABLES_BASE).expect("reclaimed table offset");
        resolver.write_word(
            LINUX_PAGE_TABLES_BASE,
            reclaimed_offset + 8 * core::mem::size_of::<u64>(),
            stale_leaf,
        );

        host.map_private_aliased(target, target_ipa, 0x4000, RWX, None)
            .expect("partially populate the reused L3");
        unsafe {
            host.sync_to_host(&*resolver)
                .expect("publish partial reuse")
        };

        let observer = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("observe live reused table")
        };
        assert_eq!(
            observer.translate(target + 8 * PT_PAGE),
            None,
            "allocating a live free-list page must clear descriptors written after retirement"
        );
    }

    #[test]
    fn live_leaf_revoke_and_repoint_is_observed_by_host_translation_and_snapshot() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        let va = 0x50_0000;
        let ipa = 0x80_0000;
        mgr.map_aliased(va, ipa, 0x1000, RX, None).expect("map");
        unsafe { mgr.restore_quiesced_snapshot_to_host(&*resolver).unwrap() };

        unsafe { mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>) };
        assert!(mgr.is_live());
        assert_eq!(mgr.translate(va), Some(ipa));

        let snap = mgr.snapshot_image().expect("snapshot");
        assert_eq!(snap.translate(va), Some(ipa));

        // Walk to find the leaf descriptor's offset in the primary arena
        let walk = mgr.debug_walk(va);
        let leaf_desc = walk[3];
        assert_ne!(leaf_desc & VALID, 0);

        // Find the leaf entry offset in arena 0
        let mut leaf_offset = None;
        for offset in (0..mgr.arenas[0].allocated_span() as usize).step_by(8) {
            if resolver.read_word(LINUX_PAGE_TABLES_BASE, offset) == leaf_desc {
                leaf_offset = Some(offset);
                break;
            }
        }
        let leaf_offset = leaf_offset.expect("leaf entry must exist in hardware arena");

        // Simulate guest revoking the leaf descriptor in hardware
        resolver.write_word(LINUX_PAGE_TABLES_BASE, leaf_offset, 0);

        // Host translation and snapshot must observe the revocation immediately
        assert_eq!(
            mgr.translate(va),
            None,
            "live translation must observe revocation"
        );
        assert_eq!(
            mgr.snapshot_image().expect("snapshot").translate(va),
            None,
            "live snapshot must observe revocation"
        );

        // Simulate guest repointing the leaf descriptor to a new IPA
        let new_ipa = 0x90_0000;
        let new_desc = (leaf_desc & !PA_MASK_TABLE) | (new_ipa & PA_MASK_TABLE);
        resolver.write_word(LINUX_PAGE_TABLES_BASE, leaf_offset, new_desc);

        // Host translation and snapshot must observe the repointed IPA
        assert_eq!(mgr.translate(va), Some(new_ipa));
        assert_eq!(
            mgr.snapshot_image().expect("snapshot").translate(va),
            Some(new_ipa)
        );
    }

    #[test]
    fn live_host_permission_edit_preserves_independently_updated_output() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        let va = 0x50_0000;
        let ipa = 0x80_0000;
        mgr.map_aliased(va, ipa, 0x1000, RX, None).expect("map");
        unsafe { mgr.restore_quiesced_snapshot_to_host(&*resolver).unwrap() };

        unsafe { mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>) };

        let walk = mgr.debug_walk(va);
        let leaf_desc = walk[3];
        let mut leaf_offset = None;
        for offset in (0..mgr.arenas[0].allocated_span() as usize).step_by(8) {
            if resolver.read_word(LINUX_PAGE_TABLES_BASE, offset) == leaf_desc {
                leaf_offset = Some(offset);
                break;
            }
        }
        let leaf_offset = leaf_offset.expect("leaf offset");

        // Guest independently repoints the leaf in hardware before host permission edit
        let updated_ipa = 0x88_0000;
        let updated_desc = (leaf_desc & !PA_MASK_TABLE) | (updated_ipa & PA_MASK_TABLE);
        resolver.write_word(LINUX_PAGE_TABLES_BASE, leaf_offset, updated_desc);

        // Host edits permission to readonly
        mgr.set_readonly(va, 0x1000, false, None)
            .expect("set readonly");
        unsafe { mgr.sync_to_host(&*resolver).expect("sync readonly") };

        // Output IPA should be updated_ipa and permission should be RO (AP_RO = 1 << 7)
        let hw_desc = resolver.read_word(LINUX_PAGE_TABLES_BASE, leaf_offset);
        assert_eq!(hw_desc & PA_MASK_TABLE, updated_ipa);
        assert_eq!(hw_desc & (1 << 7), 1 << 7, "AP must be RO");
        assert_eq!(mgr.translate(va), Some(updated_ipa));
    }

    #[test]
    fn live_rollback_undo_restores_preimage_without_resurrecting_stale_bytes() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        let va = 0x50_0000;
        let ipa_a = 0x80_0000;
        mgr.map_aliased(va, ipa_a, 0x1000, RX, None).expect("map");
        unsafe { mgr.restore_quiesced_snapshot_to_host(&*resolver).unwrap() };

        unsafe { mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>) };
        assert_eq!(mgr.translate(va), Some(ipa_a));

        // Begin transaction
        mgr.begin_undo().unwrap();

        // Mutate to ipa_b
        let ipa_b = 0x90_0000;
        mgr.map_aliased(va, ipa_b, 0x1000, RX, None)
            .expect("remap to B");
        assert_eq!(
            mgr.translate(va),
            Some(ipa_b),
            "staged write visible in transaction"
        );

        // Rollback
        unsafe { mgr.rollback_undo(&*resolver, None).unwrap() };
        assert_eq!(mgr.translate(va), Some(ipa_a), "restores preimage A");
        assert_eq!(
            mgr.snapshot_image().expect("snapshot").translate(va),
            Some(ipa_a)
        );
    }

    #[test]
    fn two_live_roots_using_identical_vas_stay_distinct() {
        let root1_base = 0x9a00_0000;
        let root2_base = 0x9b00_0000;
        let resolver = MockLiveResolver::new();
        resolver.register_arena(root1_base, LINUX_PAGE_TABLES_SIZE as usize);
        resolver.register_arena(root2_base, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr1 = hvpatch_manager();
        mgr1.rebase(root1_base, None).expect("rebase 1");
        let mut mgr2 = hvpatch_manager();
        mgr2.rebase(root2_base, None).expect("rebase 2");

        let va = 0x40_0000;
        let ipa1 = 0x1000;
        let ipa2 = 0x2000;

        mgr1.map_aliased(va, ipa1, 0x1000, RX, None).expect("map 1");
        mgr2.map_aliased(va, ipa2, 0x1000, RX, None).expect("map 2");

        unsafe {
            mgr1.restore_quiesced_snapshot_to_host(&*resolver).unwrap();
            mgr2.restore_quiesced_snapshot_to_host(&*resolver).unwrap();
        }

        unsafe {
            mgr1.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
            mgr2.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }

        assert_eq!(mgr1.translate(va), Some(ipa1));
        assert_eq!(mgr2.translate(va), Some(ipa2));

        let snap1 = mgr1.snapshot_image().expect("snap1");
        let snap2 = mgr2.snapshot_image().expect("snap2");
        assert_eq!(snap1.translate(va), Some(ipa1));
        assert_eq!(snap2.translate(va), Some(ipa2));
    }

    #[test]
    fn failed_resolution_errors_on_translate_debug_walk_and_snapshot() {
        let resolver = MockLiveResolver::new();
        // Do NOT register LINUX_PAGE_TABLES_BASE arena -> resolution fails

        let mut mgr = hvpatch_manager();
        unsafe {
            mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }

        let va = 0x50_0000;
        assert_eq!(
            mgr.try_translate(va),
            Err(PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE))
        );
        assert_eq!(
            mgr.try_debug_walk(va),
            Err(PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE))
        );
        assert_eq!(
            mgr.snapshot_image().unwrap_err(),
            PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)
        );
        let mut target = hvpatch_manager();
        assert_eq!(
            mgr.snapshot_into(&mut target).unwrap_err(),
            PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)
        );
        assert_eq!(
            mgr.into_bytes().unwrap_err(),
            PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)
        );
    }

    #[test]
    fn live_atomic_snapshot_observes_concurrent_leaf_mutations_without_stale_shadow() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        let va = 0x60_0000;
        let ipa = 0x70_0000;
        mgr.map_aliased(va, ipa, 0x1000, RX, None).expect("map");
        unsafe { mgr.restore_quiesced_snapshot_to_host(&*resolver).unwrap() };
        unsafe { mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>) };

        let walk = mgr.debug_walk(va);
        let leaf_desc = walk[3];
        let mut leaf_offset = None;
        for offset in (0..mgr.arenas[0].allocated_span() as usize).step_by(8) {
            if resolver.read_word(LINUX_PAGE_TABLES_BASE, offset) == leaf_desc {
                leaf_offset = Some(offset);
                break;
            }
        }
        let leaf_offset = leaf_offset.expect("leaf offset");

        // Concurrent atomic update in guest hardware backing
        let new_ipa = 0x75_0000;
        let new_desc = (leaf_desc & !PA_MASK_TABLE) | (new_ipa & PA_MASK_TABLE);
        resolver.write_word(LINUX_PAGE_TABLES_BASE, leaf_offset, new_desc);

        // Snapshot into existing target
        let mut snap_target = hvpatch_manager();
        mgr.snapshot_into(&mut snap_target).expect("snapshot_into");
        assert_eq!(snap_target.translate(va), Some(new_ipa));
    }

    #[test]
    fn live_bound_restore_image_writes_descriptors_to_hardware_memory() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut mgr = hvpatch_manager();
        let va = 0x50_0000;
        let ipa = 0x80_0000;
        mgr.map_aliased(va, ipa, 0x1000, RX, None).expect("map");

        // Snapshot image
        let snap = mgr.snapshot_image().expect("snapshot");

        // Overwrite resolver memory with garbage
        let garbage = vec![0xcc; LINUX_PAGE_TABLES_SIZE as usize];
        resolver
            .arenas
            .lock()
            .unwrap()
            .insert(LINUX_PAGE_TABLES_BASE, garbage);

        // Restore snapshot to host
        unsafe { snap.restore_quiesced_snapshot_to_host(&*resolver).unwrap() };

        // Verify host memory matches snapshot
        let host_bytes = resolver
            .arenas
            .lock()
            .unwrap()
            .get(&LINUX_PAGE_TABLES_BASE)
            .unwrap()
            .clone();
        assert_eq!(&host_bytes[..snap.as_bytes().len()], snap.as_bytes());
    }

    #[test]
    fn snapshot_failure_must_not_clone_live_authority() {
        let resolver = MockLiveResolver::new();
        // Do not register backing for LINUX_PAGE_TABLES_BASE
        let mut mgr = hvpatch_manager();
        unsafe {
            mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        assert!(mgr.is_live());
        assert_eq!(
            mgr.snapshot_image().unwrap_err(),
            PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)
        );

        let mut target = hvpatch_manager();
        assert_eq!(
            mgr.snapshot_into(&mut target).unwrap_err(),
            PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)
        );

        // When backing is available, snapshot_image produces an Owned offline snapshot
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        let clone = mgr.snapshot_image().expect("snapshot image");
        assert!(
            !clone.is_live(),
            "cloned snapshot from live manager must NOT be live"
        );
    }

    #[test]
    fn restore_quiesced_snapshot_to_host_fails_and_preserves_on_missing_root_or_extension() {
        use std::sync::{Arc, Mutex};

        let mut mgr = hvpatch_manager();
        exhaust_spare_pool(&mut mgr, LINUX_MMAP_BASE);
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let ext_base = SubstrateGpa(0xb0_0000_0000);
        let mut source = TestArenaSource {
            id: TableArenaSourceId(ext_base),
            available: Arc::new(Mutex::new(vec![ext_base])),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let va = LINUX_MMAP_BASE + 600 * TWO_MIB + 0x1000;
        mgr.set_rw(va, 0x1000, false, Some(&mut source))
            .expect("grows into extension arena");
        assert_eq!(mgr.arenas.len(), 2);

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];

        // 1. Missing root arena fails closed
        let missing_root = [(ext_base.0, host_arena1.as_mut_ptr())];
        let err_root = unsafe { mgr.restore_quiesced_snapshot_to_host(&missing_root[..]) };
        assert_eq!(
            err_root,
            Err(PageTableError::UnresolvedArena(mgr.base())),
            "missing root arena must fail closed"
        );

        // 2. Missing extension arena fails closed
        let missing_ext = [(mgr.base(), host_arena0.as_mut_ptr())];
        let err_ext = unsafe { mgr.restore_quiesced_snapshot_to_host(&missing_ext[..]) };
        assert_eq!(
            err_ext,
            Err(PageTableError::UnresolvedArena(ext_base.0)),
            "missing extension arena must fail closed"
        );

        assert!(
            host_arena0.iter().all(|byte| *byte == 0),
            "missing extension must not partially overwrite the root backing"
        );
        assert!(host_arena1.iter().all(|byte| *byte == 0));

        // 3. Complete resolver succeeds
        let full = [
            (mgr.base(), host_arena0.as_mut_ptr()),
            (ext_base.0, host_arena1.as_mut_ptr()),
        ];
        assert!(unsafe { mgr.restore_quiesced_snapshot_to_host(TestArenas(&full[..])) }.is_ok());
    }

    #[test]
    fn short_backing_and_nonzero_offset_range_safety_without_ub() {
        let resolver = MockLiveResolver::new();
        // Provide only 4096 bytes of backing (short backing)
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, 4096);

        // new_live with primary capacity 65536 > 4096 must fail safely
        let new_res = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                65536,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
        };
        assert_eq!(
            new_res.err(),
            Some(PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)),
            "new_live with capacity exceeding short backing must fail"
        );

        // make_live on an existing manager attaches the short resolver
        let mut mgr = hvpatch_manager();
        unsafe {
            mgr.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }

        // Reading at offset 0 (0..8 <= 4096) resolves
        let loc0 = TableLocation::new(0, 0);
        assert!(mgr.read_desc(loc0).is_ok());

        // Reading at nonzero offset within 4096 (e.g. 2048..2056 <= 4096) resolves
        let loc2048 = TableLocation::new(0, 2048);
        assert!(mgr.read_desc(loc2048).is_ok());

        // Reading at offset 4096 (4096..4104 > 4096) fails closed without UB
        let loc4096 = TableLocation::new(0, 4096);
        assert_eq!(
            mgr.read_desc(loc4096).err(),
            Some(PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)),
            "read_desc at offset exceeding short backing must fail closed"
        );

        // Snapshot requests prefix_len (e.g. 65536 > 4096) and fails safely
        assert_eq!(
            mgr.snapshot_image().err(),
            Some(PageTableError::UnresolvedArena(LINUX_PAGE_TABLES_BASE)),
            "snapshot_image on short backing must fail closed"
        );
    }

    #[test]
    fn new_live_discovers_the_last_occupied_spare_page_before_allocating() {
        let resolver = MockLiveResolver::new();
        let capacity = SPARE_START_OFFSET as usize + 8 * PT_PAGE as usize;
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, capacity);
        let occupied_page = SPARE_START_OFFSET + 3 * PT_PAGE;
        resolver.write_word(LINUX_PAGE_TABLES_BASE, occupied_page as usize, VALID);

        let mut manager = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                capacity,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("bind live page-table backing")
        };
        let expected_next = occupied_page + PT_PAGE;
        assert_eq!(
            manager.arenas[0].next_free, expected_next,
            "live construction must not reissue a table page already visible to hardware"
        );
        assert_eq!(
            manager.alloc_table(None).unwrap(),
            LINUX_PAGE_TABLES_BASE + expected_next,
            "the first allocation follows the last occupied live spare page"
        );
    }

    #[test]
    fn guest_leaf_publication_validates_the_whole_span_before_exposing_it() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x9000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[1024 + indexes[2]].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l3 = 1536 + indexes[3];
        words[l3 + 2].store(USER_PAGE_FLAGS | NON_GLOBAL, Ordering::Relaxed);

        let result = unsafe {
            publish_existing_invalid_private_pages(
                words.as_mut_ptr(),
                root,
                words.len() * core::mem::size_of::<AtomicU64>(),
                GuestLeafPublication {
                    va,
                    ipa,
                    len: 3 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
            )
        };
        assert_eq!(result, Err(GuestLeafPublicationError::AlreadyValid));
        assert_eq!(words[l3].load(Ordering::Relaxed), 0);
        assert_eq!(words[l3 + 1].load(Ordering::Relaxed), 0);

        words[l3 + 2].store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe {
                publish_existing_invalid_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    GuestLeafPublication {
                        va,
                        ipa,
                        len: 3 * PT_PAGE,
                        writable: true,
                        executable: false,
                    },
                )
            },
            Ok(3)
        );
        for page in 0..3 {
            let descriptor = words[l3 + page].load(Ordering::Acquire);
            assert_eq!(descriptor & PA_MASK_4KIB, ipa + page as u64 * PT_PAGE);
            assert!(terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Read
            ));
            assert!(terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Write
            ));
            assert!(!terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Execute
            ));
            assert_ne!(descriptor & NON_GLOBAL, 0);
        }
    }

    #[test]
    fn host_protection_retags_private_write_intent_and_fork_preserves_it() {
        let mut mgr = manager();
        let va = 0x4000_0000;
        mgr.set_rw(va, PT_PAGE as usize, true, None).unwrap();
        let (off, _) = mgr.leaf_offset(va, false, None).unwrap();
        let initial = mgr.read_desc(off).unwrap() | SW_EL1_PRIVATE;
        mgr.write_desc(off, initial).unwrap();
        // Even an already-RW hardware leaf needs its software intent updated.
        mgr.set_rw(va, PT_PAGE as usize, true, None).unwrap();
        let writable = terminal_descriptor(mgr.debug_walk(va));
        assert!(terminal_descriptor_may_write(writable));
        assert_ne!(writable & SW_EL1_MAY_EXEC, 0);
        mgr.set_fork_readonly(va, PT_PAGE as usize, None).unwrap();
        let cow = terminal_descriptor(mgr.debug_walk(va));
        assert!(terminal_descriptor_may_write(cow));
        assert!(terminal_descriptor_permits_host_buffer(
            cow,
            LeafAccess::Write
        ));
        assert!(!terminal_descriptor_permits_el0(cow, LeafAccess::Write));
        mgr.set_readonly(va, PT_PAGE as usize, false, None).unwrap();
        let readonly = terminal_descriptor(mgr.debug_walk(va));
        assert!(!terminal_descriptor_permits_host_buffer(
            readonly,
            LeafAccess::Write
        ));
        assert!(!el1_cow(readonly));
        mgr.set_rw(va, PT_PAGE as usize, false, None).unwrap();
        assert!(terminal_descriptor_may_write(terminal_descriptor(
            mgr.debug_walk(va)
        )));
    }

    #[test]
    fn allocation_free_guest_permission_edit_cycles_existing_l3_leaves() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[1024 + indexes[2]].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l3 = 1536 + indexes[3];
        unsafe {
            publish_existing_invalid_private_pages(
                words.as_mut_ptr(),
                root,
                words.len() * core::mem::size_of::<AtomicU64>(),
                GuestLeafPublication {
                    va,
                    ipa,
                    len: 2 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
            )
        }
        .expect("publish tagged leaves");

        for (readable, writable) in [(true, false), (false, false), (true, true)] {
            unsafe {
                protect_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    GuestPermissionEdit {
                        va,
                        len: 2 * PT_PAGE,
                        readable,
                        writable,
                        executable: false,
                    },
                )
            }
            .expect("permission transition");
            for page in 0..2 {
                let descriptor = words[l3 + page].load(Ordering::Acquire);
                assert!(
                    terminal_descriptor_permits_host_buffer(descriptor, LeafAccess::Write)
                        == writable,
                    "host copyout must follow current EL1 permissions"
                );
                assert_eq!(descriptor & PA_MASK_4KIB, ipa + page as u64 * PT_PAGE);
                assert_eq!(
                    terminal_descriptor_permits_el0(descriptor, LeafAccess::Read),
                    readable || writable
                );
                assert_eq!(
                    terminal_descriptor_permits_el0(descriptor, LeafAccess::Write),
                    writable
                );
                assert!(!terminal_descriptor_permits_el0(
                    descriptor,
                    LeafAccess::Execute
                ));
            }
        }

        let before = words[l3].load(Ordering::Acquire);
        assert_eq!(
            unsafe {
                protect_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    GuestPermissionEdit {
                        va,
                        len: 2 * PT_PAGE,
                        readable: true,
                        writable: true,
                        executable: true,
                    },
                )
            },
            Err(GuestPermissionEditError::PermissionWidening)
        );
        assert_eq!(words[l3].load(Ordering::Acquire), before);
    }

    #[test]
    fn allocation_free_guest_permission_edit_updates_complete_l2_block() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(3 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l2 = 1024 + indexes[2];
        let block = (ipa & PA_MASK_2MIB)
            | USER_BLOCK_FLAGS
            | NON_GLOBAL
            | UXN
            | SW_EL1_PRIVATE
            | SW_EL1_MAY_WRITE;
        let adjacent = ((ipa + (1 << 21)) & PA_MASK_2MIB)
            | USER_BLOCK_FLAGS
            | NON_GLOBAL
            | UXN
            | SW_EL1_PRIVATE
            | SW_EL1_MAY_WRITE;
        words[l2].store(block, Ordering::Relaxed);
        words[l2 + 1].store(adjacent, Ordering::Relaxed);

        assert_eq!(
            unsafe {
                protect_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    GuestPermissionEdit {
                        va,
                        len: 1 << 21,
                        readable: true,
                        writable: false,
                        executable: false,
                    },
                )
            },
            Ok(512)
        );
        let protected = words[l2].load(Ordering::Acquire);
        assert_eq!(protected & PA_MASK_2MIB, ipa & PA_MASK_2MIB);
        assert_eq!(protected & TYPE_BITS, TYPE_BLOCK);
        assert!(terminal_descriptor_permits_el0(protected, LeafAccess::Read));
        assert!(!terminal_descriptor_permits_el0(
            protected,
            LeafAccess::Write
        ));
        assert_eq!(words[l2 + 1].load(Ordering::Acquire), adjacent);

        let before = words[l2].load(Ordering::Acquire);
        assert_eq!(
            unsafe {
                protect_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    GuestPermissionEdit {
                        va: va + PT_PAGE,
                        len: PT_PAGE,
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                )
            },
            Err(GuestPermissionEditError::NotPrivateAnonymous)
        );
        assert_eq!(words[l2].load(Ordering::Acquire), before);
    }

    #[test]
    fn allocation_free_guest_retirement_retires_complete_l2_and_l3_terminals() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l2 = 1024 + indexes[2];
        let block = (ipa & PA_MASK_2MIB)
            | USER_BLOCK_FLAGS
            | NON_GLOBAL
            | UXN
            | SW_EL1_PRIVATE
            | SW_EL1_MAY_WRITE;
        words[l2].store(block, Ordering::Relaxed);

        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    va,
                    1 << 21,
                )
            },
            Ok(512)
        );
        let retired_block = words[l2].load(Ordering::Acquire);
        assert_eq!(retired_block & VALID, 0);
        assert_ne!(retired_block & SW_RETIRED, 0);
        assert_eq!(retired_block & PA_MASK_2MIB, ipa & PA_MASK_2MIB);

        let leaf_va = va + (1 << 21);
        let leaf_ipa = ipa + (1 << 21);
        let leaf_indexes = indices(leaf_va);
        words[l2 + 1].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l3 = 1536 + leaf_indexes[3];
        words[l3].store(
            (leaf_ipa & PA_MASK_4KIB)
                | USER_PAGE_FLAGS
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE
                | SW_EL1_MAY_WRITE,
            Ordering::Relaxed,
        );
        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    leaf_va,
                    PT_PAGE,
                )
            },
            Ok(1)
        );
        let retired_leaf = words[l3].load(Ordering::Acquire);
        assert_eq!(retired_leaf & VALID, 0);
        assert_ne!(retired_leaf & SW_RETIRED, 0);
        assert_eq!(retired_leaf & PA_MASK_4KIB, leaf_ipa);
    }

    #[test]
    fn allocation_free_guest_retirement_refuses_partial_or_untagged_ranges() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(3 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l2 = 1024 + indexes[2];
        let tagged = (ipa & PA_MASK_2MIB)
            | USER_BLOCK_FLAGS
            | NON_GLOBAL
            | UXN
            | SW_EL1_PRIVATE
            | SW_EL1_MAY_WRITE;
        words[l2].store(tagged, Ordering::Relaxed);

        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    va + PT_PAGE,
                    PT_PAGE,
                )
            },
            Err(GuestRetirementError::NotPrivateAnonymous)
        );
        assert_eq!(words[l2].load(Ordering::Acquire), tagged);

        let untagged = tagged & !SW_EL1_PRIVATE;
        words[l2].store(untagged, Ordering::Release);
        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    va,
                    1 << 21,
                )
            },
            Err(GuestRetirementError::NotPrivateAnonymous)
        );
        assert_eq!(words[l2].load(Ordering::Acquire), untagged);
    }

    #[test]
    fn guest_retirement_accepts_prepared_and_af_clear_leaves() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[1024 + indexes[2]].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let leaf = 1536 + indexes[3];
        let prepared = (ipa & PA_MASK_4KIB) | (USER_PAGE_FLAGS & !VALID) | NON_GLOBAL | UXN;
        words[leaf].store(
            prepared | SW_EL1_PRIVATE | SW_EL1_MAY_WRITE,
            Ordering::Relaxed,
        );
        words[leaf + 1].store(
            ((ipa + PT_PAGE) & PA_MASK_4KIB)
                | (USER_PAGE_FLAGS & !ACCESS_FLAG)
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE,
            Ordering::Relaxed,
        );
        words[leaf + 2].store(
            ((ipa + 2 * PT_PAGE) & PA_MASK_4KIB)
                | USER_PAGE_FLAGS
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE,
            Ordering::Relaxed,
        );
        words[leaf + 3].store(
            ((ipa + 3 * PT_PAGE) & PA_MASK_4KIB)
                | USER_PAGE_FLAGS
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE,
            Ordering::Relaxed,
        );
        words[leaf + 4].store(
            ((ipa + 4 * PT_PAGE) & PA_MASK_4KIB)
                | (USER_PAGE_FLAGS & !ACCESS_FLAG)
                | NON_GLOBAL
                | UXN
                | SW_EL1_PRIVATE,
            Ordering::Relaxed,
        );

        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    va,
                    5 * PT_PAGE,
                )
            },
            Ok(5)
        );
        for page in 0..5 {
            let descriptor = words[leaf + page].load(Ordering::Acquire);
            assert_eq!(descriptor & VALID, 0);
            assert_ne!(descriptor & SW_RETIRED, 0);
            assert_eq!(descriptor & PA_MASK_4KIB, ipa + page as u64 * PT_PAGE);
        }
        // The former second representation (bit 58 without private authority)
        // cannot license retirement of a new grant.
        words[leaf].store(prepared | SW_EL1_MAY_EXEC, Ordering::Release);
        assert_eq!(
            unsafe {
                retire_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    words.len() * core::mem::size_of::<AtomicU64>(),
                    None,
                    va,
                    PT_PAGE,
                )
            },
            Err(GuestRetirementError::NotPrivateAnonymous)
        );
    }

    #[test]
    fn private_marker_without_a_retained_output_is_not_a_grant() {
        let descriptor = (USER_PAGE_FLAGS & !VALID) | SW_EL1_PRIVATE;
        assert!(!terminal_descriptor_is_prepared_private(descriptor));
        assert!(!terminal_descriptor_permits_host_buffer(
            descriptor,
            LeafAccess::Write
        ));
    }

    #[test]
    fn live_guest_publication_builds_missing_hierarchy_transactionally() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let offline = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x9000_0000;
        assert_eq!(
            terminal_descriptor(offline.debug_walk(va)) & VALID,
            0,
            "the red fixture must begin without an accessible translation"
        );
        assert_eq!(
            offline.debug_walk(va)[3],
            0,
            "the red fixture must exercise missing hierarchy rather than an existing L3 leaf"
        );
        unsafe {
            offline
                .restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
        }

        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture")
        };
        assert_eq!(
            live.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa,
                len: 3 * PT_PAGE,
                writable: true,
                executable: false,
            }),
            Ok(3)
        );

        for page in 0..3 {
            let page_va = va + page * PT_PAGE;
            assert_eq!(live.translate(page_va), Some(ipa + page * PT_PAGE));
            let descriptor = terminal_descriptor(live.debug_walk(page_va));
            assert!(terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Read
            ));
            assert!(terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Write
            ));
            assert!(!terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Execute
            ));
            assert_ne!(descriptor & NON_GLOBAL, 0);
        }
        assert_eq!(live.translate(va - PT_PAGE), None);
        assert_eq!(live.translate(va + 3 * PT_PAGE), None);

        let occupied = GuestLeafPublication {
            va: va + 2 * PT_PAGE,
            ipa: ipa + 0x20_0000,
            len: 2 * PT_PAGE,
            writable: true,
            executable: false,
        };
        assert_eq!(
            live.publish_live_private_pages_transaction(occupied),
            Err(GuestLeafPublicationError::AlreadyValid)
        );
        assert_eq!(
            live.translate(va + 3 * PT_PAGE),
            None,
            "whole-range preflight must reject before exposing a later page"
        );
    }

    #[test]
    fn live_guest_permission_transaction_preserves_frames_and_refuses_widening() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let offline = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x009b_4000_0000;
        unsafe {
            offline
                .restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
        }

        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture")
        };
        live.publish_live_private_pages_transaction(GuestLeafPublication {
            va,
            ipa,
            len: 3 * PT_PAGE,
            writable: true,
            executable: false,
        })
        .expect("publish resident anonymous span");

        let outputs = (0..3)
            .map(|page| {
                live.translate(va + page * PT_PAGE)
                    .expect("resident output")
            })
            .collect::<Vec<_>>();
        assert!(
            outputs
                .iter()
                .copied()
                .eq((0..3).map(|page| ipa + page * PT_PAGE))
        );

        live.protect_live_private_pages_transaction(GuestPermissionEdit {
            va,
            len: 3 * PT_PAGE,
            readable: true,
            writable: false,
            executable: false,
        })
        .expect("RW to RO");
        for page in 0..3 {
            let descriptor = terminal_descriptor(live.debug_walk(va + page * PT_PAGE));
            assert!(terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Read
            ));
            assert!(!terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Write
            ));
            assert!(!terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Execute
            ));
            assert_eq!(descriptor & PA_MASK_4KIB, outputs[page as usize]);
        }

        live.protect_live_private_pages_transaction(GuestPermissionEdit {
            va,
            len: 3 * PT_PAGE,
            readable: false,
            writable: false,
            executable: false,
        })
        .expect("RO to PROT_NONE");
        for page in 0..3 {
            let descriptor = terminal_descriptor(live.debug_walk(va + page * PT_PAGE));
            assert_ne!(descriptor & VALID, 0, "PROT_NONE retains the live VMA leaf");
            for access in [LeafAccess::Read, LeafAccess::Write, LeafAccess::Execute] {
                assert!(!terminal_descriptor_permits_el0(descriptor, access));
            }
            assert_eq!(descriptor & PA_MASK_4KIB, outputs[page as usize]);
        }

        live.protect_live_private_pages_transaction(GuestPermissionEdit {
            va,
            len: 3 * PT_PAGE,
            readable: true,
            writable: true,
            executable: false,
        })
        .expect("PROT_NONE to RW");
        assert!(
            outputs.iter().enumerate().all(|(page, output)| {
                live.translate(va + page as u64 * PT_PAGE) == Some(*output)
            })
        );

        let before = live
            .snapshot_image()
            .expect("snapshot before refused widening");
        assert_eq!(
            live.protect_live_private_pages_transaction(GuestPermissionEdit {
                va,
                len: 3 * PT_PAGE,
                readable: true,
                writable: true,
                executable: true,
            }),
            Err(GuestPermissionEditError::PermissionWidening)
        );
        assert_eq!(
            live.snapshot_image()
                .expect("snapshot after refused widening")
                .as_bytes(),
            before.as_bytes(),
            "a refused widening must not publish a partial edit"
        );
    }

    #[test]
    fn live_guest_publication_replaces_a_retired_leaf_with_the_new_grant() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut offline = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let stale_ipa = va;
        let granted_ipa = 0x009b_4000_1000;
        offline
            .set_rw(va, PT_PAGE as usize, false, None)
            .expect("publish predecessor");
        offline
            .invalidate(va, PT_PAGE as usize, None)
            .expect("retire predecessor");
        let retired = terminal_descriptor(offline.debug_walk(va));
        assert_eq!(retired & VALID, 0);
        assert_ne!(retired & SW_RETIRED, 0);
        assert_eq!(retired & PA_MASK_4KIB, stale_ipa);
        unsafe {
            offline
                .restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish retired fixture");
        }

        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live retired fixture")
        };
        assert_eq!(
            live.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa: granted_ipa,
                len: PT_PAGE,
                writable: true,
                executable: false,
            }),
            Ok(1)
        );

        let published = terminal_descriptor(live.debug_walk(va));
        assert_eq!(published & SW_RETIRED, 0);
        assert_eq!(published & PA_MASK_4KIB, granted_ipa);
        assert!(terminal_descriptor_permits_el0(
            published,
            LeafAccess::Write
        ));
        assert!(!terminal_descriptor_permits_el0(
            published,
            LeafAccess::Execute
        ));
    }

    #[test]
    fn live_snapshot_includes_hierarchy_allocated_by_guest_editor() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut host = hvpatch_manager();
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
            host.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        let host_prefix_before = host.copied_bytes();

        let mut guest = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture in guest editor")
        };
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x009b_4000_1000;
        assert_eq!(
            guest.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa,
                len: PT_PAGE,
                writable: true,
                executable: false,
            }),
            Ok(1)
        );
        assert!(
            guest.copied_bytes() > host_prefix_before,
            "guest publication must allocate hierarchy beyond the host's cached prefix"
        );

        let snapshot = host.snapshot_image().expect("snapshot host authority");
        assert_eq!(
            snapshot.translate(va),
            Some(ipa),
            "fork snapshot must include a live hierarchy page allocated by EL1"
        );
        assert!(
            snapshot.copied_bytes() >= guest.copied_bytes(),
            "snapshot prefix must cover the guest-published hierarchy"
        );
    }

    #[test]
    fn host_debug_walk_reaches_guest_grown_primary_tables_beyond_owned_prefix() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let host = hvpatch_manager();
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
        }
        let host_prefix_before = host.copied_bytes();

        let mut guest = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture in guest editor")
        };
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x009b_4000_1000;
        guest
            .publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa,
                len: PT_PAGE,
                writable: true,
                executable: false,
            })
            .expect("publish guest-grown hierarchy");
        assert!(guest.copied_bytes() > host_prefix_before);

        let walk = unsafe {
            host.debug_walk_host(&*resolver, va)
                .expect("walk hardware-visible guest hierarchy")
        };
        let leaf = terminal_descriptor(walk);
        assert_eq!(leaf & PA_MASK_4KIB, ipa);
        assert!(terminal_descriptor_has_el1_private_authority(leaf));
    }

    #[test]
    fn live_host_edit_adopts_hierarchy_allocated_by_guest_editor() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut host = hvpatch_manager();
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
            host.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        let host_prefix_before = host.copied_bytes();

        let mut guest = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture in guest editor")
        };
        let va = LINUX_MMAP_BASE + 5 * PT_PAGE;
        let len = 16 * 1024 * 1024;
        let ipa = 0x009b_4000_0000;
        assert_eq!(
            guest.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa,
                len,
                writable: true,
                executable: false,
            }),
            Ok((len / PT_PAGE) as usize)
        );
        assert!(
            guest.copied_bytes() > host_prefix_before,
            "guest publication must grow the hierarchy beyond the host's cached prefix"
        );

        host.unmap_aliased(va, len as usize, None)
            .expect("host edit must adopt guest-grown live tables");
        unsafe {
            host.sync_to_host(&*resolver)
                .expect("publish host invalidation");
        }
        assert_eq!(host.translate(va), None);
        assert_eq!(host.translate(va + len - PT_PAGE), None);
        assert!(
            host.copied_bytes() >= guest.copied_bytes(),
            "host allocator high-water mark must cover every guest-grown table"
        );
    }

    #[test]
    fn live_host_unmap_preserves_adjacent_guest_private_leaf() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut host = hvpatch_manager();
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
            host.sync_to_host(&*resolver)
                .expect("finish the host's bootstrap publication");
        }

        let mut guest = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture in guest editor")
        };
        let va = LINUX_MMAP_BASE + 5 * PT_PAGE;
        let target_len = 256 * PT_PAGE;
        let adjacent_va = va + target_len;
        let ipa = 0x009b_4000_0000;
        assert_eq!(
            guest.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa,
                len: target_len + PT_PAGE,
                writable: true,
                executable: false,
            }),
            Ok(257)
        );
        assert_eq!(guest.translate(adjacent_va), Some(ipa + target_len));

        for (readable, writable) in [(true, false), (true, true), (false, false), (true, true)] {
            guest
                .protect_live_private_pages_transaction(GuestPermissionEdit {
                    va,
                    len: target_len,
                    readable,
                    writable,
                    executable: false,
                })
                .expect("permission edit must stay inside the target range");
        }
        assert_eq!(guest.translate(adjacent_va), Some(ipa + target_len));

        unsafe {
            host.adopt_live_tables_for_range(&*resolver, va, target_len as usize)
                .expect("host shadow must adopt the guest-grown hierarchy before editing");
        }
        host.unmap_aliased(va, target_len as usize, None)
            .expect("host unmap must preserve the adjacent guest leaf");
        unsafe {
            host.sync_to_host(&*resolver)
                .expect("publish host invalidation");
        }

        assert_eq!(host.translate(va), None);
        assert_eq!(
            host.translate(adjacent_va),
            Some(ipa + target_len),
            "unmapping a guest-grown range must not reclaim its neighbor's live table"
        );
    }

    #[test]
    fn live_host_allocator_never_reissues_guest_grown_table_pages() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);

        let mut host = hvpatch_manager();
        unsafe {
            host.restore_quiesced_snapshot_to_host(&*resolver)
                .expect("publish fixture");
            host.make_live(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        assert!(host.free_tables.is_empty());
        let host_prefix_before = host.copied_bytes();

        let mut guest = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt live fixture in guest editor")
        };
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        assert_eq!(
            guest.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa: 0x009b_4000_1000,
                len: PT_PAGE,
                writable: true,
                executable: false,
            }),
            Ok(1)
        );
        let guest_prefix = guest.copied_bytes();
        assert!(guest_prefix > host_prefix_before);

        let allocated = host
            .alloc_table_for_test()
            .expect("host allocator must advance beyond guest-grown tables");
        assert!(
            allocated >= LINUX_PAGE_TABLES_BASE + guest_prefix,
            "host reissued a guest-grown table page: allocated=0x{allocated:x} guest_prefix=0x{guest_prefix:x}"
        );
    }

    #[test]
    fn live_guest_publication_refuses_table_exhaustion_without_partial_mapping() {
        let full = MockLiveResolver::new();
        full.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        let offline = hvpatch_manager();
        let capacity = offline.copied_bytes() as usize;
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        unsafe {
            offline
                .restore_quiesced_snapshot_to_host(&*full)
                .expect("publish fixture");
        }

        let constrained = MockLiveResolver::new();
        let bytes = full
            .arenas
            .lock()
            .unwrap()
            .get(&LINUX_PAGE_TABLES_BASE)
            .unwrap()[..capacity]
            .to_vec();
        constrained
            .arenas
            .lock()
            .unwrap()
            .insert(LINUX_PAGE_TABLES_BASE, bytes.clone());
        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                capacity,
                Arc::clone(&constrained) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .expect("adopt constrained fixture")
        };
        assert_eq!(live.spare_tables_available(), 0);
        assert_eq!(
            live.publish_live_private_pages_transaction(GuestLeafPublication {
                va,
                ipa: 0x9000_0000,
                len: 3 * PT_PAGE,
                writable: true,
                executable: false,
            }),
            Err(GuestLeafPublicationError::Manager(
                PageTableError::OutOfTables
            ))
        );
        assert_eq!(live.translate(va), None);
        assert_eq!(
            constrained
                .arenas
                .lock()
                .unwrap()
                .get(&LINUX_PAGE_TABLES_BASE)
                .unwrap()
                .as_slice(),
            bytes.as_slice(),
            "capacity refusal must leave every hardware-visible byte unchanged"
        );
    }

    #[test]
    fn prepared_private_leaf_commits_only_on_authorized_first_touch() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[1024 + indexes[2]].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let leaf = 1536 + indexes[3];
        let prepared = (ipa & PA_MASK_4KIB)
            | (USER_PAGE_FLAGS & !VALID)
            | NON_GLOBAL
            | UXN
            | SW_EL1_PRIVATE
            | SW_EL1_MAY_WRITE;
        words[leaf].store(prepared, Ordering::Relaxed);
        let len = words.len() * core::mem::size_of::<AtomicU64>();
        let commit = |words: &mut Vec<AtomicU64>, expected_ipa, access| unsafe {
            commit_existing_el1_prepared_page(
                words.as_mut_ptr(),
                root,
                len,
                None,
                va,
                expected_ipa,
                access,
            )
        };

        assert_eq!(
            commit(&mut words, ipa + PT_PAGE, LeafAccess::Read),
            Err(GuestPreparedCommitError::WrongBacking)
        );
        assert_eq!(words[leaf].load(Ordering::Acquire) & VALID, 0);
        assert_eq!(
            commit(&mut words, ipa, LeafAccess::Read),
            Ok(GuestPreparedCommit::Committed)
        );
        assert_eq!(
            el1_private_leaf_state(words[leaf].load(Ordering::Acquire)),
            El1PrivateLeafState::Resident
        );
        assert_eq!(
            commit(&mut words, ipa, LeafAccess::Write),
            Ok(GuestPreparedCommit::AlreadyResident)
        );
        words[leaf].store((prepared & !AP_MASK) | AP_PRIV_RO, Ordering::Relaxed);
        assert_eq!(
            commit(&mut words, ipa, LeafAccess::Read),
            Err(GuestPreparedCommitError::PermissionDenied)
        );
        assert_eq!(words[leaf].load(Ordering::Acquire) & VALID, 0);
        words[leaf].store(prepared | SW_RETIRED, Ordering::Relaxed);
        assert_eq!(
            commit(&mut words, ipa, LeafAccess::Read),
            Err(GuestPreparedCommitError::NotPrepared)
        );
        assert_eq!(words[leaf].load(Ordering::Acquire) & VALID, 0);
    }

    #[test]
    fn allocation_free_guest_fork_arming_sets_readonly_and_non_global() {
        use core::sync::atomic::{AtomicU64, Ordering};

        let root = 0x8800_0000_0000;
        let va = 0x4000_0000;
        let ipa = 0x009b_4000_0000;
        let mut words: Vec<AtomicU64> = (0..(4 * 512)).map(|_| AtomicU64::new(0)).collect();
        let indexes = indices(va);
        words[indexes[0]].store((root + 0x1000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[512 + indexes[1]].store((root + 0x2000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        words[1024 + indexes[2]].store((root + 0x3000) | TYPE_TABLE_OR_PAGE, Ordering::Relaxed);
        let l3 = 1536 + indexes[3];

        // Active RW private leaf.
        let active =
            (ipa & PA_MASK_4KIB) | USER_PAGE_FLAGS | UXN | SW_EL1_PRIVATE | SW_EL1_MAY_WRITE;
        words[l3].store(active, Ordering::Relaxed);

        let byte_len = words.len() * core::mem::size_of::<AtomicU64>();
        let armed_pages =
            unsafe { arm_existing_el1_fork_pages(words.as_mut_ptr(), root, byte_len, va, PT_PAGE) };
        assert_eq!(armed_pages, Ok(1));
        let armed = words[l3].load(Ordering::Acquire);
        assert_eq!(armed & AP_MASK, AP_RO);
        assert_ne!(armed & NON_GLOBAL, 0);
        assert_ne!(armed & SW_EL1_PRIVATE, 0);
        assert_ne!(armed & SW_EL1_MAY_WRITE, 0);
        assert!(el1_cow(armed));
        assert!(terminal_descriptor_permits_host_buffer(
            armed,
            LeafAccess::Write
        ));
        assert_eq!(
            unsafe {
                protect_existing_el1_private_pages(
                    words.as_mut_ptr(),
                    root,
                    byte_len,
                    None,
                    GuestPermissionEdit {
                        va,
                        len: PT_PAGE,
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                )
            },
            Err(GuestPermissionEditError::PermissionWidening)
        );
        assert_eq!(words[l3].load(Ordering::Acquire), armed);

        // A narrowed page must not gain write intent or EL0 access at fork.
        for ap in [AP_RO, AP_PRIV_RO] {
            words[l3].store((active & !AP_MASK) | ap, Ordering::Relaxed);
            unsafe { arm_existing_el1_fork_pages(words.as_mut_ptr(), root, byte_len, va, PT_PAGE) }
                .unwrap();
            let protected = words[l3].load(Ordering::Acquire);
            assert_eq!(protected & AP_MASK, ap);
            assert!(!terminal_descriptor_permits_host_buffer(
                protected,
                LeafAccess::Write
            ));
            assert_eq!(
                unsafe {
                    retire_existing_el1_private_pages(
                        words.as_mut_ptr(),
                        root,
                        byte_len,
                        None,
                        va,
                        PT_PAGE,
                    )
                },
                Ok(1)
            );
            assert_eq!(words[l3].load(Ordering::Acquire) & VALID, 0);
        }
    }
    #[test]
    fn retained_private_backing_permits_copyout_without_guest_residency() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        mgr.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa: LINUX_ALIAS_IPA_BASE + 0x20_0000,
                len: PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        mgr.set_prot_none(va, PT_PAGE as usize, None).unwrap();
        let descriptor = terminal_descriptor(mgr.debug_walk(va));
        assert!(terminal_descriptor_has_el1_private_authority(descriptor));
        assert_eq!(mgr.translate(va), None);
        assert!(terminal_descriptor_permits_host_buffer(
            descriptor,
            LeafAccess::Write
        ));
        assert!(terminal_descriptor_permits_host_buffer(
            descriptor,
            LeafAccess::Read
        ));
        assert!(!terminal_descriptor_permits_host_buffer(
            descriptor,
            LeafAccess::Execute
        ));
        assert!(!terminal_descriptor_permits_host_buffer(
            descriptor | SW_RETIRED,
            LeafAccess::Write
        ));
        assert!(!terminal_descriptor_permits_host_buffer(
            (descriptor & !AP_MASK) | AP_RO,
            LeafAccess::Write
        ));
        assert!(!terminal_descriptor_permits_host_buffer(
            (descriptor & !AP_MASK) | AP_PRIV_RO,
            LeafAccess::Read
        ));
    }

    #[test]
    fn fork_keeps_prepared_private_leaf_write_intent_for_sigframe_copyout() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;
        mgr.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa,
                len: 4 * PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        let altstack = va + 2 * PT_PAGE;
        let before = terminal_descriptor(mgr.debug_walk(altstack));
        assert!(terminal_descriptor_is_prepared_private(before));
        assert!(terminal_descriptor_permits_host_buffer(
            before,
            LeafAccess::Write
        ));

        mgr.set_fork_readonly(va, (4 * PT_PAGE) as usize, None)
            .unwrap();
        let child = terminal_descriptor(mgr.debug_walk(altstack));
        assert!(terminal_descriptor_is_prepared_private(child));
        assert_eq!(mgr.translate(altstack), None);
        assert_eq!(
            mgr.translate_retained_output(altstack),
            Some(ipa + 2 * PT_PAGE)
        );
        assert!(
            terminal_descriptor_permits_host_buffer(child, LeafAccess::Write),
            "fork must not turn an untouched writable altstack into a host-denied leaf"
        );
    }

    #[test]
    fn forked_bus_tail_does_not_inherit_prepared_el1_private_authority() {
        let mut parent = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        parent
            .publish_private_pages(
                GuestLeafPublication {
                    va,
                    ipa: LINUX_ALIAS_IPA_BASE + 0x20_0000,
                    len: 4 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
                va,
                None,
            )
            .unwrap();
        let bus_page = va + 3 * PT_PAGE;
        // The file's last page is wholly beyond EOF. Host protection leaves
        // an invalid descriptor that the fork snapshot carries to its child.
        parent
            .set_prot_none(bus_page, PT_PAGE as usize, None)
            .unwrap();
        parent
            .mark_bus_fault(bus_page, PT_PAGE as usize, None)
            .unwrap();
        parent
            .set_fork_readonly(va, (4 * PT_PAGE) as usize, None)
            .unwrap();
        let child_bus = terminal_descriptor(parent.debug_walk(bus_page));
        assert_eq!(child_bus & VALID, 0);
        assert!(!terminal_descriptor_is_prepared_private(child_bus));
        assert!(
            !terminal_descriptor_has_el1_private_authority(child_bus),
            "a BUS leaf cannot inherit EL1-private prepared backing"
        );
        assert!(terminal_descriptor_is_prepared_private(
            terminal_descriptor(parent.debug_walk(va + 2 * PT_PAGE))
        ));
    }

    #[test]
    fn retired_prot_none_leaf_cannot_deny_a_fresh_writable_mapping() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;
        mgr.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa: old_ipa,
                len: PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        mgr.set_prot_none_denying_host_buffers(va, PT_PAGE as usize, None)
            .unwrap();
        assert!(!terminal_descriptor_permits_host_buffer(
            terminal_descriptor(mgr.debug_walk(va)),
            LeafAccess::Write
        ));
        assert_eq!(
            mgr.clear_retired_for_new_mapping(va, PT_PAGE as usize, None),
            Err(PageTableError::BadAddress),
            "a protected live mapping cannot be mistaken for a vacant VA"
        );
        mgr.invalidate(va, PT_PAGE as usize, None).unwrap();
        // A new anonymous VMA at the same VA is initially a cold reservation.
        // The predecessor output and protection cannot describe that VMA.
        mgr.clear_retired_for_new_mapping(va, PT_PAGE as usize, None)
            .unwrap();
        mgr.set_prot_none(va, PT_PAGE as usize, None).unwrap();
        let descriptor = terminal_descriptor(mgr.debug_walk(va));
        assert_eq!(descriptor & (SW_RETIRED | SW_EL1_PRIVATE | PA_MASK_4KIB), 0);
        assert!(terminal_descriptor_permits_host_buffer(
            descriptor,
            LeafAccess::Write
        ));
        let new_ipa = old_ipa + 0x40_0000;
        mgr.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa: new_ipa,
                len: 2 * PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        let prepared = terminal_descriptor(mgr.debug_walk(va + PT_PAGE));
        assert_eq!(prepared & PA_MASK_4KIB, new_ipa + PT_PAGE);
        assert!(terminal_descriptor_permits_host_buffer(
            prepared,
            LeafAccess::Write
        ));
        mgr.set_readonly(va + PT_PAGE, PT_PAGE as usize, false, None)
            .unwrap();
        let readonly = terminal_descriptor(mgr.debug_walk(va + PT_PAGE));
        assert!(terminal_descriptor_permits_host_buffer(
            readonly,
            LeafAccess::Read
        ));
        assert!(!terminal_descriptor_permits_host_buffer(
            readonly,
            LeafAccess::Write
        ));
        mgr.set_prot_none_denying_host_buffers(va + PT_PAGE, PT_PAGE as usize, None)
            .unwrap();
        assert!(!terminal_descriptor_permits_host_buffer(
            terminal_descriptor(mgr.debug_walk(va + PT_PAGE)),
            LeafAccess::Read
        ));
    }

    /// Descriptor witness for roreadwrite/protnonesyscall beside a still-cold
    /// prepared page. This does not model the backend's copyout transport.
    #[test]
    fn el1_single_page_protection_survives_neighbor_first_touch_and_discard() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        unsafe {
            hvpatch_manager()
                .restore_quiesced_snapshot_to_host(&*resolver)
                .unwrap();
        }
        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .unwrap()
        };
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x009b_4000_0000;
        live.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa,
                len: 3 * PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        unsafe {
            live.sync_to_host(&*resolver).unwrap();
        }
        let words = resolver
            .host_ptr_for_base(LINUX_PAGE_TABLES_BASE)
            .unwrap()
            .cast();
        for readable in [true, false] {
            let edit = GuestPermissionEdit {
                va,
                len: PT_PAGE,
                readable,
                writable: false,
                executable: false,
            };
            assert_eq!(
                unsafe {
                    protect_existing_el1_private_pages(
                        words,
                        LINUX_PAGE_TABLES_BASE,
                        LINUX_PAGE_TABLES_SIZE as usize,
                        None,
                        edit,
                    )
                },
                Ok(1)
            );
            // A later first touch and DONTNEED re-arm on a different page must
            // not republish the host's original RW permission over this page.
            live.set_rw(va + 2 * PT_PAGE, PT_PAGE as usize, false, None)
                .unwrap();
            unsafe {
                live.sync_to_host(&*resolver).unwrap();
            }
            assert_eq!(live.translate(va + PT_PAGE), None);
            let protected = terminal_descriptor(live.debug_walk(va));
            assert!(!terminal_descriptor_permits_host_buffer(
                protected,
                LeafAccess::Write
            ));
            assert_eq!(
                terminal_descriptor_permits_host_buffer(protected, LeafAccess::Read),
                readable
            );
            assert_eq!(protected & PA_MASK_4KIB, ipa);
            live.set_prot_none(va + 2 * PT_PAGE, PT_PAGE as usize, None)
                .unwrap();
            unsafe {
                live.sync_to_host(&*resolver).unwrap();
            }
            assert_eq!(live.translate(va + 2 * PT_PAGE), None);
            assert_eq!(
                live.translate_retained_output(va + 2 * PT_PAGE),
                Some(ipa + 2 * PT_PAGE)
            );
            assert_eq!(terminal_descriptor(live.debug_walk(va)), protected);
            assert_eq!(
                unsafe {
                    protect_existing_el1_private_pages(
                        words,
                        LINUX_PAGE_TABLES_BASE,
                        LINUX_PAGE_TABLES_SIZE as usize,
                        None,
                        GuestPermissionEdit {
                            readable: true,
                            writable: true,
                            ..edit
                        },
                    )
                },
                Ok(1)
            );
            assert!(terminal_descriptor_permits_host_buffer(
                terminal_descriptor(live.debug_walk(va)),
                LeafAccess::Write
            ));
        }
        // Only touched leaves are hardware-accessible. The private tag does
        // not make the middle leaf valid or prove dispatcher residency.
        live.set_rw(va + 2 * PT_PAGE, PT_PAGE as usize, false, None)
            .unwrap();
        unsafe {
            live.sync_to_host(&*resolver).unwrap();
        }
        assert_eq!(
            (0..3)
                .map(|page| live.translate(va + page * PT_PAGE).is_some())
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        for page in 0..3 {
            assert!(terminal_descriptor_has_el1_private_authority(
                terminal_descriptor(live.debug_walk(va + page * PT_PAGE))
            ));
        }
    }

    #[test]
    fn host_grant_first_touch_then_permission_cycles_stay_in_guest() {
        let resolver = MockLiveResolver::new();
        resolver.register_arena(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        unsafe {
            hvpatch_manager()
                .restore_quiesced_snapshot_to_host(&*resolver)
                .unwrap();
        }
        let mut live = unsafe {
            PageTableManager::new_live(
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
                LINUX_PAGE_TABLES_SIZE as usize,
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>,
            )
            .unwrap()
        };
        let va = LINUX_MMAP_BASE + 0x4080_0000;
        let ipa = 0x009b_4000_0000;
        const PAGES: u64 = 256;
        live.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa,
                len: PAGES * PT_PAGE,
                writable: true,
                executable: false,
            },
            va,
            None,
        )
        .unwrap();
        // Mirror later host first-touch protection commits, without new grants.
        for page in 1..PAGES {
            assert_eq!(live.translate(va + page * PT_PAGE), None);
            live.set_rw(va + page * PT_PAGE, PT_PAGE as usize, false, None)
                .unwrap();
        }
        unsafe {
            live.sync_to_host(&*resolver).unwrap();
        }
        let words = resolver
            .host_ptr_for_base(LINUX_PAGE_TABLES_BASE)
            .unwrap()
            .cast();
        let mut served = 0;
        for _ in 0..4 {
            for (readable, writable) in [(true, false), (true, true), (false, false), (true, true)]
            {
                let edit = GuestPermissionEdit {
                    va,
                    len: PAGES * PT_PAGE,
                    readable,
                    writable,
                    executable: false,
                };
                assert_eq!(
                    unsafe {
                        protect_existing_el1_private_pages(
                            words,
                            LINUX_PAGE_TABLES_BASE,
                            LINUX_PAGE_TABLES_SIZE as usize,
                            None,
                            edit,
                        )
                    },
                    Ok(PAGES as usize)
                );
                served += 1;
                for page in 0..PAGES {
                    let descriptor = terminal_descriptor(live.debug_walk(va + page * PT_PAGE));
                    assert_eq!(descriptor & PA_MASK_4KIB, ipa + page * PT_PAGE);
                    assert_eq!(
                        terminal_descriptor_permits_host_buffer(descriptor, LeafAccess::Write),
                        writable
                    );
                    assert_eq!(
                        terminal_descriptor_permits_host_buffer(descriptor, LeafAccess::Read),
                        readable
                    );
                }
            }
        }
        assert_eq!(served, 16);
    }

    #[test]
    fn frame_grant_retains_speculative_outputs_without_exposing_pages() {
        let mut mgr = manager();
        let va = LINUX_HIGH_VA_THRESHOLD;
        let ipa = LINUX_ALIAS_IPA_BASE + 0x20_0000;
        mgr.publish_private_pages(
            GuestLeafPublication {
                va,
                ipa,
                len: 4 * PT_PAGE,
                writable: true,
                executable: false,
            },
            va + PT_PAGE,
            None,
        )
        .unwrap();
        for page in [0, 2, 3] {
            let address = va + page * PT_PAGE;
            assert_eq!(mgr.translate(address), None, "speculative page must fault");
            assert_eq!(
                mgr.translate_retained_output(address),
                Some(ipa + page * PT_PAGE)
            );
            assert!(
                terminal_descriptor_has_el1_private_authority(terminal_descriptor(
                    mgr.debug_walk(address)
                )),
                "first-touch must retain the grant's private authority"
            );
            assert!(
                terminal_descriptor_permits_host_buffer(
                    terminal_descriptor(mgr.debug_walk(address)),
                    LeafAccess::Write
                ),
                "prepared writable backing must admit host copyout without guest residency"
            );
            assert_eq!(
                el1_private_leaf_state(terminal_descriptor(mgr.debug_walk(address))),
                El1PrivateLeafState::Prepared,
                "an untouched grant page must retain its retirement authority"
            );
        }
        assert_eq!(mgr.translate(va + PT_PAGE), Some(ipa + PT_PAGE));
        mgr.set_readonly(va + 2 * PT_PAGE, PT_PAGE as usize, false, None)
            .unwrap();
        assert_eq!(mgr.translate(va + 2 * PT_PAGE), Some(ipa + 2 * PT_PAGE));
        assert_eq!(mgr.translate(va + 3 * PT_PAGE), None);
    }

    fn live_arena_bytes(resolver: &MockLiveResolver) -> Vec<u8> {
        resolver
            .arenas
            .lock()
            .unwrap()
            .get(&LINUX_PAGE_TABLES_BASE)
            .expect("primary arena")
            .clone()
    }

    #[test]
    fn guest_owned_live_image_refuses_every_host_descriptor_store() {
        let (mut mgr, resolver) = create_live_fixture();
        let snapshot = mgr.snapshot_image().expect("offline snapshot");
        mgr.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        let before = live_arena_bytes(&resolver);

        // Ordinary host edit funnel: stage, refuse publication, discard.
        mgr.begin_undo().unwrap();
        mgr.set_readonly(LINUX_MMAP_BASE, 0x4000, false, None)
            .expect("staging is not a live store");
        assert_eq!(
            unsafe { mgr.sync_to_host(&*resolver) },
            Err(PageTableError::GuestOwnsLiveDescriptors)
        );
        unsafe { mgr.rollback_undo(&*resolver, None) }.expect("discard staged edit");
        assert_eq!(live_arena_bytes(&resolver), before);
        assert_eq!(
            mgr.translate(LINUX_MMAP_BASE),
            snapshot.translate(LINUX_MMAP_BASE),
            "the discarded host edit is not observable through the live image"
        );

        // Guest-publication transactions are host-venue publishers too.
        let publication = GuestLeafPublication {
            va: LINUX_MMAP_BASE + 0x40_0000,
            ipa: LINUX_HVPATCH_GLOBAL_FRAME_BASE,
            len: 2 * PT_PAGE,
            writable: true,
            executable: false,
        };
        assert_eq!(
            mgr.publish_live_private_pages_transaction(publication),
            Err(GuestLeafPublicationError::Manager(
                PageTableError::GuestOwnsLiveDescriptors
            ))
        );
        assert_eq!(live_arena_bytes(&resolver), before);

        // Snapshot restore through a guest-owned image is refused too.
        assert_eq!(
            unsafe { mgr.restore_quiesced_snapshot_to_host(&*resolver) },
            Err(PageTableError::GuestOwnsLiveDescriptors)
        );
        assert_eq!(live_arena_bytes(&resolver), before);

        // The host lane is unchanged.
        mgr.set_live_descriptor_owner(LiveDescriptorOwner::Host);
        mgr.begin_undo().unwrap();
        mgr.set_readonly(LINUX_MMAP_BASE, 0x4000, false, None)
            .unwrap();
        unsafe { mgr.sync_to_host(&*resolver) }.expect("host lane publishes");
        mgr.commit_undo();
        assert_ne!(live_arena_bytes(&resolver), before);
    }

    #[test]
    fn primary_table_grants_are_exact_and_reversible() {
        let (mut mgr, _resolver) = create_live_fixture();
        let cursor = mgr.arenas[0].next_free;
        let grants = mgr.reserve_table_grants(3, None).expect("three pages");
        assert_eq!(
            grants.as_slice(),
            &[
                LINUX_PAGE_TABLES_BASE + cursor,
                LINUX_PAGE_TABLES_BASE + cursor + PT_PAGE,
                LINUX_PAGE_TABLES_BASE + cursor + 2 * PT_PAGE,
            ]
        );
        assert_eq!(mgr.arenas[0].next_free, cursor + 3 * PT_PAGE);
        // The host allocator never hands a reserved page to another edit.
        let next = mgr.alloc_table_for_test().expect("host allocation");
        assert!(!grants.as_slice().contains(&next));

        // The unused suffix returns to the allocator and is granted again.
        mgr.release_table_grants(grants.unused_after(1)).unwrap();
        let again = mgr.reserve_table_grants(2, None).expect("reuse");
        let mut reused = again.as_slice().to_vec();
        reused.sort_unstable();
        assert_eq!(reused, grants.as_slice()[1..].to_vec());

        // A shortfall without a source reserves nothing.
        let free_before = mgr.free_tables.clone();
        let cursor_before = mgr.arenas[0].next_free;
        let remaining = (mgr.arenas[0].capacity as u64 - cursor_before) / PT_PAGE;
        if remaining < descriptor_txn::MAX_TABLE_GRANTS as u64 {
            assert_eq!(
                mgr.reserve_table_grants(remaining as usize + 1, None),
                Err(PageTableError::OutOfTables)
            );
        }
        assert_eq!(
            mgr.reserve_table_grants(descriptor_txn::MAX_TABLE_GRANTS + 1, None),
            Err(PageTableError::OutOfTables)
        );
        assert_eq!(mgr.free_tables, free_before);
        assert_eq!(mgr.arenas[0].next_free, cursor_before);
    }

    /// The guest lane's table supply grows like the host editor's: once the
    /// primary arena is exhausted, grants come from extension arenas taken
    /// from the image's source (EL1 reaches every arena through its table
    /// view). Red before 2026-09-30: grants were primary-only, so a process
    /// with more than one arena of tables (`pagetablegrow`, a sparse
    /// `MAP_FIXED` storm) hit `OutOfTables` and the carrier aborted in
    /// `brk`/`mmap` (`protect_range ... Manager(OutOfTables)`).
    #[test]
    fn table_grants_grow_into_extension_arenas_once_the_primary_is_exhausted() {
        let (mut mgr, resolver) = create_live_fixture();
        mgr.arenas[0].next_free = mgr.arenas[0].capacity as u64;
        mgr.free_tables.clear();
        assert_eq!(
            mgr.reserve_table_grants(3, None),
            Err(PageTableError::OutOfTables),
            "without a source the shortfall is refused whole"
        );
        assert_eq!(mgr.arenas.len(), 1);

        let extension = SubstrateGpa(LINUX_PAGE_TABLES_BASE + 0x40_0000);
        resolver.register_arena(extension.0, mgr.layout.extension_arena_capacity);
        let available = std::sync::Arc::new(std::sync::Mutex::new(vec![extension]));
        let returned = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut source = TestArenaSource {
            id: TableArenaSourceId(extension),
            available: std::sync::Arc::clone(&available),
            returned: std::sync::Arc::clone(&returned),
        };
        let grants = mgr
            .reserve_table_grants(3, Some(&mut source))
            .expect("grants from a new extension arena");
        assert_eq!(
            grants.as_slice(),
            &[
                extension.0,
                extension.0 + PT_PAGE,
                extension.0 + 2 * PT_PAGE
            ]
        );
        assert_eq!(mgr.arenas.len(), 2);
        assert_eq!(mgr.arenas[1].next_free, 3 * PT_PAGE);
        // The arena stays with the image: the next grant needs no new one.
        let more = mgr.reserve_table_grants(2, None).expect("same arena");
        assert_eq!(
            more.as_slice(),
            &[extension.0 + 3 * PT_PAGE, extension.0 + 4 * PT_PAGE]
        );
        assert!(returned.lock().unwrap().is_empty());
        // Every granted page is a spare table the host may take back.
        for &page in grants.as_slice().iter().chain(more.as_slice()) {
            assert!(mgr.is_spare_table(page));
        }
    }

    /// A guest editor can link a table page past the host's cached cursor
    /// (the live arena grew under another image of this MM). A grant must
    /// never name that page: two parents linking one table make two VA
    /// ranges alias the same leaves. The grant path shares the host
    /// allocator's occupied-candidate check.
    #[test]
    fn primary_table_grants_skip_a_guest_linked_page_past_the_cursor() {
        let (mut mgr, resolver) = create_live_fixture();
        let cursor = mgr.arenas[0].next_free;
        // EL1 filled the second candidate page (a linked L3 table).
        let occupied = cursor + PT_PAGE;
        resolver.write_word(LINUX_PAGE_TABLES_BASE, occupied as usize + 8, VALID);
        let grants = mgr.reserve_table_grants(3, None).expect("three pages");
        for &page in grants.as_slice() {
            assert!(
                page > LINUX_PAGE_TABLES_BASE + occupied,
                "grant 0x{page:x} at or below the guest-linked page 0x{:x}",
                LINUX_PAGE_TABLES_BASE + occupied
            );
        }
        assert_eq!(mgr.arenas[0].next_free, occupied + 4 * PT_PAGE);
    }

    #[derive(Default)]
    struct RecordingMaintenance {
        barriers: core::cell::Cell<usize>,
        invalidations: core::cell::RefCell<Vec<(u64, u64)>>,
    }

    impl descriptor_txn::TableMaintenance for RecordingMaintenance {
        fn publish_barrier(&self) {
            self.barriers.set(self.barriers.get() + 1);
        }
        fn invalidate_range(&self, va: u64, len: u64) {
            self.invalidations.borrow_mut().push((va, len));
        }
    }

    /// Execute a submitted transaction as EL1 would: over the live primary
    /// arena, rooted at the root it authenticated for the MM.
    fn guest_apply(
        resolver: &MockLiveResolver,
        slot: &descriptor_txn::DescriptorTxnSlot,
        mm_key: u64,
        maintenance: &RecordingMaintenance,
    ) -> Option<descriptor_txn::DescriptorReceipt> {
        let host = resolver
            .host_ptr_for_range(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize)
            .unwrap();
        let words = unsafe {
            descriptor_txn::PrimaryTableWords::new(
                host.cast::<core::sync::atomic::AtomicU64>(),
                LINUX_PAGE_TABLES_BASE,
                LINUX_PAGE_TABLES_SIZE as usize,
                maintenance,
            )
        }
        .unwrap();
        let mut journal = descriptor_txn::InlineJournal::new();
        descriptor_txn::apply_submitted_descriptor_txn(
            slot,
            mm_key,
            &words,
            SubstrateGpa(LINUX_PAGE_TABLES_BASE),
            &mut journal,
            || {},
        )
    }

    fn txn_backing(seed: u64) -> descriptor_txn::BackingIdentity {
        let nz = |v| core::num::NonZeroU64::new(v).unwrap();
        descriptor_txn::BackingIdentity {
            frame_id: nz(seed),
            mapping_id: nz(seed + 1),
            owner_generation: nz(seed + 2),
            inventory_revision: nz(seed + 3),
        }
    }

    #[test]
    fn guest_owned_lane_publishes_a_grant_only_through_el1_transactions() {
        use descriptor_txn::{
            DescriptorOp, DescriptorOutcome, DescriptorTxnId, DescriptorTxnSlot, PageSpan,
        };
        let (mut mgr, resolver) = create_live_fixture();
        mgr.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        // A fresh 2 MiB window inside the reserved sparse mmap arena: the
        // boot image covers it with invalid coarse reservation blocks, so the
        // grant needs split tables from the host allocator.
        let va = LINUX_MMAP_BASE + 0x80_0000;
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let fault = va + 3 * PT_PAGE;
        let op = DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va,
                ipa,
                len: 8 * PT_PAGE,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(fault, PT_PAGE),
            backing: txn_backing(10),
        };
        let id = DescriptorTxnId {
            mm_key: core::num::NonZeroU64::new(41).unwrap(),
            generation: core::num::NonZeroU64::new(1).unwrap(),
        };
        let before = live_arena_bytes(&resolver);
        let txn = mgr
            .prepare_guest_descriptor_txn(id, op, None)
            .expect("plan and reserve");
        assert_eq!(
            live_arena_bytes(&resolver),
            before,
            "planning and grant reservation store nothing"
        );
        assert!(
            !txn.tables.is_empty(),
            "the reservation block must be split"
        );

        let slot = DescriptorTxnSlot::new();
        assert!(slot.submit(&txn));
        assert!(slot.pending_covering(41, fault));
        let maintenance = RecordingMaintenance::default();
        // Another MM's EL1 editor cannot apply it.
        assert!(guest_apply(&resolver, &slot, 42, &maintenance).is_none());
        let receipt = guest_apply(&resolver, &slot, 41, &maintenance).expect("claimed");
        assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
        assert!(
            maintenance.barriers.get() >= 1,
            "links follow a publish barrier"
        );
        let host_receipt = slot.take_receipt(id).unwrap();
        let verified = mgr
            .settle_guest_descriptor_receipt(&txn, &host_receipt)
            .expect("authentic receipt");
        assert_eq!(verified.resident(), PageSpan::new(fault, PT_PAGE));

        // The host live view observes exactly the guest's publication.
        assert_eq!(mgr.translate(fault), Some(ipa + 3 * PT_PAGE));
        for page in 0..8 {
            let address = va + page * PT_PAGE;
            let leaf = terminal_descriptor(mgr.debug_walk(address));
            assert_eq!(leaf & PA_MASK_4KIB, ipa + page * PT_PAGE);
            assert_eq!(
                el1_private_leaf_state(leaf),
                if address == fault {
                    El1PrivateLeafState::Resident
                } else {
                    El1PrivateLeafState::Prepared
                },
                "page {page}"
            );
        }
        // Reserved grants the guest linked are never reissued by the host.
        let next = mgr.alloc_table_for_test().unwrap();
        assert!(!txn.tables.as_slice().contains(&next));

        // Host copyout into a prepared page is a guest Publish, not a store.
        let copyout = DescriptorOp::Publish {
            span: PageSpan::new(va, PT_PAGE),
            expected_ipa: SubstrateGpa(ipa),
            access: LeafAccess::Write,
        };
        let id2 = DescriptorTxnId {
            generation: core::num::NonZeroU64::new(2).unwrap(),
            ..id
        };
        let copyout_txn = mgr
            .prepare_guest_descriptor_txn(id2, copyout, None)
            .unwrap();
        assert!(copyout_txn.tables.is_empty());
        let before = live_arena_bytes(&resolver);
        assert!(slot.submit(&copyout_txn));
        assert_eq!(live_arena_bytes(&resolver), before);
        guest_apply(&resolver, &slot, 41, &maintenance).unwrap();
        let receipt = slot.take_receipt(id2).unwrap();
        let verified = mgr
            .settle_guest_descriptor_receipt(&copyout_txn, &receipt)
            .unwrap();
        assert_eq!(verified.resident(), PageSpan::new(va, PT_PAGE));
        assert_eq!(mgr.translate(va), Some(ipa));

        // A refused submission returns every grant it carried.
        let id3 = DescriptorTxnId {
            generation: core::num::NonZeroU64::new(3).unwrap(),
            ..id
        };
        let occupied = mgr.prepare_guest_descriptor_txn(id3, op, None);
        assert_eq!(
            occupied,
            Err(GuestTxnPrepareError::Refused(
                descriptor_txn::DescriptorRefusal::AlreadyValid
            ))
        );
    }

    #[test]
    fn host_lane_images_never_build_guest_transactions() {
        let (mut mgr, _resolver) = create_live_fixture();
        let id = descriptor_txn::DescriptorTxnId {
            mm_key: core::num::NonZeroU64::new(1).unwrap(),
            generation: core::num::NonZeroU64::new(1).unwrap(),
        };
        assert_eq!(
            mgr.prepare_guest_descriptor_txn(
                id,
                descriptor_txn::DescriptorOp::Retire(descriptor_txn::PageSpan::new(
                    LINUX_MMAP_BASE,
                    PT_PAGE
                )),
                None
            ),
            Err(GuestTxnPrepareError::NotGuestOwned)
        );
    }

    /// A guest fork-arm transaction and the host editor produce the same
    /// terminal descriptor for every page of every armed range and of their
    /// neighbours, across prepared/resident EL1 grants, untagged host
    /// aliases, fully and partially covered coarse blocks, kernel-only
    /// ranges and never-populated reservations.
    #[test]
    fn guest_fork_arm_matches_the_host_editor_page_for_page() {
        use core::sync::atomic::AtomicU64;
        use descriptor_txn::{
            CallerInvalidatesAsid, DescriptorOutcome, InlineJournal, PrimaryTableWords,
            TableGrants, execute_descriptor_op,
        };
        const TWO_MIB: u64 = 1 << 21;
        let mut image = hvpatch_manager();
        let grant_va = LINUX_MMAP_BASE + 0x40_0000;
        image
            .publish_private_pages(
                GuestLeafPublication {
                    va: grant_va,
                    ipa: LINUX_HVPATCH_GLOBAL_FRAME_BASE,
                    len: 4 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
                grant_va + PT_PAGE,
                None,
            )
            .unwrap();
        let block_va = LINUX_MMAP_BASE + 4 * TWO_MIB;
        image
            .set_rw(block_va, 3 * TWO_MIB as usize, false, None)
            .unwrap();
        image.declare_live_hardware_image();
        // (va, len, kernel_only, executable)
        let ranges = [
            (grant_va, 4 * PT_PAGE, false, false),
            (block_va, TWO_MIB, false, false),
            (block_va + TWO_MIB + 3 * PT_PAGE, 5 * PT_PAGE, false, false),
            (
                block_va + 2 * TWO_MIB + 64 * PT_PAGE,
                2 * PT_PAGE,
                true,
                false,
            ),
            (
                LINUX_MMAP_BASE + 16 * TWO_MIB + PT_PAGE,
                3 * PT_PAGE,
                false,
                false,
            ),
        ];

        let mut host = image.snapshot_image().unwrap();
        host.declare_live_hardware_image();
        for &(va, len, kernel_only, executable) in &ranges {
            if kernel_only {
                host.set_kernel_readonly(va, len as usize, executable, None)
                    .unwrap();
            } else {
                host.set_fork_readonly(va, len as usize, None).unwrap();
            }
        }

        let mut guest = image;
        let base = guest.base();
        let mut bytes = guest.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let words: Vec<AtomicU64> = bytes
            .chunks_exact(8)
            .map(|w| AtomicU64::new(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let maintenance = CallerInvalidatesAsid;
        let live = unsafe {
            PrimaryTableWords::new(
                words.as_ptr().cast_mut(),
                base,
                words.len() * 8,
                &maintenance,
            )
        }
        .unwrap();
        let mut linked_total = 0;
        for &(va, len, kernel_only, executable) in &ranges {
            let op = guest.fork_arm_op(va, len, kernel_only, executable, false);
            let plan = descriptor_txn::plan_descriptor_op(&live, SubstrateGpa(base), op).unwrap();
            let grants: TableGrants = guest.reserve_table_grants(plan.table_grants, None).unwrap();
            let outcome = execute_descriptor_op(
                &live,
                SubstrateGpa(base),
                op,
                &grants,
                &mut InlineJournal::new(),
            );
            let DescriptorOutcome::Applied(applied) = outcome else {
                panic!("fork arm {va:#x} not applied: {outcome:?}");
            };
            linked_total += usize::from(applied.tables_linked);
        }
        assert!(linked_total >= 2, "range edges inside coarse blocks split");

        let guest_bytes: Vec<u8> = words
            .iter()
            .flat_map(|w| w.load(core::sync::atomic::Ordering::Relaxed).to_le_bytes())
            .collect();
        for &(va, len, _, _) in &ranges {
            let mut page = va.saturating_sub(2 * PT_PAGE);
            while page < va + len + 2 * PT_PAGE {
                let host_leaf = terminal_descriptor(host.debug_walk(page));
                let guest_leaf = terminal_descriptor(walk_descriptors(&guest_bytes, base, page));
                assert_eq!(
                    host_leaf, guest_leaf,
                    "page {page:#x}: host {host_leaf:#x} guest {guest_leaf:#x}"
                );
                page += PT_PAGE;
            }
        }
    }

    /// A host-published writable leaf (no EL1 grant produced it) is invisible
    /// to EL1 COW: fork arming left it read-only without the EL1-private tags,
    /// so EL1 declined every write to it (`NotEl1Private`). Arming a guest-lane
    /// MM's compound range adopts it: the classifier then sees an armed leaf
    /// with recorded write intent, and a non-adopting arm still does not.
    #[test]
    fn fork_arming_adopts_host_published_leaves_for_el1_cow() {
        use descriptor_txn::guest_cow::{GuestCowClass, GuestCowNotArmed};
        const TWO_MIB: u64 = 1 << 21;
        let va = LINUX_MMAP_BASE + 4 * TWO_MIB + 3 * PT_PAGE;
        let mut image = hvpatch_manager();
        image
            .set_rw(va & !(TWO_MIB - 1), 2 * TWO_MIB as usize, false, None)
            .unwrap();
        let mut plain = image.snapshot_image().unwrap();
        plain
            .set_fork_readonly(va, 4 * PT_PAGE as usize, None)
            .unwrap();
        let leaf = terminal_descriptor(plain.debug_walk(va));
        assert_eq!(leaf & SW_EL1_PRIVATE, 0, "host arming leaves it untagged");
        image
            .set_fork_readonly_adopting(va, 4 * PT_PAGE as usize, None)
            .unwrap();
        for page in 0..4 {
            let leaf = terminal_descriptor(image.debug_walk(va + page * PT_PAGE));
            assert!(
                el1_cow(leaf),
                "page {page}: armed and EL1-private: {leaf:#x}"
            );
            assert_ne!(leaf & SW_EL1_MAY_WRITE, 0, "recorded Linux write intent");
            assert_eq!(leaf & AP_MASK, AP_RO, "hardware write restriction");
            assert!(descriptor_txn::guest_cow::is_guest_cow_write_leaf(3, leaf));
        }
        // A read-only leaf has no recoverable write intent: never adopted.
        let mut ro = image.snapshot_image().unwrap();
        let ro_va = LINUX_MMAP_BASE + 8 * TWO_MIB;
        ro.set_rw(ro_va, 2 * TWO_MIB as usize, false, None).unwrap();
        ro.set_readonly(ro_va + PT_PAGE, 2 * PT_PAGE as usize, false, None)
            .unwrap();
        ro.set_fork_readonly_adopting(ro_va + PT_PAGE, 2 * PT_PAGE as usize, None)
            .unwrap();
        let leaf = terminal_descriptor(ro.debug_walk(ro_va + PT_PAGE));
        assert_eq!(leaf & SW_EL1_PRIVATE, 0);
        let _ = (GuestCowClass::AlreadyWritable, GuestCowNotArmed::Unmapped);
    }

    #[test]
    fn imported_private_block_admission_uses_one_table_and_preserves_neighbor() {
        let mut image = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 32 * (1 << 21);
        let len = 1 << 21;
        image.set_rw(va, 2 * len, false, None).unwrap();
        let neighbor = terminal_descriptor(image.debug_walk(va + len as u64));
        let before = image.pool_stats().0;
        image
            .apply_rule(
                va,
                len,
                TerminalRule::Pt {
                    op: Some(PtOp::ReadWrite { exec: false }),
                    reset_retired: false,
                    deny_host_buffers: false,
                    fork_arm: true,
                    adopt_private: true,
                },
                None,
            )
            .unwrap();
        assert_eq!(image.pool_stats().0 - before, 1);
        for page in 0..512 {
            assert!(descriptor_txn::guest_cow::is_guest_cow_write_leaf(
                3,
                terminal_descriptor(image.debug_walk(va + page * 4096))
            ));
        }
        assert_eq!(
            terminal_descriptor(image.debug_walk(va + len as u64)),
            neighbor
        );
    }

    #[test]
    fn imported_private_source_is_armed_after_permission_admission() {
        use descriptor_txn::guest_cow::is_guest_cow_write_leaf;
        let source = 0x9000_0000 | USER_PAGE_FLAGS | AP_RO | UXN;
        let rule = TerminalRule::Pt {
            op: Some(PtOp::ReadWrite { exec: false }),
            reset_retired: false,
            deny_host_buffers: false,
            fork_arm: true,
            adopt_private: true,
        };
        let admitted = terminal_rule_edit(true, rule, source, 3, 0x4000_0000)
            .unwrap()
            .unwrap();
        assert!(
            is_guest_cow_write_leaf(3, admitted),
            "private import must enter guest COW: {admitted:#x}"
        );
        assert_eq!(admitted & PA_MASK_4KIB, source & PA_MASK_4KIB);
        assert_eq!(admitted & AP_MASK, AP_RO);
    }

    /// A recycled image is overwritten by `snapshot_into`, whose result must
    /// equal `snapshot_image`: an offline copy is never guest-owned, even
    /// when the pooled image last belonged to a guest-owned MM.
    #[test]
    fn recycled_snapshot_is_an_offline_host_owned_image() {
        let mut source = hvpatch_manager();
        source.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        assert_eq!(
            source.snapshot_image().unwrap().live_descriptor_owner(),
            LiveDescriptorOwner::Host
        );
        let mut recycled = hvpatch_manager();
        recycled.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        source.snapshot_into(&mut recycled).unwrap();
        assert_eq!(recycled.live_descriptor_owner(), LiveDescriptorOwner::Host);
    }

    /// Every host-originated range rule produces the same terminal
    /// descriptor through the guest executor (`DescriptorOp::Terminal`) as
    /// through the host editor (`apply_rule`), page for page, across
    /// prepared/resident/retired EL1 grants, untagged coarse alias blocks,
    /// partially covered blocks and never-populated reservations. This is
    /// the proof that host mprotect/munmap/BUS-tail edits submitted on the
    /// guest lane keep exactly the host lane's semantics.
    #[test]
    fn guest_terminal_rules_match_the_host_editor_page_for_page() {
        use core::sync::atomic::AtomicU64;
        use descriptor_txn::{
            CallerInvalidatesAsid, DescriptorOutcome, InlineJournal, PrimaryTableWords,
            TableGrants, execute_descriptor_op,
        };
        const TWO_MIB: u64 = 1 << 21;
        // Bulk-prepare four pages; only `fault_page` becomes resident.
        let publish = |image: &mut PageTableManager, va: u64, ipa: u64, fault_page: u64| {
            image
                .publish_private_pages(
                    GuestLeafPublication {
                        va,
                        ipa,
                        len: 4 * PT_PAGE,
                        writable: true,
                        executable: false,
                    },
                    va + fault_page.min(3) * PT_PAGE,
                    None,
                )
                .unwrap();
        };
        let rw = |exec| TerminalRule::pt(PtOp::ReadWrite { exec });
        let ro = |exec| TerminalRule::pt(PtOp::ReadOnly { exec });
        let composed = |op, reset_retired, deny_host_buffers, fork_arm| TerminalRule::Pt {
            op,
            reset_retired,
            deny_host_buffers,
            fork_arm,
            adopt_private: false,
        };
        // Each case gets its own disjoint neighbourhood: (va, len, rule).
        let mut image = hvpatch_manager();
        let base_va = LINUX_MMAP_BASE + 0x40_0000;
        let frame = LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        let mut cases = Vec::new();
        let mut slot = 0;
        let mut next = |image: &mut PageTableManager, fault_page: u64| {
            let va = base_va + slot * 0x10_0000;
            publish(image, va, frame + slot * 0x10_0000, fault_page);
            slot += 1;
            va
        };
        // Protection over prepared+resident grants, with and without exec.
        let va = next(&mut image, 2);
        cases.push((va, 4 * PT_PAGE, rw(false)));
        let va = next(&mut image, 2);
        cases.push((va + PT_PAGE, 2 * PT_PAGE, ro(true)));
        // Host-forwarded PROT_NONE that denies host buffers.
        let va = next(&mut image, 3);
        cases.push((
            va,
            4 * PT_PAGE,
            composed(Some(PtOp::Invalidate), false, true, false),
        ));
        // munmap retirement, then a new mapping over the retired grant.
        let va = next(&mut image, 2);
        cases.push((va, 4 * PT_PAGE, TerminalRule::pt(PtOp::Retire)));
        let retired_va = next(&mut image, 4);
        image
            .apply(retired_va, 4 * PT_PAGE as usize, PtOp::Retire, None)
            .unwrap();
        cases.push((
            retired_va,
            4 * PT_PAGE,
            composed(Some(PtOp::ReadWrite { exec: false }), true, false, false),
        ));
        let reset_only = next(&mut image, 4);
        image
            .apply(reset_only, 2 * PT_PAGE as usize, PtOp::Retire, None)
            .unwrap();
        cases.push((reset_only, 2 * PT_PAGE, composed(None, true, false, false)));
        // mprotect to write over a fork-armed range re-arms it.
        let va = next(&mut image, 4);
        image
            .set_fork_readonly(va, 4 * PT_PAGE as usize, None)
            .unwrap();
        cases.push((
            va,
            4 * PT_PAGE,
            composed(Some(PtOp::ReadWrite { exec: false }), false, false, true),
        ));
        // BUS tail over prepared-only leaves.
        let va = next(&mut image, 0);
        cases.push((va + PT_PAGE, 3 * PT_PAGE, TerminalRule::BusFault));
        // Coarse untagged alias blocks: whole, bisected, and a never-populated
        // reservation (empty terminals).
        let block_va = LINUX_MMAP_BASE + 8 * TWO_MIB;
        image
            .set_rw(block_va, 2 * TWO_MIB as usize, false, None)
            .unwrap();
        cases.push((block_va, TWO_MIB, ro(false)));
        cases.push((
            block_va + TWO_MIB + 3 * PT_PAGE,
            5 * PT_PAGE,
            TerminalRule::pt(PtOp::Retire),
        ));
        cases.push((
            LINUX_MMAP_BASE + 20 * TWO_MIB + PT_PAGE,
            3 * PT_PAGE,
            rw(true),
        ));
        // Fork arming that adopts host-published writable leaves as
        // EL1-private: one rule, both venues.
        let adopt_va = LINUX_MMAP_BASE + 12 * TWO_MIB;
        image
            .set_rw(adopt_va, 2 * TWO_MIB as usize, false, None)
            .unwrap();
        cases.push((
            adopt_va + 3 * PT_PAGE,
            4 * PT_PAGE,
            TerminalRule::fork_arm(true),
        ));
        image.declare_live_hardware_image();

        let original = image.snapshot_image().unwrap();
        let mut host = image.snapshot_image().unwrap();
        host.declare_live_hardware_image();
        for &(va, len, rule) in &cases {
            host.apply_rule(va, len as usize, rule, None).unwrap();
        }
        // Not vacuous: every case edits at least one page.
        for &(va, len, rule) in &cases {
            assert!(
                (0..len / PT_PAGE).any(|page| {
                    let page = va + page * PT_PAGE;
                    terminal_descriptor(host.debug_walk(page))
                        != terminal_descriptor(original.debug_walk(page))
                }),
                "{rule:?} at {va:#x} changed nothing"
            );
        }

        let mut guest = image;
        let base = guest.base();
        let mut bytes = guest.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let words: Vec<AtomicU64> = bytes
            .chunks_exact(8)
            .map(|w| AtomicU64::new(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let maintenance = CallerInvalidatesAsid;
        let live = unsafe {
            PrimaryTableWords::new(
                words.as_ptr().cast_mut(),
                base,
                words.len() * 8,
                &maintenance,
            )
        }
        .unwrap();
        for &(va, len, rule) in &cases {
            let op = guest.terminal_op(va, len, rule);
            let plan = descriptor_txn::plan_descriptor_op(&live, SubstrateGpa(base), op).unwrap();
            let grants: TableGrants = guest.reserve_table_grants(plan.table_grants, None).unwrap();
            let outcome = execute_descriptor_op(
                &live,
                SubstrateGpa(base),
                op,
                &grants,
                &mut InlineJournal::new(),
            );
            assert!(
                matches!(outcome, DescriptorOutcome::Applied(_)),
                "{rule:?} at {va:#x}: {outcome:?}"
            );
        }

        let guest_bytes: Vec<u8> = words
            .iter()
            .flat_map(|w| w.load(core::sync::atomic::Ordering::Relaxed).to_le_bytes())
            .collect();
        for &(va, len, rule) in &cases {
            let mut page = va.saturating_sub(2 * PT_PAGE);
            while page < va + len + 2 * PT_PAGE {
                let host_leaf = terminal_descriptor(host.debug_walk(page));
                let guest_leaf = terminal_descriptor(walk_descriptors(&guest_bytes, base, page));
                assert_eq!(
                    host_leaf, guest_leaf,
                    "{rule:?} page {page:#x}: host {host_leaf:#x} guest {guest_leaf:#x}"
                );
                page += PT_PAGE;
            }
        }
    }

    /// The per-terminal refusals the host editor reports as `BadAddress`
    /// roll the whole guest transaction back.
    #[test]
    fn guest_terminal_rule_refusals_roll_back() {
        use core::sync::atomic::AtomicU64;
        use descriptor_txn::{
            CallerInvalidatesAsid, DescriptorOutcome, DescriptorRefusal, InlineJournal,
            PrimaryTableWords, TableGrants, execute_descriptor_op,
        };
        let mut image = hvpatch_manager();
        let va = LINUX_MMAP_BASE + 0x40_0000;
        image
            .publish_private_pages(
                GuestLeafPublication {
                    va,
                    ipa: LINUX_HVPATCH_GLOBAL_FRAME_BASE,
                    len: 4 * PT_PAGE,
                    writable: true,
                    executable: false,
                },
                va + 2 * PT_PAGE,
                None,
            )
            .unwrap();
        image.declare_live_hardware_image();
        let base = image.base();
        let mut bytes = image.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let words: Vec<AtomicU64> = bytes
            .chunks_exact(8)
            .map(|w| AtomicU64::new(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let snapshot = |words: &[AtomicU64]| -> Vec<u64> {
            words
                .iter()
                .map(|w| w.load(core::sync::atomic::Ordering::Relaxed))
                .collect()
        };
        let maintenance = CallerInvalidatesAsid;
        let live = unsafe {
            PrimaryTableWords::new(
                words.as_ptr().cast_mut(),
                base,
                words.len() * 8,
                &maintenance,
            )
        }
        .unwrap();
        for (rule, refusal) in [
            // A new mapping over a live grant.
            (
                TerminalRule::Pt {
                    op: Some(PtOp::ReadWrite { exec: false }),
                    reset_retired: true,
                    deny_host_buffers: false,
                    fork_arm: false,
                    adopt_private: false,
                },
                DescriptorRefusal::Occupied,
            ),
            // A BUS tail over a resident page.
            (TerminalRule::BusFault, DescriptorRefusal::AlreadyValid),
        ] {
            let before = snapshot(&words);
            let op = image.terminal_op(va, 4 * PT_PAGE, rule);
            let outcome = execute_descriptor_op(
                &live,
                SubstrateGpa(base),
                op,
                &TableGrants::NONE,
                &mut InlineJournal::new(),
            );
            assert!(
                matches!(
                    outcome,
                    DescriptorOutcome::Refused(r) | DescriptorOutcome::RolledBack(r) if r == refusal
                ),
                "{rule:?}: {outcome:?}"
            );
            assert_eq!(snapshot(&words), before, "{rule:?} left stores behind");
            let mut host = image.snapshot_image().unwrap();
            assert_eq!(
                host.apply_rule(va, 4 * PT_PAGE as usize, rule, None),
                Err(PageTableError::BadAddress)
            );
        }
    }

    /// The host alias teardown (`unmap_aliased`: retire, then reclaim every
    /// spare sub-table left reclaimable) and the guest executor's reclaiming
    /// `Terminal{Retire}` produce the same terminal descriptor and the same
    /// walk for every page, and return the same set of tables to the pool:
    /// a freed L3, a partially unmapped alias that frees nothing, a split
    /// 2 MiB alias block that keeps its new table, two L3 tables plus the L2
    /// they emptied, and an invalid identity block whose split table is
    /// dropped again at once.
    #[test]
    fn guest_unmap_aliased_matches_the_host_editor_and_frees_the_same_tables() {
        use core::sync::atomic::AtomicU64;
        use descriptor_txn::{
            CallerInvalidatesAsid, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId,
            InlineJournal, PrimaryTableWords, execute_descriptor_txn,
        };
        const TWO_MIB: u64 = 1 << 21;
        const ONE_GIB: u64 = 1 << 30;
        let g = LINUX_HIGH_VA_THRESHOLD;
        let g2 = g + ONE_GIB;
        let ipa = LINUX_ALIAS_IPA_BASE;
        let mut image = hvpatch_manager();
        image
            .map_aliased(g + TWO_MIB, ipa, PT_PAGE, RWX, None)
            .unwrap();
        image
            .map_aliased(g + 2 * TWO_MIB, ipa + 0x10_0000, 2 * PT_PAGE, RWX, None)
            .unwrap();
        // Keeps G's L2 table live.
        image
            .map_aliased(g + 3 * TWO_MIB, ipa + 0x20_0000, PT_PAGE, RWX, None)
            .unwrap();
        image
            .map_aliased(g + 4 * TWO_MIB, ipa + 0x40_0000, TWO_MIB, RX, None)
            .unwrap();
        image
            .map_aliased(g2, ipa + 0x60_0000, PT_PAGE, RWX, None)
            .unwrap();
        image
            .map_aliased(g2 + 4 * TWO_MIB, ipa + 0x70_0000, PT_PAGE, RWX, None)
            .unwrap();
        let ident_va = g + 8 * TWO_MIB;
        let l2_table = image.debug_walk(g + TWO_MIB)[1] & PA_MASK_TABLE;
        image
            .write_desc_for_test(
                l2_table + indices(ident_va)[2] as u64 * 8,
                (ident_va & PA_MASK_2MIB) | (USER_BLOCK_FLAGS & !VALID) | NON_GLOBAL,
            )
            .unwrap();
        image.declare_live_hardware_image();
        let unmaps = [
            (g + TWO_MIB, PT_PAGE),
            (g + 2 * TWO_MIB, PT_PAGE),
            (g + 4 * TWO_MIB + 8 * PT_PAGE, 2 * PT_PAGE),
            (g2, 5 * TWO_MIB),
            (ident_va + PT_PAGE, 2 * PT_PAGE),
        ];

        let original = image.snapshot_image().unwrap();
        let mut host = image.snapshot_image().unwrap();
        host.declare_live_hardware_image();
        host.set_multi_vcpu(false);
        let sorted = |mut v: Vec<u64>| {
            v.sort_unstable();
            v
        };
        // The host pool after each unmap.
        let mut host_pools = Vec::new();
        for &(va, len) in &unmaps {
            host.unmap_aliased(va, len as usize, None).unwrap();
            host_pools.push((sorted(host.free_tables.clone()), host.pool_stats()));
        }

        let mut guest = image;
        let base = guest.base();
        let mut bytes = guest.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let words: Vec<AtomicU64> = bytes
            .chunks_exact(8)
            .map(|w| AtomicU64::new(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let maintenance = CallerInvalidatesAsid;
        let live = unsafe {
            PrimaryTableWords::new(
                words.as_ptr().cast_mut(),
                base,
                words.len() * 8,
                &maintenance,
            )
        }
        .unwrap();
        let mut guest_reclaimed = Vec::new();
        let expected_reclaims = [1, 0, 0, 3, 1];
        for (generation, &(va, len)) in unmaps.iter().enumerate() {
            let DescriptorOp::Terminal { span, mut edit } = guest.unmap_aliased_op(va, len) else {
                unreachable!()
            };
            let op = DescriptorOp::Terminal { span, edit };
            let plan = descriptor_txn::plan_descriptor_op(&live, SubstrateGpa(base), op).unwrap();
            edit.reclaim_budget = plan.reclaimed_tables as u8;
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: core::num::NonZeroU64::new(9).unwrap(),
                    generation: core::num::NonZeroU64::new(generation as u64 + 1).unwrap(),
                },
                root: SubstrateGpa(base),
                op: DescriptorOp::Terminal { span, edit },
                tables: guest.reserve_table_grants(plan.table_grants, None).unwrap(),
            };
            let receipt =
                execute_descriptor_txn(&live, SubstrateGpa(base), &txn, &mut InlineJournal::new());
            assert!(
                matches!(receipt.outcome, DescriptorOutcome::Applied(_)),
                "unmap {va:#x}: {receipt:?}"
            );
            let verified = guest
                .settle_guest_descriptor_receipt(&txn, &receipt)
                .expect("authentic receipt");
            // Not vacuous: G's first L3; nothing for a partial unmap or a
            // split block; G2's two L3s and their L2; the dropped split of
            // the identity block.
            assert_eq!(
                verified.reclaimed_tables().len(),
                expected_reclaims[generation],
                "unmap {va:#x}"
            );
            guest_reclaimed.extend_from_slice(verified.reclaimed_tables());
            // The same tables came back: after every unmap the free pools
            // (and bump cursors) agree.
            assert_eq!(
                (sorted(guest.free_tables.clone()), guest.pool_stats()),
                host_pools[generation],
                "unmap {va:#x}"
            );
        }
        assert!(!guest_reclaimed.contains(&l2_table), "G's L2 stays live");
        assert!(guest_reclaimed.contains(&(original.debug_walk(g2)[1] & PA_MASK_TABLE)));

        let guest_bytes: Vec<u8> = words
            .iter()
            .flat_map(|w| w.load(core::sync::atomic::Ordering::Relaxed).to_le_bytes())
            .collect();
        let mut probes: Vec<u64> = Vec::new();
        for &(va, len) in &unmaps {
            let mut page = va.saturating_sub(2 * PT_PAGE);
            while page < va + len + 2 * PT_PAGE {
                probes.push(page);
                page += PT_PAGE;
            }
        }
        probes.extend([
            g + 3 * TWO_MIB,
            g2 + 3 * TWO_MIB,
            ident_va + TWO_MIB - PT_PAGE,
        ]);
        for page in probes {
            let host_walk = host.debug_walk(page);
            let guest_walk = walk_descriptors(&guest_bytes, base, page);
            assert_eq!(
                host_walk, guest_walk,
                "page {page:#x}: host {host_walk:x?} guest {guest_walk:x?}"
            );
        }
        assert_eq!(host.debug_walk(g2)[1], 0, "G2's L2 table was unlinked");
        assert_eq!(host.debug_walk(g + TWO_MIB)[2], 0, "G's first L3 unlinked");
        assert!(host.is_valid(g + 3 * TWO_MIB) && host.is_valid(g + 2 * TWO_MIB + PT_PAGE));
    }

    /// On the guest-owned live lane an alias munmap is one EL1 transaction:
    /// the host plans and narrows the reclaim budget, EL1 unlinks under
    /// break-before-make, the freed table crosses the slot in the receipt,
    /// and settlement returns it exactly once so the host reissues it.
    #[test]
    fn guest_alias_unmap_returns_the_freed_table_to_the_host_allocator() {
        use descriptor_txn::{DescriptorOutcome, DescriptorTxnId, DescriptorTxnSlot};
        const TWO_MIB: u64 = 1 << 21;
        let (mut mgr, resolver) = create_live_fixture();
        let g = LINUX_HIGH_VA_THRESHOLD;
        mgr.begin_undo().unwrap();
        mgr.map_aliased(g + TWO_MIB, LINUX_ALIAS_IPA_BASE, PT_PAGE, RWX, None)
            .unwrap();
        mgr.map_aliased(
            g + 2 * TWO_MIB,
            LINUX_ALIAS_IPA_BASE + 0x10_0000,
            PT_PAGE,
            RWX,
            None,
        )
        .unwrap();
        unsafe { mgr.sync_to_host(&*resolver).unwrap() };
        mgr.commit_undo();
        mgr.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        let l3 = mgr.debug_walk(g + TWO_MIB)[2] & PA_MASK_TABLE;

        let id = DescriptorTxnId {
            mm_key: core::num::NonZeroU64::new(41).unwrap(),
            generation: core::num::NonZeroU64::new(1).unwrap(),
        };
        let before = live_arena_bytes(&resolver);
        let txn = mgr
            .prepare_guest_descriptor_txn(id, mgr.unmap_aliased_op(g + TWO_MIB, PT_PAGE), None)
            .expect("plan");
        assert_eq!(
            live_arena_bytes(&resolver),
            before,
            "planning stores nothing"
        );
        assert_eq!(txn.op.reclaim_budget(), 1, "narrowed to the plan");
        assert!(txn.tables.is_empty());

        let slot = DescriptorTxnSlot::new();
        assert!(slot.submit(&txn));
        let maintenance = RecordingMaintenance::default();
        let receipt = guest_apply(&resolver, &slot, 41, &maintenance).expect("claimed");
        assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
        assert!(
            maintenance
                .invalidations
                .borrow()
                .contains(&(g + TWO_MIB, TWO_MIB)),
            "the unlinked entry's whole span is invalidated before the receipt"
        );
        let host_receipt = slot.take_receipt(id).unwrap();
        let free_before = mgr.free_tables.len();
        let verified = mgr
            .settle_guest_descriptor_receipt(&txn, &host_receipt)
            .expect("authentic receipt");
        assert_eq!(verified.reclaimed_tables(), &[l3]);
        assert_eq!(mgr.free_tables.len(), free_before + 1);
        assert_eq!(mgr.translate(g + TWO_MIB), None);
        assert_eq!(mgr.debug_walk(g + TWO_MIB)[2], 0);
        assert_eq!(
            mgr.translate(g + 2 * TWO_MIB),
            Some(LINUX_ALIAS_IPA_BASE + 0x10_0000),
            "the sibling alias keeps its table"
        );
        // Settling the same receipt again would free the page twice.
        assert_eq!(
            mgr.settle_guest_descriptor_receipt(&txn, &host_receipt),
            Err(GuestTxnSettleError::Receipt(
                descriptor_txn::ReceiptError::InconsistentReceipt
            ))
        );
        assert_eq!(mgr.free_tables.len(), free_before + 1);
        // The next grant reissues the reclaimed page.
        let grants = mgr.reserve_table_grants(1, None).unwrap();
        assert_eq!(grants.as_slice(), &[l3]);
    }

    /// Receipts naming tables the host allocator never issued, or already
    /// holds free, are refused whole: nothing returns to the pool.
    #[test]
    fn guest_reclaim_settlement_refuses_tables_the_allocator_does_not_own() {
        use core::sync::atomic::AtomicU64;
        use descriptor_txn::{
            CallerInvalidatesAsid, DescriptorApplied, DescriptorOutcome, DescriptorReceipt,
            DescriptorTxn, DescriptorTxnId, InlineJournal, PrimaryTableWords, ReceiptError,
            ReclaimedTables, execute_descriptor_txn,
        };
        const TWO_MIB: u64 = 1 << 21;
        let g = LINUX_HIGH_VA_THRESHOLD;
        let mut image = hvpatch_manager();
        image
            .map_aliased(g + TWO_MIB, LINUX_ALIAS_IPA_BASE, PT_PAGE, RWX, None)
            .unwrap();
        image
            .map_aliased(
                g + 2 * TWO_MIB,
                LINUX_ALIAS_IPA_BASE + 0x10_0000,
                PT_PAGE,
                RWX,
                None,
            )
            .unwrap();
        image.declare_live_hardware_image();
        let l3 = image.debug_walk(g + TWO_MIB)[2] & PA_MASK_TABLE;
        let base = image.base();
        let mut bytes = image.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let words: Vec<AtomicU64> = bytes
            .chunks_exact(8)
            .map(|w| AtomicU64::new(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let maintenance = CallerInvalidatesAsid;
        let live = unsafe {
            PrimaryTableWords::new(
                words.as_ptr().cast_mut(),
                base,
                words.len() * 8,
                &maintenance,
            )
        }
        .unwrap();
        let descriptor_txn::DescriptorOp::Terminal { span, mut edit } =
            image.unmap_aliased_op(g + TWO_MIB, PT_PAGE)
        else {
            unreachable!()
        };
        edit.reclaim_budget = 2;
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: core::num::NonZeroU64::new(3).unwrap(),
                generation: core::num::NonZeroU64::new(1).unwrap(),
            },
            root: SubstrateGpa(base),
            op: descriptor_txn::DescriptorOp::Terminal { span, edit },
            tables: descriptor_txn::TableGrants::NONE,
        };
        let receipt =
            execute_descriptor_txn(&live, SubstrateGpa(base), &txn, &mut InlineJournal::new());
        let DescriptorOutcome::Applied(genuine) = receipt.outcome else {
            panic!("{receipt:?}");
        };
        assert_eq!(genuine.reclaimed.as_slice(), &[l3]);
        let forged = |pages: &[u64]| DescriptorReceipt {
            outcome: DescriptorOutcome::Applied(DescriptorApplied {
                reclaimed: ReclaimedTables::from_pages(pages).unwrap(),
                ..genuine
            }),
            ..receipt
        };
        let primary_end = base + image.arenas[0].capacity as u64;
        let never_issued = base + image.arenas[0].next_free;
        let already_free = {
            let spare = image.alloc_table_for_test().unwrap();
            image.release_table_grants(&[spare]).unwrap();
            spare
        };
        for pages in [
            // Spare-tail pages the bump cursor never issued.
            &[never_issued][..],
            &[primary_end - PT_PAGE],
            // A page the allocator already holds free.
            &[l3, already_free],
            // Duplicates and boot tables fail verification itself.
            &[l3, l3],
            &[base + PT_PAGE],
        ] {
            let free_before = image.free_tables.clone();
            let next_before = image.arenas[0].next_free;
            assert_eq!(
                image.settle_guest_descriptor_receipt(&txn, &forged(pages)),
                Err(GuestTxnSettleError::Receipt(
                    ReceiptError::InconsistentReceipt
                )),
                "{pages:x?}"
            );
            assert_eq!(image.free_tables, free_before, "{pages:x?}");
            assert_eq!(image.arenas[0].next_free, next_before);
        }
        let verified = image
            .settle_guest_descriptor_receipt(&txn, &receipt)
            .expect("the genuine receipt settles");
        assert_eq!(verified.reclaimed_tables(), &[l3]);
        assert_eq!(image.free_tables.iter().filter(|&&pa| pa == l3).count(), 1);
    }

    /// The two idle EL1 COW copy-alias leaves are an invariant of every
    /// HVPatch MM image: table descriptors down to L3, and each leaf invalid,
    /// AP=00 (EL1-only) and recording its own VA, exactly as
    /// `copy_window::with_cow_copy_aliases` requires. No host range edit,
    /// coalesce or reclaim may change that.
    mod cow_copy_window_provisioning {
        use super::*;
        use crate::aarch64::descriptor_txn::copy_window::{
            COW_COPY_WINDOW_BASE as WINDOW, COW_COPY_WINDOW_LEN,
        };
        use carrick_mem::memory::{LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE};

        const TWO_MIB: u64 = 1 << 21;

        fn hvpatch() -> PageTableManager {
            PageTableManager::new(
                stage1_hvpatch_page_tables(),
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
            )
        }

        fn window_leaves(mgr: &PageTableManager) -> [u64; 2] {
            [WINDOW, WINDOW + PT_PAGE].map(|va| mgr.try_debug_walk(va).unwrap()[3])
        }

        fn assert_idle(mgr: &PageTableManager, why: &str) {
            for va in [WINDOW, WINDOW + PT_PAGE] {
                let walk = mgr.try_debug_walk(va).unwrap();
                for (level, descriptor) in walk.iter().take(3).enumerate() {
                    assert_eq!(
                        descriptor & TYPE_BITS,
                        TYPE_TABLE_OR_PAGE,
                        "{why}: L{level} of {va:#x} is not a table descriptor: {walk:x?}"
                    );
                }
                assert_eq!(walk[3] & VALID, 0, "{why}: {va:#x} translates: {walk:x?}");
                assert_eq!(walk[3] & AP_MASK, 0, "{why}: {va:#x} admits EL0: {walk:x?}");
                assert_eq!(
                    walk[3] & PA_MASK_4KIB,
                    va,
                    "{why}: {va:#x} lost its identity output: {walk:x?}"
                );
            }
        }

        #[test]
        fn hvpatch_boot_image_provisions_the_idle_window() {
            const {
                assert!(WINDOW >= LINUX_EL1_KERNEL_BASE);
                assert!(
                    WINDOW + COW_COPY_WINDOW_LEN <= LINUX_EL1_KERNEL_BASE + LINUX_EL1_KERNEL_SIZE
                );
            }
            assert_idle(&hvpatch(), "boot image");
        }

        /// Exec rebuild remaps every kernel-only image range with
        /// `map_kernel_aliased`, including the whole 64 MiB EL1 region, at
        /// its identity IPA or a leased one.
        #[test]
        fn kernel_alias_remap_of_the_el1_region_keeps_the_window_idle() {
            for ipa in [LINUX_EL1_KERNEL_BASE, LINUX_HVPATCH_GLOBAL_FRAME_BASE] {
                assert!(ipa.is_multiple_of(TWO_MIB));
                let mut mgr = hvpatch();
                let before = window_leaves(&mgr);
                mgr.map_kernel_aliased(LINUX_EL1_KERNEL_BASE, ipa, LINUX_EL1_KERNEL_SIZE, None)
                    .expect("remap EL1 region");
                assert_idle(&mgr, "EL1 region kernel remap");
                assert_eq!(window_leaves(&mgr), before);
                for va in [
                    LINUX_EL1_KERNEL_BASE,
                    WINDOW - PT_PAGE,
                    WINDOW + COW_COPY_WINDOW_LEN,
                    LINUX_EL1_KERNEL_BASE + LINUX_EL1_KERNEL_SIZE - PT_PAGE,
                ] {
                    assert_eq!(
                        mgr.translate(va),
                        Some(ipa + (va - LINUX_EL1_KERNEL_BASE)),
                        "{va:#x} keeps the requested kernel alias"
                    );
                }
            }
        }

        /// Fork arming (host `set_kernel_readonly`, `set_fork_readonly`) and
        /// every other protection edit over a range containing the window
        /// steps around it: neither leaf becomes a valid mapping of the IPA
        /// its VA names.
        #[test]
        fn range_edits_over_the_el1_region_never_touch_the_window() {
            type Edit = fn(&mut PageTableManager) -> Result<PageTableApplyOutcome, PageTableError>;
            const LEN: usize = LINUX_EL1_KERNEL_SIZE as usize;
            let edits: [(&str, Edit); 8] = [
                ("kernel ro", |m| {
                    m.set_kernel_readonly(LINUX_EL1_KERNEL_BASE, LEN, false, None)
                }),
                ("kernel rx", |m| {
                    m.set_kernel_readonly(LINUX_EL1_KERNEL_BASE, LEN, true, None)
                }),
                ("fork ro", |m| {
                    m.set_fork_readonly(LINUX_EL1_KERNEL_BASE, LEN, None)
                }),
                ("ro", |m| {
                    m.set_readonly(LINUX_EL1_KERNEL_BASE, LEN, false, None)
                }),
                ("rw", |m| m.set_rw(LINUX_EL1_KERNEL_BASE, LEN, false, None)),
                ("prot none", |m| {
                    m.set_prot_none(LINUX_EL1_KERNEL_BASE, LEN, None)
                }),
                ("retire", |m| m.invalidate(LINUX_EL1_KERNEL_BASE, LEN, None)),
                ("unmap", |m| {
                    m.unmap_aliased(LINUX_EL1_KERNEL_BASE, LEN, None)
                }),
            ];
            for offline in [false, true] {
                for (name, edit) in edits {
                    let mut mgr = hvpatch();
                    if offline {
                        mgr.declare_offline_private_image();
                    }
                    let before = window_leaves(&mgr);
                    edit(&mut mgr).unwrap_or_else(|e| panic!("{name}: {e:?}"));
                    assert_idle(&mgr, name);
                    assert_eq!(window_leaves(&mgr), before, "{name} rewrote a window leaf");
                }
            }
        }

        /// An offline fork/exec image coalesces uniform spare tables and
        /// reclaims empty ones. Invalidating every neighbor of the window
        /// makes its L3 table uniform and reclaimable; it must survive both.
        #[test]
        fn offline_coalesce_and_reclaim_keep_the_window_table() {
            let block = WINDOW & !(TWO_MIB - 1);
            let mut mgr = hvpatch();
            mgr.declare_offline_private_image();
            mgr.set_prot_none(block, TWO_MIB as usize, None)
                .expect("invalidate the window's 2 MiB block");
            assert_idle(&mgr, "prot-none coalesce");
            mgr.unmap_aliased(block, TWO_MIB as usize, None)
                .expect("retire the window's 2 MiB block");
            assert_idle(&mgr, "unmap reclaim");
            mgr.reclaim_pending = true;
            mgr.reclaim_all_invalid_tables().expect("sweep");
            assert_idle(&mgr, "reclaim sweep");
            mgr.set_kernel_readonly(block, TWO_MIB as usize, false, None)
                .expect("re-arm the block");
            assert_idle(&mgr, "kernel re-arm");
        }

        /// Single-page editors outside the range rule refuse the window
        /// rather than retarget or revalidate a Carrick-owned leaf.
        #[test]
        fn page_editors_refuse_the_window() {
            let mut mgr = hvpatch();
            let before = window_leaves(&mgr);
            assert_eq!(
                mgr.repoint_preserving_attributes(
                    WINDOW - PT_PAGE,
                    LINUX_HVPATCH_GLOBAL_FRAME_BASE,
                    3 * PT_PAGE,
                    None
                ),
                Err(PageTableError::CarrickOwnedWindow)
            );
            assert_eq!(
                mgr.set_writable_preserving_attributes(WINDOW + PT_PAGE, PT_PAGE as usize, None),
                Err(PageTableError::CarrickOwnedWindow)
            );
            assert_eq!(
                mgr.clear_inaccessible_invalid_fork_leaf(WINDOW),
                Err(PageTableError::CarrickOwnedWindow)
            );
            assert_eq!(window_leaves(&mgr), before);
        }

        /// Provisioning makes the exact idle shape from any predecessor:
        /// a valid kernel block (the compatibility image), a block alias at
        /// another IPA, or leaves some editor revalidated.
        #[test]
        fn provisioning_restores_the_exact_idle_shape() {
            let expected = window_leaves(&hvpatch());
            let mut identity = PageTableManager::new(
                stage1_identity_page_tables(),
                LINUX_PAGE_TABLES_BASE,
                test_layout(),
            );
            identity.set_multi_vcpu(false);
            let mut scoped = hvpatch();
            let mut forged = hvpatch();
            for index in 0..2 {
                let va = WINDOW + index * PT_PAGE;
                let (loc, level) = forged.leaf_offset(va, false, None).unwrap();
                assert_eq!(level, 3);
                forged
                    .write_desc(loc, LINUX_HVPATCH_GLOBAL_FRAME_BASE | KERNEL_PAGE_FLAGS)
                    .unwrap();
            }
            for (name, mgr) in [("identity", &mut identity), ("forged", &mut forged)] {
                mgr.provision_cow_copy_window(None)
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_idle(mgr, name);
            }
            assert_eq!(window_leaves(&forged), expected);
            scoped
                .provision_cow_copy_window(None)
                .expect("reprovision a provisioned image");
            assert_eq!(window_leaves(&scoped), expected, "idempotent");
        }
    }
    #[test]
    fn fork_restriction_never_synthesizes_output_for_absent_terminals() {
        for level in 1..=3 {
            for asid_scoped in [false, true] {
                for rule in [
                    TerminalRule::pt(PtOp::ForkReadOnly),
                    TerminalRule::fork_arm(true),
                ] {
                    assert_eq!(
                        terminal_rule_edit(asid_scoped, rule, 0, level, 0x6002_e4e000),
                        Ok(None),
                        "fork cannot turn an absent terminal into an identity output at level {level}"
                    );
                }
            }
        }
    }
}
