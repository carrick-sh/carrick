//! Exact range and proposal identities, independent of syscall lowering.
pub use carrick_guest_arch::{GuestLen, UserVa};
pub use carrick_mmu_core::HostBackingIdentity;

macro_rules! identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(u64);
        impl $name {
            pub const fn new(raw: u64) -> Option<Self> {
                if raw == 0 { None } else { Some(Self(raw)) }
            }
            pub const fn raw(self) -> u64 {
                self.0
            }
        }
    };
}

identity!(ReservationMm);
identity!(ReservationGeneration);
identity!(ReservationSequence);
identity!(
    /// One incarnation of anonymous memory in one root: minted when a node is
    /// created over retired or never-mapped memory, kept across splits,
    /// protection and attribute edits, never reused within the root. A host
    /// residency fact tagged with it is live only while the page's node still
    /// carries it, so a guest-venue retire kills the fact without telling the
    /// host.
    ReservationIncarnation
);

/// Page-aligned half-open Linux 4 KiB virtual range; never an IPA/host VA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationRange {
    start: u64,
    end: u64,
}
impl ReservationRange {
    pub const fn new(start: u64, end: u64) -> Option<Self> {
        if start < end && start.is_multiple_of(4096) && end.is_multiple_of(4096) {
            Some(Self { start, end })
        } else {
            None
        }
    }
    pub const fn start(self) -> u64 {
        self.start
    }
    pub const fn end(self) -> u64 {
        self.end
    }
    pub const fn len(self) -> u64 {
        self.end - self.start
    }
    pub const fn is_empty(self) -> bool {
        false
    }
    pub const fn contains(self, va: u64) -> bool {
        self.start <= va && va < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReservationProtection(u64);
impl ReservationProtection {
    pub const NONE: Self = Self(0);
    pub const READ_WRITE: Self = Self(3);
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !7 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn permits(self, access: Self) -> bool {
        self.0 & access.0 == access.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ReservationOperation {
    Prepare = 1,
    Protect = 2,
    Retire = 3,
    /// `mremap(2)` relocation: retire `source`, prepare `range` with
    /// `protection`, and move the first `min(source, range)` bytes of
    /// contents (residency) from the source to the destination.
    Move = 4,
}

/// The generation is the *current* committed root revision. The pending
/// sequence is never reused, including after refusal. Every successful edit
/// advances the revision; a stale fault grant cannot authorize a reused VA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationRequest {
    pub mm: ReservationMm,
    pub generation: ReservationGeneration,
    pub sequence: ReservationSequence,
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub operation: ReservationOperation,
    /// `Move` only: the retired source range, disjoint from `range`.
    pub source: Option<ReservationRange>,
}

/// Exact backing service accounting. Zero is valid for a lazy reservation or
/// permission-only transaction; it does not imply anonymous pages are resident.
/// `receipt` identifies the substrate transaction even when no frames moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationBackingReceipt {
    pub receipt: u64,
    pub granted_bytes: u64,
    pub returned_bytes: u64,
}

/// Created only by the admitted exact-MM descriptor/backing transaction owner.
/// Fields are private so policy cannot accidentally treat the request as done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationCompletion {
    request: ReservationRequest,
    backing: ReservationBackingReceipt,
}
impl ReservationCompletion {
    /// # Safety
    /// The caller must hold the exact-MM transaction authority and prove:
    /// - `request` is still the pending proposal with these exact fields;
    /// - backing/inventory grant and return agree with `backing`;
    /// - all descriptor edits, invalidation and required zero-fill completed;
    /// - no observer can see a later descriptor edit before T1's commit.
    ///
    /// Never call this after partial failure or with a mere host syscall result.
    pub unsafe fn after_descriptor_and_backing_commit(
        request: ReservationRequest,
        backing: ReservationBackingReceipt,
    ) -> Option<Self> {
        (backing.receipt != 0
            && backing.granted_bytes.is_multiple_of(4096)
            && backing.returned_bytes.is_multiple_of(4096))
        .then_some(Self { request, backing })
    }
    pub const fn request(self) -> ReservationRequest {
        self.request
    }
    pub const fn backing(self) -> ReservationBackingReceipt {
        self.backing
    }
    pub fn authenticates(self, pending: ReservationRequest) -> bool {
        self.request == pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_completion_is_exact_across_two_mms_and_reused_vas() {
        let request = ReservationRequest {
            mm: ReservationMm::new(17).unwrap(),
            generation: ReservationGeneration::new(2).unwrap(),
            sequence: ReservationSequence::new(3).unwrap(),
            range: ReservationRange::new(0x1000, 0x3000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            operation: ReservationOperation::Prepare,
            source: None,
        };
        // Mock substrate: no descriptors/backing exist in this ABI test.
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        assert!(completion.authenticates(request));
        let mut changed = request;
        changed.mm = ReservationMm::new(18).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.generation = ReservationGeneration::new(3).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.sequence = ReservationSequence::new(4).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.protection = ReservationProtection::NONE;
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.operation = ReservationOperation::Retire;
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.range = ReservationRange::new(0x1000, 0x2000).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.operation = ReservationOperation::Move;
        changed.source = ReservationRange::new(0x8000, 0xa000);
        assert!(!completion.authenticates(changed));
    }
}

/// Attributes of one reservation node, fixed when the node is inserted (host
/// import, host opaque insertion, or a host attribute edit). EL1 edits only
/// plain private anonymous nodes; any edit touching another node is a
/// host-served operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReservationNodeFlags(u32);
impl ReservationNodeFlags {
    pub const EMPTY: Self = Self(0);
    /// The root describes anonymous contents (faults may be planned from it).
    /// Absent: an opaque host mapping that is only a placement obstacle.
    pub const ANONYMOUS: Self = Self(1 << 0);
    /// `MAP_PRIVATE`; absent means `MAP_SHARED`.
    pub const PRIVATE: Self = Self(1 << 1);
    /// `MAP_GROWSDOWN`/stack mapping.
    pub const GROWSDOWN: Self = Self(1 << 2);
    /// `mlock(2)`/`MAP_LOCKED`.
    pub const LOCKED: Self = Self(1 << 3);
    /// `MADV_DONTFORK`: absent from a forked child.
    pub const DONTFORK: Self = Self(1 << 4);
    /// `MADV_WIPEONFORK`: copied to a forked child without contents.
    pub const WIPEONFORK: Self = Self(1 << 5);
    /// `MADV_DONTDUMP`.
    pub const DONTDUMP: Self = Self(1 << 6);
    /// File-backed mapping provenance; source custody remains in HostBacking.
    pub const FILE: Self = Self(1 << 7);
    /// Shared anonymous provenance without private anonymous edit authority.
    pub const SHARED_ANONYMOUS: Self = Self(1 << 8);
    pub const ANONYMOUS_PRIVATE: Self = Self(Self::ANONYMOUS.0 | Self::PRIVATE.0);
    /// Attributes the host sets with `set_flags` (`mlock`, `madvise`).
    pub const ATTRIBUTES: Self = Self(
        Self::GROWSDOWN.0
            | Self::LOCKED.0
            | Self::DONTFORK.0
            | Self::WIPEONFORK.0
            | Self::DONTDUMP.0,
    );
    /// Attributes a private anonymous VMA keeps across EL1 edits: they ride
    /// `mprotect` splits and `mremap` moves, and never make the node
    /// host-owned. `GROWSDOWN` is not one of them (a stack is host-owned).
    pub const CARRIED: Self =
        Self(Self::LOCKED.0 | Self::DONTFORK.0 | Self::WIPEONFORK.0 | Self::DONTDUMP.0);
    const ALL: u32 =
        Self::ANONYMOUS_PRIVATE.0 | Self::ATTRIBUTES.0 | Self::FILE.0 | Self::SHARED_ANONYMOUS.0;

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    /// Non-anonymous mappings participate in placement but cannot be edited.
    pub anonymous: bool,
    /// Insertion-time attributes; anything but plain private anonymous is
    /// host-owned and every EL1 edit touching it forwards.
    pub flags: ReservationNodeFlags,
    pub generation: ReservationGeneration,
    pub host_backing: Option<crate::HostBackingIdentity>,
}

/// Byte charges of committed nodes, whole-root or within one range: every
/// node (`RLIMIT_AS`), `RLIMIT_DATA` nodes, and `LOCKED` anonymous nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charges {
    pub bytes: u64,
    pub data: u64,
    pub locked: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ReservationNodeData {
    pub start: u64,
    pub end: u64,
    pub first: u64,
    pub last: u64,
    pub gap: u64,
    pub bytes: u64,
    pub data: u64,
    /// Subtree bytes of `LOCKED` anonymous nodes.
    pub locked: u64,
    /// This node's [`ReservationIncarnation`]; zero never names one.
    pub incarnation: u64,
    pub left: u32,
    pub right: u32,
    pub height: u32,
    /// [`ReservationProtection`] bits (three) and [`ReservationNodeFlags`]
    /// bits (seven), packed so the bootstrap table fits its region.
    pub prot: u16,
    pub flags: u16,
    pub host_backing: Option<crate::HostBackingIdentity>,
}
/// ISA binding of the existing shared region. No owner logic belongs here.
pub trait ReservationGeometry {
    const RESERVATIONS_OFFSET: usize;
    const ZONE_OFFSET: usize;
    const REGION_BASE: u64;
    const BOOTSTRAP_BASE: u64;
    const BOOTSTRAP_SIZE: u64;
    fn authorizes_internal_read(address: u64, len: u64) -> bool;
}

/// The Linux client interprets the neutral node; core owns its storage and work.
pub trait ReservationPolicy {
    fn place<M: ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
    ) -> Result<ReservationRange, Refusal>;
    fn mmap<M: ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
        protection: ReservationProtection,
    ) -> Result<Decision, Refusal>;
    fn mremap<M: ReservationPolicyAccess>(
        root: &mut M,
        source: ReservationRange,
        new_len: GuestLen,
        target: MoveTarget,
    ) -> Result<Decision, Refusal>;
    fn brk<M: ReservationPolicyAccess>(
        root: &mut M,
        requested: UserVa,
    ) -> Result<Decision, Refusal>;
    fn root_editable(node: &ReservationNodeData) -> bool;
    fn flags(node: &ReservationNodeData) -> ReservationNodeFlags;
    fn protection(node: &ReservationNodeData) -> ReservationProtection;
    fn charged_data(node: &ReservationNodeData) -> u64;
    fn charged_locked(node: &ReservationNodeData) -> u64;
    fn charges_within(node: &ReservationNodeData, start: u64, end: u64) -> Charges;
    fn mapping(node: &ReservationNodeData, generation: ReservationGeneration) -> Mapping;
    fn same_mapping(node: &ReservationNodeData, other: &ReservationNodeData) -> bool;
    fn charges_data(flags: ReservationNodeFlags, protection: ReservationProtection) -> bool;
}

/// Borrowed policy access to the existing guarded store. This carries no MM
/// state, permit or cursor; proposals remain uncommitted owner transactions.
pub trait ReservationPolicyAccess {
    fn is_admitted(&self) -> bool;
    fn has_pending_edit(&self) -> bool;
    fn fork_pending(&self) -> bool;
    fn layout(&self) -> Layout;
    fn next_range(&mut self, address: UserVa) -> Option<ReservationRange>;
    fn first_fit(&mut self, len: GuestLen) -> Option<UserVa>;
    fn in_layout(&self, range: ReservationRange) -> bool;
    fn mapping(&mut self, address: UserVa) -> Option<Mapping>;
    fn run_covering(&mut self, range: ReservationRange) -> Option<ReservationNodeData>;
    fn pending_result(&self) -> Option<UserVa>;
    fn write_pending_backing(&mut self, backing: HostBackingIdentity) -> Result<(), Refusal>;
    fn set_byte_break(&mut self, requested: UserVa) -> Result<(), Refusal>;
    fn refuse(&mut self, request: ReservationRequest) -> Result<(), Refusal>;
    #[allow(clippy::too_many_arguments)]
    fn propose(
        &mut self,
        range: ReservationRange,
        protection: ReservationProtection,
        operation: ReservationOperation,
        result: UserVa,
        byte_break: UserVa,
        preserve: bool,
        source: Option<ReservationRange>,
        flags: ReservationNodeFlags,
    ) -> Result<Decision, Refusal>;
}

/// Native allocator adapter, called only after the root guard is consumed.
///
/// # Safety
/// Allocations must cover the returned receipt and remain live until freed.
/// Published allocations belong to the carrier store until carrier teardown.
pub unsafe trait ReservationMetadataAllocator {
    fn allocate_with_extent(
        &self,
        layout: core::alloc::Layout,
    ) -> Option<(*mut u8, crate::ExtentGrantReceipt)>;
    fn deallocate(&self, ptr: *mut u8, layout: core::alloc::Layout);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Busy,
    PreparedConflict,
    Stale,
    Invalid,
    Collision,
    Hole,
    ForeignMapping,
    Limit,
    MetadataRequired,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Layout {
    pub heap: ReservationRange,
    pub arena: ReservationRange,
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    /// Charges outside this admitted anonymous arena/heap.
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Anywhere,
    Hint(u64),
    Fixed(u64),
    NoReplace(u64),
}

/// Destination intent interpreted by the selected reservation client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveTarget {
    /// No `MREMAP_MAYMOVE`: resize in place or fail with ENOMEM.
    InPlace,
    /// `MREMAP_MAYMOVE`: resize in place when the following range is free,
    /// otherwise relocate to a first-fit arena range.
    MayMove,
    /// `MREMAP_MAYMOVE | MREMAP_FIXED`: relocate to exactly this address,
    /// replacing root-editable anonymous nodes there.
    Fixed(u64),
    /// `MREMAP_MAYMOVE | MREMAP_DONTUNMAP` (with `MREMAP_FIXED` when
    /// `Some`): the source mapping stays, and a same-size destination is
    /// prepared with the source's protection and attributes.
    KeepSource(Option<u64>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Complete(u64),
    Work(ReservationRequest),
}
