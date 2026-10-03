//! Anonymous reservation transaction ABI (T1 policy / T2 descriptors).
//!
//! A request is a proposal, never permission to replay a Linux syscall. T2
//! authenticates its MM, generation and sequence against the pending proposal,
//! completes the descriptor transaction and backing grant/return, then returns
//! a completion for that exact request. Only T1 commits reservation metadata.
//! Refusal leaves the old reservation visible; a failed descriptor rollback
//! must fail stopped, never manufacture a refusal/completion.

/// Shared reservation bootstrap region, before T2's descriptor transaction slots.
pub const EL1_RESERVATIONS_OFFSET: u64 = crate::EL1_COUNTERS_OFFSET + 0x1_8000;
pub const EL1_RESERVATIONS_END: u64 = crate::EL1_COUNTERS_OFFSET + 0x8_0000;
/// Protocol revision of the request/flag vocabulary below. Folded into
/// [`crate::EL1_ABI_LAYOUT_HASH`]: an image that decodes `Move`, node flags or
/// the request's `source` differently must not attach to this host.
pub const RESERVATION_PROTOCOL_VERSION: u64 = 3;

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
    /// EL1 may edit private anonymous or retained private file nodes,
    /// preserving their carried attributes. File nodes additionally require
    /// a retained source in the production reservation node.
    pub const fn root_editable(self) -> bool {
        let kind = self.0 & !Self::CARRIED.0;
        kind == Self::ANONYMOUS_PRIVATE.0 || kind == (Self::PRIVATE.0 | Self::FILE.0)
    }
    /// `RLIMIT_DATA` covers private writable non-stack mappings (getrlimit(2),
    /// mmap(2)); shared, stack and read-only nodes are not charged.
    pub const fn charges_data(self, protection: ReservationProtection) -> bool {
        self.contains(Self::PRIVATE)
            && !self.contains(Self::GROWSDOWN)
            && protection.bits() & 2 != 0
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

#[cfg(test)]
mod flag_tests {
    use super::*;
    #[test]
    fn reservation_node_flags_classify_data_and_root_ownership() {
        let rw = ReservationProtection::READ_WRITE;
        let anon = ReservationNodeFlags::ANONYMOUS_PRIVATE;
        assert!(anon.root_editable());
        assert!(anon.charges_data(rw));
        assert!(!anon.charges_data(ReservationProtection::NONE));
        // Shared writable: not RLIMIT_DATA.
        assert!(!ReservationNodeFlags::ANONYMOUS.charges_data(rw));
        assert!(!ReservationNodeFlags::ANONYMOUS.root_editable());
        // Stack: not RLIMIT_DATA, host-owned.
        let stack = anon.union(ReservationNodeFlags::GROWSDOWN);
        assert!(!stack.charges_data(rw));
        assert!(!stack.root_editable());
        // Private writable opaque (file) mapping is charged.
        assert!(ReservationNodeFlags::PRIVATE.charges_data(rw));
        for flag in [
            ReservationNodeFlags::LOCKED,
            ReservationNodeFlags::DONTFORK,
            ReservationNodeFlags::WIPEONFORK,
            ReservationNodeFlags::DONTDUMP,
        ] {
            assert!(anon.union(flag).root_editable());
            assert!(ReservationNodeFlags::CARRIED.contains(flag));
            assert!(ReservationNodeFlags::ATTRIBUTES.contains(flag));
            assert!(!ReservationNodeFlags::PRIVATE.union(flag).root_editable());
        }
        assert_eq!(ReservationNodeFlags::from_bits(1 << 9), None);
    }
}
