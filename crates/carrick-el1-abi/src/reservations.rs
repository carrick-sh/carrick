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

use carrick_core_abi::*;

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
