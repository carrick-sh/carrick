//! Linux reservation ownership, VMA interpretation and charges.
use carrick_core::mm::reservation::{Charges, Mapping, ReservationNodeData};
use carrick_core_abi::*;

/// Linux edit authority and rlimit charging for the neutral flag record.
pub trait NodeFlagsPolicy {
    fn root_editable(self) -> bool;
    fn charges_data(self, protection: ReservationProtection) -> bool;
}
impl NodeFlagsPolicy for ReservationNodeFlags {
    /// EL1 may edit private anonymous or retained private file nodes,
    /// preserving their carried attributes. File nodes additionally require
    /// a retained source in the production reservation node.
    fn root_editable(self) -> bool {
        let kind = self.bits() & !Self::CARRIED.bits();
        kind == Self::ANONYMOUS_PRIVATE.bits() || kind == (Self::PRIVATE.bits() | Self::FILE.bits())
    }
    /// `RLIMIT_DATA` covers private writable non-stack mappings (getrlimit(2),
    /// mmap(2)); shared, stack and read-only nodes are not charged.
    fn charges_data(self, protection: ReservationProtection) -> bool {
        self.contains(Self::PRIVATE)
            && !self.contains(Self::GROWSDOWN)
            && protection.bits() & 2 != 0
    }
}
/// Linux reservation interpretation. The backing tree and storage stay neutral.
pub trait NodeDataPolicy {
    fn root_editable(&self) -> bool;
    fn flags(&self) -> ReservationNodeFlags;
    fn protection(&self) -> ReservationProtection;
    fn charged_data(&self) -> u64;
    fn charged_locked(&self) -> u64;
    fn charges_within(&self, start: u64, end: u64) -> Charges;
    fn mapping(&self, generation: ReservationGeneration) -> Mapping;
    fn same_mapping(&self, other: &ReservationNodeData) -> bool;
}
impl NodeDataPolicy for ReservationNodeData {
    fn root_editable(&self) -> bool {
        self.flags().root_editable()
            && (!self.flags().contains(ReservationNodeFlags::FILE) || self.host_backing.is_some())
    }
    fn flags(&self) -> ReservationNodeFlags {
        // Nodes are only written from validated flags.
        ReservationNodeFlags::from_bits(u32::from(self.flags))
            .unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(&self) -> ReservationProtection {
        ReservationProtection::from_bits(u64::from(self.prot))
            .unwrap_or(ReservationProtection::NONE)
    }
    fn charged_data(&self) -> u64 {
        if self.flags().charges_data(self.protection()) {
            self.end - self.start
        } else {
            0
        }
    }
    fn charged_locked(&self) -> u64 {
        if self.flags().contains(ReservationNodeFlags::ANONYMOUS)
            && self.flags().contains(ReservationNodeFlags::LOCKED)
        {
            self.end - self.start
        } else {
            0
        }
    }
    /// Charges of the part of this one node inside `[start, end)`.
    fn charges_within(&self, start: u64, end: u64) -> Charges {
        let bytes = self.end.min(end).saturating_sub(self.start.max(start));
        Charges {
            bytes,
            data: if self.charged_data() != 0 { bytes } else { 0 },
            locked: if self.charged_locked() != 0 { bytes } else { 0 },
        }
    }
    fn mapping(&self, generation: ReservationGeneration) -> Mapping {
        // Nodes are only constructed from validated ABI ranges/protections.
        Mapping {
            range: ReservationRange::new(self.start, self.end).expect("reservation range"),
            protection: self.protection(),
            anonymous: self.flags().contains(ReservationNodeFlags::ANONYMOUS),
            flags: self.flags(),
            generation,
            host_backing: self.host_backing,
        }
    }
    /// Whether an adjacent node is the same Linux mapping (a VMA boundary
    /// the tree keeps only to separate incarnations).
    fn same_mapping(&self, other: &ReservationNodeData) -> bool {
        self.prot == other.prot
            && self.flags == other.flags
            && match (self.host_backing, other.host_backing) {
                (None, None) => true,
                (Some(a), Some(b)) if self.start <= other.start => {
                    a.advance(other.start - self.start) == Some(b)
                }
                (Some(a), Some(b)) => b.advance(self.start - other.start) == Some(a),
                _ => false,
            }
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
