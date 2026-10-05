//! Linux reservation ownership, VMA interpretation and charges.
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
/// Linux interpretation of the one neutral root store.
pub struct LinuxReservationPolicy;
impl carrick_core_abi::ReservationPolicy for LinuxReservationPolicy {
    fn root_editable(node: &ReservationNodeData) -> bool {
        Self::flags(node).root_editable()
            && (!Self::flags(node).contains(ReservationNodeFlags::FILE)
                || node.host_backing.is_some())
    }
    fn flags(node: &ReservationNodeData) -> ReservationNodeFlags {
        // Nodes are only written from validated flags.
        ReservationNodeFlags::from_bits(u32::from(node.flags))
            .unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(node: &ReservationNodeData) -> ReservationProtection {
        ReservationProtection::from_bits(u64::from(node.prot))
            .unwrap_or(ReservationProtection::NONE)
    }
    fn charged_data(node: &ReservationNodeData) -> u64 {
        if Self::charges_data(Self::flags(node), Self::protection(node)) {
            node.end - node.start
        } else {
            0
        }
    }
    fn charged_locked(node: &ReservationNodeData) -> u64 {
        if Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS)
            && Self::flags(node).contains(ReservationNodeFlags::LOCKED)
        {
            node.end - node.start
        } else {
            0
        }
    }
    /// Charges of the part of this one node inside `[start, end)`.
    fn charges_within(node: &ReservationNodeData, start: u64, end: u64) -> Charges {
        let bytes = node.end.min(end).saturating_sub(node.start.max(start));
        Charges {
            bytes,
            data: if Self::charged_data(node) != 0 {
                bytes
            } else {
                0
            },
            locked: if Self::charged_locked(node) != 0 {
                bytes
            } else {
                0
            },
        }
    }
    fn mapping(node: &ReservationNodeData, generation: ReservationGeneration) -> Mapping {
        // Nodes are only constructed from validated ABI ranges/protections.
        Mapping {
            range: ReservationRange::new(node.start, node.end).expect("reservation range"),
            protection: Self::protection(node),
            anonymous: Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS),
            flags: Self::flags(node),
            generation,
            host_backing: node.host_backing,
        }
    }
    /// Whether an adjacent node is the same Linux mapping (a VMA boundary
    /// the tree keeps only to separate incarnations).
    fn same_mapping(node: &ReservationNodeData, other: &ReservationNodeData) -> bool {
        node.prot == other.prot
            && node.flags == other.flags
            && match (node.host_backing, other.host_backing) {
                (None, None) => true,
                (Some(a), Some(b)) if node.start <= other.start => {
                    a.advance(other.start - node.start) == Some(b)
                }
                (Some(a), Some(b)) => b.advance(node.start - other.start) == Some(a),
                _ => false,
            }
    }
    fn charges_data(flags: ReservationNodeFlags, protection: ReservationProtection) -> bool {
        flags.charges_data(protection)
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
