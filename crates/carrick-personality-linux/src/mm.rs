//! Linux reservation ownership, VMA interpretation and charges.
mod reservation;
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
/// Linux-owned state projected through the neutral root's opaque wire payload.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LinuxReservationState {
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}
impl From<ReservationPolicyPayload> for LinuxReservationState {
    fn from(payload: ReservationPolicyPayload) -> Self {
        let [
            brk,
            address_limit,
            data_limit,
            external_address_bytes,
            external_data_bytes,
        ] = payload.words();
        Self {
            brk,
            address_limit,
            data_limit,
            external_address_bytes,
            external_data_bytes,
        }
    }
}
impl From<LinuxReservationState> for ReservationPolicyPayload {
    fn from(state: LinuxReservationState) -> Self {
        Self::new([
            state.brk,
            state.address_limit,
            state.data_limit,
            state.external_address_bytes,
            state.external_data_bytes,
        ])
    }
}
/// Linux admission record. This is an input projection, never a second store.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LinuxReservationLayout {
    pub heap: ReservationRange,
    pub arena: ReservationRange,
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}
impl From<LinuxReservationLayout> for Layout {
    fn from(l: LinuxReservationLayout) -> Self {
        Self {
            heap: l.heap,
            arena: l.arena,
            policy: LinuxReservationState {
                brk: l.brk,
                address_limit: l.address_limit,
                data_limit: l.data_limit,
                external_address_bytes: l.external_address_bytes,
                external_data_bytes: l.external_data_bytes,
            }
            .into(),
        }
    }
}
impl From<Layout> for LinuxReservationLayout {
    fn from(l: Layout) -> Self {
        let state = LinuxReservationState::from(l.policy);
        Self {
            heap: l.heap,
            arena: l.arena,
            brk: state.brk,
            address_limit: state.address_limit,
            data_limit: state.data_limit,
            external_address_bytes: state.external_address_bytes,
            external_data_bytes: state.external_data_bytes,
        }
    }
}

/// Linux interpretation of the one neutral root store.
pub struct LinuxReservationPolicy;
impl carrick_core_abi::ReservationPolicy for LinuxReservationPolicy {
    fn validates_layout(layout: Layout) -> bool {
        let brk = LinuxReservationState::from(layout.policy).brk;
        layout.heap.contains(brk) || brk == layout.heap.end()
    }
    fn active_value(policy: ReservationPolicyPayload) -> u64 {
        LinuxReservationState::from(policy).brk
    }
    fn apply_value(policy: &mut ReservationPolicyPayload, value: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.brk = value;
        *policy = state.into();
    }
    fn admits_charges(
        policy: ReservationPolicyPayload,
        total: Charges,
        removed: Charges,
        added: Charges,
    ) -> Result<(), Refusal> {
        let layout = LinuxReservationState::from(policy);
        reservation::admits_charges(layout, total, removed, added)
    }
    fn update_limits(policy: &mut ReservationPolicyPayload, address: u64, data: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.address_limit = address;
        state.data_limit = data;
        *policy = state.into();
    }
    fn update_external_charges(policy: &mut ReservationPolicyPayload, address: u64, data: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.external_address_bytes = address;
        state.external_data_bytes = data;
        *policy = state.into();
    }
    fn authenticates_maintenance(
        layout: Layout,
        request: ReservationRequest,
        pending_value: u64,
    ) -> bool {
        let old = LinuxReservationState::from(layout.policy).brk;
        request.operation == ReservationOperation::Retire
            && request.protection == ReservationProtection::NONE
            && request.source.is_none()
            && pending_value < old
            && pending_value.checked_add(4095).map(|end| end & !4095) == Some(request.range.start())
            && old.checked_add(4095).map(|end| end & !4095) == Some(request.range.end())
    }
    fn validates_attributes(node: &ReservationNodeData, set: ReservationNodeFlags) -> bool {
        !set.contains(ReservationNodeFlags::WIPEONFORK)
            || Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS_PRIVATE)
    }
    fn inherits(node: &ReservationNodeData) -> bool {
        !Self::flags(node).contains(ReservationNodeFlags::DONTFORK)
    }

    fn place<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
    ) -> Result<ReservationRange, Refusal> {
        reservation::place(root, placement, len)
    }
    fn mmap<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
        protection: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        reservation::mmap(root, placement, len, protection)
    }
    fn mremap<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        source: ReservationRange,
        new_len: GuestLen,
        target: MoveTarget,
    ) -> Result<Decision, Refusal> {
        reservation::mremap(root, source, new_len, target)
    }
    fn brk<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        requested: UserVa,
    ) -> Result<Decision, Refusal> {
        reservation::brk(root, requested)
    }
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
    fn mapping(
        node: &ReservationNodeData,
        generation: ReservationGeneration,
    ) -> Result<Mapping, Refusal> {
        // Nodes are only constructed from validated ABI ranges/protections.
        Ok(Mapping {
            range: ReservationRange::new(node.start, node.end).ok_or(Refusal::Invalid)?,
            protection: Self::protection(node),
            anonymous: Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS),
            flags: Self::flags(node),
            generation,
            host_backing: node.host_backing,
        })
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

use carrick_core::mm::transaction::MmError;
/// Linux wire encoding of the neutral owner's typed refusal.
pub trait MmErrorLinux {
    fn errno(self) -> u32;
}
impl MmErrorLinux for MmError {
    fn errno(self) -> u32 {
        match self {
            Self::Fault => 14,
            Self::UnsupportedExecutableCow => 95,
            Self::Stale => 3,
            Self::Busy => 16,
            Self::NoMemory => 12,
            Self::MetadataRequired | Self::Wait(_) => 11,
            Self::Invalid => 22,
            Self::Core | Self::Reservation(_) | Self::Table(_) => 5,
        }
    }
}

pub const fn cancelled_copy_errno() -> u32 {
    125
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
