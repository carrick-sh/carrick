//! Neutral interpretation of the reservation root store and geometry for non-Linux personalities.

use carrick_core_abi::{
    Charges, Decision, GuestLen, Layout, Mapping, MoveTarget, Placement, Refusal,
    ReservationGeneration, ReservationGeometry, ReservationNodeData, ReservationNodeFlags,
    ReservationOperation, ReservationPolicy, ReservationPolicyAccess, ReservationPolicyPayload,
    ReservationProposal, ReservationProtection, ReservationRange, ReservationRequest, UserVa,
};

/// Neutral interpretation of the reservation root store for non-Linux personalities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeutralReservationPolicy;

impl ReservationPolicy for NeutralReservationPolicy {
    fn validates_layout(_layout: Layout) -> bool {
        true
    }
    fn active_value(_policy: ReservationPolicyPayload) -> u64 {
        0
    }
    fn apply_value(_policy: &mut ReservationPolicyPayload, _value: u64) {}
    fn admits_charges(
        _policy: ReservationPolicyPayload,
        _total: Charges,
        _removed: Charges,
        _added: Charges,
    ) -> Result<(), Refusal> {
        Ok(())
    }
    fn update_limits(_policy: &mut ReservationPolicyPayload, _address: u64, _data: u64) {}
    fn update_external_charges(_policy: &mut ReservationPolicyPayload, _address: u64, _data: u64) {}
    fn authenticates_maintenance(
        _layout: Layout,
        _request: ReservationRequest,
        _pending_value: u64,
    ) -> bool {
        true
    }
    fn validates_attributes(_node: &ReservationNodeData, _set: ReservationNodeFlags) -> bool {
        true
    }
    fn inherits(_node: &ReservationNodeData) -> bool {
        true
    }
    fn place<M: ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
    ) -> Result<ReservationRange, Refusal> {
        let len_val = len.raw();
        if !root.is_admitted() {
            return Err(Refusal::Stale);
        }
        if len_val == 0 {
            return Err(Refusal::Invalid);
        }
        let len_val = len_val
            .checked_add(4095)
            .map(|v| v & !4095)
            .ok_or(Refusal::Limit)?;
        let address = match placement {
            Placement::Fixed(addr) | Placement::NoReplace(addr) => {
                if !addr.is_multiple_of(4096) {
                    return Err(Refusal::Invalid);
                }
                addr
            }
            Placement::Anywhere => root
                .first_fit(GuestLen::new(len_val))
                .ok_or(Refusal::Limit)?
                .raw(),
            Placement::Hint(addr) => {
                let addr = addr & !4095;
                if let Some(r) = addr
                    .checked_add(len_val)
                    .and_then(|end| ReservationRange::new(addr, end))
                {
                    if root.in_layout(r)
                        && root
                            .next_range(UserVa::new(addr))
                            .is_none_or(|n| n.start() >= r.end())
                    {
                        addr
                    } else {
                        root.first_fit(GuestLen::new(len_val))
                            .ok_or(Refusal::Limit)?
                            .raw()
                    }
                } else {
                    return Err(Refusal::Invalid);
                }
            }
        };
        let end = address.checked_add(len_val).ok_or(Refusal::Limit)?;
        let range = ReservationRange::new(address, end).ok_or(Refusal::Invalid)?;
        if matches!(placement, Placement::NoReplace(_))
            && root
                .next_range(UserVa::new(address))
                .is_some_and(|n| n.start() < range.end())
        {
            return Err(Refusal::Collision);
        }
        Ok(range)
    }
    fn mmap<M: ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
        protection: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        let range = Self::place(root, placement, len)?;
        let address = range.start();
        root.propose(ReservationProposal {
            range,
            protection,
            operation: ReservationOperation::Prepare,
            result: UserVa::new(address),
            policy_value: UserVa::new(0),
            require_coverage: false,
            source: None,
            flags: ReservationNodeFlags::ANONYMOUS_PRIVATE,
        })
    }
    fn mremap<M: ReservationPolicyAccess>(
        _root: &mut M,
        _source: ReservationRange,
        _new_len: GuestLen,
        _target: MoveTarget,
    ) -> Result<Decision, Refusal> {
        Err(Refusal::Invalid)
    }
    fn brk<M: ReservationPolicyAccess>(
        _root: &mut M,
        _requested: UserVa,
    ) -> Result<Decision, Refusal> {
        Err(Refusal::Invalid)
    }
    fn root_editable(_node: &ReservationNodeData) -> bool {
        true
    }
    fn flags(node: &ReservationNodeData) -> ReservationNodeFlags {
        ReservationNodeFlags::from_bits(node.flags as u32).unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(node: &ReservationNodeData) -> ReservationProtection {
        ReservationProtection::from_bits(node.prot as u64).unwrap_or(ReservationProtection::NONE)
    }
    fn charged_data(_node: &ReservationNodeData) -> u64 {
        0
    }
    fn charged_locked(_node: &ReservationNodeData) -> u64 {
        0
    }
    fn charges_within(_node: &ReservationNodeData, _start: u64, _end: u64) -> Charges {
        Charges::default()
    }
    fn mapping(
        node: &ReservationNodeData,
        generation: ReservationGeneration,
    ) -> Result<Mapping, Refusal> {
        let range = ReservationRange::new(node.start, node.end).ok_or(Refusal::Invalid)?;
        let protection = Self::protection(node);
        let flags = Self::flags(node);
        Ok(Mapping {
            range,
            protection,
            anonymous: flags.contains(ReservationNodeFlags::ANONYMOUS),
            flags,
            generation,
            host_backing: node.host_backing,
        })
    }
    fn same_mapping(node: &ReservationNodeData, other: &ReservationNodeData) -> bool {
        node.prot == other.prot && node.flags == other.flags
    }
    fn charges_data(_flags: ReservationNodeFlags, _protection: ReservationProtection) -> bool {
        false
    }
}

/// Neutral geometry for non-Linux personalities in host and test environments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeutralReservationGeometry;

impl ReservationGeometry for NeutralReservationGeometry {
    const RESERVATIONS_OFFSET: usize = 0;
    const ZONE_OFFSET: usize = 0x20000;
    const REGION_BASE: u64 = 0;
    const BOOTSTRAP_BASE: u64 = 0;
    const BOOTSTRAP_SIZE: u64 = 0x100000;
    fn authorizes_internal_read(_address: u64, _len: u64) -> bool {
        true
    }
}
