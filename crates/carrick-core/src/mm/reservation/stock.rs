//! Bounded anonymous stock selection. This is policy, not a publication permit.
//! Backend occupancy is evidence only; the locked root owns revalidation.
use super::{DeferredReturn, Reservations};
use alloc::vec::Vec;
use carrick_core_abi::{
    GuestLen, Mapping, Refusal, ReservationGeneration, ReservationGeometry, ReservationIncarnation,
    ReservationMm, ReservationNodeFlags, ReservationPolicy, ReservationProtection,
    ReservationRange, ReservationRequest, ReservationSequence, UserVa,
};

/// Maximum observations in each policy input and selected-node snapshot.
/// Fragmentation beyond this bound refuses speculative planning, without edits.
pub const STOCK_OBSERVATIONS: usize = 256;

/// Descriptor/residency occupancy and host-only observations, bounded before
/// entering the owner. Pending edits and owed returns are read from the root,
/// never accepted as backend assertions.
#[derive(
    ::core::clone::Clone,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct StockExclusions {
    occupied: Vec<ReservationRange>,
    host_only: Vec<ReservationRange>,
}
impl StockExclusions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn exclude_occupied(&mut self, range: ReservationRange) -> Result<(), Refusal> {
        self.push(range, false)
    }
    pub fn exclude_host_only(&mut self, range: ReservationRange) -> Result<(), Refusal> {
        self.push(range, true)
    }
    fn push(&mut self, range: ReservationRange, host: bool) -> Result<(), Refusal> {
        if self.occupied.len() + self.host_only.len() == STOCK_OBSERVATIONS {
            return Err(Refusal::MetadataRequired);
        }
        if host {
            &mut self.host_only
        } else {
            &mut self.occupied
        }
        .push(range);
        Ok(())
    }
}

/// Exact-MM selection including future holes. Deliberately distinct from
/// `ReservationFaultPlan`: this cannot authenticate an ordinary frame grant.
/// No physical ownership, descriptor access or publication is conferred here.
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct PrivateStockPlan {
    mm: ReservationMm,
    root_incarnation: ReservationGeneration,
    mapping_incarnation: ReservationIncarnation,
    range: ReservationRange,
    fault_page: UserVa,
    protection: ReservationProtection,
    observation_version: ReservationGeneration,
    request_sequence: Option<ReservationSequence>,
    max_len: GuestLen,
    // Ordered node facts imply every intervening hole as well as node identity.
    nodes: Vec<(Mapping, ReservationIncarnation)>,
    exclusions: StockExclusions,
    pending: Option<ReservationRequest>,
    owed: Vec<DeferredReturn>,
}
impl PrivateStockPlan {
    pub fn range(&self) -> ReservationRange {
        self.range
    }
    pub fn protection(&self) -> ReservationProtection {
        self.protection
    }
}

fn overlaps(a: ReservationRange, b: ReservationRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

impl<P: ReservationPolicy, G: ReservationGeometry, C: Copy + Send + Sync + zerocopy::FromZeros>
    Reservations<'_, P, G, C>
{
    /// Select the maximal eligible run around the fault within its bulk
    /// window. Nodes retain the old same-protection anonymous policy; future
    /// holes stay within the mmap arena's half window. Heap is never stock.
    pub fn private_stock_plan(
        &mut self,
        address: UserVa,
        max_len: GuestLen,
        exclusions: &StockExclusions,
    ) -> Result<PrivateStockPlan, Refusal> {
        if !self.is_admitted() {
            return Err(Refusal::Stale);
        }
        if self.fork_pending() {
            return Err(Refusal::Busy);
        }
        let max = max_len.raw();
        if max == 0 || !max.is_multiple_of(4096) {
            return Err(Refusal::Invalid);
        }
        let page = address.raw() & !4095;
        let (mapping, mapping_incarnation) = self.node(page).ok_or(Refusal::Hole)?;
        let layout = self.state().layout;
        if !mapping.anonymous
            || !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
            || mapping.host_backing.is_some()
            || overlaps(mapping.range, layout.heap)
        {
            return Err(Refusal::ForeignMapping);
        }
        if mapping.protection == ReservationProtection::NONE {
            return Err(Refusal::Limit);
        }
        let window_start = page - page % max;
        let window = ReservationRange::new(
            window_start,
            window_start.checked_add(max).ok_or(Refusal::Invalid)?,
        )
        .ok_or(Refusal::Invalid)?;
        let half = (max / 2).max(4096);
        let half_start = page - page % half;
        let arena_start = half_start.max(layout.arena.start());
        let arena_end = half_start.saturating_add(half).min(layout.arena.end());
        let mut nodes = Vec::new();
        let mut node_cursor = window.start();
        while let Some(node) = self.next(node_cursor) {
            if node.start >= window.end() {
                break;
            }
            if nodes.len() == STOCK_OBSERVATIONS {
                return Err(Refusal::MetadataRequired);
            }
            let incarnation =
                ReservationIncarnation::new(node.incarnation).ok_or(Refusal::Invalid)?;
            nodes.push((P::mapping(&node, self.generation())?, incarnation));
            node_cursor = node.end;
        }
        let mut eligible = Vec::new();
        let mut cursor = window.start();
        let hole = |runs: &mut Vec<ReservationRange>, start: u64, end: u64| {
            if let Some(range) = ReservationRange::new(start.max(arena_start), end.min(arena_end)) {
                runs.push(range);
            }
        };
        for (node, _) in &nodes {
            let start = node.range.start().max(window.start());
            let end = node.range.end().min(window.end());
            if start > cursor {
                hole(&mut eligible, cursor, start);
            }
            cursor = cursor.max(end);
            if node.anonymous
                && node.flags.contains(ReservationNodeFlags::PRIVATE)
                && node.host_backing.is_none()
                && node.protection == mapping.protection
                && !overlaps(node.range, layout.heap)
            {
                eligible.push(ReservationRange::new(start, end).ok_or(Refusal::Invalid)?);
            }
        }
        if cursor < window.end() {
            hole(&mut eligible, cursor, window.end());
        }
        let index = eligible
            .iter()
            .position(|range| range.contains(page))
            .ok_or(Refusal::Hole)?;
        let mut start = eligible[index].start();
        let mut end = eligible[index].end();
        for range in eligible[..index].iter().rev() {
            if range.end() != start {
                break;
            }
            start = range.start();
        }
        for range in &eligible[index + 1..] {
            if range.start() != end {
                break;
            }
            end = range.end();
        }
        let pending = self.pending();
        let mut owed = Vec::new();
        self.observe_deferred_returns(&mut |entry| owed.push(entry));
        // Return journal is already bounded by DEFERRED_RETURNS. No backend
        // can suppress these exclusions or authorize a pending destination.
        let pending_ranges = pending
            .into_iter()
            .flat_map(|request| [Some(request.range), request.source])
            .flatten();
        for blocked in exclusions
            .occupied
            .iter()
            .copied()
            .chain(exclusions.host_only.iter().copied())
            .chain(owed.iter().map(|entry| entry.range))
            .chain(pending_ranges)
        {
            if blocked.end() <= start || blocked.start() >= end {
                continue;
            }
            if blocked.contains(page) {
                return Err(Refusal::Busy);
            }
            if blocked.end() <= page {
                start = start.max(blocked.end());
            } else {
                end = end.min(blocked.start());
            }
        }
        let range = ReservationRange::new(start, end).ok_or(Refusal::Invalid)?;
        Ok(PrivateStockPlan {
            mm: self.mm,
            root_incarnation: self.incarnation(),
            mapping_incarnation,
            range,
            fault_page: UserVa::new(page),
            protection: mapping.protection,
            observation_version: self.generation(),
            request_sequence: ReservationSequence::new(self.state().sequence),
            max_len,
            nodes,
            exclusions: exclusions.clone(),
            pending,
            owed,
        })
    }

    /// Re-read owner facts under this root editor, including pending/owed
    /// state and all node/hole observations. Fresh backend observations are
    /// required; neither their equality nor a version counter suffices alone.
    /// Refusal changes no root, journal, inventory or descriptor state.
    pub fn revalidate_private_stock_plan(
        &mut self,
        plan: &PrivateStockPlan,
        exclusions: &StockExclusions,
    ) -> Result<(), Refusal> {
        if plan.mm != self.mm || plan.root_incarnation != self.incarnation() {
            return Err(Refusal::Stale);
        }
        let current = self.private_stock_plan(plan.fault_page, plan.max_len, exclusions)?;
        if current != *plan {
            return Err(Refusal::Stale);
        }
        Ok(())
    }
}
