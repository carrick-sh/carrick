//! Anonymous first-touch fault arming, residency tracking, and grow-down stack fault resolution.

use super::anonymous::broken_root;
use super::*;
use carrick_el1::memory::reservations::{Mapping, Refusal, Reservations};
use carrick_el1_abi::{ReservationIncarnation, ReservationProtection, ReservationRange};
use carrick_fatal::carrick_fatal;

#[derive(Clone, Copy)]
pub struct ResidentFaultRange {
    pub(crate) range: carrick_vfs::GuestMemoryRange,
    pub(crate) prot: LinuxProtFlags,
}

/// The first-touch ARMING set: the extents whose stage-1 leaves are
/// deliberately invalid so the guest's first touch of each page traps, with
/// the protection to publish when it does.
///
/// Every anonymous first touch consults and edits this set, so its
/// representation IS a term of the per-fault cost. It used to be an unsorted
/// `Vec<ResidentFaultRange>` that `resident_fault_plan` scanned linearly and
/// that committing a single 4 KiB page REBUILT WHOLE — a fresh
/// `Vec::with_capacity(n)` plus an n-element copy per fault — so the cost of
/// one first touch grew with the number of live anonymous mappings in the mm.
/// Measured on `target/conformance/eco-load/fault-population-reducer.sh`
/// (one process, one 8,192-page batch per step): **12.0 µs per fault with an
/// empty population, 36.5 µs with 8,000 untouched anonymous mappings held**.
///
/// A `BTreeMap` keyed by each extent's START gives the three operations the
/// fault path needs in O(log n) with no whole-set rewrite: a page's arming is
/// the last entry at or below it, and committing a page splits at most one
/// entry. The set is non-overlapping by construction — [`Self::arm`] disarms
/// what it covers before inserting — which is also what makes the "last entry
/// at or below" lookup exact.
#[derive(Clone, Default)]
pub struct FirstTouchArming {
    revision: u64,
    /// `start -> (end, prot)`, non-overlapping, ordered by `start`.
    extents: std::collections::BTreeMap<u64, FirstTouchArm>,
}

#[derive(Clone, Copy)]
struct FirstTouchArm {
    end: u64,
    prot: LinuxProtFlags,
}

impl FirstTouchArming {
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    /// Arm `range` for first-touch observation at `prot`, replacing whatever
    /// armed the pages it covers.
    pub(crate) fn arm(&mut self, range: carrick_vfs::GuestMemoryRange, prot: LinuxProtFlags) {
        self.disarm(range);
        let mut start = range.start().raw();
        let mut end = range.end().raw();
        if let Some((&previous_start, &previous)) = self.extents.range(..start).next_back()
            && previous.end == start
            && previous.prot == prot
        {
            self.extents.remove(&previous_start);
            start = previous_start;
        }
        if let Some(&next) = self.extents.get(&end)
            && next.prot == prot
        {
            self.extents.remove(&end);
            end = next.end;
        }
        self.extents.insert(start, FirstTouchArm { end, prot });
    }

    /// The protection to publish for a first touch of `page`, or `None` when
    /// no pending edit names it.
    pub(crate) fn prot_for_page(&self, page: u64) -> Option<LinuxProtFlags> {
        self.extents
            .range(..=page)
            .next_back()
            .filter(|(_, arm)| page < arm.end)
            .map(|(_, arm)| arm.prot)
    }

    /// The armed range around `page`, clipped to one `max_len`-aligned bulk
    /// window. A host frame grant may prepare backing for the result in one
    /// transaction; first-touch publication remains page-granular.
    fn grant_for_page(&self, page: u64, max_len: u64) -> Option<ResidentFaultRange> {
        if max_len == 0 {
            return None;
        }
        let (&arm_start, arm) = self.extents.range(..=page).next_back()?;
        if page >= arm.end {
            return None;
        }
        let window_start = page - page % max_len;
        let window_end = window_start.checked_add(max_len)?;
        let range = carrick_vfs::GuestMemoryRange::new(
            GuestVa(arm_start.max(window_start)),
            GuestVa(arm.end.min(window_end)),
        )?;
        Some(ResidentFaultRange {
            range,
            prot: arm.prot,
        })
    }

    /// Drop `range` from the set, keeping the parts of any extent that lie
    /// outside it. This is the commit path for one page, so it must not touch
    /// entries the range does not overlap.
    pub(crate) fn disarm(&mut self, range: carrick_vfs::GuestMemoryRange) {
        self.revision = self.revision.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "dispatch::first_touch_revision",
                "first-touch arming revision exhausted"
            )
        });
        let (start, end) = (range.start().raw(), range.end().raw());
        // The one entry that may begin BEFORE `range` and still cover it.
        if let Some((&head_start, &head)) = self.extents.range(..start).next_back()
            && head.end > start
        {
            self.extents.remove(&head_start);
            self.insert_nonempty(head_start, start, head.prot);
            if head.end > end {
                self.insert_nonempty(end, head.end, head.prot);
            }
        }
        // Every entry that BEGINS inside `range`.
        while let Some((&covered_start, &covered)) = self.extents.range(start..end).next() {
            self.extents.remove(&covered_start);
            if covered.end > end {
                self.insert_nonempty(end, covered.end, covered.prot);
            }
        }
    }

    fn insert_nonempty(&mut self, start: u64, end: u64, prot: LinuxProtFlags) {
        if end > start {
            self.extents.insert(start, FirstTouchArm { end, prot });
        }
    }

    /// The armed sub-ranges inside `range`, clipped to it — the pages an
    /// explicit populate has to publish itself because their first touch will
    /// never happen.
    pub(crate) fn intersections(
        &self,
        range: carrick_vfs::GuestMemoryRange,
    ) -> Vec<ResidentFaultRange> {
        let (start, end) = (range.start().raw(), range.end().raw());
        let head = self
            .extents
            .range(..start)
            .next_back()
            .filter(|(_, arm)| arm.end > start)
            .map(|(&arm_start, arm)| (arm_start, *arm));
        head.into_iter()
            .chain(
                self.extents
                    .range(start..end)
                    .map(|(&arm_start, arm)| (arm_start, *arm)),
            )
            .filter_map(|(arm_start, arm)| {
                carrick_vfs::GuestMemoryRange::new(
                    GuestVa(arm_start.max(start)),
                    GuestVa(arm.end.min(end)),
                )
                .map(|clipped| ResidentFaultRange {
                    range: clipped,
                    prot: arm.prot,
                })
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.extents
            .range(..end)
            .next_back()
            .is_some_and(|(&arm_start, arm)| arm_start < end && arm.end > start)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.extents.len()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = ResidentFaultRange> + '_ {
        self.extents.iter().filter_map(|(&start, arm)| {
            carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(arm.end)).map(|range| {
                ResidentFaultRange {
                    range,
                    prot: arm.prot,
                }
            })
        })
    }
}

/// Who a residency fact was observed under. A root-owned anonymous page's
/// fact names the root node incarnation that held the page; a guest-venue
/// `munmap` retires that incarnation without telling the host, so the fact
/// stops matching and is dead by construction. Everything else (host setup,
/// host-owned rows, the heap, a range the host venue's own pending proposal
/// holds) is the host's own fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResidencyOwner {
    Host,
    Root(ReservationIncarnation),
}

/// Residency facts: the pages carrick has made resident, each tagged with
/// the [`ResidencyOwner`] it was observed under. A fact answers only for its
/// own owner: [`Self::contains`] asks "resident under THIS owner?", so a
/// fact about a retired incarnation can never describe a new mapping at the
/// same address.
#[derive(Clone, Default)]
pub struct ResidentFacts {
    /// `start -> (end, owner)`, non-overlapping, ordered by `start`.
    facts: std::collections::BTreeMap<u64, (u64, ResidencyOwner)>,
}

impl ResidentFacts {
    /// Record `range` resident under `owner`, replacing any fact it covers.
    pub(crate) fn insert(&mut self, range: carrick_vfs::GuestMemoryRange, owner: ResidencyOwner) {
        self.remove(range);
        let mut start = range.start().raw();
        let mut end = range.end().raw();
        if let Some((&previous_start, &(previous_end, previous_owner))) =
            self.facts.range(..start).next_back()
            && previous_end == start
            && previous_owner == owner
        {
            self.facts.remove(&previous_start);
            start = previous_start;
        }
        if let Some(&(next_end, next_owner)) = self.facts.get(&end)
            && next_owner == owner
        {
            self.facts.remove(&end);
            end = next_end;
        }
        self.facts.insert(start, (end, owner));
    }

    /// Drop every fact inside `range`, whatever its owner.
    pub(crate) fn remove(&mut self, range: carrick_vfs::GuestMemoryRange) {
        let (start, end) = (range.start().raw(), range.end().raw());
        if let Some((&head_start, &(head_end, owner))) = self.facts.range(..start).next_back()
            && head_end > start
        {
            self.facts.insert(head_start, (start, owner));
            if head_end > end {
                self.facts.insert(end, (head_end, owner));
            }
        }
        while let Some((&covered_start, &(covered_end, owner))) =
            self.facts.range(start..end).next()
        {
            self.facts.remove(&covered_start);
            if covered_end > end {
                self.facts.insert(end, (covered_end, owner));
            }
        }
    }

    /// Whether `page` is resident under exactly `owner`.
    pub(crate) fn contains(&self, page: u64, owner: ResidencyOwner) -> bool {
        self.facts
            .range(..=page)
            .next_back()
            .is_some_and(|(_, &(end, fact))| page < end && fact == owner)
    }

    /// The parts of `[start, end)` resident under exactly `owner`, clipped,
    /// in address order: O(log n + k).
    pub(crate) fn within(&self, start: u64, end: u64, owner: ResidencyOwner) -> Vec<(u64, u64)> {
        let head = self
            .facts
            .range(..start)
            .next_back()
            .filter(|(_, (fact_end, _))| *fact_end > start)
            .map(|(&fact_start, &fact)| (fact_start, fact));
        head.into_iter()
            .chain(
                self.facts
                    .range(start..end)
                    .map(|(&fact_start, &fact)| (fact_start, fact)),
            )
            .filter(|(_, (_, fact))| *fact == owner)
            .map(|(fact_start, (fact_end, _))| (fact_start.max(start), fact_end.min(end)))
            .filter(|(clipped_start, clipped_end)| clipped_start < clipped_end)
            .collect()
    }

    /// Hand `range` to a new owner: facts observed under `live` become facts
    /// under `owner`; every other fact inside `range` describes memory that
    /// no longer exists there and is dropped.
    pub(crate) fn hand_over(
        &mut self,
        range: carrick_vfs::GuestMemoryRange,
        live: ResidencyOwner,
        owner: ResidencyOwner,
    ) {
        let kept = self.within(range.start().raw(), range.end().raw(), live);
        self.remove(range);
        for (start, end) in kept {
            if let Some(piece) = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) {
                self.insert(piece, owner);
            }
        }
    }

    /// Every fact's range regardless of owner, coalesced.
    #[cfg(test)]
    pub(crate) fn ranges(&self) -> Vec<carrick_vfs::GuestMemoryRange> {
        let mut ranges = Vec::new();
        for (&start, &(end, _)) in &self.facts {
            if let Some(range) = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) {
                locked_ranges_insert(&mut ranges, range);
            }
        }
        ranges
    }
}

fn bus_fault_contains(ranges: &[(u64, u64)], address: u64) -> bool {
    ranges.iter().any(|&(start, len)| {
        start
            .checked_add(len)
            .is_some_and(|end| address >= start && address < end)
    })
}

/// Who answers one page's first-touch facts.
///
/// On a delegated MM the root owns whether an anonymous page exists and at
/// which protection; the host keeps only what its own venue backed. A page
/// the root holds as plain anonymous memory outside the heap is tracked from
/// the root (EL1 reservations are metadata backed on demand, so every such
/// page is observed on first touch). A root hole has nothing to observe:
/// whatever the host recorded there describes a mapping the guest venue has
/// already retired.
#[derive(Clone, Copy, Debug)]
pub(in crate::dispatch) enum FirstTouchOwner {
    /// Host setup, a host-owned (opaque) root node, the root's heap, or the
    /// range this MM's pending host proposal holds: the host's own arming.
    Host,
    /// A root-owned anonymous page outside the heap: its node and incarnation.
    Root(Mapping, ReservationIncarnation),
    /// No root node covers the page.
    Unmapped,
}

/// The parts of `range` the root holds no committed node for. A pending
/// proposal is not part of the committed tree, so its range reads as holes
/// wherever it does not replace a committed node.
pub(in crate::dispatch) fn root_holes(
    model: &mut Reservations<'_>,
    range: ReservationRange,
) -> Result<Vec<(u64, u64)>, Refusal> {
    let mut holes = Vec::new();
    let mut cursor = range.start();
    model.observe_range(range, &mut |mapping| {
        if mapping.range.start() > cursor {
            holes.push((cursor, mapping.range.start()));
        }
        cursor = cursor.max(mapping.range.end());
    })?;
    if cursor < range.end() {
        holes.push((cursor, range.end()));
    }
    Ok(holes)
}

/// One root-owned first-touch piece: an anonymous node outside the heap,
/// clipped to the query, with the incarnation its residency facts must name.
#[derive(Clone, Copy, Debug)]
pub(in crate::dispatch) struct RootPiece {
    pub(in crate::dispatch) range: carrick_vfs::GuestMemoryRange,
    pub(in crate::dispatch) protection: ReservationProtection,
    pub(in crate::dispatch) incarnation: ReservationIncarnation,
}

impl RootPiece {
    pub(in crate::dispatch) fn owner(&self) -> ResidencyOwner {
        ResidencyOwner::Root(self.incarnation)
    }
}

impl MemState {
    /// Who answers `page`'s first-touch facts (see [`FirstTouchOwner`]).
    pub(in crate::dispatch) fn first_touch_owner(&self, page: u64) -> FirstTouchOwner {
        let Some(root) = self.delegated_root() else {
            return FirstTouchOwner::Host;
        };
        if self.venue_owns(page, page.saturating_add(1)) {
            return FirstTouchOwner::Host;
        }
        let node = root
            .with_root(|model| Ok(model.node(page)))
            .unwrap_or_else(|refusal| broken_root("a first-touch observation", refusal));
        match node {
            None => FirstTouchOwner::Unmapped,
            Some((mapping, incarnation))
                if mapping.anonymous
                    && !super::anonymous::in_heap(
                        mapping.range.start(),
                        mapping.range.end(),
                        self.layout,
                    ) =>
            {
                FirstTouchOwner::Root(mapping, incarnation)
            }
            Some(_) => FirstTouchOwner::Host,
        }
    }

    /// Record `range` resident, each piece under the owner that holds it
    /// now. O(log n + k) in the root nodes `range` touches.
    pub(in crate::dispatch) fn record_resident(&mut self, range: carrick_vfs::GuestMemoryRange) {
        let (start, end) = (range.start().raw(), range.end().raw());
        let pieces = if self.venue_owns(start, end) {
            Vec::new()
        } else {
            self.root_first_touch_pieces(start, end)
        };
        let mut cursor = start;
        for piece in &pieces {
            if let Some(host) = carrick_vfs::GuestMemoryRange::new(
                GuestVa(cursor),
                GuestVa(piece.range.start().raw()),
            ) {
                self.resident.insert(host, ResidencyOwner::Host);
            }
            self.resident.insert(piece.range, piece.owner());
            cursor = piece.range.end().raw();
        }
        if let Some(host) = carrick_vfs::GuestMemoryRange::new(GuestVa(cursor), GuestVa(end)) {
            self.resident.insert(host, ResidencyOwner::Host);
        }
    }

    /// The root-owned first-touch pieces (anonymous nodes outside the heap)
    /// overlapping `[start, end)`, clipped to it, in address order, one per
    /// node. Empty in host setup.
    pub(in crate::dispatch) fn root_first_touch_pieces(
        &self,
        start: u64,
        end: u64,
    ) -> Vec<RootPiece> {
        let Some(root) = self.delegated_root() else {
            return Vec::new();
        };
        let Some(range) = ReservationRange::new(start, end) else {
            return Vec::new();
        };
        let layout = self.layout;
        let mut pieces = Vec::new();
        root.with_root(|model| {
            model.observe_nodes(range, &mut |mapping, incarnation| {
                let (node_start, node_end) = (mapping.range.start(), mapping.range.end());
                if !mapping.anonymous || super::anonymous::in_heap(node_start, node_end, layout) {
                    return;
                }
                if let Some(clipped) = carrick_vfs::GuestMemoryRange::new(
                    GuestVa(node_start.max(start)),
                    GuestVa(node_end.min(end)),
                ) {
                    pieces.push(RootPiece {
                        range: clipped,
                        protection: mapping.protection,
                        incarnation,
                    });
                }
            })
        })
        .unwrap_or_else(|refusal| broken_root("a first-touch observation", refusal));
        pieces
    }

    /// The protection a first touch of root-owned `page` publishes, or
    /// `None` when it is already resident or inaccessible.
    fn root_owes_backing_at(&self, page: u64) -> bool {
        self.delegated_root().is_some_and(|root| {
            root.with_root(|model| {
                let mut overlaps = false;
                model.observe_deferred_returns(&mut |entry| {
                    overlaps |= entry.range.start() <= page && page < entry.range.end();
                });
                Ok(overlaps)
            })
            .unwrap_or_else(|refusal| {
                super::anonymous::broken_root("a resident fault predecessor observation", refusal)
            })
        })
    }

    pub(in crate::dispatch) fn root_armed_prot(
        &self,
        mapping: &Mapping,
        incarnation: ReservationIncarnation,
        page: u64,
    ) -> Option<LinuxProtFlags> {
        if self
            .resident
            .contains(page, ResidencyOwner::Root(incarnation))
        {
            return None;
        }
        let prot = LinuxProtFlags::from_bits_truncate(mapping.protection.bits());
        (!prot.is_empty()).then_some(prot)
    }

    /// The root-derived counterpart of [`FirstTouchArming::grant_for_page`]:
    /// the contiguous run around `page`, clipped to one `max_len`-aligned
    /// window, of non-resident same-protection root-owned pages AND of the
    /// root's holes inside the mmap arena. The holes are first-touch stock:
    /// backing prepared ahead of any mapping, which EL1 hands to a later
    /// guest-venue `mmap` there and commits on first touch only where the
    /// root then holds a node (see `carrick_el1::fault`). The run never
    /// covers a resident page, another node (heap, host-owned, other
    /// protection), an owed return the host has not reconciled, or backing
    /// an earlier grant of this MM already prepared.
    fn root_grant_for_page(
        &self,
        mapping: &Mapping,
        incarnation: ReservationIncarnation,
        page: u64,
        max_len: u64,
    ) -> Option<ResidentFaultRange> {
        if max_len == 0 {
            return None;
        }
        let prot = self.root_armed_prot(mapping, incarnation, page)?;
        let root = self.delegated_root()?;
        let window_start = page - page % max_len;
        let window_end = window_start.checked_add(max_len)?;
        let window = ReservationRange::new(window_start, window_end)?;
        // Stock stays inside the arena and inside the half window holding
        // `page`: a stock grant never claims a whole block, which only a
        // mapping that fills it may (EL1 cannot retire part of a block).
        let half = (max_len / 2).max(crate::linux_abi::LINUX_PAGE_SIZE);
        let arena_start = (page - page % half).max(self.layout.mmap_base);
        let arena_end = (page - page % half)
            .saturating_add(half)
            .min(self.layout.mmap_base.saturating_add(self.layout.mmap_size));
        let mut eligible: Vec<(u64, u64)> = Vec::new();
        let mut owed: Vec<(u64, u64)> = Vec::new();
        root.with_root(|model| {
            let mut cursor = window_start;
            let hole = |eligible: &mut Vec<(u64, u64)>, start: u64, end: u64| {
                let (start, end) = (start.max(arena_start), end.min(arena_end));
                if start < end {
                    eligible.push((start, end));
                }
            };
            model.observe_nodes(window, &mut |node, node_incarnation| {
                let (start, end) = (
                    node.range.start().max(window_start),
                    node.range.end().min(window_end),
                );
                if start > cursor {
                    hole(&mut eligible, cursor, start);
                }
                cursor = cursor.max(end);
                if !node.anonymous
                    || node.protection != mapping.protection
                    || super::anonymous::in_heap(node.range.start(), node.range.end(), self.layout)
                {
                    return;
                }
                // Committed pages split the run, exactly as a commit
                // disarms them: each piece answers under its own
                // incarnation.
                let mut piece_start = start;
                for (resident_start, resident_end) in
                    self.resident
                        .within(start, end, ResidencyOwner::Root(node_incarnation))
                {
                    if resident_start > piece_start {
                        eligible.push((piece_start, resident_start));
                    }
                    piece_start = piece_start.max(resident_end);
                }
                if piece_start < end {
                    eligible.push((piece_start, end));
                }
            })?;
            if cursor < window_end {
                hole(&mut eligible, cursor, window_end);
            }
            model.observe_deferred_returns(&mut |entry| {
                owed.push((entry.range.start(), entry.range.end()));
            });
            Ok(())
        })
        .unwrap_or_else(|refusal| broken_root("a first-touch grant plan", refusal));
        // Holes the host itself still records resident are not stock, and
        // no span this MM's committed backing still occupies is fresh.
        let mut blocked = owed;
        if let Ok(len) = usize::try_from(max_len) {
            blocked.extend(
                self.deferred_anonymous
                    .materialized_within(GuestVa(window_start), len)
                    .into_iter()
                    .map(|span| (span.start.raw(), span.end.raw())),
            );
        }
        blocked.extend(
            self.resident
                .within(window_start, window_end, ResidencyOwner::Host),
        );
        if let Some(table) = carrick_el1_abi::frame_grant_residency_host() {
            table.live_spans_overlapping(root.mm().raw(), window_start, max_len, |start, end| {
                blocked.push((start, end));
            });
        }
        // The maximal contiguous eligible run containing `page`.
        eligible.sort_unstable();
        let index = eligible
            .iter()
            .position(|&(start, end)| start <= page && page < end)?;
        let (mut start, mut end) = eligible[index];
        for &(piece_start, piece_end) in eligible[..index].iter().rev() {
            if piece_end != start {
                break;
            }
            start = piece_start;
        }
        for &(piece_start, piece_end) in &eligible[index + 1..] {
            if piece_start != end {
                break;
            }
            end = piece_end;
        }
        for (blocked_start, blocked_end) in blocked {
            if blocked_end <= start || blocked_start >= end {
                continue;
            }
            if blocked_start <= page && page < blocked_end {
                return None;
            }
            if blocked_end <= page {
                start = start.max(blocked_end);
            } else {
                end = end.min(blocked_start);
            }
        }
        let range = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end))?;
        Some(ResidentFaultRange { range, prot })
    }

    /// Retire the host's residency facts for `holes`: ranges the root held
    /// no node for, now handed out again. Their facts are already dead
    /// (they name retired incarnations); this only reclaims them.
    pub(in crate::dispatch) fn retire_stale_first_touch(&mut self, holes: &[(u64, u64)]) {
        for &(start, end) in holes {
            let Some(range) = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end))
            else {
                continue;
            };
            let _ = self
                .deferred_anonymous
                .retire(GuestVa(start), (end - start) as usize);
            self.resident.remove(range);
            locked_ranges_remove(&mut self.resident_tracked_ranges, range);
            locked_ranges_remove(&mut self.locked_ranges, range);
            self.resident_fault_ranges.disarm(range);
        }
    }

    /// Facts the host venue recorded for a range its own pending proposal
    /// held now belong to the node incarnations the completion committed.
    pub(in crate::dispatch) fn adopt_completed_residency(&mut self, start: u64, end: u64) {
        for piece in self.root_first_touch_pieces(start, end) {
            self.resident
                .hand_over(piece.range, ResidencyOwner::Host, piece.owner());
        }
    }

    /// Hand a demoted root node's first-touch observation to the host: its
    /// pages become host-owned, so the host tracks them and arms every page
    /// not yet resident (under the node's own incarnation) at the node's
    /// protection.
    pub(in crate::dispatch) fn adopt_root_first_touch(&mut self, piece: &RootPiece) {
        let range = piece.range;
        self.resident
            .hand_over(range, piece.owner(), ResidencyOwner::Host);
        locked_ranges_insert(&mut self.resident_tracked_ranges, range);
        self.resident_fault_ranges.disarm(range);
        let mut untouched = vec![range];
        for (start, end) in
            self.resident
                .within(range.start().raw(), range.end().raw(), ResidencyOwner::Host)
        {
            if let Some(resident) = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end))
            {
                locked_ranges_remove(&mut untouched, resident);
            }
        }
        // The root's untouched pages are fresh zero; as host facts they keep
        // that provenance, or their bulk frame grant could never publish
        // (a guest-venue mmap never reserved them with the host).
        for sub in &untouched {
            let (start, end) = (sub.start().raw(), sub.end().raw());
            if let Ok(len) = usize::try_from(end - start) {
                let _ = self.deferred_anonymous.adopt_pristine(GuestVa(start), len);
            }
        }
        let prot = LinuxProtFlags::from_bits_truncate(piece.protection.bits());
        if prot.is_empty() {
            return;
        }
        for sub in untouched {
            self.resident_fault_ranges.arm(sub, prot);
        }
    }
}

/// The pages of `range` that lie inside a first-touch tracked extent and have
/// not been committed resident: exactly the pages whose leaf must stay
/// invalid so their first touch is still observed. On a delegated MM the
/// root-owned pieces are tracked too, each against its own incarnation.
pub(crate) fn tracked_nonresident_subranges(
    mem: &MemState,
    range: carrick_vfs::GuestMemoryRange,
) -> Vec<carrick_vfs::GuestMemoryRange> {
    let (range_start, range_end) = (range.start().raw(), range.end().raw());
    let pieces = mem.root_first_touch_pieces(range_start, range_end);
    let mut out = Vec::new();
    let first = mem
        .resident_tracked_ranges
        .partition_point(|tracked| tracked.end().raw() <= range_start);
    for tracked in &mem.resident_tracked_ranges[first..] {
        if tracked.start().raw() >= range_end {
            break;
        }
        let start = tracked.start().raw().max(range_start);
        let end = tracked.end().raw().min(range_end);
        let Some(sub) = carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) else {
            continue;
        };
        // Host tracking answers only for host-owned pages.
        let mut host = vec![sub];
        for piece in &pieces {
            locked_ranges_remove(&mut host, piece.range);
        }
        for (resident_start, resident_end) in mem.resident.within(start, end, ResidencyOwner::Host)
        {
            if let Some(resident) =
                carrick_vfs::GuestMemoryRange::new(GuestVa(resident_start), GuestVa(resident_end))
            {
                locked_ranges_remove(&mut host, resident);
            }
        }
        for piece in host {
            locked_ranges_insert(&mut out, piece);
        }
    }
    for piece in &pieces {
        let mut untouched = vec![piece.range];
        for (resident_start, resident_end) in mem.resident.within(
            piece.range.start().raw(),
            piece.range.end().raw(),
            piece.owner(),
        ) {
            if let Some(resident) =
                carrick_vfs::GuestMemoryRange::new(GuestVa(resident_start), GuestVa(resident_end))
            {
                locked_ranges_remove(&mut untouched, resident);
            }
        }
        for sub in untouched {
            locked_ranges_insert(&mut out, sub);
        }
    }
    out
}

/// Owns alias exclusion from grow-down fault lookup through backend protection
/// and dispatcher metadata publication.
pub struct MmapGrowdownFaultPlan<'permit> {
    pub(crate) start: u64,
    pub(crate) len: usize,
    pub(crate) exclusion: super::HostAliasDispatchGuard<'permit>,
}

impl MmapGrowdownFaultPlan<'_> {
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Byte length of the grow-down extent this plan protects and publishes.
    /// No `is_empty`: a plan is only minted for a non-empty extent, so the
    /// question the lint asks cannot be true for a live plan.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

/// Owns alias exclusion from resident-fault lookup through backend protection
/// and residency publication.
pub struct ResidentFaultPlan<'permit> {
    pub(crate) page: u64,
    pub(crate) prot: u64,
    pub(crate) exclusion: super::HostAliasDispatchGuard<'permit>,
}

/// Why a verified publication cannot settle against this MM's current facts.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishedFrameGrantRefusal {
    ReceiptShape,
    Identity,
    PublicationProtection,
    BusFault,
    ReturnOwed,
    HostUnarmed,
    Unmapped,
    ProtectionChanged {
        published: LinuxProtFlags,
        current: LinuxProtFlags,
    },
}

/// Owns alias exclusion from a bulk first-touch lookup through host backing
/// preparation and fault-page residency publication.
pub struct ResidentFrameGrantPlan<'permit> {
    pub(crate) fault_page: u64,
    pub(crate) start: u64,
    pub(crate) len: u64,
    pub(crate) prot: u64,
    /// Planned from a delegated root: its span may include first-touch
    /// stock over root holes, and its provenance is the root's.
    pub(crate) root_owned: bool,
    /// The span covers root holes: its grant holds first-touch stock.
    pub(crate) stock: bool,
    pub(crate) exclusion: super::HostAliasDispatchGuard<'permit>,
}

impl ResidentFrameGrantPlan<'_> {
    pub fn fault_page(&self) -> u64 {
        self.fault_page
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn prot(&self) -> u64 {
        self.prot
    }

    /// Whether a grant published earlier for `(start, len, prot)` may
    /// commit this plan's faulting page. Settlement commits only that page,
    /// so it needs that page still armed (this plan exists) with the
    /// published protection, inside the published span. The rest of the
    /// arming may have moved while EL1 held the transaction: an adjacent
    /// mapping merged into the extent, or a sibling's first touch committed
    /// other pages of the span. A reprotected arming does not settle.
    pub fn covers_published(&self, (start, len, prot): (u64, u64, u64)) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        prot == self.prot && (start..end).contains(&self.fault_page)
    }

    pub fn root_owned(&self) -> bool {
        self.root_owned
    }
}

impl ResidentFaultPlan<'_> {
    pub fn page(&self) -> u64 {
        self.page
    }

    pub fn prot(&self) -> u64 {
        self.prot
    }
}

impl<'a> MemView<'a> {
    pub(in crate::dispatch) fn record_mmap_bus_fault_range(&self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        self.mem().lock().bus_fault_ranges.push((start, len));
    }

    pub(crate) fn mmap_fault_is_sigbus(&self, addr: u64) -> bool {
        bus_fault_contains(&self.mem().lock().bus_fault_ranges, addr)
    }

    /// Read-only classifier used at the trap boundary before it chooses the
    /// statically separate fault-mutation route.
    ///
    /// This routes on the whole first-touch and grow-down EXTENTS, not only on
    /// the pages whose stage-1 edit is still pending. A sibling thread can take
    /// its fault against the invalid leaf, lose the MM mutation authority to
    /// the thread that commits the page, and only then reach this classifier;
    /// the pending-edit set no longer names its page, but the fault is stale,
    /// not a `SIGSEGV`. The authority re-asks the exact question against the
    /// live leaf (`resolve_mutating_fault`) — this classifier only has to keep
    /// such a fault on that route.
    pub(crate) fn fault_requires_mm_mutation(&self, addr: u64) -> bool {
        let page = page_floor(addr, self.linux_page_size());
        let mem_authority = self.mem();
        let mem = mem_authority.lock();
        // Binary search, not a scan: this classifier runs on EVERY guest
        // fault and `resident_tracked_ranges` is one entry per live anonymous
        // extent. `growdown_ranges` stays a scan — there is one entry per
        // MAP_GROWSDOWN VMA and a process has a handful.
        let tracked = match mem.first_touch_owner(page) {
            FirstTouchOwner::Host => ranges_contain_page(&mem.resident_tracked_ranges, page),
            FirstTouchOwner::Root(..) => true,
            FirstTouchOwner::Unmapped => false,
        } || mem
            .growdown_ranges
            .iter()
            .any(|&(low, _current, end)| page >= low && page < end);
        if !tracked {
            crate::probes::hvpatch_first_touch_deliver(
                addr,
                carrick_observability::probes::HvpatchFirstTouchDeliverReason::NotTracked,
                0,
            );
        }
        tracked
    }

    pub(in crate::dispatch::mem) fn record_growdown_mapping(&self, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let page_size = self.linux_page_size();
        let stack_span = 256 * page_size;
        let low = end.saturating_sub(stack_span);
        self.mem().lock().growdown_ranges.push((low, start, end));
    }

    pub(crate) fn mmap_growdown_fault_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        addr: u64,
    ) -> Option<MmapGrowdownFaultPlan<'permit>> {
        let exclusion = self.begin_host_alias_dispatch(permit);
        let page = page_floor(addr, self.linux_page_size());
        let mem_authority_6 = self.mem();
        let mem = mem_authority_6.lock();
        for &(low, current, _end) in &mem.growdown_ranges {
            if page >= low && page < current {
                if super::overlaps_el0_clock_stub(page, current - page) {
                    return None;
                }
                let obstacle = mem
                    .dynamic_maps
                    .iter()
                    .any(|map| map.start < current && map.end > low && map.start != current)
                    || mem.root_anonymous_overlaps(low, current - low);
                if obstacle {
                    return None;
                }
                let len = usize::try_from(current - page).ok()?;
                return Some(MmapGrowdownFaultPlan {
                    start: page,
                    len,
                    exclusion: exclusion.with_vma_revision(self.mem().revision_publisher()),
                });
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn with_mmap_growdown_fault_plan_for_test<T>(
        &self,
        addr: u64,
        use_plan: impl FnOnce(MmapGrowdownFaultPlan<'_>) -> T,
    ) -> Option<T> {
        super::mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.mmap_growdown_fault_plan(permit, addr).map(use_plan)
        })
    }

    pub(crate) fn commit_mmap_growdown(&self, plan: MmapGrowdownFaultPlan) {
        if !self.owns_host_alias_dispatch(&plan.exclusion) {
            carrick_fatal!(
                "dispatch::mmap_growdown",
                "caller lacks host alias dispatch exclusion in commit_mmap_growdown"
            );
        }
        let mem_authority_7 = self.mem();
        let mut mem = mem_authority_7.lock();
        for (_low, current, _end) in &mut mem.growdown_ranges {
            if plan.start < *current {
                *current = plan.start;
                break;
            }
        }
        drop(mem);
    }

    pub(in crate::dispatch::mem) fn track_resident_fault_range(
        &self,
        address: u64,
        length: u64,
        prot: LinuxProtFlags,
    ) {
        let Some(range) = carrick_vfs::GuestMemoryRange::new(
            GuestVa(address),
            GuestVa(address.saturating_add(length)),
        ) else {
            return;
        };
        let mem_authority_29 = self.mem();
        let mut mem = mem_authority_29.lock();
        locked_ranges_insert(&mut mem.resident_tracked_ranges, range);
        mem.resident_fault_ranges.arm(range, prot);
    }

    /// Keep first-touch residency arming coherent across an arena `mprotect`.
    ///
    /// The backend edit above made every leaf in the range carry the new
    /// permission, including the pages of a tracked extent the guest has
    /// never touched. Left alone, those pages would become accessible
    /// without the fault that marks them resident (so `mincore` keeps
    /// answering "absent" after a write), and their pending edit would keep
    /// the ARMING-time protection -- a `PROT_NONE` page would be installed
    /// read-write by the next fault instead of delivering SIGSEGV. So every
    /// tracked, still-non-resident page inside the range goes back to an
    /// invalid leaf, and its pending edit is replaced with the new
    /// protection (or dropped for `PROT_NONE`, which has nothing to install;
    /// a later accessible `mprotect` re-arms it here again). Resident pages
    /// keep the valid leaf the edit just published.
    pub(in crate::dispatch::mem) fn rearm_first_touch_after_mprotect(
        &self,
        memory: &mut impl CurrentMmMemory,
        address: u64,
        length: u64,
        prot: LinuxProtFlags,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let Some(range) = carrick_vfs::GuestMemoryRange::new(
            GuestVa(address),
            GuestVa(address.saturating_add(length)),
        ) else {
            return Ok(());
        };
        let untouched = {
            let mem_authority = self.mem();
            let mem = mem_authority.lock();
            tracked_nonresident_subranges(&mem, range)
        };
        if untouched.is_empty() {
            return Ok(());
        }
        for sub in &untouched {
            memory.protect_range(sub.start().raw(), sub.len(), 0)?;
        }
        let mem_authority = self.mem();
        let mut mem = mem_authority.lock();
        mem.resident_fault_ranges.disarm(range);
        if !prot.is_empty() {
            for sub in untouched {
                mem.resident_fault_ranges.arm(sub, prot);
            }
        }
        Ok(())
    }

    pub(in crate::dispatch::mem) fn mark_range_resident(&self, start: u64, len: u64) {
        if let Some(range) =
            carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem().lock().record_resident(range);
        }
    }

    pub(in crate::dispatch::mem) fn mark_range_nonresident(&self, start: u64, len: u64) {
        let Some(range) =
            carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        else {
            return;
        };
        let authority = self.mem();
        if let Some(table) = carrick_el1_abi::frame_grant_residency_host() {
            table.retire_overlapping(authority.mm_id.raw(), start, len);
        }
        let mut mem = authority.lock();
        mem.resident.remove(range);
        let _ = mem
            .deferred_anonymous
            .clear_zero_read_residency(GuestVa(start), len as usize);
    }

    pub(crate) fn resident_fault_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        address: u64,
    ) -> Option<ResidentFaultPlan<'permit>> {
        let exclusion = self.begin_host_alias_dispatch(permit);
        let page = page_floor(address, self.linux_page_size());
        let mem_authority_32 = self.mem();
        let mem = mem_authority_32.lock();
        if bus_fault_contains(&mem.bus_fault_ranges, page) {
            return None;
        }
        if mem.root_owes_backing_at(page) {
            return None;
        }
        let prot = match mem.first_touch_owner(page) {
            FirstTouchOwner::Host => mem.resident_fault_ranges.prot_for_page(page)?,
            FirstTouchOwner::Root(mapping, incarnation) => {
                mem.root_armed_prot(&mapping, incarnation, page)?
            }
            FirstTouchOwner::Unmapped => return None,
        }
        .bits();
        Some(ResidentFaultPlan {
            page,
            prot,
            exclusion,
        })
    }

    pub(crate) fn resident_frame_grant_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        address: u64,
        max_len: u64,
    ) -> Option<ResidentFrameGrantPlan<'permit>> {
        let page_size = self.linux_page_size();
        if max_len == 0 || !max_len.is_multiple_of(page_size) {
            return None;
        }
        let exclusion = self.begin_host_alias_dispatch(permit);
        let page = page_floor(address, page_size);
        let mem_authority = self.mem();
        let mem = mem_authority.lock();
        let (grant, root_owned) = match mem.first_touch_owner(page) {
            FirstTouchOwner::Host => (
                mem.resident_fault_ranges.grant_for_page(page, max_len)?,
                false,
            ),
            FirstTouchOwner::Root(mapping, incarnation) => (
                mem.root_grant_for_page(&mapping, incarnation, page, max_len)?,
                true,
            ),
            FirstTouchOwner::Unmapped => return None,
        };
        let mut start = grant.range.start().raw();
        let mut end = grant.range.end().raw();
        // First-touch arming may cover an eager private-file snapshot's BUS
        // tail. A bulk grant may prepare only the contiguous backed span
        // containing the faulting page; otherwise publication tags the BUS
        // page as live EL1-private backing before signal classification.
        for &(bus_start, bus_len) in &mem.bus_fault_ranges {
            let bus_end = bus_start.checked_add(bus_len)?;
            if bus_start <= page && page < bus_end {
                return None;
            }
            if bus_end <= page {
                start = start.max(bus_end);
            } else if bus_start > page {
                end = end.min(bus_start);
            }
        }
        if start >= end {
            return None;
        }
        let stock = root_owned
            && mem.delegated_root().is_some_and(|root| {
                ReservationRange::new(start, end).is_some_and(|span| {
                    root.with_root(|model| root_holes(model, span))
                        .is_ok_and(|holes| !holes.is_empty())
                })
            });
        Some(ResidentFrameGrantPlan {
            root_owned,
            stock,
            fault_page: page,
            start,
            len: end - start,
            prot: grant.prot.bits(),
            exclusion,
        })
    }

    pub(crate) fn published_frame_grant_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        grant: carrick_el1_abi::FrameGrantResidencyIdentity,
        protection: LinuxProtFlags,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
    ) -> Result<ResidentFrameGrantPlan<'permit>, PublishedFrameGrantRefusal> {
        let (publication, backing) = receipt
            .prepared_backing()
            .ok_or(PublishedFrameGrantRefusal::ReceiptShape)?;
        let resident = receipt.resident();
        let end = publication
            .va
            .checked_add(publication.len)
            .ok_or(PublishedFrameGrantRefusal::ReceiptShape)?;
        if grant.mm_key != permit.mm().raw()
            || receipt.id().mm_key.get() != grant.mm_key
            || (publication.va, publication.ipa, publication.len)
                != (grant.semantic_base, grant.physical_ipa, grant.len)
            || (
                backing.frame_id.get(),
                backing.mapping_id.get(),
                backing.owner_generation.get(),
                backing.inventory_revision.get(),
            ) != (
                grant.frame_id,
                grant.mapping_id,
                grant.owner_generation,
                grant.inventory_revision,
            )
            || resident.len != self.linux_page_size()
            || resident.va < publication.va
            || resident
                .end()
                .ok_or(PublishedFrameGrantRefusal::ReceiptShape)?
                > end
        {
            return Err(PublishedFrameGrantRefusal::Identity);
        }
        if protection.is_empty()
            || protection.contains(LinuxProtFlags::WRITE) != publication.writable
            || protection.contains(LinuxProtFlags::EXEC) != publication.executable
        {
            return Err(PublishedFrameGrantRefusal::PublicationProtection);
        }
        let exclusion = self.begin_host_alias_dispatch(permit);
        let mem_authority = self.mem();
        let mem = mem_authority.lock();
        if bus_fault_contains(&mem.bus_fault_ranges, resident.va) {
            return Err(PublishedFrameGrantRefusal::BusFault);
        }
        if mem.root_owes_backing_at(resident.va) {
            return Err(PublishedFrameGrantRefusal::ReturnOwed);
        }
        // The authenticated publication is not a fresh allocation. EL1's
        // residency reconciliation may already have committed this page.
        let (prot, root_owned) = match mem.first_touch_owner(resident.va) {
            FirstTouchOwner::Root(mapping, _) => (
                LinuxProtFlags::from_bits_truncate(mapping.protection.bits()),
                true,
            ),
            FirstTouchOwner::Host => (
                mem.resident_fault_ranges
                    .prot_for_page(resident.va)
                    .ok_or(PublishedFrameGrantRefusal::HostUnarmed)?,
                false,
            ),
            FirstTouchOwner::Unmapped => return Err(PublishedFrameGrantRefusal::Unmapped),
        };
        if prot != protection {
            return Err(PublishedFrameGrantRefusal::ProtectionChanged {
                published: protection,
                current: prot,
            });
        }
        let stock = root_owned
            && mem.delegated_root().is_some_and(|root| {
                ReservationRange::new(publication.va, end).is_some_and(|span| {
                    !root
                        .with_root(|model| root_holes(model, span))
                        .unwrap_or_else(|refusal| {
                            broken_root("a published grant stock observation", refusal)
                        })
                        .is_empty()
                })
            });
        Ok(ResidentFrameGrantPlan {
            root_owned,
            stock,
            fault_page: resident.va,
            start: publication.va,
            len: publication.len,
            prot: prot.bits(),
            exclusion,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn seed_resident_fault_for_test(&self, page: u64, prot: u64) {
        self.track_resident_fault_range(
            page,
            self.linux_page_size(),
            LinuxProtFlags::from_bits_truncate(prot),
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_resident_fault_plan_for_test<T>(
        &self,
        addr: u64,
        use_plan: impl FnOnce(ResidentFaultPlan<'_>) -> T,
    ) -> Option<T> {
        super::mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.resident_fault_plan(permit, addr).map(use_plan)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_resident_frame_grant_plan_for_test<T>(
        &self,
        addr: u64,
        max_len: u64,
        use_plan: impl FnOnce(ResidentFrameGrantPlan<'_>) -> T,
    ) -> Option<T> {
        super::mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.resident_frame_grant_plan(permit, addr, max_len)
                .map(use_plan)
        })
    }

    pub(crate) fn commit_resident_fault(&self, plan: ResidentFaultPlan) {
        if !self.owns_host_alias_dispatch(&plan.exclusion) {
            carrick_fatal!(
                "dispatch::resident_fault",
                "caller lacks host alias dispatch exclusion during commit_resident_fault"
            );
        }
        let Some(end) = plan.page.checked_add(self.linux_page_size()) else {
            return;
        };
        let Some(range) = carrick_vfs::GuestMemoryRange::new(GuestVa(plan.page), GuestVa(end))
        else {
            return;
        };
        let mem_authority_33 = self.mem();
        let mut mem = mem_authority_33.lock();
        mem.record_resident(range);
        mem.resident_fault_ranges.disarm(range);
    }

    pub(crate) fn commit_resident_frame_grant(&self, plan: ResidentFrameGrantPlan<'_>) {
        if !self.owns_host_alias_dispatch(&plan.exclusion) {
            carrick_fatal!(
                "dispatch::resident_frame_grant",
                "caller lacks host alias dispatch exclusion during commit_resident_frame_grant"
            );
        }
        if plan.stock
            && let Some(span) =
                ReservationRange::new(plan.start, plan.start.saturating_add(plan.len))
        {
            // Returned at the next reconciliation unless a mapping adopts
            // it first (`returns::first_touch_stock`).
            self.mem().lock().first_touch_stock.push(span);
        }
        // Physical preparation can be bulk; only the faulting Linux page
        // has become accessible. Keep every speculative page armed, so a
        // later touch publishes its retained output and records residency.
        self.commit_resident_fault(ResidentFaultPlan {
            page: plan.fault_page,
            prot: plan.prot,
            exclusion: plan.exclusion,
        });
    }

    /// Before a root-owned plan's backing is prepared: its span is fresh
    /// zero by the root's answer (untouched pages of live incarnations and
    /// root holes no live grant or owed return covers). A guest-venue mmap
    /// never reserved that provenance with the host; publish it now, under
    /// the same permit, for exactly the span about to be granted.
    pub(crate) fn adopt_frame_grant_provenance(&self, plan: &ResidentFrameGrantPlan<'_>) {
        if !plan.root_owned || !self.owns_host_alias_dispatch(&plan.exclusion) {
            return;
        }
        let Ok(len) = usize::try_from(plan.len) else {
            return;
        };
        let _ = self
            .mem()
            .lock()
            .deferred_anonymous
            .adopt_pristine(GuestVa(plan.start), len);
    }

    pub(in crate::dispatch::mem) fn populate_resident_range(
        &self,
        memory: &mut impl CurrentMmMemory,
        range: carrick_vfs::GuestMemoryRange,
    ) -> Result<(), LinuxErrno> {
        let faults = {
            let mem_authority_34 = self.mem();
            let mem = mem_authority_34.lock();
            mem.resident_fault_ranges.intersections(range)
        };
        for fault in &faults {
            let len = range_len_usize(fault.range)?;
            memory
                .protect_range(fault.range.start().raw(), len, fault.prot.bits())
                .map_err(|_| LINUX_ENOMEM)?;
        }
        let mem_authority_35 = self.mem();
        let mut mem = mem_authority_35.lock();
        mem.record_resident(range);
        mem.resident_fault_ranges.disarm(range);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

/// Page-aligned data runs for a sparse core payload. Zero pages have identical
/// contents when represented by holes, including pages prepared speculatively.
/// Inspect bytes, not first-touch metadata: host writes also contribute data.
pub fn core_data_runs(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut runs: Vec<std::ops::Range<usize>> = Vec::new();
    for (index, page) in bytes.chunks(LINUX_PAGE_SIZE as usize).enumerate() {
        if page.iter().all(|byte| *byte == 0) {
            continue;
        }
        let start = index * LINUX_PAGE_SIZE as usize;
        let end = start + page.len();
        if let Some(last) = runs.last_mut()
            && last.end == start
        {
            last.end = end;
        } else {
            runs.push(start..end);
        }
    }
    runs
}
