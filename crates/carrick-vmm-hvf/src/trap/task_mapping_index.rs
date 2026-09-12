//! # Task Mapping Index
//!
//! The per-task mapping table: sorted by construction, non-overlapping, and coalescing.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

/// Where one row lives inside a [`TaskMappingIndex`].
///
/// The ordered live map is keyed by `start`, so a row that has been displaced
/// into the shadow list cannot be named by a `GuestVa`. Retirement takes a
/// handle out and hands the same handle back on rollback.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum MappingRowRef {
    Live(GuestVa),
    Shadowed(usize),
}

/// An extent in either guest virtual address (VA) space or stage-2 intermediate
/// physical address (IPA) space, used to bound keyed removals.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappingExtent {
    Va(GuestVa, u64),
    Ipa(u64, u64),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MappingExtent {
    pub(crate) fn overlaps_region(&self, region: &HvfMappedRegion) -> bool {
        match self {
            Self::Va(start, length) => {
                if *length == 0 {
                    return false;
                }
                let va_start = start.0;
                let va_end = va_start.checked_add(*length);
                match va_end {
                    Some(end) => region.start < end && region.end > va_start,
                    None => region.end > va_start,
                }
            }
            Self::Ipa(base, length) => {
                if *length == 0 {
                    return false;
                }
                let ipa_start = *base;
                let ipa_end = ipa_start.checked_add(*length);
                let row_ipa_end = region.ipa.saturating_add(region.size as u64);
                let phys_end = region
                    .physical_ipa
                    .saturating_add(region.physical_size as u64);
                let matches_ipa = match ipa_end {
                    Some(end) => region.ipa < end && row_ipa_end > ipa_start,
                    None => row_ipa_end > ipa_start,
                };
                let matches_phys = match ipa_end {
                    Some(end) => region.physical_ipa < end && phys_end > ipa_start,
                    None => phys_end > ipa_start,
                };
                matches_ipa || matches_phys
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<(GuestVa, u64)> for MappingExtent {
    fn from((va, len): (GuestVa, u64)) -> Self {
        Self::Va(va, len)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<(GuestVa, usize)> for MappingExtent {
    fn from((va, len): (GuestVa, usize)) -> Self {
        Self::Va(va, len as u64)
    }
}

/// The per-task mapping table: sorted by construction, non-overlapping, and
/// coalescing.
///
/// This replaces the `Vec<HvfMappedRegion>` whose linear `iter().rev().find()`
/// scans made every first-touch fault cost O(rows): the row count grew by one
/// per materialized extent (~40k-100k rows compiling a deeply nested CPython
/// expression) and eight scans ran per fault, so fault handling was quadratic
/// in the number of extents. Two properties fix that:
///
/// * **Ordered.** `live` is a `BTreeMap` keyed by `HvfMappedRegion::start`, so
///   a VA lookup is `range(..=va).next_back()` — O(log N) instead of O(N).
/// * **Coalescing.** [`Self::insert`] merges a new row into an adjacent one
///   when the two describe the same VMA in every load-bearing respect (owner
///   generation, structural owner identity, permissions, sharing, and both
///   virtual AND physical contiguity), so a first-touch storm inside one VMA
///   stays ONE row. The row count is then O(#VMAs), not O(#faults).
///
/// **Displaced rows.** The vector this replaces allowed overlapping rows and
/// resolved them newest-first, so a new row shadowed an older one without
/// dropping it. Dropping it eagerly would change when a `stage2_lease` or a
/// backing handle is released — the exact hazard behind the earlier
/// window-corruption bug — so an overlapped row is moved to `shadowed` instead
/// of being destroyed. It keeps its handles, it is still visited by every
/// full-table pass (retirement, fork copy, `retain`), and it is still
/// consulted by VA lookups after the ordered probe misses, but it is out of
/// the ordered fast path. In practice this list stays empty; it exists so that
/// making the table non-overlapping cannot change object lifetimes.
///
/// Row identity is still authenticated per lookup by `row_projection_is_current`
/// and the owner-generation checks; ordering only decides which row is offered.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct TaskMappingIndex {
    live: std::collections::BTreeMap<GuestVa, HvfMappedRegion>,
    /// Rows an overlapping insert displaced. Retained only so that displacing
    /// a row never changes when its handles drop.
    shadowed: Vec<HvfMappedRegion>,
    /// Live rows ordered by stage-2 IPA base, `(row.ipa, row.start)` naming the
    /// `live` key. Rows may share an IPA (a fork peer keeps the same physical
    /// frame at another VA), so this is a set, not a map from IPA to row.
    ///
    /// This exists because the raw-IPA lookup the page-table walk does on EVERY
    /// fault (`diagnostic_fault_page_tables` -> `host_ptr` ->
    /// `mapping_for_ipa_range`) wants the page-table root row, which is
    /// published early at a LOW guest VA. A reverse walk of the VA-ordered map
    /// reaches it LAST, so without this index that lookup stays a full-table
    /// scan -- and a reverse `BTreeMap` walk costs several times more per row
    /// than the contiguous vector this type replaced, which measured as a NET
    /// 1.39x REGRESSION (docs/perf-results/2026-09-08-mapping-index-measurement.md).
    by_ipa: std::collections::BTreeSet<(u64, u64)>,
    /// Live rows ordered by physical stage-2 IPA base, `(row.physical_ipa, row.start)`.
    by_physical: std::collections::BTreeSet<(u64, u64)>,
    /// How many live rows have each semantic `size`. Only the largest matters: it bounds
    /// how far below a queried IPA a row that still covers it can begin.
    ipa_span_counts: std::collections::BTreeMap<u64, usize>,
    /// How many live rows have each `physical_size`.
    physical_span_counts: std::collections::BTreeMap<u64, usize>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl TaskMappingIndex {
    pub(crate) fn new() -> Self {
        Self {
            live: std::collections::BTreeMap::new(),
            shadowed: Vec::new(),
            by_ipa: std::collections::BTreeSet::new(),
            by_physical: std::collections::BTreeSet::new(),
            ipa_span_counts: std::collections::BTreeMap::new(),
            physical_span_counts: std::collections::BTreeMap::new(),
        }
    }

    /// Publish one row into the live map and both ordered views. Every live
    /// insertion goes through here so the IPA view cannot drift.
    fn live_insert(&mut self, region: HvfMappedRegion) {
        self.by_ipa.insert((region.ipa, region.start));
        self.by_physical.insert((region.physical_ipa, region.start));
        let span = region.size as u64;
        *self.ipa_span_counts.entry(span).or_insert(0) += 1;
        let phys_span = region.physical_size as u64;
        *self.physical_span_counts.entry(phys_span).or_insert(0) += 1;
        if let Some(previous) = self.live.insert(GuestVa(region.start), region) {
            // A same-start replacement: retire the row that left.
            self.forget_ipa_entry(&previous);
        }
    }

    /// Take one row out of the live map and both ordered views.
    fn live_remove(&mut self, key: &GuestVa) -> Option<HvfMappedRegion> {
        let row = self.live.remove(key)?;
        self.forget_ipa_entry(&row);
        Some(row)
    }

    fn forget_ipa_entry(&mut self, row: &HvfMappedRegion) {
        self.by_ipa.remove(&(row.ipa, row.start));
        self.by_physical.remove(&(row.physical_ipa, row.start));
        let span = row.size as u64;
        if let std::collections::btree_map::Entry::Occupied(mut span_entry) =
            self.ipa_span_counts.entry(span)
        {
            *span_entry.get_mut() -= 1;
            if *span_entry.get() == 0 {
                span_entry.remove();
            }
        }
        let phys_span = row.physical_size as u64;
        if let std::collections::btree_map::Entry::Occupied(mut span_entry) =
            self.physical_span_counts.entry(phys_span)
        {
            *span_entry.get_mut() -= 1;
            if *span_entry.get() == 0 {
                span_entry.remove();
            }
        }
    }

    /// The largest `size` any live row has, or 0 when there are none.
    fn max_ipa_span(&self) -> u64 {
        self.ipa_span_counts
            .last_key_value()
            .map(|(span, _)| *span)
            .unwrap_or_default()
    }

    /// The largest `physical_size` any live row has, or 0 when there are none.
    fn max_physical_span(&self) -> u64 {
        self.physical_span_counts
            .last_key_value()
            .map(|(span, _)| *span)
            .unwrap_or_default()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_region(region: HvfMappedRegion) -> Self {
        let mut index = Self::new();
        index.insert(region);
        index
    }

    /// Strict ordering and non-overlap of the live map, checked after every
    /// mutation in debug builds.
    #[cfg(debug_assertions)]
    fn assert_invariants(&self) {
        let mut prev: Option<(u64, u64)> = None;
        for (va, region) in &self.live {
            debug_assert_eq!(
                va.0, region.start,
                "TaskMappingIndex key must be the row start: key=0x{:x} start=0x{:x}",
                va.0, region.start
            );
            debug_assert!(
                region.start < region.end,
                "TaskMappingIndex row must be non-empty: [0x{:x}, 0x{:x})",
                region.start,
                region.end
            );
            if let Some((prev_start, prev_end)) = prev {
                debug_assert!(
                    prev_end <= region.start,
                    "TaskMappingIndex rows must be strictly increasing and non-overlapping: \
                     [0x{prev_start:x}, 0x{prev_end:x}) then [0x{:x}, 0x{:x})",
                    region.start,
                    region.end
                );
            }
            prev = Some((region.start, region.end));
        }
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn assert_invariants(&self) {}

    /// Strict ordering and non-overlap of the live map checked incrementally
    /// around a removed row's immediate neighbours in debug builds.
    #[cfg(debug_assertions)]
    fn assert_invariants_after_removal(&self, key: GuestVa) {
        let prev = self.live.range(..key).next_back();
        let next = self.live.range(key..).next();
        if let Some((prev_va, prev_row)) = prev {
            debug_assert_eq!(
                prev_va.0, prev_row.start,
                "TaskMappingIndex key must be the row start: key=0x{:x} start=0x{:x}",
                prev_va.0, prev_row.start
            );
            debug_assert!(
                prev_row.start < prev_row.end,
                "TaskMappingIndex row must be non-empty: [0x{:x}, 0x{:x})",
                prev_row.start,
                prev_row.end
            );
            if let Some((next_va, next_row)) = next {
                debug_assert_eq!(
                    next_va.0, next_row.start,
                    "TaskMappingIndex key must be the row start: key=0x{:x} start=0x{:x}",
                    next_va.0, next_row.start
                );
                debug_assert!(
                    next_row.start < next_row.end,
                    "TaskMappingIndex row must be non-empty: [0x{:x}, 0x{:x})",
                    next_row.start,
                    next_row.end
                );
                debug_assert!(
                    prev_row.end <= next_row.start,
                    "TaskMappingIndex rows must be strictly increasing and non-overlapping after removal: \
                     [0x{:x}, 0x{:x}) then [0x{:x}, 0x{:x})",
                    prev_row.start,
                    prev_row.end,
                    next_row.start,
                    next_row.end
                );
            }
        } else if let Some((next_va, next_row)) = next {
            debug_assert_eq!(
                next_va.0, next_row.start,
                "TaskMappingIndex key must be the row start: key=0x{:x} start=0x{:x}",
                next_va.0, next_row.start
            );
            debug_assert!(
                next_row.start < next_row.end,
                "TaskMappingIndex row must be non-empty: [0x{:x}, 0x{:x})",
                next_row.start,
                next_row.end
            );
        }
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn assert_invariants_after_removal(&self, _key: GuestVa) {}

    /// Publish `region`, coalescing it into an adjacent row when the two
    /// describe the same extent of the same VMA.
    ///
    /// Any live row the new one overlaps is displaced into `shadowed` rather
    /// than dropped: the new row wins every lookup (as the newest row did in
    /// the vector this replaces) without altering when the old row's handles
    /// are released.
    pub(crate) fn insert(&mut self, mut region: HvfMappedRegion) {
        if region.end > region.start {
            self.displace_overlapping(region.start, region.end);
        }

        let predecessor = self
            .live
            .range(..GuestVa(region.start))
            .next_back()
            .map(|(key, _)| *key)
            .filter(|key| {
                self.live
                    .get(key)
                    .is_some_and(|left| can_coalesce_mappings(left, &region))
            });
        if let Some(key) = predecessor
            && let Some(mut left) = self.live_remove(&key)
        {
            coalesce_mappings_into_left(&mut left, region);
            region = left;
        }

        let successor = GuestVa(region.end);
        if self
            .live
            .get(&successor)
            .is_some_and(|right| can_coalesce_mappings(&region, right))
            && let Some(right) = self.live_remove(&successor)
        {
            coalesce_mappings_into_left(&mut region, right);
        }

        self.live_insert(region);
        self.assert_invariants();
    }

    /// Move every live row intersecting `[start, end)` into `shadowed`.
    ///
    /// **This vector is not bounded, and the obvious bound is not safe.**
    /// Dropping a displaced row that lies entirely inside the incoming row's
    /// range and holds no lifetime handle
    /// ([`HvfMappedRegion::holds_backing_handle`]) is behaviour-preserving for
    /// every ORDERED query -- `candidates_for_range` yields live rows first so
    /// the incoming row already won those lookups; `first_start_between` can
    /// only answer smaller, because a dropped row's start lies in the query
    /// range only when the incoming row's start does too; and
    /// `any_lower_row_reaches` reads the immediate live predecessor, which
    /// reaches at least as far down. It is NOT safe for row IDENTITY: a fork
    /// child's inherited rows are handle-free by construction (the child sets
    /// `memory`/`host_mapping` to `None` after `mem::forget`, because the
    /// pages live on through COW), so handle-freedom does not mean "nothing to
    /// keep". `an_overlapping_publication_wins_lookups_without_dropping_the_row_it_shadows`
    /// pins exactly that case -- a child's rebased vvar row overlapping its
    /// parent's exactly -- and the drop deletes the parent incarnation it
    /// requires to stay reachable.
    ///
    /// A safe retirement has to key on whether the displaced row's owner
    /// generation still authenticates against the live global-frame owner,
    /// which is the same authority every other retirement site uses and which
    /// this type does not hold: `insert` takes no custody.
    /// `repeated_overlapping_publication_retains_one_row_per_incarnation`
    /// measures what actually accumulates.
    fn displace_overlapping(&mut self, start: u64, end: u64) {
        let mut displaced = Vec::new();
        if let Some((&key, row)) = self.live.range(..GuestVa(start)).next_back()
            && row.end > start
        {
            displaced.push(key);
        }
        displaced.extend(
            self.live
                .range(GuestVa(start)..GuestVa(end))
                .map(|(key, _)| *key),
        );
        for key in displaced {
            if let Some(row) = self.live_remove(&key) {
                self.shadowed.push(row);
            }
        }
    }

    /// Drop every row intersecting `[va, va + len)` outright.
    ///
    /// Used where the caller has already unmapped the extent and the rows
    /// describing it must not outlive that unmap.
    pub(crate) fn remove_range(&mut self, va: GuestVa, len: usize) {
        let Some(end) = va.0.checked_add(len as u64) else {
            return;
        };
        let mut doomed = Vec::new();
        if let Some((&key, row)) = self.live.range(..va).next_back()
            && row.end > va.0
        {
            doomed.push(key);
        }
        doomed.extend(self.live.range(va..GuestVa(end)).map(|(key, _)| *key));
        for key in doomed {
            self.live_remove(&key);
        }
        self.shadowed
            .retain(|row| row.end <= va.0 || row.start >= end);
        self.assert_invariants();
    }

    pub(crate) fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&HvfMappedRegion) -> bool,
    {
        let dropped: Vec<GuestVa> = self
            .live
            .iter()
            .filter(|(_, row)| !predicate(row))
            .map(|(key, _)| *key)
            .collect();
        for key in dropped {
            self.live_remove(&key);
        }
        self.shadowed.retain(|row| predicate(row));
        self.assert_invariants();
    }

    /// Keyed removal API: for a set of VA and/or IPA extents, visits ONLY the rows
    /// those extents can contain, applying `predicate` to them. Rows matching
    /// `predicate` are removed.
    ///
    /// For [`MappingExtent::Ipa`], candidate discovery searches BOTH `by_ipa`
    /// (semantic projection, windowed by [`Self::max_ipa_span`]) and `by_physical`
    /// (physical stage-2 owner extent, windowed by [`Self::max_physical_span`]).
    /// This guarantees that whether the queried extent is a semantic projection or
    /// a physical lease extent, all candidate rows intersecting the extent are
    /// discovered in sublinear time without requiring containment assumptions.
    pub(crate) fn remove_rows_matching_in_ranges<F>(
        &mut self,
        ranges: &[MappingExtent],
        mut predicate: F,
    ) -> usize
    where
        F: FnMut(&HvfMappedRegion) -> bool,
    {
        if ranges.is_empty() || self.is_empty() {
            return 0;
        }

        let mut candidate_keys = std::collections::BTreeSet::new();

        for range in ranges {
            match range {
                MappingExtent::Va(start, length) => {
                    if *length == 0 {
                        continue;
                    }
                    let va_start = start.0;
                    let va_end = va_start.checked_add(*length);
                    if let Some((&key, row)) = self.live.range(..start).next_back() {
                        if row.end > va_start {
                            candidate_keys.insert(key);
                        }
                    }
                    match va_end {
                        Some(end) => {
                            for (&key, _) in self.live.range(*start..GuestVa(end)) {
                                candidate_keys.insert(key);
                            }
                        }
                        None => {
                            for (&key, _) in self.live.range(*start..) {
                                candidate_keys.insert(key);
                            }
                        }
                    }
                }
                MappingExtent::Ipa(base, length) => {
                    if *length == 0 {
                        continue;
                    }
                    let ipa_start = *base;
                    let ipa_end = ipa_start.checked_add(*length);
                    let floor = ipa_start.saturating_sub(self.max_ipa_span());
                    let ceil = ipa_end
                        .and_then(|e| e.checked_add(self.max_ipa_span()))
                        .unwrap_or(u64::MAX);
                    let range_bounds = if ceil < u64::MAX {
                        (
                            std::ops::Bound::Included((floor, 0)),
                            std::ops::Bound::Excluded((ceil, 0)),
                        )
                    } else {
                        (
                            std::ops::Bound::Included((floor, 0)),
                            std::ops::Bound::Unbounded,
                        )
                    };
                    for &(_row_ipa, start) in self.by_ipa.range(range_bounds) {
                        candidate_keys.insert(GuestVa(start));
                    }
                    let floor_phys = ipa_start.saturating_sub(self.max_physical_span());
                    let ceil_phys = ipa_end
                        .and_then(|e| e.checked_add(self.max_physical_span()))
                        .unwrap_or(u64::MAX);
                    let range_bounds_phys = if ceil_phys < u64::MAX {
                        (
                            std::ops::Bound::Included((floor_phys, 0)),
                            std::ops::Bound::Excluded((ceil_phys, 0)),
                        )
                    } else {
                        (
                            std::ops::Bound::Included((floor_phys, 0)),
                            std::ops::Bound::Unbounded,
                        )
                    };
                    for &(_phys_ipa, start) in self.by_physical.range(range_bounds_phys) {
                        candidate_keys.insert(GuestVa(start));
                    }
                }
            }
        }

        let mut doomed_live = Vec::new();
        for key in candidate_keys {
            if let Some(row) = self.live.get(&key) {
                if ranges.iter().any(|r| r.overlaps_region(row)) {
                    note_task_mapping_row_visited();
                    if predicate(row) {
                        doomed_live.push(key);
                    }
                }
            }
        }

        let mut removed_count = 0;
        for key in doomed_live {
            if self.live_remove(&key).is_some() {
                self.assert_invariants_after_removal(key);
                removed_count += 1;
            }
        }

        let mut idx = 0;
        while idx < self.shadowed.len() {
            let overlaps = ranges
                .iter()
                .any(|r| r.overlaps_region(&self.shadowed[idx]));
            if overlaps {
                note_task_mapping_row_visited();
                if predicate(&self.shadowed[idx]) {
                    self.shadowed.remove(idx);
                    removed_count += 1;
                    continue;
                }
            }
            idx += 1;
        }

        removed_count
    }

    pub(crate) fn clear(&mut self) {
        self.live.clear();
        self.shadowed.clear();
        self.by_ipa.clear();
        self.by_physical.clear();
        self.ipa_span_counts.clear();
        self.physical_span_counts.clear();
    }

    /// Total row count, live and displaced.
    pub(crate) fn len(&self) -> usize {
        self.live.len() + self.shadowed.len()
    }

    /// Rows in the ordered live map. Read by the per-fault census so a probe
    /// consumer can separate the population from the displaced backlog.
    pub(crate) fn live_len(&self) -> usize {
        self.live.len()
    }

    /// Rows an overlapping insert displaced, still holding their handles.
    pub(crate) fn shadowed_len(&self) -> usize {
        self.shadowed.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.live.is_empty() && self.shadowed.is_empty()
    }

    /// Live rows only, ordered by start. Used only for exact-start lookups.
    pub(crate) fn get(&self, key: &GuestVa) -> Option<&HvfMappedRegion> {
        self.live.get(key)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn first(&self) -> Option<&HvfMappedRegion> {
        self.live.values().next()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn first_mut(&mut self) -> Option<&mut HvfMappedRegion> {
        self.live.values_mut().next()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last(&self) -> Option<&HvfMappedRegion> {
        self.live.values().next_back()
    }

    /// Every row, ascending by start; displaced rows lead so that a reversed
    /// walk still yields the newest row first, as the vector did.
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &HvfMappedRegion> {
        self.shadowed
            .iter()
            .chain(self.live.values())
            .inspect(|_| note_task_mapping_row_visited())
    }

    pub(crate) fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut HvfMappedRegion> {
        self.shadowed.iter_mut().chain(self.live.values_mut())
    }

    pub(crate) fn into_values(self) -> impl DoubleEndedIterator<Item = HvfMappedRegion> {
        self.shadowed.into_iter().chain(self.live.into_values())
    }

    /// Rows that can overlap `[va, va + length)`, newest first.
    ///
    /// Live rows are ordered and non-overlapping, so the walk starts just below
    /// the range end and stops at the first row ending at or before `va` --
    /// every earlier row ends there too. That is O(overlapping rows + 1), not
    /// O(N). A lookup may legitimately name a VA below the row it wants (a
    /// compound COW span begins before its live semantic view), which is why
    /// this is an overlap query and not a `range(..=va).next_back()` probe.
    /// Displaced rows follow, preserving the vector's newest-first resolution.
    pub(crate) fn candidates_for_range(
        &self,
        va: GuestVa,
        length: u64,
    ) -> impl Iterator<Item = &HvfMappedRegion> {
        let start = va.0;
        let end = GuestVa(start.saturating_add(length.max(1)));
        self.live
            .range(..end)
            .rev()
            .map(|(_, row)| row)
            .take_while(move |row| row.end > start)
            .chain(self.shadowed.iter().rev())
            .inspect(|_| note_task_mapping_row_visited())
    }

    /// The lowest row start strictly inside `(after, before)` for which
    /// `accept` holds, or `None`.
    ///
    /// This is the "where does the next live neighbour begin" question the
    /// sparse-materialization window arm asks before it publishes. It used to
    /// be a full `filter().map().min()` scan because the vector was unsorted;
    /// ordered rows answer it from the range itself.
    pub(crate) fn first_start_between<F>(
        &self,
        after: GuestVa,
        before: GuestVa,
        mut accept: F,
    ) -> Option<u64>
    where
        F: FnMut(&HvfMappedRegion) -> bool,
    {
        use std::ops::Bound;
        let live = self
            .live
            .range((Bound::Excluded(after), Bound::Excluded(before)))
            .map(|(_, row)| row)
            .inspect(|_| note_task_mapping_row_visited())
            .find(|row| accept(row))
            .map(|row| row.start);
        note_hot_path_rows(HotPathScan::TaskMappings, self.shadowed.len());
        let displaced = self
            .shadowed
            .iter()
            .filter(|row| row.start > after.0 && row.start < before.0 && accept(row))
            .map(|row| row.start)
            .min();
        live.into_iter().chain(displaced).min()
    }

    /// Whether any row begins below `current` and still extends past
    /// `floor` -- i.e. whether widening a window down to `floor` would
    /// overlap a live neighbour.
    ///
    /// Live rows are ordered and non-overlapping, so `end` is monotonic and
    /// only the row immediately below `current` can reach furthest down.
    pub(crate) fn any_lower_row_reaches(&self, current: GuestVa, floor: u64) -> bool {
        note_task_mapping_row_visited();
        if self
            .live
            .range(..current)
            .next_back()
            .is_some_and(|(_, row)| row.end > floor)
        {
            return true;
        }
        note_hot_path_rows(HotPathScan::TaskMappings, self.shadowed.len());
        self.shadowed
            .iter()
            .any(|row| row.start < current.0 && row.end > floor)
    }

    /// Rows that can cover `[ipa, ipa + length)` in the stage-2 IPA domain,
    /// nearest-IPA first, then the displaced rows.
    ///
    /// A row covers the query only if `row.ipa <= ipa`, so the walk starts at
    /// the query and descends; no row beginning more than `max_ipa_span` below
    /// it can still reach it, which ends the walk. Where the old reverse
    /// vector scan visited every row to find the page-table root, this visits
    /// the rows whose IPA is actually near the one asked for.
    pub(crate) fn candidates_for_ipa_range(
        &self,
        ipa: u64,
        length: u64,
    ) -> impl Iterator<Item = &HvfMappedRegion> {
        let floor = ipa.saturating_sub(self.max_ipa_span());
        self.by_ipa
            .range(..=(ipa, u64::MAX))
            .rev()
            .inspect(|_| note_task_mapping_row_visited())
            .take_while(move |(row_ipa, _)| *row_ipa >= floor)
            .filter_map(|(_, start)| self.live.get(&GuestVa(*start)))
            .filter(move |row| {
                row.ipa
                    .checked_add(row.size as u64)
                    .is_some_and(|limit| ipa >= row.ipa && ipa.saturating_add(length) <= limit)
            })
            .chain(
                self.shadowed
                    .iter()
                    .rev()
                    .inspect(|_| note_task_mapping_row_visited())
                    .filter(move |row| {
                        row.ipa.checked_add(row.size as u64).is_some_and(|limit| {
                            ipa >= row.ipa && ipa.saturating_add(length) <= limit
                        })
                    }),
            )
    }

    /// The row covering `[va, va + length)`, or `None`.
    pub(crate) fn mapping_for_range(&self, va: GuestVa, length: usize) -> Option<&HvfMappedRegion> {
        self.candidates_for_range(va, length as u64)
            .find(|row| row.contains_range(va.0, length))
    }

    /// Split every dynamic-alias row across `[va, va + len)`.
    ///
    /// Rebasing a row changes its key, so affected rows are lifted out, run
    /// through the one shared splitting routine, and re-published.
    pub(crate) fn split_local_rows_for_unmap(&mut self, va: u64, len: usize) {
        let Some(end) = va.checked_add(len as u64) else {
            return;
        };
        let mut affected: Vec<HvfMappedRegion> = Vec::new();
        let mut keys = Vec::new();
        if let Some((&key, row)) = self.live.range(..GuestVa(va)).next_back()
            && row.end > va
        {
            keys.push(key);
        }
        keys.extend(
            self.live
                .range(GuestVa(va)..GuestVa(end))
                .map(|(key, _)| *key),
        );
        for key in keys {
            if let Some(row) = self.live_remove(&key) {
                affected.push(row);
            }
        }
        let mut index = 0;
        while index < self.shadowed.len() {
            let row = &self.shadowed[index];
            if row.start < end && va < row.end {
                affected.push(self.shadowed.remove(index));
            } else {
                index += 1;
            }
        }
        split_local_mapping_rows_for_unmap(&mut affected, va, len);
        for row in affected {
            self.insert(row);
        }
        self.assert_invariants();
    }

    /// Detach the structural owner claiming `[ipa, ipa + length)`, naming the
    /// row so a failed retirement can put it back.
    pub(crate) fn take_structural_owner(
        &mut self,
        ipa: u64,
        length: u64,
    ) -> Option<(MappingRowRef, std::sync::Arc<StructuralBackingOwner>)> {
        let claims = |mapping: &HvfMappedRegion| {
            mapping.structural_owner.as_ref().is_some_and(|owner| {
                (mapping.physical_ipa, mapping.physical_size as u64) == (ipa, length)
                    || (owner.physical_ipa <= ipa
                        && ipa.checked_add(length).is_some_and(|candidate_end| {
                            owner
                                .physical_ipa
                                .checked_add(owner.physical_size as u64)
                                .is_some_and(|owner_end| candidate_end <= owner_end)
                        }))
            })
        };
        for (position, mapping) in self.shadowed.iter_mut().enumerate() {
            if claims(mapping) {
                let owner = mapping.structural_owner.take()?;
                return Some((MappingRowRef::Shadowed(position), owner));
            }
        }
        for (&va, mapping) in self.live.iter_mut() {
            if claims(mapping) {
                let owner = mapping.structural_owner.take()?;
                return Some((MappingRowRef::Live(va), owner));
            }
        }
        None
    }

    pub(crate) fn row(&self, row: MappingRowRef) -> Option<&HvfMappedRegion> {
        match row {
            MappingRowRef::Live(va) => self.live.get(&va),
            MappingRowRef::Shadowed(position) => self.shadowed.get(position),
        }
    }

    pub(crate) fn restore_structural_owner(
        &mut self,
        row: MappingRowRef,
        owner: std::sync::Arc<StructuralBackingOwner>,
    ) {
        let slot = match row {
            MappingRowRef::Live(va) => self.live.get_mut(&va),
            MappingRowRef::Shadowed(position) => self.shadowed.get_mut(position),
        };
        if let Some(mapping) = slot {
            mapping.structural_owner = Some(owner);
        }
    }

    pub(crate) fn take_stage2_lease(
        &mut self,
        ipa: u64,
        length: u64,
    ) -> Option<GlobalFrameStage2Lease> {
        self.iter_mut().find_map(|mapping| {
            (mapping.stage2_lease.as_ref().is_some_and(|lease| {
                let (base, len) = lease.key();
                base <= ipa && ipa.checked_add(length).is_some_and(|end| end <= base + len)
            }))
            .then(|| mapping.stage2_lease.take())
            .flatten()
        })
    }

    pub(crate) fn take_exact_unowned_stage2_lease(
        &mut self,
        ipa: u64,
        length: u64,
        host_addr: usize,
    ) -> Option<GlobalFrameStage2Lease> {
        let expected = InventoryStage2OwnerIdentity {
            host_addr,
            generation: 0,
        };
        self.iter_mut().find_map(|mapping| {
            let exact_owner = mapped_region_stage2_owner_identity(mapping) == Some(expected);
            let exact_lease = mapping
                .stage2_lease
                .as_ref()
                .is_some_and(|lease| lease.key() == (ipa, length) && lease.active && lease.mapped);
            (exact_owner && exact_lease)
                .then(|| mapping.stage2_lease.take())
                .flatten()
        })
    }
}

/// Positional access for tests only. Production code addresses rows by
/// `GuestVa` or by an ordered range; a positional index would reintroduce the
/// push-order assumption this type exists to remove.
#[cfg(all(target_os = "macos", target_arch = "aarch64", test))]
impl std::ops::Index<usize> for TaskMappingIndex {
    type Output = HvfMappedRegion;

    #[allow(clippy::expect_used)]
    fn index(&self, position: usize) -> &Self::Output {
        self.iter().nth(position).expect("mapping row in range")
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64", test))]
impl std::ops::IndexMut<usize> for TaskMappingIndex {
    #[allow(clippy::expect_used)]
    fn index_mut(&mut self, position: usize) -> &mut Self::Output {
        self.iter_mut().nth(position).expect("mapping row in range")
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl FromIterator<HvfMappedRegion> for TaskMappingIndex {
    fn from_iter<I: IntoIterator<Item = HvfMappedRegion>>(iter: I) -> Self {
        let mut index = Self::new();
        index.extend(iter);
        index
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Extend<HvfMappedRegion> for TaskMappingIndex {
    fn extend<T: IntoIterator<Item = HvfMappedRegion>>(&mut self, iter: T) {
        for region in iter {
            self.insert(region);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl IntoIterator for TaskMappingIndex {
    type Item = HvfMappedRegion;
    type IntoIter = std::iter::Chain<
        std::vec::IntoIter<HvfMappedRegion>,
        std::collections::btree_map::IntoValues<GuestVa, HvfMappedRegion>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.shadowed.into_iter().chain(self.live.into_values())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<'a> IntoIterator for &'a mut TaskMappingIndex {
    type Item = &'a mut HvfMappedRegion;
    type IntoIter = std::iter::Chain<
        std::slice::IterMut<'a, HvfMappedRegion>,
        std::collections::btree_map::ValuesMut<'a, GuestVa, HvfMappedRegion>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.shadowed.iter_mut().chain(self.live.values_mut())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<'a> IntoIterator for &'a TaskMappingIndex {
    type Item = &'a HvfMappedRegion;
    type IntoIter = std::iter::Chain<
        std::slice::Iter<'a, HvfMappedRegion>,
        std::collections::btree_map::Values<'a, GuestVa, HvfMappedRegion>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.shadowed.iter().chain(self.live.values())
    }
}

/// Whether two adjacent rows describe one extent of one VMA and may be merged.
///
/// Every field that a lookup or a retirement keys on must agree, and the two
/// rows must be contiguous in BOTH the semantic VA domain and the physical
/// domain. A row carrying an owned handle (`memory`, `host_mapping`,
/// `stage2_lease`) never merges: merging would have to choose which handle the
/// survivor keeps.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn can_coalesce_mappings(left: &HvfMappedRegion, right: &HvfMappedRegion) -> bool {
    if left.end != right.start {
        return false;
    }
    // A row whose `size` is not its semantic extent is an offset projection of
    // a larger physical owner; its `size` cannot be added.
    if left.end.saturating_sub(left.start) != left.size as u64
        || right.end.saturating_sub(right.start) != right.size as u64
    {
        return false;
    }
    if left.owner_generation != right.owner_generation
        || left.perms != right.perms
        || left.is_dynamic_alias != right.is_dynamic_alias
        || left.sharing != right.sharing
        || left.guest_writable != right.guest_writable
    {
        return false;
    }
    match (&left.structural_owner, &right.structural_owner) {
        (None, None) => {}
        (Some(left_owner), Some(right_owner))
            if std::sync::Arc::ptr_eq(left_owner, right_owner) => {}
        _ => return false,
    }
    if left.memory.is_some()
        || right.memory.is_some()
        || left.host_mapping.is_some()
        || right.host_mapping.is_some()
        || left.stage2_lease.is_some()
        || right.stage2_lease.is_some()
    {
        return false;
    }
    if left.ipa.saturating_add(left.size as u64) != right.ipa {
        return false;
    }
    if !left.host_addr.is_null() || !right.host_addr.is_null() {
        if (left.host_addr as usize).saturating_add(left.size) != right.host_addr as usize {
            return false;
        }
    }
    if left.shared_key_base != right.shared_key_base {
        return false;
    }
    if left.shared_key_base == 0 && left.shared_key_offset == 0 && right.shared_key_offset == 0 {
        // Neither row carries a shared-key projection.
    } else if left.shared_key_offset.saturating_add(left.size as u64) != right.shared_key_offset {
        return false;
    }
    let adjacent_physical =
        left.physical_ipa.saturating_add(left.physical_size as u64) == right.physical_ipa;
    let same_compound = left.physical_ipa == right.physical_ipa
        && left.physical_size == right.physical_size
        && left.size.saturating_add(right.size) <= left.physical_size;
    adjacent_physical || same_compound
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn coalesce_mappings_into_left(left: &mut HvfMappedRegion, right: HvfMappedRegion) {
    let adjacent_physical =
        left.physical_ipa.saturating_add(left.physical_size as u64) == right.physical_ipa;
    left.end = right.end;
    left.size = left.size.saturating_add(right.size);
    if adjacent_physical {
        left.physical_size = left.physical_size.saturating_add(right.physical_size);
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod task_mapping_index_tests {
    use super::super::thread_sibling_tests;
    use super::*;

    /// A first-touch page inside one VMA, with a host pointer that tracks the
    /// physical extent the way sparse materialization publishes it.
    fn touched_page(start: u64, ipa: u64, host_base: usize) -> HvfMappedRegion {
        let mut region = thread_sibling_tests::mapped_region(start, start + 0x1000, ipa);
        region.host_addr = host_base as *mut u8;
        region.is_dynamic_alias = true;
        region.owner_generation = 7;
        region
    }

    #[test]
    fn a_first_touch_storm_inside_one_vma_stays_one_row() {
        // The defect this type replaces: the vector grew one row per
        // materialized extent, so every fault's scans grew with the fault
        // count. 10k contiguous 4 KiB extents describe ONE 40 MiB VMA.
        const PAGES: u64 = 10_000;
        let va_base = 0x6000_0000_u64;
        let ipa_base = 0x9b00_0000_u64;
        let host_base = 0x1_0000_0000_usize;

        let mut index = TaskMappingIndex::new();
        for page in 0..PAGES {
            let offset = page * 0x1000;
            index.insert(touched_page(
                va_base + offset,
                ipa_base + offset,
                host_base + offset as usize,
            ));
        }

        assert_eq!(
            index.len(),
            1,
            "contiguous first-touch extents inside one VMA must coalesce to one row",
        );
        let row = index.iter().next().expect("the coalesced row");
        assert_eq!(row.start, va_base);
        assert_eq!(row.end, va_base + PAGES * 0x1000);
        assert_eq!(row.size as u64, PAGES * 0x1000);
        assert_eq!(row.physical_ipa, ipa_base);
        assert_eq!(row.physical_size as u64, PAGES * 0x1000);

        // Every page must still resolve through the single row.
        for page in [0, 1, PAGES / 2, PAGES - 1] {
            let offset = page * 0x1000;
            let found = index
                .mapping_for_range(GuestVa(va_base + offset), 0x1000)
                .expect("every coalesced page must still resolve");
            assert_eq!(found.start, va_base);
        }
    }

    #[test]
    fn faults_arriving_out_of_order_still_coalesce_and_stay_sorted() {
        // Fork copies, extension arenas and unmap tails publish out of order;
        // that is exactly why the vector could not be binary-searched.
        let va_base = 0x6000_0000_u64;
        let ipa_base = 0x9b00_0000_u64;
        let host_base = 0x1_0000_0000_usize;
        let mut index = TaskMappingIndex::new();
        for page in [3_u64, 0, 4, 2, 1] {
            let offset = page * 0x1000;
            index.insert(touched_page(
                va_base + offset,
                ipa_base + offset,
                host_base + offset as usize,
            ));
        }
        assert_eq!(
            index.len(),
            1,
            "out-of-order publication must still coalesce"
        );
        let row = index.iter().next().expect("row");
        assert_eq!((row.start, row.end), (va_base, va_base + 5 * 0x1000));
    }

    #[test]
    fn a_discontiguity_in_any_domain_keeps_the_rows_separate() {
        let va_base = 0x6000_0000_u64;
        let ipa_base = 0x9b00_0000_u64;
        let host_base = 0x1_0000_0000_usize;

        // Virtually contiguous but physically disjoint.
        let mut split_physical = TaskMappingIndex::new();
        split_physical.insert(touched_page(va_base, ipa_base, host_base));
        split_physical.insert(touched_page(
            va_base + 0x1000,
            ipa_base + 0x8000,
            host_base + 0x8000,
        ));
        assert_eq!(
            split_physical.len(),
            2,
            "physically disjoint pages must not merge into one row",
        );

        // Physically contiguous but virtually disjoint.
        let mut split_virtual = TaskMappingIndex::new();
        split_virtual.insert(touched_page(va_base, ipa_base, host_base));
        split_virtual.insert(touched_page(
            va_base + 0x8000,
            ipa_base + 0x1000,
            host_base + 0x1000,
        ));
        assert_eq!(
            split_virtual.len(),
            2,
            "virtually disjoint pages must not merge into one row",
        );

        // Contiguous everywhere but a different owner generation: a different
        // incarnation of the frame, which retirement keys on.
        let mut split_generation = TaskMappingIndex::new();
        split_generation.insert(touched_page(va_base, ipa_base, host_base));
        let mut newer = touched_page(va_base + 0x1000, ipa_base + 0x1000, host_base + 0x1000);
        newer.owner_generation = 8;
        split_generation.insert(newer);
        assert_eq!(
            split_generation.len(),
            2,
            "rows of different owner generations must not merge",
        );

        // Contiguous everywhere but differently writable: coalescing here would
        // hand a lookup the wrong protection.
        let mut split_perms = TaskMappingIndex::new();
        split_perms.insert(touched_page(va_base, ipa_base, host_base));
        let mut read_only = touched_page(va_base + 0x1000, ipa_base + 0x1000, host_base + 0x1000);
        read_only.guest_writable = false;
        split_perms.insert(read_only);
        assert_eq!(
            split_perms.len(),
            2,
            "rows with different guest writability must not merge",
        );
    }

    #[test]
    fn a_fork_copy_publishes_in_order_and_an_unmap_split_keeps_the_tail_sorted() {
        let va_base = 0x6000_0000_u64;
        let ipa_base = 0x9b00_0000_u64;
        let host_base = 0x1_0000_0000_usize;

        // Two VMAs separated by a hole, published child-style (highest first).
        let mut index = TaskMappingIndex::new();
        for base in [0x10_0000_u64, 0x0_u64] {
            for page in 0..4_u64 {
                let offset = base + page * 0x1000;
                index.insert(touched_page(
                    va_base + offset,
                    ipa_base + offset,
                    host_base + offset as usize,
                ));
            }
        }
        assert_eq!(index.len(), 2, "each VMA coalesces to exactly one row");
        let starts: Vec<u64> = index.iter().map(|row| row.start).collect();
        assert_eq!(starts, vec![va_base, va_base + 0x10_0000]);

        // Punch a hole in the middle of the first VMA. The head keeps its
        // start, the tail is re-keyed at the end of the unmap, and iteration
        // stays strictly increasing and non-overlapping.
        index.split_local_rows_for_unmap(va_base + 0x1000, 0x1000);
        let rows: Vec<(u64, u64)> = index.iter().map(|row| (row.start, row.end)).collect();
        assert_eq!(
            rows,
            vec![
                (va_base, va_base + 0x1000),
                (va_base + 0x2000, va_base + 0x4000),
                (va_base + 0x10_0000, va_base + 0x10_4000),
            ],
            "an unmap split must leave a sorted, non-overlapping table",
        );
        let tail = index
            .mapping_for_range(GuestVa(va_base + 0x2000), 0x1000)
            .expect("the split tail must still resolve");
        assert_eq!(
            tail.ipa,
            ipa_base + 0x2000,
            "the tail keeps its translation"
        );
        assert!(
            index
                .mapping_for_range(GuestVa(va_base + 0x1000), 0x1000)
                .is_none(),
            "the unmapped page must no longer resolve",
        );
    }

    #[test]
    fn an_overlapping_publication_wins_lookups_without_dropping_the_row_it_shadows() {
        // The vector resolved overlaps newest-first and kept the shadowed row
        // alive; a fork child's rebased vvar row overlaps its parent's exactly.
        let va = 0x2e00_0000_0000_u64;
        let mut index = TaskMappingIndex::new();
        let mut parent = thread_sibling_tests::mapped_region(va, va + 0x4000, 0x2e00_0000_0000);
        parent.owner_generation = 1;
        let mut child = thread_sibling_tests::mapped_region(va, va + 0x4000, 0x2e00_0000_4000);
        child.owner_generation = 2;
        index.insert(parent);
        index.insert(child);

        assert_eq!(index.len(), 2, "the shadowed row must not be dropped");
        let resolved = index
            .mapping_for_range(GuestVa(va), 0x1000)
            .expect("the newest row resolves");
        assert_eq!(
            resolved.owner_generation, 2,
            "the newest publication must win the lookup",
        );
        let generations: Vec<u64> = index
            .candidates_for_range(GuestVa(va), 0x1000)
            .map(|row| row.owner_generation)
            .collect();
        assert_eq!(
            generations,
            vec![2, 1],
            "both incarnations stay reachable, newest first",
        );
    }

    /// What the displaced-row backlog actually accumulates, and why the
    /// obvious bound is refused.
    ///
    /// Repeated `MAP_FIXED` over one range publishes a fresh incarnation each
    /// time -- new backing, new IPA, new owner generation -- and every one of
    /// them displaces its predecessor, so the vector grows by one per
    /// republication and every full-table pass and every displaced-row lookup
    /// tail pays for the whole history. This test states that growth rather
    /// than asserting it away: the safe retirement needs the displaced row's
    /// owner generation authenticated against the live global-frame owner, and
    /// `insert` holds no custody to authenticate against. See
    /// `TaskMappingIndex::displace_overlapping`.
    ///
    /// The per-fault census in
    /// `docs/perf-results/2026-09-08-mapping-index-census.md` measured the
    /// backlog at 1 row in every bucket of every reducer depth from 100,000 to
    /// 800,000, so this is a latent bound, not a measured cost.
    #[test]
    fn repeated_overlapping_publication_retains_one_row_per_incarnation() {
        const REPUBLICATIONS: u64 = 32;
        let va = 0x2e00_0000_0000_u64;
        let mut index = TaskMappingIndex::new();
        for generation in 1..=REPUBLICATIONS {
            let mut row = thread_sibling_tests::mapped_region(
                va,
                va + 0x4000,
                0x2e00_0000_0000 + generation * 0x4000,
            );
            row.owner_generation = generation;
            assert!(
                !row.holds_backing_handle(),
                "the fixture models an inherited, handle-free row"
            );
            index.insert(row);
        }

        assert_eq!(
            index.live_len(),
            1,
            "one live row per range: the newest incarnation"
        );
        assert_eq!(
            index.shadowed_len() as u64,
            REPUBLICATIONS - 1,
            "every earlier incarnation is retained; this is the unbounded shape"
        );
        assert_eq!(
            index
                .mapping_for_range(GuestVa(va), 0x1000)
                .map(|row| row.owner_generation),
            Some(REPUBLICATIONS),
            "the newest incarnation still wins the lookup"
        );
        assert_eq!(
            index.candidates_for_range(GuestVa(va), 0x1000).count() as u64,
            REPUBLICATIONS,
            "and every retained incarnation is still offered, newest first"
        );
    }

    #[test]
    fn a_compound_span_beginning_below_its_semantic_view_is_still_a_candidate() {
        // A 16 KiB COW compound is looked up by the compound base, which is
        // BELOW the start of the live 4 KiB semantic row.
        let semantic_va = 0x6001_17d000_u64;
        let compound_va = semantic_va - 0x1000;
        let mut index = TaskMappingIndex::new();
        index.insert(thread_sibling_tests::mapped_region(
            semantic_va,
            semantic_va + 0x1000,
            0x9b03_b61000,
        ));
        let candidates: Vec<u64> = index
            .candidates_for_range(GuestVa(compound_va), CowArmedRanges::COMPOUND_SIZE)
            .map(|row| row.start)
            .collect();
        assert_eq!(
            candidates,
            vec![semantic_va],
            "a row starting above the queried VA must still be offered when the range overlaps it",
        );
    }

    #[test]
    fn a_raw_ipa_lookup_does_not_walk_the_table_to_reach_a_low_va_row() {
        // The page-table root is published early at a LOW guest VA, so a
        // reverse walk of the VA-ordered map reaches it LAST -- that is the
        // scan that made this representation a net regression
        // (docs/perf-results/2026-09-08-mapping-index-measurement.md). The IPA
        // view must reach it without visiting the storm.
        let root_va = 0x1_0000_u64;
        let root_ipa = 0x8800_0000_0000_u64;
        let mut index = TaskMappingIndex::new();
        index.insert(thread_sibling_tests::mapped_region(
            root_va,
            root_va + 0x20_0000,
            root_ipa,
        ));
        for extent in 0..5_000_u64 {
            let va = 0x6000_0000_0000 + extent * 0x2_0000;
            let ipa = 0x9b00_0000_0000 + extent * 0x2_0000;
            let mut row = thread_sibling_tests::mapped_region(va, va + 0x1000, ipa);
            row.owner_generation = extent + 1;
            index.insert(row);
        }
        assert_eq!(
            index.len(),
            5_001,
            "distinct owner generations do not merge"
        );

        let visited = index.candidates_for_ipa_range(root_ipa + 0x4000, 8).count();
        assert_eq!(
            visited, 1,
            "the root row must be reached without walking the extent storm",
        );
        let resolved = index
            .candidates_for_ipa_range(root_ipa + 0x4000, 8)
            .next()
            .expect("root row resolves by IPA");
        assert_eq!(resolved.start, root_va);

        // A raw IPA that no row backs must not walk the whole table either: the
        // walk stops once no remaining row can still reach the query.
        assert_eq!(
            index
                .candidates_for_ipa_range(0x9b00_0000_0000 - 0x100_0000, 8)
                .count(),
            0,
            "an unbacked IPA below every extent resolves to nothing",
        );
    }

    #[test]
    fn a_lookup_walks_a_bounded_number_of_rows_regardless_of_table_size() {
        // The property the fault path needs: resolution cost must not grow
        // with the number of unrelated VMAs.
        let mut index = TaskMappingIndex::new();
        for vma in 0..2_000_u64 {
            let va = 0x6000_0000 + vma * 0x20_0000;
            index.insert(thread_sibling_tests::mapped_region(
                va,
                va + 0x1000,
                0x9b00_0000 + vma * 0x20_0000,
            ));
        }
        assert_eq!(index.len(), 2_000);
        let probe = 0x6000_0000 + 1_999 * 0x20_0000;
        assert_eq!(
            index.candidates_for_range(GuestVa(probe), 0x1000).count(),
            1,
            "an ordered probe must offer only the rows that overlap the query",
        );
        assert_eq!(
            index
                .candidates_for_range(GuestVa(0x5000_0000), 0x1000)
                .count(),
            0,
            "a query below every row must offer nothing",
        );
    }

    struct SimpleRng(u64);

    impl SimpleRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn gen_range(&mut self, min: u64, max: u64) -> u64 {
            if min >= max {
                return min;
            }
            min + (self.next_u64() % (max - min))
        }
    }

    fn make_test_region(
        start: u64,
        size: u64,
        ipa: u64,
        generation: u64,
        physical_ipa: u64,
        physical_size: u64,
    ) -> HvfMappedRegion {
        let mut region = thread_sibling_tests::mapped_region(start, start + size, ipa);
        region.owner_generation = generation;
        region.physical_ipa = physical_ipa;
        region.physical_size = physical_size as usize;
        region
    }

    #[test]
    fn differential_keyed_removal_matches_full_walk_retain_2000_cases() {
        let mut rng = SimpleRng::new(0xc001_cafe_d00d_feed);
        const CASES: usize = 2000;
        let base_va = 0x6000_0000_u64;
        let base_ipa = 0x9b00_0000_u64;

        for case in 0..CASES {
            let mut reference = TaskMappingIndex::new();
            let mut keyed = TaskMappingIndex::new();

            let num_rows = rng.gen_range(2, 20);
            let mut generated_rows = Vec::new();
            for i in 0..num_rows {
                let page_idx = i * 4 + rng.gen_range(0, 3);
                let start = base_va + page_idx * 0x1000;
                let ipa = base_ipa + page_idx * 0x1000;
                let generation = rng.gen_range(1, 5);

                // Shape selection:
                // 0..4: Compound 16 KiB physical owner with 4 KiB projection at offsets 0, 4, 8, 12 KiB
                // 5: Standard identity mapping
                // 6: Projection NOT inside physical extent (escapes physical base)
                let shape = rng.gen_range(0, 7);
                let (size, physical_ipa, physical_size) = match shape {
                    0 => (0x1000, ipa, 0x4000),
                    1 => (0x1000, ipa.saturating_sub(0x1000), 0x4000),
                    2 => (0x1000, ipa.saturating_sub(0x2000), 0x4000),
                    3 => (0x1000, ipa.saturating_sub(0x3000), 0x4000),
                    4 => (0x1000, ipa, 0x1000),
                    5 => {
                        let page_count = rng.gen_range(1, 4);
                        (page_count * 0x1000, ipa, page_count * 0x1000)
                    }
                    _ => (0x1000, ipa.saturating_add(0x10_0000), 0x1000),
                };

                let r1 =
                    make_test_region(start, size, ipa, generation, physical_ipa, physical_size);
                let r2 =
                    make_test_region(start, size, ipa, generation, physical_ipa, physical_size);
                reference.insert(r1);
                keyed.insert(r2);
                generated_rows.push((physical_ipa, physical_size, generation));
            }

            // Select a target physical extent to retire (either from existing rows or random).
            let (target_phys_ipa, target_phys_size, target_gen) =
                if rng.next_u64() % 3 != 0 && !generated_rows.is_empty() {
                    let pick = (rng.next_u64() as usize) % generated_rows.len();
                    generated_rows[pick]
                } else {
                    let q_page = rng.gen_range(0, 45);
                    let q_len = rng.gen_range(1, 4) * 0x1000;
                    (base_ipa + q_page * 0x1000, q_len, rng.gen_range(1, 5))
                };

            let extent = MappingExtent::Ipa(target_phys_ipa, target_phys_size);
            let predicate = move |m: &HvfMappedRegion| {
                (m.physical_ipa, m.physical_size as u64) == (target_phys_ipa, target_phys_size)
                    && m.owner_generation == target_gen
            };

            // OLD semantics: full-table retain over ALL rows checking only predicate
            reference.retain(|m| !predicate(m));
            // NEW semantics: keyed extent removal
            keyed.remove_rows_matching_in_ranges(&[extent], predicate);

            assert_eq!(
                reference.len(),
                keyed.len(),
                "case {case} ({extent:?}): total row count mismatch, ref={} keyed={}",
                reference.len(),
                keyed.len()
            );
            assert_eq!(
                reference.live_len(),
                keyed.live_len(),
                "case {case} ({extent:?}): live row count mismatch, ref={} keyed={}",
                reference.live_len(),
                keyed.live_len()
            );
            assert_eq!(
                reference.shadowed_len(),
                keyed.shadowed_len(),
                "case {case} ({extent:?}): shadowed row count mismatch, ref={} keyed={}",
                reference.shadowed_len(),
                keyed.shadowed_len()
            );
            let ref_rows: Vec<(u64, u64, u64, u64)> = reference
                .iter()
                .map(|m| (m.start, m.end, m.ipa, m.owner_generation))
                .collect();
            let keyed_rows: Vec<(u64, u64, u64, u64)> = keyed
                .iter()
                .map(|m| (m.start, m.end, m.ipa, m.owner_generation))
                .collect();
            assert_eq!(
                ref_rows, keyed_rows,
                "case {case} ({extent:?}): row contents mismatch"
            );
        }
    }

    #[test]
    fn visit_count_for_extent_removal_is_sublinear_in_4096_rows() {
        let mut index = TaskMappingIndex::new();
        const N: u64 = 4096;
        let va_base = 0x6000_0000_0000_u64;
        let ipa_base = 0x9b00_0000_0000_u64;

        // Insert N=4,096 non-coalescing rows (spaced by 2 MiB, distinct owner generations).
        for i in 0..N {
            let va = va_base + i * 0x20_0000;
            let ipa = ipa_base + i * 0x20_0000;
            let mut row = thread_sibling_tests::mapped_region(va, va + 0x1000, ipa);
            row.owner_generation = i + 1;
            index.insert(row);
        }

        assert_eq!(index.live_len(), N as usize);

        // Test 1: Remove one extent by VA in the middle of 4,096 rows.
        let target_idx = 2048_u64;
        let target_va = va_base + target_idx * 0x20_0000;
        let extent_va = MappingExtent::Va(GuestVa(target_va), 0x1000);

        let before_va = hot_path_rows_scanned(HotPathScan::TaskMappings);
        let removed = index.remove_rows_matching_in_ranges(&[extent_va], |_| true);
        assert_eq!(removed, 1, "target row must be removed");
        assert_eq!(index.live_len(), (N - 1) as usize);

        let visited_va = hot_path_rows_scanned(HotPathScan::TaskMappings) - before_va;
        assert!(
            visited_va <= 3,
            "keyed VA removal on N=4096 rows must visit O(1 + log N) rows, visited {visited_va}"
        );

        // Test 2: Remove one extent by IPA in the middle of the remaining rows.
        let target_idx_2 = 1024_u64;
        let target_ipa_2 = ipa_base + target_idx_2 * 0x20_0000;
        let extent_ipa = MappingExtent::Ipa(target_ipa_2, 0x1000);

        let before_ipa = hot_path_rows_scanned(HotPathScan::TaskMappings);
        let removed_ipa = index.remove_rows_matching_in_ranges(&[extent_ipa], |_| true);
        assert_eq!(removed_ipa, 1, "target row must be removed by IPA");
        assert_eq!(index.live_len(), (N - 2) as usize);

        let visited_ipa = hot_path_rows_scanned(HotPathScan::TaskMappings) - before_ipa;
        assert!(
            visited_ipa <= 4,
            "keyed IPA removal on N=4096 rows must visit O(1 + log N) rows, visited {visited_ipa}"
        );
    }
}
