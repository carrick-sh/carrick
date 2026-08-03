//! Interval bookkeeping for native-lane guest protection overrides.
//!
//! The native memory model records, per guest span, the Linux protection the
//! guest last asked for WHERE IT DIFFERS from the owning region's
//! `default_prot`. The predecessor structure was `BTreeMap<page, prot>` --
//! one entry per 16 KiB host page -- which made every guest
//! `mmap(PROT_NONE, MAP_ANON|MAP_PRIVATE)` reservation cost O(pages): Go's
//! allocator reserves ~4.5 GiB per process this way (66 x 64 MiB + 2 x
//! ~512 MiB `sysReserve` calls), and each reserve paid one BTree insert per
//! page (~295k entries per Go process) plus per-page walks on every later
//! query. Host `mprotect` applies to ranges, so there is no per-page hardware
//! state to mirror; intervals are the honest representation, and a
//! reservation becomes one entry.
//!
//! Invariants: entries are non-overlapping, sorted, non-empty, and adjacent
//! entries with equal protection are coalesced. Callers keep entries
//! host-page-aligned (the structure itself is alignment-agnostic). An address
//! with no entry carries its region's `default_prot` -- absence is
//! meaningful, so "set to default" is [`NativeProtRanges::clear`], not a
//! `set` of the default value.

use std::collections::BTreeMap;

/// Sorted, coalesced `[start, end) -> prot` intervals of guest protection
/// overrides. See the module doc for semantics and invariants.
#[derive(Debug, Default, Clone)]
pub struct NativeProtRanges {
    /// `start -> (end, prot)`.
    map: BTreeMap<u64, (u64, u64)>,
}

impl NativeProtRanges {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The override covering `addr`, if any. `None` means the owning region's
    /// `default_prot` applies.
    pub fn prot_at(&self, addr: u64) -> Option<u64> {
        let (_, &(end, prot)) = self.map.range(..=addr).next_back()?;
        (addr < end).then_some(prot)
    }

    /// The overrides intersecting `[start, end)`, clipped to the query span,
    /// in address order.
    pub fn overlaps(&self, start: u64, end: u64) -> Vec<(u64, u64, u64)> {
        if start >= end {
            return Vec::new();
        }
        let mut out = Vec::new();
        // The entry straddling `start`, if any.
        if let Some((_, &(entry_end, prot))) = self.map.range(..start).next_back()
            && entry_end > start
        {
            out.push((start, entry_end.min(end), prot));
        }
        for (&entry_start, &(entry_end, prot)) in self.map.range(start..end) {
            out.push((entry_start, entry_end.min(end), prot));
        }
        out
    }

    /// Every distinct override value currently stored. Order is by interval
    /// address; values may repeat.
    pub fn iter_prots(&self) -> impl Iterator<Item = u64> + '_ {
        self.map.values().map(|&(_, prot)| prot)
    }

    /// Record `prot` as the override for `[start, end)`, replacing whatever
    /// the span held. O(log n + k) for k replaced entries.
    pub fn set(&mut self, start: u64, end: u64, prot: u64) {
        if start >= end {
            return;
        }
        self.splice(start, end);
        self.map.insert(start, (end, prot));
        self.coalesce_around(start);
    }

    /// Remove every override in `[start, end)`, returning the span to its
    /// region default. O(log n + k).
    pub fn clear(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.splice(start, end);
    }

    /// Cut `[start, end)` out of the map, splitting straddling entries so
    /// the span is entirely absent afterwards.
    fn splice(&mut self, start: u64, end: u64) {
        // An entry straddling `start` keeps its head (and, when it spans the
        // whole splice, its tail).
        if let Some((&entry_start, &(entry_end, prot))) = self.map.range(..start).next_back()
            && entry_end > start
        {
            self.map.insert(entry_start, (start, prot));
            if entry_end > end {
                self.map.insert(end, (entry_end, prot));
            }
        }
        // Entries starting inside the span are removed; one reaching past
        // `end` keeps its tail.
        let inside: Vec<u64> = self.map.range(start..end).map(|(&s, _)| s).collect();
        for entry_start in inside {
            let Some((entry_end, prot)) = self.map.remove(&entry_start) else {
                continue;
            };
            if entry_end > end {
                self.map.insert(end, (entry_end, prot));
            }
        }
    }

    /// Merge the entry starting at `start` with equal-prot neighbours it now
    /// touches.
    fn coalesce_around(&mut self, start: u64) {
        let Some(&(mut merged_end, prot)) = self.map.get(&start) else {
            return;
        };
        let mut merged_start = start;
        if let Some((&left_start, &(left_end, left_prot))) = self.map.range(..start).next_back()
            && left_end == start
            && left_prot == prot
        {
            self.map.remove(&left_start);
            self.map.remove(&start);
            merged_start = left_start;
            self.map.insert(merged_start, (merged_end, prot));
        }
        if let Some(&(right_end, right_prot)) = self.map.get(&merged_end)
            && right_prot == prot
        {
            self.map.remove(&merged_end);
            merged_end = right_end;
            self.map.insert(merged_start, (merged_end, prot));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(ranges: &NativeProtRanges) -> Vec<(u64, u64, u64)> {
        ranges.overlaps(0, u64::MAX)
    }

    #[test]
    fn set_and_point_query() {
        let mut ranges = NativeProtRanges::default();
        assert!(ranges.is_empty());
        assert_eq!(ranges.prot_at(0x4000), None);
        ranges.set(0x4000, 0xc000, 0);
        assert_eq!(ranges.prot_at(0x3fff), None);
        assert_eq!(ranges.prot_at(0x4000), Some(0));
        assert_eq!(ranges.prot_at(0xbfff), Some(0));
        assert_eq!(ranges.prot_at(0xc000), None);
        assert!(!ranges.is_empty());
    }

    #[test]
    fn empty_span_is_a_no_op() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x4000, 0x4000, 3);
        ranges.clear(0x8000, 0x4000);
        assert!(ranges.is_empty());
    }

    #[test]
    fn overwrite_splits_straddling_entries() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x0, 0x10000, 3);
        ranges.set(0x4000, 0x8000, 0);
        assert_eq!(
            entries(&ranges),
            vec![(0x0, 0x4000, 3), (0x4000, 0x8000, 0), (0x8000, 0x10000, 3)]
        );
        // Middle hole: the straddling entry keeps head AND tail.
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x0, 0x10000, 3);
        ranges.clear(0x4000, 0x8000);
        assert_eq!(
            entries(&ranges),
            vec![(0x0, 0x4000, 3), (0x8000, 0x10000, 3)]
        );
        assert_eq!(ranges.prot_at(0x4000), None);
    }

    #[test]
    fn set_replaces_multiple_covered_entries() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x0, 0x4000, 1);
        ranges.set(0x8000, 0xc000, 2);
        ranges.set(0x10000, 0x14000, 4);
        ranges.set(0x2000, 0x12000, 7);
        assert_eq!(
            entries(&ranges),
            vec![
                (0x0, 0x2000, 1),
                (0x2000, 0x12000, 7),
                (0x12000, 0x14000, 4)
            ]
        );
    }

    #[test]
    fn adjacent_equal_prot_coalesces() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x4000, 0x8000, 0);
        ranges.set(0x8000, 0xc000, 0);
        ranges.set(0x0, 0x4000, 0);
        assert_eq!(entries(&ranges), vec![(0x0, 0xc000, 0)]);
        // Different prot stays separate.
        ranges.set(0xc000, 0x10000, 3);
        assert_eq!(
            entries(&ranges),
            vec![(0x0, 0xc000, 0), (0xc000, 0x10000, 3)]
        );
    }

    #[test]
    fn overlaps_clips_to_query_span() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x0, 0x10000, 5);
        assert_eq!(ranges.overlaps(0x4000, 0x8000), vec![(0x4000, 0x8000, 5)]);
        assert_eq!(ranges.overlaps(0x10000, 0x20000), Vec::new());
    }

    #[test]
    fn clear_of_absent_span_is_a_no_op() {
        let mut ranges = NativeProtRanges::default();
        ranges.set(0x0, 0x4000, 3);
        ranges.clear(0x8000, 0x10000);
        assert_eq!(entries(&ranges), vec![(0x0, 0x4000, 3)]);
    }
}
