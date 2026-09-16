//! Canonical semantic VMA representation, indexing, and projection.

use super::*;

/// Provenance of backing for a canonical semantic VMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VmaBackingProvenance {
    PrivateAnonymous,
    SharedAnonymous,
    PrivateFile,
    SharedFile,
    SpecialKernelSynthetic,
}

impl VmaBackingProvenance {
    pub const fn is_private_anonymous(self) -> bool {
        matches!(self, Self::PrivateAnonymous)
    }

    pub const fn allows_wipe_on_fork(self) -> bool {
        self.is_private_anonymous()
    }
}

/// Canonical semantic VMA representation owned by `MemState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticVma {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub provenance: VmaBackingProvenance,
    pub fork_policy: carrick_abi::VmaForkPolicy,
    /// `MADV_DONTDUMP`/`MADV_DODUMP`: whether this VMA's CONTENTS reach a core
    /// dump. The VMA itself is still listed either way, matching Linux.
    pub dump_policy: carrick_abi::VmaDumpPolicy,
    pub droppable: bool,
    pub path: String,
    pub file_page_offset: Option<u64>,
}

impl SemanticVma {
    pub(crate) fn attributes(&self) -> VmaAttributes {
        VmaAttributes {
            read: self.read,
            write: self.write,
            execute: self.execute,
            provenance: self.provenance,
            fork_policy: self.fork_policy,
            dump_policy: self.dump_policy,
            droppable: self.droppable,
            path: self.path.clone(),
            file_page_offset: self.file_page_offset,
        }
    }

    pub(crate) fn with_range_and_attrs(start: u64, end: u64, attrs: VmaAttributes) -> Self {
        Self {
            start,
            end,
            read: attrs.read,
            write: attrs.write,
            execute: attrs.execute,
            provenance: attrs.provenance,
            fork_policy: attrs.fork_policy,
            dump_policy: attrs.dump_policy,
            droppable: attrs.droppable,
            path: attrs.path,
            file_page_offset: attrs.file_page_offset,
        }
    }
}

/// Attributes of a semantic VMA excluding its virtual address range (`start`..`end`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmaAttributes {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub provenance: VmaBackingProvenance,
    pub fork_policy: carrick_abi::VmaForkPolicy,
    pub dump_policy: carrick_abi::VmaDumpPolicy,
    pub droppable: bool,
    pub path: String,
    pub file_page_offset: Option<u64>,
}

impl VmaAttributes {
    pub fn offset_by(&self, delta_bytes: u64) -> Self {
        let mut cloned = self.clone();
        if let Some(base) = cloned.file_page_offset {
            cloned.file_page_offset = Some(base + (delta_bytes >> 12));
        }
        cloned
    }

    pub fn can_merge_with(&self, next: &Self, prev_len_bytes: u64) -> bool {
        let offset_contiguous = match (self.file_page_offset, next.file_page_offset) {
            (None, None) => true,
            (Some(o1), Some(o2)) => o1.checked_add(prev_len_bytes >> 12) == Some(o2),
            _ => false,
        };
        if !offset_contiguous {
            return false;
        }
        // Full equality merge compatibility: any non-offset attribute difference
        // prevents merging.
        let mut expected = next.clone();
        expected.file_page_offset = self.file_page_offset;
        *self == expected
    }
}

/// Error returned when an `insert` operation detects an overlapping VMA range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaOverlapError {
    pub start: u64,
    pub end: u64,
}

impl std::fmt::Display for VmaOverlapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot insert VMA [0x{:x}, 0x{:x}): overlaps with existing range",
            self.start, self.end
        )
    }
}

impl std::error::Error for VmaOverlapError {}

#[cfg(test)]
thread_local! {
    static VMA_VISIT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Sorted, non-overlapping collection of `SemanticVma` entries for an address space.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmaMap {
    vmas: Vec<SemanticVma>,
}

impl VmaMap {
    pub const fn new() -> Self {
        Self { vmas: Vec::new() }
    }

    #[cfg(test)]
    pub fn reset_visit_count() {
        VMA_VISIT_COUNT.with(|c| c.set(0));
    }

    #[cfg(test)]
    pub fn visit_count() -> usize {
        VMA_VISIT_COUNT.with(|c| c.get())
    }

    #[cfg(test)]
    #[inline]
    fn record_visit() {
        VMA_VISIT_COUNT.with(|c| c.set(c.get() + 1));
    }

    pub fn from_vec(vmas: Vec<SemanticVma>) -> Self {
        let mut map = Self { vmas: Vec::new() };
        map.insert_many_replacing(vmas);
        map
    }

    pub fn into_vec(self) -> Vec<SemanticVma> {
        self.vmas
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[SemanticVma] {
        &self.vmas
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SemanticVma> {
        self.vmas.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, SemanticVma> {
        self.vmas.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.vmas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vmas.is_empty()
    }

    fn check_range(start: u64, end: u64) -> bool {
        start < end
    }

    fn try_merge_adjacent(&mut self, left_idx: usize) -> bool {
        if left_idx + 1 >= self.vmas.len() {
            return false;
        }
        #[cfg(test)]
        {
            Self::record_visit();
            Self::record_visit();
        }
        let can_merge = self.vmas[left_idx].end == self.vmas[left_idx + 1].start
            && self.vmas[left_idx].attributes().can_merge_with(
                &self.vmas[left_idx + 1].attributes(),
                self.vmas[left_idx].end - self.vmas[left_idx].start,
            );
        if can_merge {
            let new_end = self.vmas[left_idx + 1].end;
            self.vmas[left_idx].end = new_end;
            self.vmas.remove(left_idx + 1);
            true
        } else {
            false
        }
    }

    /// Coalesce adjacent, compatible VMAs.
    ///
    /// In debug mode, verifies the sorted and non-overlapping invariant.
    pub fn coalesce(&mut self) {
        if self.vmas.len() <= 1 {
            return;
        }
        let mut coalesced: Vec<SemanticVma> = Vec::with_capacity(self.vmas.len());
        for vma in self.vmas.drain(..) {
            if let Some(last) = coalesced.last_mut() {
                debug_assert!(
                    last.start <= vma.start && last.end <= vma.start,
                    "VMA collection must be sorted and non-overlapping"
                );
                if last.end == vma.start
                    && last
                        .attributes()
                        .can_merge_with(&vma.attributes(), last.end - last.start)
                {
                    last.end = vma.end;
                    continue;
                }
            }
            coalesced.push(vma);
        }
        self.vmas = coalesced;
    }

    /// Remove any portion of VMAs intersecting `[start, end)`.
    ///
    /// Slices partial VMAs, adjusts `file_page_offset` on right-hand remainders,
    /// and drops fully covered VMAs. Sub-range operations on non-existent ranges
    /// are safe no-ops. Operates in O(log n + affected) time.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        if !Self::check_range(start, end) {
            return;
        }

        let first = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.end <= start
        });
        let last = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.start < end
        });

        if first >= last {
            return;
        }

        let mut replacements = Vec::with_capacity(2);

        #[cfg(test)]
        Self::record_visit();
        let left_vma = &self.vmas[first];
        if left_vma.start < start {
            let left_attrs = left_vma.attributes();
            replacements.push(SemanticVma::with_range_and_attrs(
                left_vma.start,
                start,
                left_attrs,
            ));
        }

        #[cfg(test)]
        Self::record_visit();
        let right_vma = &self.vmas[last - 1];
        if right_vma.end > end {
            let right_attrs = right_vma.attributes().offset_by(end - right_vma.start);
            replacements.push(SemanticVma::with_range_and_attrs(
                end,
                right_vma.end,
                right_attrs,
            ));
        }

        self.vmas.splice(first..last, replacements);
    }

    /// Modify attributes of any VMAs overlapping `[start, end)`.
    ///
    /// Slices VMAs as needed, adjusts `file_page_offset`, invokes `modify` on the
    /// middle slice's attributes, and coalesces the result. Sub-range operations on
    /// non-existent ranges are safe no-ops. Operates in O(log n + affected) time.
    pub fn modify_range<F>(&mut self, start: u64, end: u64, mut modify: F)
    where
        F: FnMut(&mut VmaAttributes),
    {
        if !Self::check_range(start, end) {
            return;
        }

        let first = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.end <= start
        });
        let last = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.start < end
        });

        if first >= last {
            return;
        }

        let affected_count = last - first;
        let mut replacements = Vec::with_capacity(affected_count + 2);

        for i in first..last {
            #[cfg(test)]
            Self::record_visit();
            let vma = &self.vmas[i];

            if vma.start < start {
                let left_attrs = vma.attributes();
                replacements.push(SemanticVma::with_range_and_attrs(
                    vma.start, start, left_attrs,
                ));
            }

            let mid_start = vma.start.max(start);
            let mid_end = vma.end.min(end);
            let mut mid_attrs = vma.attributes().offset_by(mid_start - vma.start);
            modify(&mut mid_attrs);
            replacements.push(SemanticVma::with_range_and_attrs(
                mid_start, mid_end, mid_attrs,
            ));

            if end < vma.end {
                let right_attrs = vma.attributes().offset_by(end - vma.start);
                replacements.push(SemanticVma::with_range_and_attrs(end, vma.end, right_attrs));
            }
        }

        if replacements.len() > 1 {
            let mut coalesced: Vec<SemanticVma> = Vec::with_capacity(replacements.len());
            for vma in replacements {
                if let Some(last_vma) = coalesced.last_mut() {
                    if last_vma.end == vma.start
                        && last_vma
                            .attributes()
                            .can_merge_with(&vma.attributes(), last_vma.end - last_vma.start)
                    {
                        last_vma.end = vma.end;
                        continue;
                    }
                }
                coalesced.push(vma);
            }
            replacements = coalesced;
        }

        let repl_count = replacements.len();
        self.vmas.splice(first..last, replacements);

        if repl_count > 0 {
            if first + repl_count < self.vmas.len() {
                self.try_merge_adjacent(first + repl_count - 1);
            }
            if first > 0 {
                self.try_merge_adjacent(first - 1);
            }
        }
    }

    /// Insert a VMA into the map.
    ///
    /// # Invariants
    /// - Inserts out-of-order VMAs into ascending address order.
    /// - Rejects overlapping insertions with `Err(VmaOverlapError)`.
    ///   To overwrite existing mappings, use [`VmaMap::insert_replacing`].
    /// - Automatically coalesces adjacent VMAs if all attributes match and
    ///   file page offsets are contiguous.
    /// - Operates in O(log n) time.
    pub fn insert(&mut self, vma: SemanticVma) -> Result<(), VmaOverlapError> {
        if !Self::check_range(vma.start, vma.end) {
            return Ok(());
        }
        let idx = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.start < vma.start
        });

        if idx > 0 {
            #[cfg(test)]
            Self::record_visit();
            if self.vmas[idx - 1].end > vma.start {
                return Err(VmaOverlapError {
                    start: vma.start,
                    end: vma.end,
                });
            }
        }

        if idx < self.vmas.len() {
            #[cfg(test)]
            Self::record_visit();
            if self.vmas[idx].start < vma.end {
                return Err(VmaOverlapError {
                    start: vma.start,
                    end: vma.end,
                });
            }
        }

        self.vmas.insert(idx, vma);

        self.try_merge_adjacent(idx);
        if idx > 0 {
            self.try_merge_adjacent(idx - 1);
        }

        Ok(())
    }

    /// Insert a VMA, unmapping any overlapping ranges and coalescing.
    /// Operates in O(log n + affected) time.
    pub fn insert_replacing(&mut self, vma: SemanticVma) {
        if !Self::check_range(vma.start, vma.end) {
            return;
        }
        self.remove_range(vma.start, vma.end);
        let idx = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.start < vma.start
        });
        self.vmas.insert(idx, vma);
        self.try_merge_adjacent(idx);
        if idx > 0 {
            self.try_merge_adjacent(idx - 1);
        }
    }

    /// Insert multiple non-overlapping VMAs.
    pub fn insert_many<I>(&mut self, vmas: I) -> Result<(), VmaOverlapError>
    where
        I: IntoIterator<Item = SemanticVma>,
    {
        for vma in vmas {
            self.insert(vma)?;
        }
        Ok(())
    }

    /// Insert multiple VMAs, unmapping overlapping ranges and coalescing.
    pub fn insert_many_replacing<I>(&mut self, vmas: I)
    where
        I: IntoIterator<Item = SemanticVma>,
    {
        for vma in vmas {
            self.insert_replacing(vma);
        }
    }

    /// Find the VMA containing `addr`.
    pub fn find(&self, addr: u64) -> Option<&SemanticVma> {
        let idx = self.vmas.partition_point(|v| {
            #[cfg(test)]
            Self::record_visit();
            v.end <= addr
        });
        if let Some(v) = self.vmas.get(idx) {
            #[cfg(test)]
            Self::record_visit();
            if v.start <= addr && addr < v.end {
                return Some(v);
            }
        }
        None
    }

    /// Query VMAs overlapping `[start, end)`.
    pub fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = &SemanticVma> {
        let valid = start < end;
        let (first, last) = if valid {
            let first = self.vmas.partition_point(|v| {
                #[cfg(test)]
                Self::record_visit();
                v.end <= start
            });
            let last = self.vmas.partition_point(|v| {
                #[cfg(test)]
                Self::record_visit();
                v.start < end
            });
            (first, last)
        } else {
            (0, 0)
        };
        let slice = if first < last {
            &self.vmas[first..last]
        } else {
            &[]
        };
        slice.iter()
    }

    /// Transform for child address space on fork (dropping MADV_DONTFORK VMAs).
    pub fn fork_wipe(&self) -> Self {
        let mut child = self.clone();
        child.apply_fork_wipe();
        child
    }

    pub fn apply_fork_wipe(&mut self) {
        self.vmas
            .retain(|vma| vma.fork_policy.copy != carrick_abi::VmaForkCopyPolicy::Omit);
    }

    /// Update protection flags for `[start, end)`.
    pub fn update_prot(&mut self, start: u64, end: u64, read: bool, write: bool, execute: bool) {
        self.modify_range(start, end, |attrs| {
            attrs.read = read;
            attrs.write = write;
            attrs.execute = execute;
        });
    }

    /// Update fork/dump policies for `[start, end)`.
    pub fn update_policy(
        &mut self,
        start: u64,
        end: u64,
        copy_update: Option<carrick_abi::VmaForkCopyPolicy>,
        child_update: Option<carrick_abi::VmaForkChildPolicy>,
        dump_update: Option<carrick_abi::VmaDumpPolicy>,
    ) {
        self.modify_range(start, end, |attrs| {
            if let Some(c) = copy_update {
                attrs.fork_policy.copy = c;
            }
            if let Some(ch) = child_update {
                attrs.fork_policy.child_contents = ch;
            }
            if let Some(d) = dump_update {
                attrs.dump_policy = d;
            }
        });
    }

    /// Grow or trim the program break heap pages.
    pub fn update_heap_pages(&mut self, old_page_end: u64, new_page_end: u64) {
        if new_page_end < old_page_end {
            self.remove_range(new_page_end, old_page_end);
        } else if new_page_end > old_page_end {
            let grown = SemanticVma {
                start: old_page_end,
                end: new_page_end,
                read: true,
                write: true,
                execute: false,
                provenance: VmaBackingProvenance::PrivateAnonymous,
                fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
                dump_policy: carrick_abi::VmaDumpPolicy::Include,
                droppable: false,
                path: "[heap]".to_owned(),
                file_page_offset: None,
            };
            let _ = self.insert(grown);
        }
    }

    #[cfg(test)]
    pub fn push(&mut self, vma: SemanticVma) {
        self.vmas.push(vma);
    }

    #[cfg(test)]
    pub fn push_unaligned_for_test(&mut self, vma: SemanticVma) {
        self.vmas.push(vma);
    }
}

impl std::ops::Deref for VmaMap {
    type Target = [SemanticVma];

    fn deref(&self) -> &Self::Target {
        &self.vmas
    }
}

impl<'a> IntoIterator for &'a VmaMap {
    type Item = &'a SemanticVma;
    type IntoIter = std::slice::Iter<'a, SemanticVma>;

    fn into_iter(self) -> Self::IntoIter {
        self.vmas.iter()
    }
}

impl IntoIterator for VmaMap {
    type Item = SemanticVma;
    type IntoIter = std::vec::IntoIter<SemanticVma>;

    fn into_iter(self) -> Self::IntoIter {
        self.vmas.into_iter()
    }
}

pub(crate) fn project_vma_summaries(mem: &MemState) -> Vec<crate::kernel::VmaSummary> {
    fn append_uncovered(
        maps: &mut Vec<ProcMapsEntry>,
        start: u64,
        end: u64,
        template: &ProcMapsEntry,
    ) {
        if start >= end {
            return;
        }
        let mut covered: Vec<(u64, u64)> = maps
            .iter()
            .filter_map(|map| {
                let covered_start = start.max(map.start);
                let covered_end = end.min(map.end);
                (covered_start < covered_end).then_some((covered_start, covered_end))
            })
            .collect();
        covered.sort_unstable();
        let mut cursor = start;
        let mut gaps = Vec::new();
        for (covered_start, covered_end) in covered {
            if cursor < covered_start {
                gaps.push((cursor, covered_start));
            }
            cursor = cursor.max(covered_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            gaps.push((cursor, end));
        }
        for (gap_start, gap_end) in gaps {
            if let Some(next) = maps.iter_mut().find(|map| {
                map.start == gap_end
                    && map.read == template.read
                    && map.write == template.write
                    && map.execute == template.execute
                    && map.sharing == template.sharing
                    && map.path == template.path
            }) {
                next.start = gap_start;
            } else {
                maps.push(ProcMapsEntry {
                    start: gap_start,
                    end: gap_end,
                    ..template.clone()
                });
            }
        }
    }

    let mut maps = project_core_maps(mem);
    let heap_template = ProcMapsEntry {
        start: mem.layout.heap_base,
        end: mem.brk_current,
        read: true,
        write: true,
        execute: false,
        sharing: ProcMapSharing::Private,
        path: "[heap]".to_owned(),
    };
    append_uncovered(
        &mut maps,
        mem.layout.heap_base,
        mem.brk_current,
        &heap_template,
    );
    for (_, current, end) in &mem.growdown_ranges {
        let template = mem
            .dynamic_maps
            .iter()
            .chain(mem.address_space_regions.iter().flatten())
            .find(|map| map.start < *end && *current < map.end)
            .cloned()
            .unwrap_or_else(|| ProcMapsEntry {
                start: *current,
                end: *end,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "[stack]".to_owned(),
            });
        append_uncovered(&mut maps, *current, *end, &template);
    }
    maps.sort_by_key(|map| (map.start, map.end));
    let mut summaries = Vec::with_capacity(maps.len() + mem.secretmem_maps.len() * 2);
    for map in maps {
        let mut boundaries = vec![map.start, map.end];
        for secret in &mem.secretmem_maps {
            let start = map.start.max(secret.start().raw());
            let end = map.end.min(secret.end().raw());
            if start < end {
                boundaries.extend([start, end]);
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        for window in boundaries.windows(2) {
            let start = window[0];
            let end = window[1];
            let kernel_visible = !mem
                .secretmem_maps
                .iter()
                .any(|secret| secret.start().raw() < end && start < secret.end().raw());
            summaries.push(crate::kernel::VmaSummary {
                start: GuestVa(start),
                end: GuestVa(end),
                access: crate::kernel::VmaAccess {
                    readable: map.read,
                    writable: map.write,
                    executable: map.execute,
                    kernel_visible,
                },
            });
        }
    }
    summaries
}

/// Linux-visible virtual size of this mm in bytes — the `VmSize` that
/// `RLIMIT_AS` is measured against — as the union of the projected VMAs. Same
/// authority as `/proc/<pid>/maps` and the core publisher, so the limit and
/// the reported size cannot disagree.
pub(crate) fn committed_va_bytes(mem: &MemState) -> u64 {
    project_vma_summaries(mem)
        .iter()
        .map(|vma| vma.end.0.saturating_sub(vma.start.0))
        .sum()
}

/// Bytes of `[start, start + len)` that are already mapped. A `MAP_FIXED`
/// replacement is charged only for the remainder, as Linux charges it after
/// unmapping the overlap.
pub(crate) fn mapped_overlap_bytes(mem: &MemState, start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    project_vma_summaries(mem)
        .iter()
        .map(|vma| vma.end.0.min(end).saturating_sub(vma.start.0.max(start)))
        .sum()
}

/// Whether a mapping counts toward `RLIMIT_DATA` (proc(5) `VmData`): private,
/// writable, and not a grow-down stack VMA — anonymous or file-backed alike.
/// `PROT_NONE` reservations and `MAP_SHARED` mappings are address space, not
/// data.
pub(crate) fn mapping_is_data(write: bool, private: bool, growsdown: bool) -> bool {
    write && private && !growsdown
}

/// Bytes charged to `RLIMIT_DATA`: the brk heap span plus every private
/// writable mapping in the visible boot image (`.data`/`.bss`) and the dynamic
/// VMAs. A dynamic map overlapping a grow-down range is stack, not data.
pub(crate) fn data_va_bytes(mem: &MemState) -> u64 {
    let heap = mem.brk_current.saturating_sub(mem.layout.heap_base);
    let is_growdown = |map: &ProcMapsEntry| {
        mem.growdown_ranges
            .iter()
            .any(|(low, _, end)| map.start < *end && map.end > *low)
    };
    let maps: u64 = mem
        .address_space_regions
        .iter()
        .flatten()
        .filter(|map| !boot_region_is_hidden_reservation(map, mem.layout))
        .chain(mem.dynamic_maps.iter())
        .filter(|map| map.start < map.end)
        .filter(|map| {
            mapping_is_data(
                map.write,
                map.sharing == ProcMapSharing::Private,
                is_growdown(map),
            )
        })
        .map(|map| map.end - map.start)
        .sum();
    heap.saturating_add(maps)
}

/// Exact Linux-visible mapping metadata used by the live core publisher.
/// Hidden reservation apertures and carrick's own EL1-only kernel hole are
/// implementation backing, not VMAs; the heap is clamped to `brk`, and dynamic
/// mappings supply the committed pieces of the hidden mmap arena.
pub(crate) fn project_core_maps(mem: &MemState) -> Vec<ProcMapsEntry> {
    let mut maps: Vec<ProcMapsEntry> = mem
        .address_space_regions
        .iter()
        .flatten()
        .filter(|map| !boot_region_is_carrick_kernel_hole(map))
        .filter(|map| !boot_region_is_hidden_reservation(map, mem.layout))
        .filter_map(|map| (map.start < map.end).then_some(map.clone()))
        .collect();
    for vma in &mem.semantic_vmas {
        if (vma.path == "[heap]"
            || (vma.start >= mem.layout.heap_base && vma.end <= mem.brk_current))
            && vma.start < vma.end
        {
            trim_dynamic_maps_for_range(&mut maps, vma.start, vma.end.saturating_sub(vma.start));
            maps.push(ProcMapsEntry {
                start: vma.start,
                end: vma.end,
                read: vma.read,
                write: vma.write,
                execute: vma.execute,
                sharing: ProcMapSharing::Private,
                path: vma.path.clone(),
            });
        }
    }
    for dynamic in &mem.dynamic_maps {
        trim_dynamic_maps_for_range(
            &mut maps,
            dynamic.start,
            dynamic.end.saturating_sub(dynamic.start),
        );
    }
    maps.extend(mem.dynamic_maps.iter().cloned());
    maps.sort_by_key(|map| (map.start, map.end));
    maps
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn trim_semantic_vmas(vmas: &mut Vec<SemanticVma>, start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        vmas.clear();
        return;
    };
    let mut map = VmaMap::from_vec(std::mem::take(vmas));
    map.remove_range(start, end);
    *vmas = map.into_vec();
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn update_semantic_vma_prot(
    vmas: &mut Vec<SemanticVma>,
    start: u64,
    len: u64,
    read: bool,
    write: bool,
    execute: bool,
) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    let mut map = VmaMap::from_vec(std::mem::take(vmas));
    map.update_prot(start, end, read, write, execute);
    *vmas = map.into_vec();
}

#[cfg(test)]
pub(crate) fn update_semantic_vma_policy(
    vmas: &mut Vec<SemanticVma>,
    start: u64,
    len: u64,
    copy_update: Option<carrick_abi::VmaForkCopyPolicy>,
    child_update: Option<carrick_abi::VmaForkChildPolicy>,
    dump_update: Option<carrick_abi::VmaDumpPolicy>,
) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    let mut map = VmaMap::from_vec(std::mem::take(vmas));
    map.update_policy(start, end, copy_update, child_update, dump_update);
    *vmas = map.into_vec();
}

#[cfg(test)]
pub(crate) fn coalesce_semantic_vmas(vmas: &mut Vec<SemanticVma>) {
    let mut map = VmaMap::from_vec(std::mem::take(vmas));
    map.coalesce();
    *vmas = map.into_vec();
}

pub(crate) fn semantic_vmas_from_boot_regions(
    regions: &[ProcMapsEntry],
    file_mappings: &[crate::core_dump::FileMapping],
    layout: MemoryLayout,
    brk_current: u64,
) -> VmaMap {
    let mut semantic_vmas = Vec::with_capacity(regions.len());
    for region in regions {
        if boot_region_is_carrick_kernel_hole(region) {
            continue;
        }
        let is_heap = region.path == "[heap]" || boot_region_is_hidden_heap_backing(region, layout);
        if !is_heap && boot_region_is_hidden_reservation(region, layout) {
            continue;
        }
        let mut start = region.start;
        let mut end = region.end;
        if is_heap {
            start = layout.heap_base;
            end = align_up_u64(brk_current, 4096).unwrap_or(brk_current);
            end = end.min(layout.heap_base.saturating_add(layout.heap_size));
        }
        if start >= end {
            continue;
        }
        let is_stack = region.path == "[stack]";
        let is_shared_aperture = region.path == "[shared]";
        let is_special =
            region.path == "[vdso]" || region.path == "[vvar]" || region.path == "[kernel]";
        // Physical boot regions can coalesce several PT_LOAD segments. File
        // identity belongs to their page-rounded subranges, not to the whole
        // physical allocation; full BSS pages retain anonymous provenance.
        let mut boundaries = vec![start, end];
        if !is_stack && !is_heap && !is_special {
            for mapping in file_mappings {
                if mapping.start < end && mapping.end > start {
                    boundaries.push(mapping.start.max(start));
                    boundaries.push(mapping.end.min(end));
                }
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        for window in boundaries.windows(2) {
            let start = window[0];
            let end = window[1];
            let file_mapping = file_mappings
                .iter()
                .find(|fm| fm.start <= start && fm.end >= end);
            let file_page_offset = file_mapping.map(|fm| {
                fm.file_page_offset + ((start - fm.start) / crate::core_dump::GUEST_PAGE as u64)
            });
            let provenance = if is_stack || is_heap {
                VmaBackingProvenance::PrivateAnonymous
            } else if is_special {
                VmaBackingProvenance::SpecialKernelSynthetic
            } else if file_mapping.is_some() {
                if region.sharing == ProcMapSharing::Shared {
                    VmaBackingProvenance::SharedFile
                } else {
                    VmaBackingProvenance::PrivateFile
                }
            } else if is_shared_aperture {
                VmaBackingProvenance::SharedAnonymous
            } else if region.sharing == ProcMapSharing::Shared {
                if !region.path.is_empty() && !region.path.starts_with('[') {
                    VmaBackingProvenance::SharedFile
                } else {
                    VmaBackingProvenance::SharedAnonymous
                }
            } else {
                if !region.path.is_empty() && !region.path.starts_with('[') {
                    VmaBackingProvenance::PrivateFile
                } else {
                    VmaBackingProvenance::PrivateAnonymous
                }
            };
            semantic_vmas.push(SemanticVma {
                start,
                end,
                read: region.read,
                write: region.write,
                execute: region.execute,
                provenance,
                fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
                dump_policy: carrick_abi::VmaDumpPolicy::Include,
                droppable: false,
                path: region.path.clone(),
                file_page_offset,
            });
        }
    }
    VmaMap::from_vec(semantic_vmas)
}

pub(crate) fn boot_region_source_intersects_hidden_backing(
    map: &ProcMapsEntry,
    mem: &MemState,
    end: u64,
) -> bool {
    if boot_region_is_hidden_mmap_backing(map, mem.layout)
        || boot_region_is_hidden_shared_aperture(map)
        || boot_region_is_hidden_private_overlay(map)
    {
        return true;
    }
    boot_region_is_hidden_heap_backing(map, mem.layout) && end > mem.brk_current
}

pub(crate) fn trim_dynamic_maps_for_range(maps: &mut Vec<ProcMapsEntry>, start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        maps.clear();
        return;
    };
    let mut next = Vec::with_capacity(maps.len());
    for map in maps.drain(..) {
        if !ranges_overlap(start, len, map.start, map.end) {
            next.push(map);
            continue;
        }
        if map.start < start {
            let mut left = map.clone();
            left.end = start;
            next.push(left);
        }
        if end < map.end {
            let mut right = map;
            right.start = end;
            next.push(right);
        }
    }
    *maps = next;
}

#[derive(Clone, Debug)]
pub(crate) struct MremapForkSemantics {
    pub(crate) source_start: u64,
    pub(crate) source_end: u64,
    pub(crate) vmas: Vec<SemanticVma>,
}

impl MremapForkSemantics {
    pub(crate) fn capture(
        vmas: &[SemanticVma],
        source_start: u64,
        source_len: u64,
    ) -> Option<Self> {
        let source_end = source_start.checked_add(source_len)?;
        let mut cursor = source_start;
        let mut captured = Vec::new();
        for vma in vmas
            .iter()
            .filter(|vma| vma.start < source_end && vma.end > source_start)
        {
            let start = vma.start.max(source_start);
            let end = vma.end.min(source_end);
            if start != cursor || end <= start {
                return None;
            }
            let mut clipped = vma.clone();
            clipped.start = start;
            clipped.end = end;
            if let Some(file_page_offset) = clipped.file_page_offset {
                clipped.file_page_offset = Some(file_page_offset + ((start - vma.start) >> 12));
            }
            captured.push(clipped);
            cursor = end;
        }
        (cursor == source_end && !captured.is_empty()).then_some(Self {
            source_start,
            source_end,
            vmas: captured,
        })
    }

    pub(crate) fn project(&self, destination_start: u64, new_len: u64) -> Option<Vec<SemanticVma>> {
        let destination_end = destination_start.checked_add(new_len)?;
        let source_len = self.source_end.checked_sub(self.source_start)?;
        let copied_len = source_len.min(new_len);
        let copied_end = self.source_start.checked_add(copied_len)?;
        let mut projected = Vec::with_capacity(self.vmas.len());
        for vma in &self.vmas {
            let source_start = vma.start.max(self.source_start);
            let source_end = vma.end.min(copied_end);
            if source_start >= source_end {
                break;
            }
            let mut moved = vma.clone();
            moved.start = destination_start.checked_add(source_start - self.source_start)?;
            moved.end = destination_start.checked_add(source_end - self.source_start)?;
            if let Some(file_page_offset) = moved.file_page_offset {
                moved.file_page_offset =
                    Some(file_page_offset + ((source_start - vma.start) >> 12));
            }
            projected.push(moved);
        }
        if new_len > source_len {
            projected.last_mut()?.end = destination_end;
        }
        (!projected.is_empty()).then_some(projected)
    }

    pub(crate) fn any_droppable(&self) -> bool {
        self.vmas.iter().any(|vma| vma.droppable)
    }
}

#[cfg(test)]
mod tests;
