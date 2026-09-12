//! # Memory Protection, Alias Registry, and COW Diagnostics
//!
//! Tracks guest memory protection ranges, the carrier-global alias registry,
//! alias publication/retirement across address spaces, and copy-on-write (COW)
//! diagnostics.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum AliasOwnershipScope {
    /// Alias belongs to the root address space of a specific container in this carrier.
    ContainerRoot(ContainerRootToken),
    /// Alias belongs to exactly one HVPatch address space.  The scope is
    /// rebound in the forked host child when an inherited shared-anonymous
    /// frame is materialized into that child's new mm. The stage-1 root slot
    /// tuple is an ownership token only; guest frames use global IPAs.
    MmRootSlot { base: u64, size: u64 },
    /// Shared-file aliases use the historical VM-global IPA namespace.
    Global,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_ownership_scope(
    sharing: GuestMappingSharing,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> AliasOwnershipScope {
    if sharing.uses_global_ipa() {
        AliasOwnershipScope::Global
    } else if let Some((base, size)) = mm_root_slot {
        AliasOwnershipScope::MmRootSlot { base, size }
    } else {
        AliasOwnershipScope::ContainerRoot(container_root)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn rebind_inherited_alias_to_process(
    mut alias: AliasBacking,
    mm_root_slot: (u64, u64),
) -> AliasBacking {
    alias.ownership_scope = AliasOwnershipScope::MmRootSlot {
        base: mm_root_slot.0,
        size: mm_root_slot.1,
    };
    alias
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AliasBacking {
    /// Guest VIRTUAL start of the alias (the syscall-path region key).
    pub(crate) start: u64,
    pub(crate) ipa: u64,
    pub(crate) host_addr: usize,
    /// Exact guest-visible VA/IPA extent. This deliberately excludes any
    /// host/HVF granule padding retained by `physical_size` below.
    pub(crate) size: usize,
    /// The whole HVF-granular stage-2 extent retained behind this semantic
    /// fragment. Partial Linux unmaps split only the live fields above; VM
    /// rebuild and frame inventory continue to use this exact physical extent.
    pub(crate) physical_ipa: u64,
    pub(crate) physical_host_addr: usize,
    pub(crate) physical_size: usize,
    pub(crate) perms: u64,
    /// Whether the guest may WRITE the alias (a PROT_READ MAP_SHARED file alias
    /// must EFAULT a syscall write, not SIGBUS the host through the raw pointer).
    pub(crate) guest_writable: bool,
    pub(crate) sharing: GuestMappingSharing,
    pub(crate) ownership_scope: AliasOwnershipScope,
    pub(crate) inventory_backing: InventoryBackingIdentity,
    pub(crate) shared_key_base: u64,
    pub(crate) shared_key_offset: u64,
    /// Which incarnation of the global-frame lease this row was published
    /// against — see [`GlobalFrameHostOwner::generation`]. Without it a row that
    /// outlives its lease silently re-authenticates against the next one.
    pub(crate) owner_generation: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn semantic_extent_size(start: u64, end: u64) -> usize {
    usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn split_local_mapping_rows_for_unmap(
    mappings: &mut Vec<HvfMappedRegion>,
    va: u64,
    len: usize,
) {
    let Some(end) = va.checked_add(len as u64) else {
        return;
    };
    let mut tails = Vec::new();
    for row in mappings.iter_mut() {
        if !row.is_dynamic_alias {
            continue;
        }
        let row_size = semantic_extent_size(row.start, row.end);
        let Some(row_end) = row.start.checked_add(row_size as u64) else {
            continue;
        };
        if row_end <= va || row.start >= end {
            continue;
        }
        let head_survives = row.start < va;
        let tail_survives = row_end > end;
        if !head_survives && !tail_survives {
            continue;
        }
        if tail_survives {
            let delta = end.saturating_sub(row.start);
            tails.push(HvfMappedRegion {
                start: end,
                end: row.end,
                ipa: row.ipa.saturating_add(delta),
                physical_ipa: row.physical_ipa,
                physical_size: row.physical_size,
                host_addr: row.host_addr.wrapping_add(delta as usize),
                size: usize::try_from(row_end.saturating_sub(end)).unwrap_or_default(),
                perms: row.perms,
                memory: None,
                host_mapping: None,
                structural_owner: row.structural_owner.clone(),
                stage2_lease: None,
                is_dynamic_alias: true,
                sharing: row.sharing,
                guest_writable: row.guest_writable,
                shared_key_base: row.shared_key_base,
                shared_key_offset: row.shared_key_offset.saturating_add(delta),
                owner_generation: row.owner_generation,
            });
        }
        if head_survives {
            row.end = va;
            row.size = usize::try_from(va.saturating_sub(row.start)).unwrap_or_default();
        } else {
            // Only the tail survives: advance this row onto it and let the
            // pushed fragment be dropped below.
            let delta = end.saturating_sub(row.start);
            row.ipa = row.ipa.saturating_add(delta);
            row.host_addr = row.host_addr.wrapping_add(delta as usize);
            row.shared_key_offset = row.shared_key_offset.saturating_add(delta);
            row.start = end;
            row.size = usize::try_from(row_end.saturating_sub(end)).unwrap_or_default();
            tails.pop();
        }
    }
    mappings.retain(|row| {
        if !row.is_dynamic_alias {
            return true;
        }
        let row_size = semantic_extent_size(row.start, row.end);
        let Some(row_end) = row.start.checked_add(row_size as u64) else {
            return true;
        };
        !(row.start >= va && row_end <= end)
    });
    mappings.append(&mut tails);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_kernel_only_stage1_range(start: u64, len: usize) -> bool {
    let end = start.saturating_add(len as u64);
    start >= crate::memory::LINUX_KERNEL_REGION_BASE
        && end
            <= crate::memory::LINUX_KERNEL_REGION_BASE
                .saturating_add(carrick_mem::memory::LINUX_KERNEL_REGION_SIZE)
}

/// The carrier-global alias registry, partitioned by owning scope.
///
/// This was a flat `Vec<AliasBacking>`. Because the container is
/// carrier-global but almost every question asked of it is per-process, a
/// guest process exit had to walk every OTHER live process's rows to find its
/// own: measured 2026-08-30 at 45.4% of all carrier user CPU under a
/// fork/exit storm, and O(N^2) across N exiting processes. The address
/// translation path had the same shape — `lookup_shared_alias_by_va` filtered
/// by ownership scope only AFTER scanning the whole registry.
///
/// Rows are grouped by [`AliasOwnershipScope`], which is exactly the axis
/// `alias_is_owned_by_process` selects on, so retirement is a bucket removal.
/// Each row keeps a monotonic insertion sequence so the historical GLOBAL
/// order is still available exactly: several lookups take the LAST matching
/// row, and that must keep meaning "most recently registered", not "in
/// whichever scope happens to sort last".
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type AliasExactFirstIndex = std::collections::BTreeMap<
    AliasOwnershipScope,
    std::collections::BTreeMap<(u64, u64), (u64, AliasBacking)>,
>;

/// Width-class partitioned start-keyed index for interval containment and overlap queries.
///
/// Lookups ask "the row registered LAST (or FIRST) whose window contains probe"
/// or "rows whose windows overlap [start, end)". Keying by `(class, start)` where
/// `class = ceil(log2(size))` bounds each class's walk by that class's own widest
/// member: the dense run of small (e.g. 4 KiB) rows is searched over one page,
/// and rare wide rows (e.g. 32 GiB arenas) are searched over their own width but only
/// against the few rows in that class. Candidate selection is O(log n + answers)
/// across active classes (<= 40 classes), eliminating full scans across thousands
/// of irrelevant rows.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct AliasClassIndex {
    pub(crate) by_class_start: std::collections::BTreeMap<(u32, u64), Vec<(u64, AliasBacking)>>,
    pub(crate) class_counts: std::collections::BTreeMap<u32, usize>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasClassIndex {
    /// Which size class a window of `size` bytes belongs to: the exponent
    /// of the smallest power of two that can hold it, so every member of class
    /// `c` has `size <= 1 << c`.
    pub(crate) fn class(size: u64) -> u32 {
        match size.max(1).checked_next_power_of_two() {
            Some(rounded) => rounded.ilog2(),
            None => u64::BITS,
        }
    }

    /// The widest window any member of class `c` can have.
    pub(crate) fn class_radius(class: u32) -> u64 {
        if class >= u64::BITS {
            u64::MAX
        } else {
            1_u64 << class
        }
    }

    pub(crate) fn insert(&mut self, start_key: u64, seq: u64, alias: AliasBacking) {
        let class = Self::class(alias.size as u64);
        self.by_class_start
            .entry((class, start_key))
            .or_default()
            .push((seq, alias));
        *self.class_counts.entry(class).or_default() += 1;
    }

    pub(crate) fn remove(&mut self, start_key: u64, seq: u64, alias: AliasBacking) {
        let class = Self::class(alias.size as u64);
        if let Some(rows) = self.by_class_start.get_mut(&(class, start_key)) {
            if let Some(at) = rows.iter().position(|row| *row == (seq, alias)) {
                rows.remove(at);
            }
            if rows.is_empty() {
                self.by_class_start.remove(&(class, start_key));
            }
        }
        if let std::collections::btree_map::Entry::Occupied(mut count) =
            self.class_counts.entry(class)
        {
            *count.get_mut() = count.get().saturating_sub(1);
            if *count.get() == 0 {
                count.remove();
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.by_class_start.clear();
        self.class_counts.clear();
    }

    pub(crate) fn widest_window(&self) -> u64 {
        self.class_counts
            .keys()
            .next_back()
            .copied()
            .map_or(0, Self::class_radius)
    }

    pub(crate) fn window_rows(
        &self,
        start: u64,
        end: u64,
    ) -> impl Iterator<Item = &(u64, AliasBacking)> + '_ {
        self.class_counts
            .keys()
            .copied()
            .flat_map(move |class| {
                let radius = Self::class_radius(class);
                let lower = start.saturating_sub(radius.saturating_sub(1));
                (lower < end).then_some(((class, lower), (class, end)))
            })
            .flat_map(move |(from, to)| {
                self.by_class_start.range(from..to).flat_map(|(_, rows)| {
                    note_alias_state_rows_scanned(rows.len());
                    rows.iter()
                })
            })
    }

    pub(crate) fn newest_containing(
        &self,
        probe: u64,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        let mut newest: Option<(u64, AliasBacking)> = None;
        for class in self.class_counts.keys() {
            let radius = Self::class_radius(*class);
            let lower = probe.saturating_sub(radius.saturating_sub(1));
            for (&(_class, start_key), rows) in
                self.by_class_start.range((*class, lower)..=(*class, probe))
            {
                note_alias_state_rows_scanned(rows.len());
                for &(seq, alias) in rows {
                    if newest.as_ref().is_none_or(|&(best_seq, _)| seq > best_seq)
                        && probe < start_key.saturating_add(alias.size as u64)
                        && matches(&alias)
                    {
                        newest = Some((seq, alias));
                    }
                }
            }
        }
        newest.map(|(_, alias)| alias)
    }

    pub(crate) fn oldest_containing(
        &self,
        probe: u64,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        let mut oldest: Option<(u64, AliasBacking)> = None;
        for class in self.class_counts.keys() {
            let radius = Self::class_radius(*class);
            let lower = probe.saturating_sub(radius.saturating_sub(1));
            for (&(_class, start_key), rows) in
                self.by_class_start.range((*class, lower)..=(*class, probe))
            {
                note_alias_state_rows_scanned(rows.len());
                for &(seq, alias) in rows {
                    if oldest.as_ref().is_none_or(|&(best_seq, _)| seq < best_seq)
                        && probe < start_key.saturating_add(alias.size as u64)
                        && matches(&alias)
                    {
                        oldest = Some((seq, alias));
                    }
                }
            }
        }
        oldest.map(|(_, alias)| alias)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default, Clone)]
pub(crate) struct AliasRegistry {
    pub(crate) by_scope: std::collections::BTreeMap<AliasOwnershipScope, Vec<(u64, AliasBacking)>>,
    /// First row for each exact semantic key inside a scope: insertion sequence
    /// and value. Receipt publication asks exactly this question for every row;
    /// locating it through the scope `Vec` made a k-row publication O(k * rows-in-mm).
    pub(crate) exact_first_by_scope: AliasExactFirstIndex,
    pub(crate) next_seq: u64,
    /// Monotonic semantic-mutation revision used only to prove that a fork
    /// snapshot and delayed retirement observed one coherent alias view.
    pub(crate) revision: u64,
    /// Maintained total of every bucket's length; see [`Self::len`].
    pub(crate) rows: usize,
    /// Rows keyed by guest-VA window start, and by IPA window start.
    /// Maintained for exact start lookup (`promote_exact_first_keys`) and structural testing.
    pub(crate) by_va_start: std::collections::BTreeMap<u64, Vec<(u64, AliasBacking)>>,
    pub(crate) by_ipa_start: std::collections::BTreeMap<u64, Vec<(u64, AliasBacking)>>,
    /// Exact physical stage-2 start index used by delayed owner retirement.
    /// The retired owner identity supplies the exact length/host/generation;
    /// this keeps candidate selection O(log n + rows at that physical start)
    /// instead of walking every live process in the carrier.
    pub(crate) by_physical_start: std::collections::BTreeMap<u64, Vec<(u64, AliasBacking)>>,
    /// Per-scope physical stage-2 window index. COW retention asks whether
    /// another semantic VA in this exact mm still projects the source frame;
    /// indexing by `(scope, physical_ipa)` keeps that question bounded to the
    /// two visible scopes and to rows capable of containing the compound.
    pub(crate) by_scope_physical_start:
        std::collections::BTreeMap<(AliasOwnershipScope, u64), Vec<(u64, AliasBacking)>>,
    /// Live physical window sizes per scope. The largest key is the exact
    /// lower-bound radius for that scope's containment query; unlike a global
    /// ever-grown maximum, removing a huge row shrinks the search again and a
    /// foreign process can never widen another mm's lookup.
    pub(crate) physical_size_counts_by_scope:
        std::collections::BTreeMap<AliasOwnershipScope, std::collections::BTreeMap<u64, usize>>,
    /// The VA-window and IPA-window rows, bucketed by window SIZE CLASS.
    ///
    /// Keying by `(class, start)` where `class = ceil(log2(size))` bounds each
    /// class's walk by that class's own widest member: the dense run of
    /// small (e.g. 4 KiB) rows is searched over one page, and rare wide rows
    /// (e.g. 32 GiB arenas) are searched over their own width but only
    /// against the few rows in that class. This makes interval containment
    /// queries O(log n + answers) across active classes (<= 40 classes),
    /// eliminating carrier CPU hotspots in futex resolution and alias lookup.
    pub(crate) va_classes: AliasClassIndex,
    pub(crate) ipa_classes: AliasClassIndex,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasRegistry {
    pub(crate) fn bump_revision(&mut self) {
        self.revision = self.revision.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "alias registry revision counter overflow: revision={}",
                self.revision
            );
        });
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn rebuild_exact_scope(&mut self, scope: AliasOwnershipScope) {
        let Some(rows) = self.by_scope.get(&scope) else {
            self.exact_first_by_scope.remove(&scope);
            return;
        };
        let mut exact = std::collections::BTreeMap::new();
        note_alias_state_rows_scanned(rows.len());
        for &(seq, alias) in rows {
            exact
                .entry((alias.start, alias.ipa))
                .or_insert((seq, alias));
        }
        if exact.is_empty() {
            self.exact_first_by_scope.remove(&scope);
        } else {
            self.exact_first_by_scope.insert(scope, exact);
        }
    }

    /// Binary search for `seq` in `rows` and locate the matching `alias`.
    /// The scope bucket is in monotonic insertion sequence order in production.
    /// A single row split into fragments shares the parent's sequence, so
    /// equal keys walk the equal-seq run. Probes are instrumented with
    /// [`note_alias_state_rows_scanned`].
    pub(crate) fn bucket_position_in(
        rows: &[(u64, AliasBacking)],
        seq: u64,
        alias: &AliasBacking,
        removed_positions: Option<&std::collections::BTreeSet<usize>>,
    ) -> Option<usize> {
        let Ok(pos) = rows.binary_search_by(|r| {
            note_alias_state_rows_scanned(1);
            r.0.cmp(&seq)
        }) else {
            return None;
        };
        let is_removed = |idx: usize| removed_positions.is_some_and(|set| set.contains(&idx));
        if rows[pos].1 == *alias && !is_removed(pos) {
            return Some(pos);
        }
        let mut i = pos + 1;
        while i < rows.len() && rows[i].0 == seq {
            note_alias_state_rows_scanned(1);
            if rows[i].1 == *alias && !is_removed(i) {
                return Some(i);
            }
            i += 1;
        }
        let mut j = pos;
        while j > 0 && rows[j - 1].0 == seq {
            j -= 1;
            note_alias_state_rows_scanned(1);
            if rows[j].1 == *alias && !is_removed(j) {
                return Some(j);
            }
        }
        None
    }

    /// Refresh only positions affected by a scope-bucket edit. Earlier first
    /// occurrences still mask duplicate keys in the suffix. Tail unmaps leave
    /// the existing prefix tree intact instead of allocating it again.
    /// Re-establish `exact_first_by_scope` for exactly the keys a mutation
    /// disturbed, by asking `by_va_start` for the surviving row with the
    /// lowest sequence — the same promotion the batch-remove path already
    /// performs, and the reason this scope's row order no longer has to be
    /// rescanned. Cost is O(touched keys * rows sharing that guest VA), never
    /// O(rows in the mm).
    pub(crate) fn promote_exact_first_keys(
        &mut self,
        scope: AliasOwnershipScope,
        keys: &std::collections::BTreeSet<(u64, u64)>,
    ) {
        for &(start, ipa) in keys {
            let next_remaining = self.by_va_start.get(&start).and_then(|va_rows| {
                note_alias_state_rows_scanned(va_rows.len());
                va_rows
                    .iter()
                    .filter(|r| r.1.ownership_scope == scope && r.1.ipa == ipa)
                    .min_by_key(|r| r.0)
                    .copied()
            });
            match next_remaining {
                Some((next_seq, next_alias)) => {
                    self.exact_first_by_scope
                        .entry(scope)
                        .or_default()
                        .insert((start, ipa), (next_seq, next_alias));
                }
                None => {
                    if let Some(exact) = self.exact_first_by_scope.get_mut(&scope) {
                        exact.remove(&(start, ipa));
                    }
                }
            }
        }
        if self
            .exact_first_by_scope
            .get(&scope)
            .is_some_and(|e| e.is_empty())
        {
            self.exact_first_by_scope.remove(&scope);
        }
    }

    pub(crate) fn index_insert(&mut self, seq: u64, alias: AliasBacking) {
        self.by_va_start
            .entry(alias.start)
            .or_default()
            .push((seq, alias));
        self.va_classes.insert(alias.start, seq, alias);
        self.by_ipa_start
            .entry(alias.ipa)
            .or_default()
            .push((seq, alias));
        self.ipa_classes.insert(alias.ipa, seq, alias);
        self.by_physical_start
            .entry(alias.physical_ipa)
            .or_default()
            .push((seq, alias));
        self.by_scope_physical_start
            .entry((alias.ownership_scope, alias.physical_ipa))
            .or_default()
            .push((seq, alias));
        *self
            .physical_size_counts_by_scope
            .entry(alias.ownership_scope)
            .or_default()
            .entry(alias.physical_size as u64)
            .or_default() += 1;
    }

    pub(crate) fn index_remove(&mut self, seq: u64, alias: AliasBacking) {
        if let Some(rows) = self.by_va_start.get_mut(&alias.start) {
            if let Some(at) = rows.iter().position(|row| *row == (seq, alias)) {
                rows.remove(at);
            }
            if rows.is_empty() {
                self.by_va_start.remove(&alias.start);
            }
        }
        self.va_classes.remove(alias.start, seq, alias);
        if let Some(rows) = self.by_ipa_start.get_mut(&alias.ipa) {
            if let Some(at) = rows.iter().position(|row| *row == (seq, alias)) {
                rows.remove(at);
            }
            if rows.is_empty() {
                self.by_ipa_start.remove(&alias.ipa);
            }
        }
        self.ipa_classes.remove(alias.ipa, seq, alias);
        if let Some(rows) = self.by_physical_start.get_mut(&alias.physical_ipa) {
            if let Some(at) = rows.iter().position(|row| *row == (seq, alias)) {
                rows.remove(at);
            }
            if rows.is_empty() {
                self.by_physical_start.remove(&alias.physical_ipa);
            }
        }
        let physical_key = (alias.ownership_scope, alias.physical_ipa);
        if let Some(rows) = self.by_scope_physical_start.get_mut(&physical_key) {
            if let Some(at) = rows.iter().position(|row| *row == (seq, alias)) {
                rows.remove(at);
            }
            if rows.is_empty() {
                self.by_scope_physical_start.remove(&physical_key);
            }
        }
        if let Some(counts) = self
            .physical_size_counts_by_scope
            .get_mut(&alias.ownership_scope)
        {
            if let Some(count) = counts.get_mut(&(alias.physical_size as u64)) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&(alias.physical_size as u64));
                }
            }
            if counts.is_empty() {
                self.physical_size_counts_by_scope
                    .remove(&alias.ownership_scope);
            }
        }
    }

    #[cfg(test)]
    /// Rebuild all window indexes from the buckets. Used where a registry is
    /// constructed directly rather than through the mutators.
    pub(crate) fn reindex(&mut self) {
        self.by_va_start.clear();
        self.va_classes.clear();
        self.by_ipa_start.clear();
        self.ipa_classes.clear();
        self.by_physical_start.clear();
        self.by_scope_physical_start.clear();
        self.physical_size_counts_by_scope.clear();
        self.exact_first_by_scope.clear();
        let rows: Vec<(u64, AliasBacking)> = self
            .by_scope
            .values()
            .flat_map(|rows| rows.iter().copied())
            .collect();
        for (seq, alias) in rows {
            self.index_insert(seq, alias);
        }
        for scope in self.by_scope.keys().copied().collect::<Vec<_>>() {
            self.rebuild_exact_scope(scope);
        }
    }

    /// The widest VA window any LIVE row can have: the radius of the largest
    /// live size class. Reported by the per-fault mapping-index census as the
    /// bound the containment queries actually pay, so the probe keeps naming
    /// the thing it named before the class index replaced the monotone
    /// `widest_va` -- except that this one shrinks again when the wide row
    /// retires.
    pub(crate) fn widest_va_window(&self) -> u64 {
        self.va_classes.widest_window()
    }

    /// Every row whose guest-VA window can overlap `[start, end)`, in
    /// unspecified order, each visited at most once.
    pub(crate) fn va_window_rows(
        &self,
        start: u64,
        end: u64,
    ) -> impl Iterator<Item = &(u64, AliasBacking)> + '_ {
        self.va_classes.window_rows(start, end)
    }

    /// [`Self::newest_matching`] for a predicate that requires the row's
    /// guest-VA window to contain `va`.
    pub(crate) fn newest_containing_va(
        &self,
        va: u64,
        matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.va_classes.newest_containing(va, matches)
    }

    /// [`Self::oldest_matching`] for a predicate that requires the row's IPA
    /// window to contain `ipa`.
    pub(crate) fn oldest_containing_ipa(
        &self,
        ipa: u64,
        matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.ipa_classes.oldest_containing(ipa, matches)
    }

    /// [`Self::newest_matching`] for a predicate that requires the row's IPA
    /// window to contain `ipa`.
    pub(crate) fn newest_containing_ipa(
        &self,
        ipa: u64,
        matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.ipa_classes.newest_containing(ipa, matches)
    }

    /// Private rows owned by one process whose exact physical stage-2 extent
    /// fully contains `[physical_ipa, physical_ipa + physical_len)`.
    ///
    /// The returned rows are candidates only. Callers must authenticate their
    /// host-owner generation before using them as lifetime evidence.
    pub(crate) fn private_owned_containing_physical(
        &self,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
        physical_ipa: u64,
        physical_len: u64,
    ) -> Vec<AliasBacking> {
        let Some(physical_end) = physical_ipa.checked_add(physical_len) else {
            return Vec::new();
        };
        let scope = Self::owned_scope(mm_root_slot, container_root);
        let widest = self
            .physical_size_counts_by_scope
            .get(&scope)
            .and_then(|counts| counts.last_key_value().map(|(&size, _)| size))
            .unwrap_or(0);
        // A row can contain the extent only if it starts in
        // `[physical_end - widest, physical_ipa]`. When the query is longer
        // than every recorded row that interval is empty, and a reversed
        // `BTreeMap::range` panics, so clamp the lower bound to the start.
        let lower = physical_end.saturating_sub(widest).min(physical_ipa);
        let rows = self
            .by_scope_physical_start
            .range((scope, lower)..=(scope, physical_ipa))
            .flat_map(|(_, rows)| rows);
        let mut candidates = Vec::new();
        for (_, alias) in rows {
            note_alias_state_rows_scanned(1);
            if alias.sharing == GuestMappingSharing::Private
                && alias
                    .physical_ipa
                    .checked_add(alias.physical_size as u64)
                    .is_some_and(|end| physical_end <= end)
            {
                candidates.push(*alias);
            }
        }
        candidates
    }

    /// Place one row in its scope bucket, keeping the bucket ordered by
    /// sequence. The ONLY way a row enters a bucket.
    ///
    /// The order is not cosmetic. `bucket_position_in` locates a row by binary
    /// search on the sequence, so an unsorted bucket does not answer "slower",
    /// it answers "this row is not here". `push` always supplies the next
    /// sequence and so always lands at the end; the unmap planner
    /// (`staged_unmap_registry`) replays EXISTING rows in the order its two
    /// source indices yield them, and only this placement makes the staged
    /// bucket agree with the live one. Ties keep insertion order, so a split
    /// row's head still precedes its tail.
    pub(crate) fn place_in_scope_bucket(&mut self, seq: u64, alias: AliasBacking) {
        let rows = self.by_scope.entry(alias.ownership_scope).or_default();
        let at = rows.partition_point(|&(row_seq, _)| row_seq <= seq);
        rows.insert(at, (seq, alias));
    }

    pub(crate) fn push(&mut self, alias: AliasBacking) {
        self.bump_revision();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.place_in_scope_bucket(seq, alias);
        self.exact_first_by_scope
            .entry(alias.ownership_scope)
            .or_default()
            .entry((alias.start, alias.ipa))
            .or_insert((seq, alias));
        self.rows = self.rows.saturating_add(1);
        self.index_insert(seq, alias);
    }

    #[cfg(test)]
    /// Replace every row, in the given order, with fresh sequences.
    pub(crate) fn replace_all(&mut self, aliases: impl IntoIterator<Item = AliasBacking>) {
        self.clear();
        self.extend(aliases);
    }

    #[cfg(test)]
    pub(crate) fn extend(&mut self, aliases: impl IntoIterator<Item = AliasBacking>) {
        for alias in aliases {
            self.push(alias);
        }
    }

    pub(crate) fn clear(&mut self) {
        if self.rows != 0 {
            self.bump_revision();
        }
        self.by_scope.clear();
        self.exact_first_by_scope.clear();
        self.by_va_start.clear();
        self.va_classes.clear();
        self.by_ipa_start.clear();
        self.ipa_classes.clear();
        self.by_physical_start.clear();
        self.by_scope_physical_start.clear();
        self.physical_size_counts_by_scope.clear();
        self.rows = 0;
        // `next_seq` is deliberately NOT reset: sequence numbers are identity
        // for ordering comparisons that may outlive a clear.
    }

    /// Total live rows.
    ///
    /// Summing the buckets makes this O(live processes), and it is read on
    /// every generic mutation; that showed up as `AliasRegistry::len` at 4.2%
    /// of carrier CPU once the bigger scans were gone.
    pub(crate) fn len(&self) -> usize {
        self.rows
    }

    /// Test-only: the total recomputed from the buckets. Production reads the
    /// maintained `rows`; `alias_registry_row_total_tracks_its_buckets` proves
    /// the two agree. Deliberately NOT a `debug_assert` inside `len`, which
    /// would re-sum every bucket in exactly the debug builds the conformance
    /// lane runs — the same mistake the frame-inventory counter made.
    #[cfg(test)]
    pub(crate) fn recomputed_len(&self) -> usize {
        self.by_scope.values().map(Vec::len).sum()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_scope.values().all(Vec::is_empty)
    }

    /// Rows of one scope, oldest first.
    pub(crate) fn scope_rows(&self, scope: AliasOwnershipScope) -> &[(u64, AliasBacking)] {
        self.by_scope.get(&scope).map_or(&[], Vec::as_slice)
    }

    /// Rows whose physical stage-2 extent starts exactly at `physical_ipa`.
    /// Owner retirement authenticates length/host/generation separately.
    pub(crate) fn physical_start_rows(&self, physical_ipa: u64) -> &[(u64, AliasBacking)] {
        let rows: &[(u64, AliasBacking)] = self
            .by_physical_start
            .get(&physical_ipa)
            .map_or(&[], Vec::as_slice);
        note_alias_state_rows_scanned(rows.len());
        rows
    }

    /// Every row in GLOBAL insertion order, oldest first. O(n log n); use
    /// [`Self::scope_rows`] when the question is scoped.
    #[cfg(test)]
    pub(crate) fn ordered(&self) -> Vec<AliasBacking> {
        let mut rows: Vec<(u64, AliasBacking)> = self
            .by_scope
            .values()
            .flat_map(|rows| rows.iter().copied())
            .collect();
        // STABLE: a row split into fragments keeps its parent's sequence,
        // so equal keys must retain their bucket-relative emission order.
        rows.sort_by_key(|(seq, _)| *seq);
        rows.into_iter().map(|(_, alias)| alias).collect()
    }

    /// Every row, in NO meaningful order, borrowed and without allocating.
    ///
    /// Use this only where the answer cannot depend on order: `any`, `min`,
    /// a per-key `find` (all rows for one `(start, ipa, scope)` live in one
    /// scope bucket, so bucket order IS their insertion order), or a whole-registry
    /// predicate. Where the caller takes the first or last match ACROSS keys,
    /// use [`Self::oldest_matching`] / [`Self::newest_matching`] instead:
    /// those answers change with the order, and getting it wrong is silent.
    /// With a thousand processes aliasing one shared futex page at the same
    /// IPA, bucket order handed different processes different `host_addr`s for
    /// the same futex word.
    ///
    /// Materializing global order here instead was measured at 89.6% of all
    /// carrier CPU (`AliasRegistry::ordered`), because these lookups are hot;
    /// the ordering primitives below are single passes with no allocation, so
    /// they cost exactly what the old flat `Vec` scan cost.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &AliasBacking> {
        self.by_scope
            .values()
            .flat_map(|rows| rows.iter().map(|(_, alias)| alias))
    }

    /// The matching row registered FIRST, in global insertion order.
    ///
    /// Superseded on every production path by the window-indexed lookups, and
    /// retained as their ORACLE: `window_indexed_lookups_match_a_full_scan`
    /// asserts the two agree across mutations, because an index that drifts
    /// from its buckets fails silently — which is exactly how the first
    /// partitioning attempt lost `futexforkrequeue`'s futex wakes.
    #[cfg(test)]
    pub(crate) fn oldest_matching(
        &self,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.by_scope
            .values()
            .flatten()
            .filter(|(_, alias)| matches(alias))
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, alias)| *alias)
    }

    /// The matching row registered LAST, in global insertion order. Oracle
    /// for the window-indexed lookups; see [`Self::oldest_matching`].
    #[cfg(test)]
    pub(crate) fn newest_matching(
        &self,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.by_scope
            .values()
            .flatten()
            .filter(|(_, alias)| matches(alias))
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, alias)| *alias)
    }

    #[cfg(feature = "foreign-cow-test-support")]
    /// Mutate the row registered LAST among those matching, and report
    /// whether one was found. Selection is identical to
    /// [`Self::newest_matching`]; a row is located by (scope, position)
    /// rather than by sequence because a split row's fragments share their
    /// parent's sequence.
    pub(crate) fn update_newest_matching(
        &mut self,
        mut matches: impl FnMut(&AliasBacking) -> bool,
        update: impl FnOnce(&mut AliasBacking),
    ) -> bool {
        let mut best: Option<(AliasOwnershipScope, usize, u64)> = None;
        for (scope, rows) in &self.by_scope {
            for (position, (seq, alias)) in rows.iter().enumerate() {
                if matches(alias) && best.is_none_or(|(_, _, best_seq)| *seq >= best_seq) {
                    best = Some((*scope, position, *seq));
                }
            }
        }
        let Some((scope, position, _)) = best else {
            return false;
        };
        let Some(rows) = self.by_scope.get_mut(&scope) else {
            return false;
        };
        let Some(slot) = rows.get_mut(position) else {
            return false;
        };
        let seq = slot.0;
        let previous = slot.1;
        update(&mut slot.1);
        let updated = slot.1;
        if updated != previous {
            self.bump_revision();
        }
        self.index_remove(seq, previous);
        self.index_insert(seq, updated);
        self.rebuild_exact_scope(scope);
        true
    }

    /// [`Self::newest_matching`] restricted to the scopes one process can see.
    /// Exact for any predicate that already required
    /// `alias_matches_process_scope`, and O(that process's rows) rather than
    /// O(carrier).
    pub(crate) fn newest_matching_for_process(
        &self,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        Self::process_visible_scopes(mm_root_slot, container_root)
            .into_iter()
            .flat_map(|scope| self.scope_rows(scope))
            .filter(|(_, alias)| matches(alias))
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, alias)| *alias)
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, alias: &AliasBacking) -> bool {
        self.scope_rows(alias.ownership_scope)
            .iter()
            .any(|(_, row)| row == alias)
    }

    #[allow(dead_code)]
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&AliasBacking) -> bool) {
        let mut dropped = Vec::new();
        let scopes = self.by_scope.keys().copied().collect::<Vec<_>>();
        for scope in scopes {
            let Some(rows) = self.by_scope.get_mut(&scope) else {
                continue;
            };
            rows.retain(|row| {
                let survives = keep(&row.1);
                if !survives {
                    dropped.push(*row);
                }
                survives
            });
            self.rebuild_exact_scope(scope);
        }
        self.rows = self.rows.saturating_sub(dropped.len());
        if !dropped.is_empty() {
            self.bump_revision();
        }
        for (seq, alias) in dropped {
            self.index_remove(seq, alias);
        }
        self.by_scope.retain(|_, rows| !rows.is_empty());
    }

    /// Remove every row of one scope and return them, oldest first. This is
    /// the process-retirement primitive: O(that scope's rows), not O(carrier).
    pub(crate) fn remove_scope(&mut self, scope: AliasOwnershipScope) -> Vec<AliasBacking> {
        let Some(rows) = self.by_scope.remove(&scope) else {
            return Vec::new();
        };
        self.exact_first_by_scope.remove(&scope);
        self.bump_revision();
        self.rows = self.rows.saturating_sub(rows.len());
        for &(seq, alias) in &rows {
            self.index_remove(seq, alias);
        }
        rows.into_iter().map(|(_, alias)| alias).collect()
    }

    /// Retain within one scope, returning the removed rows oldest first.
    pub(crate) fn retain_in_scope(
        &mut self,
        scope: AliasOwnershipScope,
        mut keep: impl FnMut(&AliasBacking) -> bool,
    ) -> Vec<AliasBacking> {
        let mut dropped = Vec::new();
        if let Some(rows) = self.by_scope.get_mut(&scope) {
            rows.retain(|row| {
                let survives = keep(&row.1);
                if !survives {
                    dropped.push(*row);
                }
                survives
            });
            self.rows = self.rows.saturating_sub(dropped.len());
            if rows.is_empty() {
                self.by_scope.remove(&scope);
            }
        }
        for &(seq, alias) in &dropped {
            self.index_remove(seq, alias);
        }
        if !dropped.is_empty() {
            self.bump_revision();
        }
        self.rebuild_exact_scope(scope);
        dropped.into_iter().map(|(_, alias)| alias).collect()
    }

    /// Rebuild one scope's rows, sequences included, keeping the row total
    /// exact. A VA unmap splits rows into fragments that must inherit their
    /// parent's sequence, so the caller needs the sequences, not just the
    /// aliases.
    #[cfg(test)]
    pub(crate) fn rebuild_scope_rows(
        &mut self,
        scope: AliasOwnershipScope,
        rebuild: impl FnOnce(Vec<(u64, AliasBacking)>) -> Vec<(u64, AliasBacking)>,
    ) {
        let Some(previous) = self.by_scope.get_mut(&scope).map(std::mem::take) else {
            return;
        };
        let before = previous.len();
        let replacement = rebuild(previous.clone());
        if replacement != previous {
            self.bump_revision();
        }
        self.rows = self
            .rows
            .saturating_sub(before)
            .saturating_add(replacement.len());
        *self
            .by_scope
            .get_mut(&scope)
            .unwrap_or_else(|| std::process::abort()) = replacement.clone();
        for (seq, alias) in previous {
            self.index_remove(seq, alias);
        }
        for (seq, alias) in replacement {
            self.index_insert(seq, alias);
        }
        self.rebuild_exact_scope(scope);
        self.drop_empty_scope(scope);
    }

    pub(crate) fn drop_empty_scope(&mut self, scope: AliasOwnershipScope) {
        if self.by_scope.get(&scope).is_some_and(Vec::is_empty) {
            self.by_scope.remove(&scope);
        }
    }

    /// The FIRST row registered for one exact semantic alias identity.
    ///
    /// Every row of one scope lives in one bucket in insertion order, so the
    /// first match in that bucket IS the first match in global insertion
    /// order — the answer the historical whole-registry `find` gave, without
    /// visiting any other process's rows.
    pub(crate) fn find_by_key(
        &self,
        start: u64,
        ipa: u64,
        scope: AliasOwnershipScope,
    ) -> Option<AliasBacking> {
        let found = self
            .exact_first_by_scope
            .get(&scope)
            .and_then(|exact| exact.get(&(start, ipa)))
            .map(|(_, entry)| *entry);
        note_alias_state_rows_scanned(usize::from(found.is_some()));
        found
    }

    /// Replace the first row for `alias`'s `(start, ipa, scope)`, or append it,
    /// and report the row that was replaced.
    /// Same first-occurrence semantics as [`Self::find_by_key`]; a replaced
    /// row keeps its sequence, so it keeps its place in the global order
    /// exactly as an in-place `Vec` write did.
    pub(crate) fn upsert_by_key(&mut self, alias: AliasBacking) -> Option<AliasBacking> {
        let scope = alias.ownership_scope;
        let exact = self
            .exact_first_by_scope
            .get(&scope)
            .and_then(|rows| rows.get(&(alias.start, alias.ipa)))
            .copied();
        if let Some((seq, previous)) = exact {
            note_alias_state_rows_scanned(1);
            let rows = self.by_scope.get_mut(&scope).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::host_alias",
                    "exact-key index scope absent from bucket map: scope={:?} start=0x{:x} ipa=0x{:x}",
                    scope,
                    alias.start,
                    alias.ipa
                );
            });
            let pos = Self::bucket_position_in(rows, seq, &previous, None).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::host_alias",
                    "exact-key index sequence not found in scope bucket: scope={:?} seq={} start=0x{:x} ipa=0x{:x}",
                    scope,
                    seq,
                    previous.start,
                    previous.ipa
                );
            });
            let slot = &mut rows[pos];
            if slot.0 != seq || slot.1 != previous {
                carrick_fatal!(
                    "hvpatch::host_alias",
                    "exact-key index entry disagrees with scope bucket: slot_seq={} seq={} slot_ipa=0x{:x} expected_ipa=0x{:x}",
                    slot.0,
                    seq,
                    slot.1.ipa,
                    previous.ipa
                );
            }
            slot.1 = alias;
            if previous != alias {
                self.bump_revision();
            }
            self.index_remove(seq, previous);
            self.index_insert(seq, alias);
            self.exact_first_by_scope
                .get_mut(&scope)
                .and_then(|rows| rows.get_mut(&(alias.start, alias.ipa)))
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::host_alias",
                        "exact-key index entry disappeared during exclusive upsert: scope={:?} start=0x{:x} ipa=0x{:x}",
                        scope,
                        alias.start,
                        alias.ipa
                    );
                })
                .1 = alias;
            return Some(previous);
        }
        self.push(alias);
        None
    }

    /// Replace several exact semantic keys without rebuilding unaffected rows.
    /// Values are appended in slice order, preserving the historical
    /// retirement behavior where a restored preimage receives a fresh global
    /// sequence after the rows that survived.
    pub(crate) fn replace_exact_keys_in_batch(
        &mut self,
        replacements: &[(AliasVersionKey, Option<AliasBacking>)],
    ) {
        let mut keys_by_scope = std::collections::BTreeMap::<
            AliasOwnershipScope,
            std::collections::BTreeSet<(u64, u64)>,
        >::new();
        for &((start, ipa, scope), replacement) in replacements {
            if let Some(replacement) = replacement
                && alias_version_key(&replacement) != (start, ipa, scope)
            {
                carrick_fatal!(
                    "hvpatch::host_alias",
                    "batch replacement value does not match target key: key=(0x{start:x}, 0x{ipa:x}, {scope:?}) replacement=(0x{:x}, 0x{:x}, {:?})",
                    replacement.start,
                    replacement.ipa,
                    replacement.ownership_scope
                );
            }
            keys_by_scope.entry(scope).or_default().insert((start, ipa));
        }
        for (scope, keys) in keys_by_scope {
            let mut to_remove = Vec::new();
            for &(start, ipa) in &keys {
                if let Some(va_rows) = self.by_va_start.get(&start) {
                    for &(_, alias) in va_rows {
                        if alias.ipa == ipa && alias.ownership_scope == scope {
                            to_remove.push(alias);
                        }
                    }
                }
            }
            let _ = self.remove_exact_values_in_batch(&to_remove);
        }
        for &(_, replacement) in replacements {
            if let Some(alias) = replacement {
                self.push(alias);
            }
        }
    }

    /// Remove only values captured from an older semantic publication. A
    /// delayed exec cleanup must not interpret `(VA, IPA, scope)` as immutable:
    /// an exec successor can reuse all three while carrying a new physical
    /// owner generation. Retiring k captured rows touches only the k rows in
    /// the secondary indexes and updates the scope bucket and exact-first index
    /// in O(k log N) without rebuilding the scope from scratch.
    pub(crate) fn remove_exact_values_in_batch(
        &mut self,
        expected: &[AliasBacking],
    ) -> Vec<AliasBacking> {
        if expected.is_empty() {
            return Vec::new();
        }
        let mut expected_by_scope =
            std::collections::BTreeMap::<AliasOwnershipScope, Vec<AliasBacking>>::new();
        for &alias in expected {
            expected_by_scope
                .entry(alias.ownership_scope)
                .or_default()
                .push(alias);
        }
        let mut removed = Vec::new();
        for (scope, scope_expected) in expected_by_scope {
            let mut removed_in_scope = Vec::new();
            let mut removed_positions = std::collections::BTreeSet::new();

            {
                let Some(rows) = self.by_scope.get(&scope) else {
                    continue;
                };
                if rows.is_empty() {
                    self.drop_empty_scope(scope);
                    continue;
                }

                for alias in scope_expected {
                    note_alias_state_rows_scanned(1);
                    let first_in_exact = self
                        .exact_first_by_scope
                        .get(&scope)
                        .and_then(|exact| exact.get(&(alias.start, alias.ipa)))
                        .copied();
                    let mut found_pos = None;
                    if let Some((seq, entry)) = first_in_exact {
                        if entry == alias {
                            if let Some(pos) = Self::bucket_position_in(
                                rows,
                                seq,
                                &alias,
                                Some(&removed_positions),
                            ) {
                                found_pos = Some((pos, seq, alias));
                            }
                        }
                    }
                    if found_pos.is_none() {
                        if let Some(va_rows) = self.by_va_start.get(&alias.start) {
                            for &(seq, a) in va_rows {
                                if a == alias && a.ipa == alias.ipa && a.ownership_scope == scope {
                                    if let Some(pos) = Self::bucket_position_in(
                                        rows,
                                        seq,
                                        &alias,
                                        Some(&removed_positions),
                                    ) {
                                        found_pos = Some((pos, seq, alias));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if let Some((pos, seq, alias)) = found_pos {
                        removed_positions.insert(pos);
                        removed_in_scope.push((pos, seq, alias));
                    }
                }
            }

            if removed_in_scope.is_empty() {
                continue;
            }

            removed_in_scope.sort_by_key(|(pos, _, _)| *pos);

            let mut promoted_keys = Vec::new();
            if let Some(exact) = self.exact_first_by_scope.get(&scope) {
                for &(_pos, seq, alias) in &removed_in_scope {
                    if let Some(&(first_seq, first_alias)) = exact.get(&(alias.start, alias.ipa)) {
                        if first_seq == seq && first_alias == alias {
                            promoted_keys.push((alias.start, alias.ipa));
                        }
                    }
                }
            }
            promoted_keys.sort_unstable();
            promoted_keys.dedup();

            for &(_, seq, alias) in &removed_in_scope {
                self.index_remove(seq, alias);
                note_alias_state_rows_scanned(1);
                removed.push(alias);
            }
            self.rows = self.rows.saturating_sub(removed_in_scope.len());
            self.bump_revision();

            let first_removed = removed_in_scope[0].0;
            if let Some(rows) = self.by_scope.get_mut(&scope) {
                let mut remove_idx = 0;
                let mut write = first_removed;
                for read in first_removed..rows.len() {
                    if remove_idx < removed_in_scope.len() && read == removed_in_scope[remove_idx].0
                    {
                        remove_idx += 1;
                    } else {
                        rows[write] = rows[read];
                        write += 1;
                    }
                }
                rows.truncate(write);
            }

            for (start, ipa) in promoted_keys {
                let next_remaining = self.by_va_start.get(&start).and_then(|va_rows| {
                    va_rows
                        .iter()
                        .filter(|r| r.1.ownership_scope == scope && r.1.ipa == ipa)
                        .min_by_key(|r| r.0)
                        .copied()
                });
                if let Some((next_seq, next_alias)) = next_remaining {
                    self.exact_first_by_scope
                        .entry(scope)
                        .or_default()
                        .insert((start, ipa), (next_seq, next_alias));
                } else if let Some(exact) = self.exact_first_by_scope.get_mut(&scope) {
                    exact.remove(&(start, ipa));
                }
            }

            if self
                .exact_first_by_scope
                .get(&scope)
                .is_some_and(|e| e.is_empty())
            {
                self.exact_first_by_scope.remove(&scope);
            }
            self.drop_empty_scope(scope);
        }
        removed
    }

    /// Every row one process can see, in global insertion order.
    ///
    /// The fork paths materialized the WHOLE carrier registry and then
    /// filtered it by scope, which is O(all processes) per fork plus a sort
    /// and an allocation. Every consumer of that vector re-applies
    /// `alias_matches_process_scope`, so restricting it here is exact.
    pub(crate) fn process_visible_ordered(
        &self,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Vec<AliasBacking> {
        let mut rows: Vec<(u64, AliasBacking)> =
            Self::process_visible_scopes(mm_root_slot, container_root)
                .into_iter()
                .flat_map(|scope| self.scope_rows(scope).iter().copied())
                .collect();
        note_alias_state_rows_scanned(rows.len());
        rows.sort_by_key(|(seq, _)| *seq);
        rows.into_iter().map(|(_, alias)| alias).collect()
    }

    /// Rows whose guest-VA window overlaps `[va, va + len)` in the process-visible scopes,
    /// ordered by sequence.
    pub(crate) fn overlapping_process_aliases(
        &self,
        va: u64,
        len: usize,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Vec<(u64, AliasBacking)> {
        if len == 0 {
            return Vec::new();
        }
        let Some(end) = va.checked_add(len as u64) else {
            return Vec::new();
        };
        if end <= va {
            return Vec::new();
        }
        let mut overlapping = Vec::new();
        for &(seq, alias) in self.va_window_rows(va, end) {
            if alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
                && alias.start.saturating_add(alias.size as u64) > va
            {
                overlapping.push((seq, alias));
            }
        }
        overlapping.sort_by_key(|(seq, _)| *seq);
        overlapping
    }

    /// Whether any live alias visible to the process overlaps `[va, end)`.
    /// Bounded to `by_va_start.range(va - widest_va .. end)` instead of walking
    /// all carrier or scope rows.
    pub(crate) fn has_live_process_alias_overlapping(
        &self,
        va: u64,
        end: u64,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> bool {
        if va >= end {
            return false;
        }
        self.va_window_rows(va, end).any(|&(_, alias)| {
            alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
                && alias.start < end
                && alias.start.saturating_add(alias.size as u64) > va
                && alias_backing_is_live(alias.physical_host_addr)
        })
    }

    /// Smallest `alias.start` strictly between `start` and `end` matching `predicate`
    /// in the process-visible scopes.
    /// Because `by_va_start` is ordered by `alias.start`, returns on the first
    /// matching key without scanning the remainder of the registry.
    pub(crate) fn first_matching_process_alias_start_between(
        &self,
        start: u64,
        end: u64,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<u64> {
        if start >= end {
            return None;
        }
        for (&alias_start, rows) in self.by_va_start.range((
            std::ops::Bound::Excluded(start),
            std::ops::Bound::Excluded(end),
        )) {
            note_alias_state_rows_scanned(rows.len());
            for &(_, alias) in rows {
                if alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
                    && matches(&alias)
                {
                    return Some(alias_start);
                }
            }
        }
        None
    }

    /// The newest alias visible to the process whose guest-VA window contains `va`.
    /// Bounded by the live VA size-class index.
    pub(crate) fn newest_process_alias_containing_va(
        &self,
        va: u64,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        self.va_classes.newest_containing(va, |alias| {
            alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
                && va >= alias.start
                && va < alias.start.saturating_add(alias.size as u64)
                && matches(alias)
        })
    }

    /// Insert a single row into buckets and indices with an explicit sequence.
    /// Used when staging a planned mutation subset without cloning or reindexing the whole registry.
    ///
    /// The sequence is an EXISTING row's, so it may be lower than one already
    /// staged; `place_in_scope_bucket` is what keeps the staged bucket in the
    /// same sequence order the live one is in.
    pub(crate) fn insert_indexed_row(&mut self, seq: u64, alias: AliasBacking) {
        self.place_in_scope_bucket(seq, alias);
        self.exact_first_by_scope
            .entry(alias.ownership_scope)
            .or_default()
            .entry((alias.start, alias.ipa))
            .or_insert((seq, alias));
        self.rows = self.rows.saturating_add(1);
        self.next_seq = self.next_seq.max(seq.saturating_add(1));
        self.index_insert(seq, alias);
    }

    /// Plan the retirement of physical leases and disarm spans for an unmap of `[va, va+len)`
    /// from the process-visible scopes without cloning the registry.
    /// Returns the planned retirement leases and the overlapping rows before unmapping.
    pub(crate) fn plan_unregister_process_alias(
        &self,
        va: u64,
        len: usize,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> (std::collections::BTreeSet<(u64, u64)>, Vec<AliasBacking>) {
        let overlapping = self.overlapping_process_aliases(va, len, mm_root_slot, container_root);
        let registry_before: Vec<AliasBacking> =
            overlapping.iter().map(|(_, alias)| *alias).collect();
        if overlapping.is_empty() {
            return (std::collections::BTreeSet::new(), registry_before);
        }
        let mut planned = self.staged_unmap_registry(&overlapping, mm_root_slot, container_root);
        let planned_leases =
            unregister_alias_entries(&mut planned, va, len, mm_root_slot, container_root);
        (planned_leases, registry_before)
    }

    /// The miniature registry the unmap planner runs `unregister_alias_entries`
    /// over: the rows that overlap the unmap, plus every row of a
    /// process-visible scope that co-holds one of their physical extents.
    ///
    /// It is a REGISTRY, not a row list, and that is load-bearing:
    /// `unregister_alias_entries` selects the rows to split through this
    /// object's own scope buckets and window index, so every invariant those
    /// carry in the live registry has to hold here too or the plan and the
    /// live unmap disagree about which frames retire. `insert_indexed_row` is
    /// where that is enforced — these rows arrive in two index orders, not in
    /// sequence order.
    pub(crate) fn staged_unmap_registry(
        &self,
        overlapping: &[(u64, AliasBacking)],
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Self {
        let scopes = Self::process_visible_scopes(mm_root_slot, container_root);
        let mut co_holders = Vec::new();
        let mut seen_extents = std::collections::BTreeSet::new();
        for (_, entry) in overlapping {
            if seen_extents.insert((entry.physical_ipa, entry.physical_size as u64)) {
                for &scope in &scopes {
                    if let Some(rows) = self
                        .by_scope_physical_start
                        .get(&(scope, entry.physical_ipa))
                    {
                        note_alias_state_rows_scanned(rows.len());
                        for &(seq, alias) in rows {
                            if alias.physical_size == entry.physical_size {
                                co_holders.push((seq, alias));
                            }
                        }
                    }
                }
            }
        }
        // Rows are identified by (sequence, semantic start): the fragments of
        // one split row keep the row's sequence, and dedup on sequence alone
        // dropped the sibling fragment from the plan (`mincoreedge`, a
        // middle-page unmap followed by the head's).
        let mut planned = Self::default();
        let mut seen_rows = std::collections::BTreeSet::new();
        for &(seq, alias) in overlapping {
            seen_rows.insert((seq, alias.start));
            planned.insert_indexed_row(seq, alias);
        }
        for (seq, alias) in co_holders {
            if seen_rows.insert((seq, alias.start)) {
                planned.insert_indexed_row(seq, alias);
            }
        }
        planned
    }

    /// The two scopes a process can see, per `alias_matches_process_scope`:
    /// the one it owns, plus the shared-file `Global` namespace.
    pub(crate) fn process_visible_scopes(
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> [AliasOwnershipScope; 2] {
        [
            Self::owned_scope(mm_root_slot, container_root),
            AliasOwnershipScope::Global,
        ]
    }

    /// The scope a process owns, per `alias_is_owned_by_process`.
    pub(crate) fn owned_scope(
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> AliasOwnershipScope {
        match mm_root_slot {
            Some((base, size)) => AliasOwnershipScope::MmRootSlot { base, size },
            None => AliasOwnershipScope::ContainerRoot(container_root),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const COW_DIAGNOSTIC_EXACT_KEY_LIMIT: usize = 1_024;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const COW_DIAGNOSTIC_EXACT_HISTORY_LIMIT: usize = 16;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CowDiagnosticRetirementOutcome {
    Retired,
    DeferredActivePins,
    RetryPending,
    TerminalizedByVmDestroy,
    NotFound,
    MismatchedGeneration {
        current_generation: u64,
        expected_generation: u64,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CowDiagnosticLifecycleKind {
    InventoryPublished,
    InventoryRemoved,
    AliasPublished,
    AliasRemoved,
    AliasPreservedReused,
    ForkSelected,
    ForkDeduplicated,
    ForkOmitted,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CowDiagnosticLifecycleSite {
    CowCommit,
    ForeignCowCommit,
    ForkPlan,
    ForkMaterialization,
    ProcessMaterialization,
    AliasUnmap,
    ReceiptRetirement,
    ProcessRetirement,
    ExecRetirement,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CowDiagnosticAliasRevisionSite {
    ForkSnapshotBegin,
    ForkSnapshotEnd,
    CowPublication,
    ForeignCowPublication,
    ExecPredecessorMutation,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CowDiagnosticEvent {
    PageTableBind {
        mm_access: usize,
        old_authority: usize,
        new_authority: usize,
        old_root: Option<u64>,
        new_root: Option<u64>,
    },
    ReplacementCommitted {
        custody: usize,
        linux_pid: i32,
        mm: u64,
        semantic_va: u64,
        old_physical_ipa: u64,
        new_physical_ipa: u64,
        new_host_addr: usize,
        new_owner_generation: u64,
        new_frame: u64,
        new_mapping: u64,
        retired_old_stage2: bool,
    },
    Retirement {
        custody: usize,
        ipa: u64,
        length: u64,
        expected_generation: Option<u64>,
        outcome: CowDiagnosticRetirementOutcome,
    },
    AliasRevision {
        site: CowDiagnosticAliasRevisionSite,
        custody: usize,
        linux_pid: i32,
        mm: u64,
        physical_ipa: u64,
        revision: u64,
    },
    Lifecycle {
        kind: CowDiagnosticLifecycleKind,
        site: CowDiagnosticLifecycleSite,
        custody: usize,
        linux_pid: i32,
        mm: u64,
        mm_root_slot_base: u64,
        semantic_va: u64,
        semantic_length: u64,
        logical_gpa: u64,
        logical_length: u64,
        physical_ipa: u64,
        physical_length: u64,
        owner_host_addr: usize,
        owner_generation: u64,
        frame: u64,
        mapping: u64,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CowDiagnosticEvent {
    pub(crate) fn is_relevant(
        &self,
        custody: usize,
        physical_ipa: u64,
        mm_access: Option<usize>,
    ) -> bool {
        match *self {
            Self::PageTableBind {
                mm_access: event_mm_access,
                ..
            } => mm_access == Some(event_mm_access),
            Self::ReplacementCommitted {
                custody: event_custody,
                old_physical_ipa,
                new_physical_ipa,
                ..
            } => {
                event_custody == custody
                    && (old_physical_ipa == physical_ipa || new_physical_ipa == physical_ipa)
            }
            Self::Retirement {
                custody: event_custody,
                ipa,
                length,
                ..
            } => {
                event_custody == custody
                    && ipa <= physical_ipa
                    && physical_ipa < ipa.saturating_add(length)
            }
            Self::AliasRevision {
                custody: event_custody,
                physical_ipa: event_physical_ipa,
                ..
            } => {
                event_custody == custody
                    && (event_physical_ipa == 0 || event_physical_ipa == physical_ipa)
            }
            Self::Lifecycle {
                custody: event_custody,
                physical_ipa: event_physical_ipa,
                physical_length,
                ..
            } => {
                (event_custody == 0 || event_custody == custody)
                    && event_physical_ipa <= physical_ipa
                    && physical_ipa < event_physical_ipa.saturating_add(physical_length)
            }
        }
    }

    pub(crate) fn exact_physical_keys(&self) -> Vec<(usize, u64)> {
        match *self {
            Self::ReplacementCommitted {
                custody,
                old_physical_ipa,
                new_physical_ipa,
                ..
            } => {
                if old_physical_ipa == new_physical_ipa {
                    vec![(custody, old_physical_ipa)]
                } else {
                    vec![(custody, old_physical_ipa), (custody, new_physical_ipa)]
                }
            }
            Self::Retirement { custody, ipa, .. } => vec![(custody, ipa)],
            Self::AliasRevision {
                custody,
                physical_ipa,
                ..
            } if physical_ipa != 0 => vec![(custody, physical_ipa)],
            Self::AliasRevision { .. } => Vec::new(),
            Self::Lifecycle {
                custody,
                physical_ipa,
                ..
            } => vec![(custody, physical_ipa)],
            Self::PageTableBind { .. } => Vec::new(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CowDiagnosticRecord {
    pub(crate) sequence: u64,
    pub(crate) event: CowDiagnosticEvent,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
pub(crate) struct CowDiagnosticHistory {
    pub(crate) rows: std::collections::VecDeque<CowDiagnosticRecord>,
    pub(crate) exact_rows:
        std::collections::BTreeMap<(usize, u64), std::collections::VecDeque<CowDiagnosticRecord>>,
    pub(crate) exact_key_order: std::collections::VecDeque<(usize, u64)>,
    pub(crate) next_sequence: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CowDiagnosticHistory {
    pub(crate) fn push(&mut self, event: CowDiagnosticEvent) {
        let record = CowDiagnosticRecord {
            sequence: self.next_sequence,
            event,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.rows.len() == COW_DIAGNOSTIC_HISTORY_LIMIT {
            self.rows.pop_front();
        }
        self.rows.push_back(record);
        for key in event.exact_physical_keys() {
            if !self.exact_rows.contains_key(&key) {
                if self.exact_key_order.len() == COW_DIAGNOSTIC_EXACT_KEY_LIMIT
                    && let Some(oldest) = self.exact_key_order.pop_front()
                {
                    self.exact_rows.remove(&oldest);
                }
                self.exact_key_order.push_back(key);
            }
            let rows = self.exact_rows.entry(key).or_default();
            if rows.len() == COW_DIAGNOSTIC_EXACT_HISTORY_LIMIT {
                rows.pop_front();
            }
            rows.push_back(record);
        }
    }

    pub(crate) fn relevant(
        &self,
        custody: usize,
        physical_ipa: u64,
        mm_access: Option<usize>,
        limit: usize,
    ) -> Vec<CowDiagnosticEvent> {
        let mut relevant = std::collections::BTreeMap::new();
        for record in self.rows.iter().chain(
            self.exact_rows
                .get(&(custody, physical_ipa))
                .into_iter()
                .flatten()
                .chain(
                    self.exact_rows
                        .get(&(0, physical_ipa))
                        .into_iter()
                        .flatten(),
                ),
        ) {
            if record.event.is_relevant(custody, physical_ipa, mm_access) {
                relevant.insert(record.sequence, record.event);
            }
        }
        relevant
            .into_values()
            .rev()
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn report_stage2_map_refusal(
    custody: &CarrierVmCustody,
    host_addr: usize,
    ipa: u64,
    size: usize,
    perms: u64,
    code: u32,
) {
    if !cow_refusal_diagnostics_enabled() {
        return;
    }
    let end = ipa.saturating_add(size as u64);
    let matching = custody
        .stage2_record_identities()
        .into_iter()
        .filter_map(|identity| custody.stage2_record_snapshot(identity.record_id))
        .filter(|record| {
            let record_end = record.ipa.saturating_add(record.len as u64);
            record.ipa < end && ipa < record_end
        })
        .take(8)
        .collect::<Vec<_>>();
    eprintln!(
        "carrick: HVPatch stage-2 map refusal custody={:p} ipa=0x{ipa:x} len=0x{size:x} host=0x{host_addr:x} perms=0x{perms:x} code=0x{code:x} overlapping_records={matching:?}",
        custody,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn record_cow_diagnostic_event(event: CowDiagnosticEvent) {
    if cow_refusal_diagnostics_enabled() {
        cow_diagnostic_history().lock().push(event);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn record_alias_revision(
    site: CowDiagnosticAliasRevisionSite,
    custody: &CarrierVmCustody,
    identity: Option<carrick_hal::FrameCowIdentity>,
    physical_ipa: u64,
    revision: u64,
) {
    record_cow_diagnostic_event(CowDiagnosticEvent::AliasRevision {
        site,
        custody: custody as *const CarrierVmCustody as usize,
        linux_pid: identity.map_or(0, |identity| identity.linux_pid),
        mm: identity.map_or(0, |identity| identity.mm),
        physical_ipa,
        revision,
    });
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_cow_inventory_lifecycle(
    kind: CowDiagnosticLifecycleKind,
    site: CowDiagnosticLifecycleSite,
    custody: &CarrierVmCustody,
    identity: Option<carrick_hal::FrameCowIdentity>,
    mm_root_slot: Option<(u64, u64)>,
    semantic_va: u64,
    semantic_length: u64,
    logical_key: (u64, u64),
    extent: InventoryExtent,
) {
    record_cow_diagnostic_event(CowDiagnosticEvent::Lifecycle {
        kind,
        site,
        custody: custody as *const CarrierVmCustody as usize,
        linux_pid: identity.map_or(0, |identity| identity.linux_pid),
        mm: identity.map_or(0, |identity| identity.mm),
        mm_root_slot_base: mm_root_slot.map_or(0, |slot| slot.0),
        semantic_va,
        semantic_length,
        logical_gpa: logical_key.0,
        logical_length: logical_key.1,
        physical_ipa: extent.stage2_base,
        physical_length: extent.stage2_length,
        owner_host_addr: extent.stage2_owner.host_addr,
        owner_generation: extent.stage2_owner.generation,
        frame: extent.frame.raw(),
        mapping: extent.mapping.raw(),
    });
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn record_cow_alias_lifecycle(
    kind: CowDiagnosticLifecycleKind,
    site: CowDiagnosticLifecycleSite,
    custody: Option<&CarrierVmCustody>,
    identity: Option<carrick_hal::FrameCowIdentity>,
    mm_root_slot: Option<(u64, u64)>,
    alias: AliasBacking,
) {
    record_cow_diagnostic_event(CowDiagnosticEvent::Lifecycle {
        kind,
        site,
        custody: custody.map_or(0, |custody| custody as *const CarrierVmCustody as usize),
        linux_pid: identity.map_or(0, |identity| identity.linux_pid),
        mm: identity.map_or(0, |identity| identity.mm),
        mm_root_slot_base: mm_root_slot.map_or(0, |slot| slot.0),
        semantic_va: alias.start,
        semantic_length: alias.size as u64,
        logical_gpa: alias.ipa,
        logical_length: alias.size as u64,
        physical_ipa: alias.physical_ipa,
        physical_length: alias.physical_size as u64,
        owner_host_addr: alias.physical_host_addr,
        owner_generation: alias.owner_generation,
        frame: 0,
        mapping: 0,
    });
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn record_alias_unmap_lifecycle(
    site: CowDiagnosticLifecycleSite,
    custody: &CarrierVmCustody,
    identity: Option<carrick_hal::FrameCowIdentity>,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    before: &[AliasBacking],
) {
    if !cow_refusal_diagnostics_enabled() {
        return;
    }
    let mut after = alias_registry()
        .lock()
        .process_visible_ordered(mm_root_slot, container_root);
    for alias in before {
        if let Some(index) = after.iter().position(|candidate| candidate == alias) {
            after.remove(index);
        } else {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasRemoved,
                site,
                Some(custody),
                identity,
                mm_root_slot,
                *alias,
            );
        }
    }
    for alias in after {
        record_cow_alias_lifecycle(
            CowDiagnosticLifecycleKind::AliasPublished,
            site,
            Some(custody),
            identity,
            mm_root_slot,
            alias,
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GlobalFrameRetirementOutcome {
    RetiredUnmapped {
        ipa: u64,
        length: u64,
        generation: u64,
    },
    DeferredActivePins {
        ipa: u64,
        length: u64,
        generation: u64,
    },
    RetryPending {
        ipa: u64,
        length: u64,
        generation: u64,
        error: String,
    },
    TerminalizedByVmDestroy {
        ipa: u64,
        length: u64,
        generation: u64,
    },
    /// No owner was registered for this (ipa, length) key.
    NotFound { ipa: u64, length: u64 },
    /// An owner was present, but its generation did not match the expected generation.
    MismatchedGeneration {
        ipa: u64,
        length: u64,
        current_generation: u64,
        expected_generation: u64,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameRetirementOutcome {
    pub(crate) fn is_retired(&self) -> bool {
        matches!(
            self,
            Self::RetiredUnmapped { .. } | Self::TerminalizedByVmDestroy { .. }
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<&GlobalFrameRetirementOutcome> for CowDiagnosticRetirementOutcome {
    fn from(outcome: &GlobalFrameRetirementOutcome) -> Self {
        match *outcome {
            GlobalFrameRetirementOutcome::RetiredUnmapped { .. } => Self::Retired,
            GlobalFrameRetirementOutcome::DeferredActivePins { .. } => Self::DeferredActivePins,
            GlobalFrameRetirementOutcome::RetryPending { .. } => Self::RetryPending,
            GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. } => {
                Self::TerminalizedByVmDestroy
            }
            GlobalFrameRetirementOutcome::NotFound { .. } => Self::NotFound,
            GlobalFrameRetirementOutcome::MismatchedGeneration {
                current_generation,
                expected_generation,
                ..
            } => Self::MismatchedGeneration {
                current_generation,
                expected_generation,
            },
        }
    }
}

/// `alias_registry` is a process-global `static` COW-inherited across `fork(2)`,
/// so a forked child inherits entries whose `host_addr` names the PARENT's
/// mapping — a host VA that is NOT backed in the child (a different process's
/// address space). Resolving a guest syscall (e.g. a `read_futex_word`) through
/// such an entry and dereferencing `host_addr` is a carrick HOST SIGSEGV
/// (EXC_BAD_ACCESS) inside the child — the cpython multiprocessing FORKSERVER
/// SyncManager crash. `mincore` returns `-1/ENOMEM` iff the range has an
/// unmapped page, so it cheaply rejects a dead inherited backing. Only ever
/// called on the alias FALLBACK (after the per-thread `self.mappings` fast path
/// misses), never per guest instruction. Conservative: on any other mincore
/// outcome treat the backing as live (the caller's read still bounds-checks).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_backing_is_live(host_addr: usize) -> bool {
    if host_addr == 0 {
        return false;
    }
    // macOS `mincore` is NO USE here: it returns 0/success even for an unmapped
    // page or an outright gap address. Use `mach_vm_region`, which returns the
    // region AT OR AFTER the queried address — `host_addr` is mapped iff that
    // region actually contains it. (This is the same query the crash report's
    // "0x… is not in any region" annotation came from.)
    pub(crate) const VM_REGION_BASIC_INFO_64: i32 = 9;
    pub(crate) const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
    unsafe extern "C" {
        fn mach_vm_region(
            target_task: libc::vm_map_t,
            address: *mut libc::mach_vm_address_t,
            size: *mut libc::mach_vm_size_t,
            flavor: i32,
            info: *mut i32,
            info_count: *mut u32,
            object_name: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
    }
    let mut addr = host_addr as libc::mach_vm_address_t;
    let mut size: libc::mach_vm_size_t = 0;
    let mut info = [0i32; 16];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut obj: libc::mach_port_t = 0;
    // SAFETY: queries this task's VM map; reads no guest data. mach_task_self_ is
    // the stable task port.
    #[allow(deprecated)]
    let kr = unsafe {
        mach_vm_region(
            libc::mach_task_self_,
            &mut addr,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut obj,
        )
    };
    kr == 0
        && (addr as usize) <= host_addr
        && host_addr < (addr as usize).saturating_add(size as usize)
}

/// Find the registered alias whose `hv_vm_map`'d IPA window contains `ipa`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn lookup_shared_alias(ipa: u64) -> Option<AliasBacking> {
    alias_registry().lock().oldest_containing_ipa(ipa, |e| {
        ipa >= e.ipa
            && ipa < e.ipa.saturating_add(e.size as u64)
            && alias_backing_is_live(e.host_addr)
    })
}

/// Find the registered alias whose guest-VA window FULLY contains `[va, va+len)`.
/// The cross-thread fallback's IPA key (`translate_va`) reads this thread's
/// software stage-1 model, which can lack a freshly-`MAP_FIXED`-committed high-VA
/// arena page that a sibling vCPU installed — even though `add_alias` already
/// registered the backing here, keyed by guest VA. The VA key resolves it.
///
/// Two safety rules make this never resolve to the WRONG backing (the failure the
/// `mapping_index_for_range` doc warns about):
/// - **Whole range in ONE entry**: a buffer straddling two aliases returns `None`
///   (→ EFAULT), never a partial backing.
/// - **Newest-first** (`.rev()`): a Go arena page is covered by BOTH the PROT_NONE
///   reservation entry AND the later `MAP_FIXED` commit; the commit is registered
///   last, and `add_alias`/`map_aliased` register the IPA they install into stage-1
///   in the same order — so the newest entry is exactly the backing the guest's own
///   page tables use.
///
/// The caller gates on `!range_no_access` so a still-PROT_NONE reservation page
/// (uncommitted) EFAULTs even though the reservation entry would contain its VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_matches_process_scope(
    ownership_scope: AliasOwnershipScope,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> bool {
    match ownership_scope {
        AliasOwnershipScope::Global => true,
        AliasOwnershipScope::ContainerRoot(container) => {
            mm_root_slot.is_none() && container == container_root
        }
        AliasOwnershipScope::MmRootSlot { base, size } => mm_root_slot == Some((base, size)),
    }
}

/// Whether an alias is private to the address space being replaced/retired.
/// Global aliases may still be referenced by another mm and are removed only
/// when their physical extent reaches its final reference.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_is_owned_by_process(
    ownership_scope: AliasOwnershipScope,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> bool {
    match (ownership_scope, mm_root_slot) {
        (AliasOwnershipScope::ContainerRoot(container), None) => container == container_root,
        (AliasOwnershipScope::MmRootSlot { base, size }, Some(root_slot)) => {
            (base, size) == root_slot
        }
        (AliasOwnershipScope::Global, _)
        | (AliasOwnershipScope::ContainerRoot(_), Some(_))
        | (AliasOwnershipScope::MmRootSlot { .. }, None) => false,
    }
}

/// Alias-registry entries owned by sibling vCPUs but absent from the forking
/// vCPU's local mapping ledger. The caller additionally checks the live stage-1
/// translation and backing lifetime before copying them.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn missing_process_aliases(
    local_aliases: &std::collections::HashSet<ProcessAliasKey>,
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> Vec<AliasBacking> {
    aliases
        .iter()
        .copied()
        .filter(|alias| {
            !local_aliases.contains(&process_alias_key(*alias))
                && alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
        })
        .collect()
}

/// Whether a per-vCPU mapping row belongs in a new process's address-space
/// inventory. Boot mappings are structural. Dynamic aliases are lifetime
/// owners as well as lookup rows, so a retired row may remain in `mappings`
/// after munmap; only an exact live-registry publication makes it semantic.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Exact-identity key of one process-scoped alias publication: the five
/// fields `mapping_is_current_for_process_fork` matches. Fork-path callers
/// walk EVERY mapping and previously linear-scanned the alias registry per
/// mapping — O(mappings x aliases) per fork, the dominant term of the
/// fork-cost-grows-with-live-count pathology (35 ms/fork at 1000 live
/// processes; futex_cmp_requeue01's 1000-waiter phase starves on it). The
/// index makes one pass over the registry and answers each mapping in O(1).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type ProcessAliasKey = (u64, u64, usize, usize, u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn process_alias_key(alias: AliasBacking) -> ProcessAliasKey {
    (
        alias.start,
        alias.ipa,
        alias.host_addr,
        alias.size,
        alias.owner_generation,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn mapped_region_process_alias_key(mapping: &HvfMappedRegion) -> ProcessAliasKey {
    (
        mapping.start,
        mapping.ipa,
        mapping.host_addr as usize,
        semantic_extent_size(mapping.start, mapping.end),
        mapping.owner_generation,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn thread_mapping_process_alias_key(mapping: &ThreadMappingDesc) -> ProcessAliasKey {
    (
        mapping.start,
        mapping.ipa,
        mapping.host_addr as usize,
        mapping.size,
        mapping.owner_generation,
    )
}

/// One-pass index of the process-scoped alias publications, keyed by
/// [`ProcessAliasKey`]. First occurrence wins, mirroring the linear scans'
/// `.find` semantics this replaces.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn process_alias_index(
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> std::collections::HashMap<ProcessAliasKey, AliasBacking> {
    let mut index = std::collections::HashMap::with_capacity(aliases.len());
    for alias in aliases {
        if alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root) {
            index
                .entry((
                    alias.start,
                    alias.ipa,
                    alias.host_addr,
                    alias.size,
                    alias.owner_generation,
                ))
                .or_insert(*alias);
        }
    }
    index
}

/// Index-backed [`mapping_is_current_for_process_fork`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn mapping_is_current_for_process_fork_indexed(
    mapping: &HvfMappedRegion,
    index: &std::collections::HashMap<ProcessAliasKey, AliasBacking>,
) -> bool {
    !mapping.is_dynamic_alias
        || index.contains_key(&(
            mapping.start,
            mapping.ipa,
            mapping.host_addr as usize,
            semantic_extent_size(mapping.start, mapping.end),
            mapping.owner_generation,
        ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn current_process_alias_keys<'a>(
    mappings: impl IntoIterator<Item = &'a HvfMappedRegion>,
    aliases: &[AliasBacking],
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> std::collections::HashSet<ProcessAliasKey> {
    let index = process_alias_index(aliases, mm_root_slot, container_root);
    mappings
        .into_iter()
        .filter(|mapping| mapping_is_current_for_process_fork_indexed(mapping, &index))
        .map(mapped_region_process_alias_key)
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn lookup_shared_alias_by_va(
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> Option<AliasBacking> {
    let end = va.saturating_add(len as u64);
    alias_registry().lock().newest_process_alias_containing_va(
        va,
        mm_root_slot,
        container_root,
        |e| {
            end <= e.start.saturating_add(e.size as u64)
                // Reject an entry whose backing is not mapped in THIS process
                // (a parent's host_addr COW-inherited into a forked child) —
                // dereferencing it would HOST-SIGSEGV the child. See
                // `alias_backing_is_live`.
                && alias_backing_is_live(e.host_addr.saturating_add((va - e.start) as usize))
        },
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn lookup_live_alias_by_va_any_scope(va: u64, len: usize) -> Option<AliasBacking> {
    let end = va.saturating_add(len as u64);
    alias_registry().lock().newest_containing_va(va, |entry| {
        va >= entry.start
            && end <= entry.start.saturating_add(entry.size as u64)
            && alias_backing_is_live(entry.host_addr.saturating_add((va - entry.start) as usize))
    })
}

/// Drop the index entry for any alias whose guest-VA window overlaps
/// `[va, va+len)` — called on a guest `munmap` of a high-VA alias (the only point
/// the backing is actually freed), BEFORE the stage-1 invalidate, so a stale
/// `host_addr` is never resolved after the OwnedHostMapping unmaps it. A thread
/// exit LEAKS the backing (`impl Drop for HvfVmState` `mem::forget`s
/// `self.mappings`), so no unregister is needed there — and critically MUST not
/// `munmap` it, since the buffer is shared with sibling threads + this registry.
/// Keyed on the VA `start` because `munmap` supplies a VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unregister_alias_entries(
    registry: &mut AliasRegistry,
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> std::collections::BTreeSet<(u64, u64)> {
    if len == 0 {
        return std::collections::BTreeSet::new();
    }
    let Some(end) = va.checked_add(len as u64) else {
        return std::collections::BTreeSet::new();
    };
    if end <= va {
        return std::collections::BTreeSet::new();
    }
    let mut overlapping = Vec::new();
    for &(seq, alias) in registry.va_window_rows(va, end) {
        if alias_matches_process_scope(alias.ownership_scope, mm_root_slot, container_root)
            && alias.start.saturating_add(alias.size as u64) > va
        {
            overlapping.push((seq, alias));
        }
    }
    if overlapping.is_empty() {
        return std::collections::BTreeSet::new();
    }

    let mut candidates = std::collections::BTreeSet::new();
    let mut touched_scopes = std::collections::BTreeSet::new();
    for (_, entry) in &overlapping {
        candidates.insert((entry.physical_ipa, entry.physical_size as u64));
        touched_scopes.insert(entry.ownership_scope);
    }

    for scope in touched_scopes {
        let mut mutations = Vec::new();
        let mut removed_count = 0usize;
        let mut inserted_count = 0usize;
        let mut touched_keys: std::collections::BTreeSet<(u64, u64)> =
            std::collections::BTreeSet::new();
        {
            let Some(rows) = registry.by_scope.get_mut(&scope) else {
                continue;
            };
            // The rows this unmap splits are already known: `overlapping` is
            // the bounded guest-VA window query above, and it is exact for
            // this predicate (`va_window_rows` visits, per live size class,
            // every start in `[va - (class radius - 1), end)`, and a row of
            // that class beginning below that bound ends at or before `va`).
            // Walking the scope's whole row vector to rediscover them made
            // every `munmap` cost O(rows in the mm); with the retired suffix
            // rebuild it was 60% of the carrier's user CPU on
            // `cpython-compile`
            // (docs/perf-results/2026-09-08-cpython-compile-per-fault-cost.md).
            //
            // A row's position is a binary search on its sequence, because a
            // scope bucket is ordered by sequence — `place_in_scope_bucket` is
            // what makes that true of the planner's staged registry as well as
            // this one, and `unmap_row_selection_agrees_between_the_scope_scan_
            // and_the_window_query` is the differential test that holds the two
            // selections equal. `claimed` keeps two rows that are equal in
            // every field from resolving to one position.
            let mut to_process = Vec::new();
            let mut claimed: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
            for &(seq, alias) in &overlapping {
                if alias.ownership_scope != scope {
                    continue;
                }
                if let Some(pos) =
                    AliasRegistry::bucket_position_in(rows, seq, &alias, Some(&claimed))
                {
                    claimed.insert(pos);
                    to_process.push((pos, seq, alias));
                }
            }
            if to_process.is_empty() {
                continue;
            }
            to_process.sort_unstable_by_key(|&(pos, _, _)| pos);
            to_process.reverse();

            for (pos, seq, entry) in to_process {
                let entry_end = entry.start.saturating_add(entry.size as u64);
                let mut fragments = Vec::with_capacity(2);
                if entry.start < va {
                    let head = AliasBacking {
                        size: usize::try_from(va - entry.start).unwrap_or_default(),
                        ..entry
                    };
                    fragments.push((seq, head));
                }
                if entry_end > end {
                    let delta = end.saturating_sub(entry.start);
                    let tail = AliasBacking {
                        start: end,
                        ipa: entry.ipa.saturating_add(delta),
                        host_addr: entry.host_addr.saturating_add(delta as usize),
                        size: usize::try_from(entry_end - end).unwrap_or_default(),
                        shared_key_offset: entry.shared_key_offset.saturating_add(delta),
                        ..entry
                    };
                    fragments.push((seq, tail));
                }
                removed_count = removed_count.saturating_add(1);
                inserted_count = inserted_count.saturating_add(fragments.len());
                match fragments.len() {
                    0 => {
                        rows.remove(pos);
                    }
                    1 => {
                        rows[pos] = fragments[0];
                    }
                    2 => {
                        rows[pos] = fragments[0];
                        rows.insert(pos + 1, fragments[1]);
                    }
                    _ => unreachable!(),
                }
                mutations.push((seq, entry, fragments));
            }
        }
        for (seq, entry, fragments) in mutations {
            // Every exact key this mutation can disturb: the row's own key, and
            // each fragment's. `refresh_exact_scope_suffix` used to answer this
            // by rebuilding the whole `rows[first_changed..]` suffix — the
            // `Vec::from_iter` that held 36% of the carrier's user CPU on
            // `cpython-compile` (docs/perf-results/2026-09-08-cpython-compile-per-fault-cost.md).
            touched_keys.insert((entry.start, entry.ipa));
            registry.index_remove(seq, entry);
            for (frag_seq, frag_entry) in fragments {
                touched_keys.insert((frag_entry.start, frag_entry.ipa));
                registry.index_insert(frag_seq, frag_entry);
            }
        }
        registry.rows = registry
            .rows
            .saturating_sub(removed_count)
            .saturating_add(inserted_count);
        registry.bump_revision();
        registry.promote_exact_first_keys(scope, &touched_keys);
        registry.drop_empty_scope(scope);
    }

    let scopes = AliasRegistry::process_visible_scopes(mm_root_slot, container_root);
    candidates.retain(|&(physical_ipa, physical_size)| {
        let retained = scopes.iter().any(|&scope| {
            registry
                .by_scope_physical_start
                .get(&(scope, physical_ipa))
                .is_some_and(|rows| {
                    note_alias_state_rows_scanned(rows.len());
                    rows.iter()
                        .any(|(_, alias)| alias.physical_size as u64 == physical_size)
                })
        });
        !retained
    });
    candidates
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retained_private_reuse_alias_fragment_in(
    custody: &CarrierVmCustody,
    registry: &AliasRegistry,
    va: u64,
    ipa: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> Option<AliasBacking> {
    if len == 0 {
        return None;
    }
    let end = va.checked_add(len as u64)?;
    let ipa_end = ipa.checked_add(len as u64)?;
    // An existing semantic fragment is already an exact lifetime owner. Do not
    // replace a wider entry with this one-page reuse observation.
    // The VA-window candidate query locates any overlapping candidate without
    // scanning unrelated processes or rows.
    let has_existing = registry
        .va_window_rows(va, va.saturating_add(1))
        .any(|(_, entry)| {
            alias_matches_process_scope(entry.ownership_scope, mm_root_slot, container_root)
                && va >= entry.start
                && end <= entry.start.saturating_add(entry.size as u64)
                && entry.ipa.checked_add(va.saturating_sub(entry.start)) == Some(ipa)
        });
    if has_existing {
        return None;
    }

    // Query `by_scope` for the process's owned scope, traversing rows newest-first.
    let owned_scope = AliasRegistry::owned_scope(mm_root_slot, container_root);
    let source = registry
        .scope_rows(owned_scope)
        .iter()
        .rev()
        .map(|(_, alias)| alias)
        .find(|entry| {
            entry.sharing == GuestMappingSharing::Private
                && ipa >= entry.physical_ipa
                && ipa_end
                    <= entry
                        .physical_ipa
                        .saturating_add(entry.physical_size as u64)
                && match global_frame_host_owner_identity_in(
                    custody,
                    entry.physical_ipa,
                    entry.physical_size as u64,
                ) {
                    Some((host_addr, generation)) => {
                        entry.owner_generation != 0
                            && host_addr == entry.physical_host_addr
                            && generation == entry.owner_generation
                    }
                    None => entry.owner_generation == 0,
                }
        })?;
    let physical_offset = usize::try_from(ipa.checked_sub(source.physical_ipa)?).ok()?;
    Some(AliasBacking {
        start: va,
        ipa,
        host_addr: source.physical_host_addr.checked_add(physical_offset)?,
        size: len,
        physical_ipa: source.physical_ipa,
        physical_host_addr: source.physical_host_addr,
        physical_size: source.physical_size,
        perms: source.perms,
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            mm_root_slot,
            container_root,
        ),
        inventory_backing: source.inventory_backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: source.owner_generation,
    })
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retained_private_reuse_alias_fragment(
    registry: &AliasRegistry,
    va: u64,
    ipa: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> Option<AliasBacking> {
    retained_private_reuse_alias_fragment_in(
        legacy_test_carrier_vm_custody(),
        registry,
        va,
        ipa,
        len,
        mm_root_slot,
        container_root,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retired_alias_disarm_spans(
    registry: &[AliasBacking],
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    retired_leases: &std::collections::BTreeSet<(u64, u64)>,
) -> Vec<CowArmedSpan> {
    let end = va.saturating_add(len as u64);
    registry
        .iter()
        .filter(|entry| {
            alias_matches_process_scope(entry.ownership_scope, mm_root_slot, container_root)
                && retired_leases.contains(&(entry.physical_ipa, entry.physical_size as u64))
        })
        .filter_map(|entry| {
            let start = entry.start.max(va);
            let entry_end = entry.start.saturating_add(entry.size as u64);
            let span_end = entry_end.min(end);
            (start < span_end).then(|| CowArmedSpan {
                va: start,
                len: usize::try_from(span_end - start).unwrap_or_default(),
                executable: false,
                kernel_only: false,
            })
        })
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unregister_alias(
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> std::collections::BTreeSet<(u64, u64)> {
    let replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let mut versions = alias_version_registry().lock();
    unregister_alias_in(
        &mut registry,
        &replay,
        &mut versions,
        va,
        len,
        mm_root_slot,
        container_root,
    )
}

/// Invalidate only keys whose effective first alias changed. Replay versions
/// for their physical owners must also be invalidated even though unmap does
/// not change replay rows; otherwise retiring an old receipt can resurrect an
/// alias removed or split here.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unregister_alias_in(
    registry: &mut AliasRegistry,
    replay: &std::collections::BTreeSet<ReplayMappingKey>,
    versions: &mut AliasVersionRegistry,
    va: u64,
    len: usize,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
) -> std::collections::BTreeSet<(u64, u64)> {
    let Some(end) = va.checked_add(len as u64).filter(|&end| end > va) else {
        return std::collections::BTreeSet::new();
    };
    let mut keys = std::collections::BTreeSet::new();
    for (_, entry) in registry.va_window_rows(va, end) {
        let entry_end = entry.start.saturating_add(entry.size as u64);
        if !alias_matches_process_scope(entry.ownership_scope, mm_root_slot, container_root)
            || entry_end <= va
        {
            continue;
        }
        keys.insert(alias_version_key(entry));
        if entry_end > end {
            keys.insert((
                end,
                entry.ipa.saturating_add(end.saturating_sub(entry.start)),
                entry.ownership_scope,
            ));
        }
    }
    // Snapshot suffix keys too: an existing row can collide with a fragment,
    // and duplicate keys retain historical first-row semantics.
    let before = keys
        .into_iter()
        .map(|key| (key, registry.find_by_key(key.0, key.1, key.2)))
        .collect::<Vec<_>>();
    let retired = unregister_alias_entries(registry, va, len, mm_root_slot, container_root);
    let mut physical_ipas = std::collections::BTreeSet::new();
    for (key, old) in before {
        let after = registry.find_by_key(key.0, key.1, key.2);
        if old == after {
            continue;
        }
        physical_ipas.extend(old.into_iter().chain(after).map(|alias| alias.physical_ipa));
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "alias epoch counter exhausted while unregistering alias: key=(0x{:x}, 0x{:x}, {:?})",
                key.0,
                key.1,
                key.2
            );
        });
        for id in reset_alias_chain(&mut versions.aliases, key, after) {
            versions.alias_version_owner.remove(&id);
        }
    }
    for physical_ipa in physical_ipas {
        bump_version_epoch(&mut versions.replay_epochs, physical_ipa).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "replay epoch counter exhausted while unregistering alias: physical_ipa=0x{physical_ipa:x}"
            );
        });
        let base = replay_rows_for_ipa(replay, physical_ipa);
        for id in reset_replay_chain(&mut versions.replays, physical_ipa, base) {
            versions.replay_version_owner.remove(&id);
        }
    }
    retired
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn clear_alias_registry() {
    mutate_external_alias_state(|_, registry| registry.clear());
}

/// Bounds lazy alias remaps per backing IPA, not per guest-run interval.
///
/// Go's pprof mapping test can touch many distinct MAP_SHARED file aliases
/// before issuing another syscall; a small global cap turns the ninth valid
/// alias into SIGSEGV. Repeated faults on the same backing still terminate.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
pub(crate) struct AliasRemapLimiter {
    pub(crate) attempts_by_ipa: std::collections::HashMap<u64, u32>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasRemapLimiter {
    pub(crate) const MAX_ATTEMPTS_PER_IPA: u32 = 8;

    pub(crate) fn allow(&mut self, ipa: u64) -> bool {
        let attempts = self.attempts_by_ipa.entry(ipa).or_default();
        if *attempts >= Self::MAX_ATTEMPTS_PER_IPA {
            return false;
        }
        *attempts += 1;
        true
    }
}

#[cfg(test)]
mod alias_differential_tests {
    use super::*;

    struct SimpleRng(u64);
    impl SimpleRng {
        fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0xdead_beef_cafe_babe
            } else {
                seed
            })
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn gen_range(&mut self, min: u64, max: u64) -> u64 {
            if min >= max {
                return min;
            }
            min + (self.next_u64() % (max - min))
        }
    }

    fn reference_newest_containing(
        index: &std::collections::BTreeMap<u64, Vec<(u64, AliasBacking)>>,
        widest: u64,
        probe: u64,
        mut matches: impl FnMut(&AliasBacking) -> bool,
    ) -> Option<AliasBacking> {
        index
            .range(probe.saturating_sub(widest)..=probe)
            .flat_map(|(_, rows)| rows)
            .filter(|(_, alias)| matches(alias))
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, alias)| *alias)
    }

    fn make_alias(va: u64, ipa: u64, size: usize, scope: AliasOwnershipScope) -> AliasBacking {
        AliasBacking {
            start: va,
            ipa,
            host_addr: 0x4000_0000 + (va as usize),
            size,
            physical_ipa: ipa,
            physical_host_addr: 0x4000_0000 + (ipa as usize),
            physical_size: size,
            perms: 3,
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 1,
        }
    }

    #[test]
    fn differential_newest_containing_matches_reference() {
        let mut rng = SimpleRng::new(0x1234_5678_9abc_def0);
        let scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };

        let widths: [usize; 16] = [
            1,
            16,
            64,
            512,
            4096,
            16384,
            65536,
            128 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            16 * 1024 * 1024,
            64 * 1024 * 1024,
            256 * 1024 * 1024,
            1024 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
            32 * 1024 * 1024 * 1024,
        ];

        let mut registry = AliasRegistry::default();
        let mut row_endpoints = Vec::new();
        let mut max_width = 0u64;

        for i in 0..300u64 {
            let width = widths[(rng.next_u64() as usize) % widths.len()];
            max_width = max_width.max(width as u64);
            let start = if i % 10 == 0 && !row_endpoints.is_empty() {
                row_endpoints[(rng.next_u64() as usize) % row_endpoints.len()]
            } else {
                rng.gen_range(0x1000_0000, 0x10_0000_0000)
            };
            let alias = make_alias(start, start, width, scope);
            registry.push(alias);
            row_endpoints.push(start);
            if let Some(end) = start.checked_add(width as u64) {
                row_endpoints.push(end);
            }
        }

        let mut probes = Vec::with_capacity(6000);
        for &pt in &row_endpoints {
            probes.push(pt.saturating_sub(1));
            probes.push(pt);
            probes.push(pt.saturating_add(1));
            probes.push(pt.saturating_add(4096));
        }
        while probes.len() < 5500 {
            probes.push(rng.gen_range(0, 0x18_0000_0000));
        }
        probes.push(0);
        probes.push(1);
        probes.push(u64::MAX - 1);
        probes.push(u64::MAX);

        for probe in probes {
            let contains_ipa = |alias: &AliasBacking| {
                probe >= alias.ipa && probe < alias.ipa.saturating_add(alias.size as u64)
            };
            let reference =
                reference_newest_containing(&registry.by_ipa_start, max_width, probe, contains_ipa);
            let actual = registry.newest_containing_ipa(probe, contains_ipa);
            assert_eq!(
                actual, reference,
                "differential query mismatch at probe 0x{probe:x}"
            );
        }
    }

    #[test]
    fn candidate_count_bounded_by_classes_and_matching_rows() {
        let scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        let mut registry = AliasRegistry::default();

        // One 32 GiB row
        let huge_start = 0x1000_0000u64;
        let huge_size = 32usize * 1024 * 1024 * 1024;
        registry.push(make_alias(huge_start, huge_start, huge_size, scope));

        // 4,096 small (4 KiB) rows starting inside the 32 GiB extent
        let small_base = 0x2000_0000u64;
        let small_size = 4096usize;
        for i in 0..4096u64 {
            let start = small_base + i * (small_size as u64);
            registry.push(make_alias(start, start, small_size, scope));
        }

        // A probe that hits a small row near the end of the small row cluster
        let target_small_idx = 4000u64;
        let probe = small_base + target_small_idx * (small_size as u64) + 64;

        let before = alias_state_rows_scanned();
        let contains_ipa = |alias: &AliasBacking| {
            probe >= alias.ipa && probe < alias.ipa.saturating_add(alias.size as u64)
        };
        let found = registry.newest_containing_ipa(probe, contains_ipa);
        assert!(found.is_some());
        let examined = alias_state_rows_scanned() - before;

        // The probe hits exactly 2 rows: the small row and the 32 GiB row.
        // There are 2 classes (4 KiB = class 12, 32 GiB = class 35).
        // Examined candidates must be <= (rows containing it + classes), which is <= 4,
        // and certainly not thousands.
        let rows_containing = 2u64;
        let classes = 2u64;
        assert!(
            examined <= rows_containing + classes,
            "examined {examined} candidates, expected <= {}",
            rows_containing + classes
        );
        assert!(
            examined < 100,
            "examined {examined} candidates, expected not thousands"
        );
    }
}
