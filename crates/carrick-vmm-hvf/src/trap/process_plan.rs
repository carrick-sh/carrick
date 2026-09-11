//! # Fork Process Spec Plan
//!
//! Construction of child stage-1 translation and mapping plan for process fork.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn thread_mapping_semantic_ipa_at(
    mapping: &ThreadMappingDesc,
    address: u64,
) -> Option<u64> {
    let offset = address.checked_sub(mapping.start)?;
    if offset >= mapping.size as u64 {
        return None;
    }
    mapping.ipa.checked_add(offset)
}

/// Fork-source mappings that own inherited inventory extents, indexed by the
/// translation they produce.
///
/// A mapping satisfies `thread_mapping_semantic_ipa_at(overlay, va) ==
/// Some(translated)` only if `overlay.ipa - overlay.start == translated - va`
/// and `va` lies inside it. The first half is independent of `va`, so it is an
/// index key; the second half stays an exact per-candidate check, so the
/// predicate is unchanged.
///
/// This exists because the previous shape asked the question by scanning EVERY
/// source mapping and, for each one, recomputing its inherited inventory
/// extents — a fresh `Vec` allocation and a full pass over the parent frame
/// inventory. Inside the per-mapping fork loop that is O(M^2 * I) for a
/// process with M mappings and an I-row inventory: measured 2026-08-30 at
/// 13.3% of carrier CPU in this function plus 8.6% in the O(1)
/// `thread_mapping_semantic_ipa_at` it calls, i.e. ~22% of a fork/exit storm
/// spent re-deriving facts that do not depend on the candidate at all. Fork is
/// the most horizontal path there is, so this cost compounds into every
/// workload that forks.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct ForkOverlayOwnerIndex {
    /// `(translation delta, mapping start) -> source mapping indexes`, for the
    /// mappings that own inherited inventory extents. The value is a list
    /// because two source mappings may legitimately share a start and a delta
    /// while differing in size; collapsing them to one index would let the
    /// surviving row be the candidate itself and silently answer "no owner".
    by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<usize>>,
    /// Largest mapping size present per delta, so a query walks back only as
    /// far as a mapping could possibly reach.
    widest_by_delta: std::collections::BTreeMap<u64, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkOverlayOwnerIndex {
    /// Build once per fork. Each mapping's inherited-extent status is computed
    /// exactly ONCE here rather than once per (candidate, overlay) pair.
    pub(crate) fn build(
        custody: &CarrierVmCustody,
        mappings: &[ThreadMappingDesc],
        inventory: &ForkInventoryByStage2,
    ) -> Self {
        note_hot_path_rows(HotPathScan::ForkMappings, mappings.len());
        let mut index = Self::default();
        for (position, overlay) in mappings.iter().enumerate() {
            if inherited_fork_inventory_extents_indexed(custody, overlay, inventory).is_empty() {
                continue;
            }
            let delta = overlay.ipa.wrapping_sub(overlay.start);
            index
                .by_delta_and_start
                .entry((delta, overlay.start))
                .or_default()
                .push(position);
            let widest = index.widest_by_delta.entry(delta).or_insert(0);
            *widest = (*widest).max(overlay.size as u64);
        }
        index
    }

    /// True when some OTHER source mapping that owns inherited inventory
    /// extents also translates `va` to `translated`.
    pub(crate) fn has_overlay_owner(
        &self,
        mappings: &[ThreadMappingDesc],
        candidate_index: usize,
        va: u64,
        translated: u64,
    ) -> bool {
        let delta = translated.wrapping_sub(va);
        let Some(&widest) = self.widest_by_delta.get(&delta) else {
            return false;
        };
        // Only a mapping starting in `[va - widest, va]` can contain `va`, so
        // this is a bounded range walk rather than a pass over the bucket. The
        // delta alone is NOT selective enough: a process whose mappings sit at
        // a constant ipa-to-va offset puts every one of them in one bucket,
        // which is the common case and would restore the linear scan.
        let lower = va.saturating_sub(widest);
        let mut visited = 0usize;
        let mut found = false;
        'search: for (&(_, start), positions) in
            self.by_delta_and_start.range((delta, lower)..=(delta, va))
        {
            debug_assert!(start <= va);
            for &position in positions {
                visited += 1;
                if position != candidate_index
                    && thread_mapping_semantic_ipa_at(&mappings[position], va) == Some(translated)
                {
                    found = true;
                    break 'search;
                }
            }
        }
        note_hot_path_rows(HotPathScan::ForkMappings, visited);
        found
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn inherited_fork_inventory_extents(
    mapping: &ThreadMappingDesc,
    inventory: &std::collections::BTreeMap<(u64, u64), InventoryExtent>,
) -> Vec<((u64, u64), InventoryExtent)> {
    inherited_fork_inventory_extents_indexed(
        legacy_test_carrier_vm_custody(),
        mapping,
        &index_fork_inventory_by_stage2(inventory),
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn fork_translation_has_overlay_owner(
    index: &ForkTranslationOverlayIndex,
    mappings: &[ProcessMappingDesc],
    candidate_index: usize,
    va: u64,
    translated: u64,
) -> bool {
    index.has_overlay_owner(mappings, candidate_index, va, translated)
}

/// Overlay owners of one forking process's translations, indexed by the
/// translation they produce.
///
/// A row can satisfy the overlay predicate only if its `ipa - start` equals
/// `translated - va` and it starts within its own length of `va`, so those two
/// facts are the index and the exact containment test stays a per-candidate
/// check. Same construction as [`ForkOverlayOwnerIndex`], and for the same
/// reason: the previous shape asked the question by scanning every source
/// mapping AND the whole carrier-global alias registry, once per mapping, so a
/// process with M mappings in a carrier holding R alias rows paid O(M * (M + R))
/// per fork. Measured 20.1% of carrier CPU under a fork/exit storm even after
/// the call was made lazy.
///
/// The alias half admits exactly the scopes the original predicate did: the
/// scopes `alias_matches_process_scope` accepts, plus this container's root
/// regardless of `mm_root_slot`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct ForkTranslationOverlayIndex {
    mappings_by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<usize>>,
    mappings_widest_by_delta: std::collections::BTreeMap<u64, u64>,
    aliases_by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<AliasBacking>>,
    aliases_widest_by_delta: std::collections::BTreeMap<u64, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkTranslationOverlayIndex {
    pub(super) fn build(
        mappings: &[ProcessMappingDesc],
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Self {
        let mut index = Self::default();
        for (position, overlay) in mappings.iter().enumerate() {
            let delta = overlay.ipa.wrapping_sub(overlay.start);
            index
                .mappings_by_delta_and_start
                .entry((delta, overlay.start))
                .or_default()
                .push(position);
            let widest = index.mappings_widest_by_delta.entry(delta).or_insert(0);
            *widest = (*widest).max(overlay.end.saturating_sub(overlay.start));
        }
        let registry = alias_registry().lock();
        let mut scopes: Vec<AliasOwnershipScope> =
            AliasRegistry::process_visible_scopes(mm_root_slot, container_root).to_vec();
        let container_scope = AliasOwnershipScope::ContainerRoot(container_root);
        if !scopes.contains(&container_scope) {
            scopes.push(container_scope);
        }
        for scope in scopes {
            let rows = registry.scope_rows(scope);
            note_alias_state_rows_scanned(rows.len());
            for (_, alias) in rows {
                let delta = alias.ipa.wrapping_sub(alias.start);
                index
                    .aliases_by_delta_and_start
                    .entry((delta, alias.start))
                    .or_default()
                    .push(*alias);
                let widest = index.aliases_widest_by_delta.entry(delta).or_insert(0);
                *widest = (*widest).max(alias.size as u64);
            }
        }
        index
    }

    pub(super) fn has_overlay_owner(
        &self,
        mappings: &[ProcessMappingDesc],
        candidate_index: usize,
        va: u64,
        translated: u64,
    ) -> bool {
        let delta = translated.wrapping_sub(va);
        if let Some(&widest) = self.mappings_widest_by_delta.get(&delta) {
            let lower = va.saturating_sub(widest);
            for (_, positions) in self
                .mappings_by_delta_and_start
                .range((delta, lower)..=(delta, va))
            {
                for &position in positions {
                    let overlay = &mappings[position];
                    if position != candidate_index
                        && va >= overlay.start
                        && va < overlay.end
                        && overlay
                            .ipa
                            .checked_add(va - overlay.start)
                            .is_some_and(|ipa| ipa == translated)
                    {
                        return true;
                    }
                }
            }
        }
        let Some(&widest) = self.aliases_widest_by_delta.get(&delta) else {
            return false;
        };
        let lower = va.saturating_sub(widest);
        self.aliases_by_delta_and_start
            .range((delta, lower)..=(delta, va))
            .flat_map(|(_, aliases)| aliases)
            .any(|alias| {
                va >= alias.start
                    && va < alias.start.saturating_add(alias.size as u64)
                    && alias.ipa.checked_add(va.saturating_sub(alias.start)) == Some(translated)
            })
    }
}

/// The boot-time shared aperture is a physical stage-2 owner, not one dense
/// guest-visible mapping. Linux `MAP_SHARED` sub-allocations install sparse
/// stage-1 leaves anywhere inside it, so the aperture's first VA may be absent
/// even while later leaves are live. Fork copies the parent's stage-1 graph
/// separately; do not treat the missing *base* leaf as a corrupt child graph.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_mapping_requires_base_translation(
    start: u64,
    size: usize,
    is_dynamic_alias: bool,
) -> bool {
    is_dynamic_alias
        || start != crate::memory::LINUX_SHARED_FILE_BASE
        || size != crate::memory::LINUX_SHARED_FILE_SIZE as usize
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_process_plan(
        &self,
        request: carrick_hal::ProcessForkRequest,
        page_tables: &mut crate::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
        mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
        syscall_transport: HvfSyscallTransport,
        carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
    ) -> Result<ProcessSpecPlan, TrapError> {
        use carrick_observability::probes::{
            HvpatchForkProcessSpecStage, HvpatchForkProcessSpecStagePhase,
        };

        let child_tid_raw = request.child_tid.raw();
        let forking_tid_raw = request.forking_tid.raw();
        let emit_stage = move |phase: HvpatchForkProcessSpecStagePhase,
                               started: std::time::Instant,
                               units: u64| {
            let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            crate::probes::hvpatch_fork_process_spec_stage(HvpatchForkProcessSpecStage::new(
                phase,
                child_tid_raw,
                forking_tid_raw,
                elapsed_ns,
                units,
            ));
        };

        crate::probes::hvpatch_fork_snapshot_begin(child_tid_raw, forking_tid_raw);
        let stage_started = std::time::Instant::now();
        const STAGE2_PAGE: u64 = 16 * 1024;
        let root_slot_end = request
            .root_slot_base
            .checked_add(request.root_slot_size)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child stage-1 root slot overflow".to_owned())
            })?;
        let mut cursor = request.root_slot_base;
        let (alias_revision_begin, aliases) = {
            let registry = alias_registry().lock();
            (
                registry.revision(),
                registry.process_visible_ordered(self.mm_root_slot, self.container_root),
            )
        };
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ForkSnapshotBegin,
            &carrier_foreign_mm_transport.custody,
            self.cow_identity,
            0,
            alias_revision_begin,
        );
        let alias_index = process_alias_index(&aliases, self.mm_root_slot, self.container_root);
        let mut seen_dynamic_aliases = std::collections::HashSet::new();
        let mut source_mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .filter_map(|mapping| {
                if !mapping.is_dynamic_alias {
                    return Some(ThreadMappingDesc::from_region(mapping));
                }
                let key = (
                    mapping.start,
                    mapping.ipa,
                    mapping.host_addr as usize,
                    semantic_extent_size(mapping.start, mapping.end),
                    mapping.owner_generation,
                );
                if !seen_dynamic_aliases.insert(key) {
                    return None;
                }
                let alias = alias_index.get(&key).copied()?;
                let source = ThreadMappingDesc::from_region(mapping);
                ThreadMappingDesc::from_alias_with_structural_owner(
                    alias,
                    std::slice::from_ref(&source),
                )
            })
            .collect();
        // Fork-union audit: `CARRICK_FORK_DEBUG_VA=<hex guest VA>` reports every
        // LOCAL mapping row covering that VA and whether the alias index kept
        // it. The `[FORKDBG] mapping` block further down only prints rows that
        // already SURVIVED this filter, so a row dropped here — the child then
        // inherits a writable stage-1 leaf onto the parent's frame with nothing
        // arming COW — was previously invisible.
        if let Some(debug_va) = fork_debug_va() {
            let window_lo = debug_va.saturating_sub(0x20_0000);
            let window_hi = debug_va.saturating_add(0x20_0000);
            for alias in aliases.iter().filter(|alias| {
                alias.start < window_hi && alias.start.saturating_add(alias.size as u64) > window_lo
            }) {
                eprintln!(
                    "[UNIONDBG pid={:?}] alias [{:#x}+{:#x}) ipa={:#x} host={:#x} \
                     phys=({:#x}+{:#x}) scope={:?} in_scope={} sharing={:?} writable={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    alias.start,
                    alias.size,
                    alias.ipa,
                    alias.host_addr,
                    alias.physical_ipa,
                    alias.physical_size,
                    alias.ownership_scope,
                    alias_matches_process_scope(
                        alias.ownership_scope,
                        self.mm_root_slot,
                        self.container_root,
                    ),
                    alias.sharing,
                    alias.guest_writable,
                    alias.start <= debug_va
                        && debug_va < alias.start.saturating_add(alias.size as u64),
                );
            }
            for mapping in self
                .mappings
                .iter()
                .filter(|mapping| mapping.start < window_hi && mapping.end > window_lo)
            {
                let kept = mapping_is_current_for_process_fork_indexed(mapping, &alias_index);
                eprintln!(
                    "[UNIONDBG pid={:?}] local row [{:#x},{:#x}) ipa={:#x} host={:p} \
                     size={:#x} sem={:#x} dyn={} sharing={:?} guest_writable={} kept={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    mapping.start,
                    mapping.end,
                    mapping.ipa,
                    mapping.host_addr,
                    mapping.size,
                    semantic_extent_size(mapping.start, mapping.end),
                    mapping.is_dynamic_alias,
                    mapping.sharing,
                    mapping.guest_writable,
                    kept,
                    mapping.start <= debug_va && debug_va < mapping.end,
                );
            }
            let armed = cow_ranges;
            let covering: Vec<_> = armed
                .iter()
                .filter(|range| {
                    range.va <= debug_va && debug_va < range.va.saturating_add(range.len as u64)
                })
                .map(|range| (range.va, range.len))
                .collect();
            eprintln!(
                "[UNIONDBG pid={:?}] fork_cow_ranges covering {debug_va:#x}: {covering:x?} \
                 (total {} ranges)",
                self.cow_identity.map(|identity| identity.linux_pid),
                armed.len(),
            );
        }
        let local_regions = source_mappings.len() as u64;
        // A structural boot mapping can physically contain a narrower semantic
        // alias at the same IPA (the private-overlay aperture is the canonical
        // case). Only an exact current local descriptor suppresses a registry
        // row; keying every local descriptor by IPA hid MAP_FIXED private
        // ownership from fork even though stage-1 already selected it.
        let local_aliases: std::collections::HashSet<ProcessAliasKey> = source_mappings
            .iter()
            .map(thread_mapping_process_alias_key)
            .collect();
        let missing = missing_process_aliases(
            &local_aliases,
            &aliases,
            self.mm_root_slot,
            self.container_root,
        );
        let candidate_regions = missing.len() as u64;
        let mut added_regions = 0_u64;
        let mut added_bytes = 0_u64;
        let mut private_added_regions = 0_u64;
        let mut shared_added_regions = 0_u64;
        let mut largest_added_bytes = 0_u64;
        for alias in missing {
            // The registry is the authoritative live-alias inventory. Scope by
            // mm root-slot scope above and require its retained host owner to be live, but
            // do not require a valid stage-1 leaf: a live PROT_NONE alias is
            // intentionally invalid in stage-1 and still must survive fork.
            if alias_backing_is_live(alias.host_addr)
                && let Some(mapping) =
                    ThreadMappingDesc::from_alias_with_structural_owner(alias, &source_mappings)
            {
                added_regions = added_regions.saturating_add(1);
                added_bytes = added_bytes.saturating_add(mapping.size as u64);
                largest_added_bytes = largest_added_bytes.max(mapping.size as u64);
                if mapping.sharing.shares_across_fork() {
                    shared_added_regions = shared_added_regions.saturating_add(1);
                } else {
                    private_added_regions = private_added_regions.saturating_add(1);
                }
                source_mappings.push(mapping);
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::AliasUnion,
            stage_started,
            source_mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        let mut mappings = Vec::with_capacity(source_mappings.len());
        let parent_inventory = self.frame_inventory.lock().extents.clone();
        let mut inventory_mappings = Vec::with_capacity(parent_inventory.len());
        let mut inherited_inventory_ids = std::collections::BTreeSet::new();

        // Put the stage-1 backing at the root slot promised by TTBR. Guest
        // frames retain their stable global IPAs and never enter this slot.
        let mut order: Vec<usize> = (0..source_mappings.len()).collect();
        order.sort_by_key(|&index| {
            u8::from(source_mappings[index].start != crate::memory::LINUX_PAGE_TABLES_BASE)
        });
        // Built once for the whole fork; the per-mapping loop below only
        // queries it. See `ForkOverlayOwnerIndex`.
        // Grouped once for the whole fork and shared by the overlay index and
        // the per-mapping inheritance test below.
        let parent_inventory_by_stage2 = index_fork_inventory_by_stage2(&parent_inventory);
        let overlay_owner_index = ForkOverlayOwnerIndex::build(
            &carrier_foreign_mm_transport.custody,
            &source_mappings,
            &parent_inventory_by_stage2,
        );
        let projection_ranges = std::sync::Arc::clone(request.projection_plan());
        let parent_extension_bases = self
            .page_tables_authority()
            .with_manager(|pt| pt.extension_arena_bases())
            .unwrap_or_default();
        for index in order {
            let mapping = &source_mappings[index];
            if parent_extension_bases.contains(&mapping.start) {
                // Parent extension page-table arenas are Carrick stage-1 backing, not guest VMAs;
                // child extension arenas are allocated and installed into stage-2 below.
                continue;
            }
            let (disposition, wiped_subranges) = match projected_fork_mapping_disposition(
                mapping,
                request.shares_mm(),
                &projection_ranges,
            ) {
                // `MADV_DONTFORK`: the child gets no mapping, no stage-1 leaf
                // and no inventory row here, which is what makes its `mincore`
                // answer ENOMEM the way Linux's does.
                ForkMappingPlan::Omit => continue,
                ForkMappingPlan::Map { disposition, wiped } => (disposition, wiped),
                ForkMappingPlan::PartialOmit => {
                    return Err(TrapError::Hypervisor(format!(
                        "hvpatch fork: MADV_DONTFORK covers only part of the physical mapping \
                         at VA 0x{:x}..0x{:x}; a hole inside one mapping is not representable, \
                         and inheriting it would hand the child memory the guest excluded",
                        mapping.start, mapping.end,
                    )));
                }
            };
            if matches!(
                disposition,
                ForkMappingDisposition::SharedFrameWritable
                    | ForkMappingDisposition::SharedFrameReadOnly
            ) {
                let inherited = inherited_fork_inventory_extents_indexed(
                    &carrier_foreign_mm_transport.custody,
                    mapping,
                    &parent_inventory_by_stage2,
                );
                // Fork lineage debug: CARRICK_FORK_DEBUG_VA=<hex guest VA>
                // prints, for the mapping covering that VA, every inherited
                // extent and — crucially — a mapping DROPPED for having none.
                // Added while hunting a deterministic zeroed 16 KiB granule in
                // a forkserver worker; the drop below is silent by design and
                // was otherwise unobservable.
                if let Some(debug_va) = fork_debug_va()
                    && mapping.start <= debug_va
                    && debug_va < mapping.end
                {
                    eprintln!(
                        "[FORKDBG] mapping [{:#x},{:#x}) ipa={:#x} phys_ipa={:#x} size={:#x} \
                         sharing={:?} dyn={} extents={} phys_host={:p}",
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.physical_ipa,
                        mapping.size,
                        mapping.sharing,
                        mapping.is_dynamic_alias,
                        inherited.len(),
                        mapping.physical_host_addr,
                    );
                    for ((gpa, length), extent) in &inherited {
                        eprintln!(
                            "[FORKDBG]   extent gpa={gpa:#x}+{length:#x} mapping={:?} frame={:?} \
                             backing={:?} lease=({:#x},{:#x})",
                            extent.mapping,
                            extent.frame,
                            extent.backing,
                            extent.stage2_base,
                            extent.stage2_length,
                        );
                    }
                    if inherited.is_empty() {
                        eprintln!(
                            "[FORKDBG]   DROPPED: no inventory extents; child will have NO backing here"
                        );
                    }
                    // Peek the PARENT frame's bytes for the debug granule: if
                    // they are already zero here, the parent reads its data
                    // through some OTHER backing than the frame the child will
                    // inherit — the divergence predates the fork.
                    let frame_offset =
                        (debug_va - mapping.start) + (mapping.ipa - mapping.physical_ipa);
                    let peek = mapping
                        .physical_host_addr
                        .wrapping_add(frame_offset as usize);
                    // SAFETY: debug-only read inside the mapping's live host
                    // backing, bounds-checked against physical_size just below.
                    if (frame_offset as usize) + 16 <= mapping.physical_size {
                        let bytes = unsafe { std::slice::from_raw_parts(peek.cast_const(), 16) };
                        eprintln!(
                            "[FORKDBG]   parent frame bytes @host+{frame_offset:#x}: {bytes:02x?}"
                        );
                    }
                    // The decisive comparison: where does the PARENT's live
                    // stage-1 actually point for this VA, versus where the
                    // inventory says the frame is? A mismatch proves the
                    // divergence the child will inherit.
                    let expected_ipa = mapping.physical_ipa + frame_offset;
                    let walk = self
                        .page_tables_authority()
                        .with_manager(|manager| manager.debug_walk(debug_va));
                    if let Some(w) = walk {
                        let leaf_pa = w[3] & 0x0000_FFFF_FFFF_F000;
                        eprintln!(
                            "[FORKDBG]   parent stage-1 leaf for {debug_va:#x}: {:#x} -> pa {leaf_pa:#x} \
                             (inventory expects {expected_ipa:#x}) {}",
                            w[3],
                            if leaf_pa == expected_ipa & !0xfff {
                                "AGREES"
                            } else {
                                "DIVERGED"
                            },
                        );
                    }
                }
                // A coarse per-vCPU host-owner row may outlive its exact
                // per-mm mapping coverage after every compound in that stage-2
                // lease was repointed. It is no longer a fork source.
                let Some((_, parent_extent)) = inherited.first().copied() else {
                    let live_translation = page_tables
                        .translate(mapping.start)
                        .or_else(|| page_tables.translate_retained_output(mapping.start));
                    if let Some(translated) = live_translation {
                        let physical_ipa = align_down(translated, CowArmedRanges::COMPOUND_SIZE);
                        let owner = global_frame_host_owner_identity_in(
                            &carrier_foreign_mm_transport.custody,
                            physical_ipa,
                            CowArmedRanges::COMPOUND_SIZE,
                        );
                        record_cow_diagnostic_event(CowDiagnosticEvent::Lifecycle {
                            kind: CowDiagnosticLifecycleKind::ForkOmitted,
                            site: CowDiagnosticLifecycleSite::ForkPlan,
                            custody: carrier_foreign_mm_transport.custody.as_ref()
                                as *const CarrierVmCustody
                                as usize,
                            linux_pid: self.cow_identity.map_or(0, |identity| identity.linux_pid),
                            mm: self.cow_identity.map_or(0, |identity| identity.mm),
                            mm_root_slot_base: self.mm_root_slot.map_or(0, |slot| slot.0),
                            semantic_va: mapping.start,
                            semantic_length: mapping.size as u64,
                            logical_gpa: mapping.physical_ipa,
                            logical_length: mapping.physical_size as u64,
                            physical_ipa,
                            physical_length: CowArmedRanges::COMPOUND_SIZE,
                            owner_host_addr: owner.map_or(0, |identity| identity.0),
                            owner_generation: owner.map_or(0, |identity| identity.1),
                            frame: 0,
                            mapping: 0,
                        });
                    }
                    let candidate_translation =
                        thread_mapping_semantic_ipa_at(mapping, mapping.start);
                    let authenticated_overlay = live_translation.is_some_and(|translated| {
                        overlay_owner_index.has_overlay_owner(
                            &source_mappings,
                            index,
                            mapping.start,
                            translated,
                        )
                    });
                    let candidate_matches_live = live_translation == candidate_translation;
                    if fork_mapping_requires_base_translation(
                        mapping.start,
                        mapping.size,
                        mapping.is_dynamic_alias,
                    ) && live_translation.is_some()
                        && (candidate_matches_live || !authenticated_overlay)
                    {
                        if let Some(translated) = live_translation {
                            self.report_physical_cow_source_refusal(
                                &carrier_foreign_mm_transport.custody,
                                mapping.start,
                                translated,
                            );
                        }
                        let alias_revision_refusal = alias_registry().lock().revision();
                        record_alias_revision(
                            CowDiagnosticAliasRevisionSite::ForkSnapshotEnd,
                            &carrier_foreign_mm_transport.custody,
                            self.cow_identity,
                            live_translation
                                .map(|ipa| align_down(ipa, CowArmedRanges::COMPOUND_SIZE))
                                .unwrap_or(0),
                            alias_revision_refusal,
                        );
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch live fork mapping VA 0x{:x} IPA 0x{:x} has no authenticated inherited inventory extent; live_translation={live_translation:#x?} candidate_translation={candidate_translation:#x?} candidate_matches_live={candidate_matches_live} authenticated_overlay={authenticated_overlay} alias_revision_begin={alias_revision_begin} alias_revision_refusal={alias_revision_refusal}",
                            mapping.start, mapping.physical_ipa,
                        )));
                    }
                    continue;
                };
                let raw = u64::from(mapping.perms);
                let fork_frame_receipt_kind =
                    fork_frame_receipt_kind(disposition, mapping.start, mapping.size);
                for ((gpa, length), extent) in &inherited {
                    let selected = inherited_inventory_ids.insert(extent.mapping);
                    record_cow_inventory_lifecycle(
                        if selected {
                            CowDiagnosticLifecycleKind::ForkSelected
                        } else {
                            CowDiagnosticLifecycleKind::ForkDeduplicated
                        },
                        CowDiagnosticLifecycleSite::ForkPlan,
                        &carrier_foreign_mm_transport.custody,
                        self.cow_identity,
                        self.mm_root_slot,
                        mapping.start,
                        mapping.size as u64,
                        (*gpa, *length),
                        *extent,
                    );
                    if selected {
                        inventory_mappings.push(ProcessInventoryDesc {
                            gpa: *gpa,
                            length: *length,
                            permissions: carrick_hal::MemPerms {
                                read: raw & 1 != 0,
                                write: raw & 2 != 0,
                                exec: raw & 4 != 0,
                            },
                            inherited_frame: Some(extent.frame),
                            inherited_mapping: Some(extent.mapping),
                            backing: extent.backing,
                            stage2_lease: (extent.stage2_base, extent.stage2_length),
                            stage2_owner: extent.stage2_owner,
                            fork_frame_receipt_kind,
                        });
                    }
                }
                mappings.push(ProcessMappingDesc {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    end: mapping.end,
                    host: ProcessMappingHost::Borrowed {
                        pointer: mapping.physical_host_addr,
                        structural_owner: mapping.structural_owner.clone(),
                    },
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr,
                    physical_size: mapping.physical_size,
                    inventory_backing: parent_extent.backing,
                    perms: mapping.perms,
                    is_dynamic_alias: mapping.is_dynamic_alias,
                    sharing: mapping.sharing,
                    guest_writable: mapping.guest_writable,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    inherited_frame: Some(parent_extent.frame),
                    stage2_lease: None,
                    owner_generation: mapping.owner_generation,
                });
                continue;
            }

            const TWO_MIB: u64 = 2 * 1024 * 1024;
            let (physical_ipa, stage2_lease) = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    let packing_alignment = if mapping.start.is_multiple_of(TWO_MIB)
                        && (mapping.physical_size as u64) >= TWO_MIB
                    {
                        TWO_MIB
                    } else {
                        STAGE2_PAGE
                    };
                    cursor = align_up(cursor, packing_alignment)?;
                    let physical_ipa = cursor;
                    cursor = cursor
                        .checked_add(mapping.physical_size as u64)
                        .ok_or_else(|| {
                            TrapError::Hypervisor(
                                "hvpatch child page-table root overflow".to_owned(),
                            )
                        })?;
                    if cursor > root_slot_end {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child page tables need more than {}-byte root slot",
                            request.root_slot_size
                        )));
                    }
                    (
                        physical_ipa,
                        Some(GlobalFrameStage2Lease::fixed(
                            physical_ipa,
                            mapping.physical_size as u64,
                        )),
                    )
                }
                ForkMappingDisposition::IndependentKernelState
                | ForkMappingDisposition::IndependentGuestZeroed => {
                    let lease = GlobalFrameStage2Lease::reserve(
                        mapping.physical_size as u64,
                        CowArmedRanges::COMPOUND_SIZE,
                    )?;
                    let physical_ipa = lease.base;
                    (physical_ipa, Some(lease))
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            // Per-mm page tables and EL1 control state are the only fresh fork
            // frames.  Both are Carrick kernel state, not the guest-private
            // mappings governed by permission-fault COW.
            let host_kind = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                }
                ForkMappingDisposition::IndependentKernelState => {
                    crate::host_mapping::HostMappingKind::PerMmKernelState
                }
                ForkMappingDisposition::IndependentGuestZeroed => {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            let host = if disposition == ForkMappingDisposition::IndependentPageTables
                && mapping.physical_size == crate::frame_pool::ROOT_SLOT_SIZE
            {
                if let Some(pool) = carrier_foreign_mm_transport.custody.root_slot_pool() {
                    if let Some(handle) = pool.allocate_slot_at(physical_ipa) {
                        ProcessMappingHost::PooledRootSlot { handle }
                    } else {
                        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                            mapping.physical_size,
                            host_kind,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "allocate HVPatch child per-mm kernel backing: {error}"
                            ))
                        })?;
                        ProcessMappingHost::Owned(owned)
                    }
                } else {
                    let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        mapping.physical_size,
                        host_kind,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "allocate HVPatch child per-mm kernel backing: {error}"
                        ))
                    })?;
                    ProcessMappingHost::Owned(owned)
                }
            } else {
                let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    mapping.physical_size,
                    host_kind,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "allocate HVPatch child per-mm kernel backing: {error}"
                    ))
                })?;
                ProcessMappingHost::Owned(owned)
            };
            if disposition == ForkMappingDisposition::IndependentGuestZeroed {
                // Seed with the parent's frame, THEN zero the wiped window.
                // `physical_size` can exceed the semantic span, and the extra
                // bytes belong to other aliases of the same frame -- copying
                // first is what keeps them intact while `MADV_WIPEONFORK`
                // still gives the child zeroes exactly where it asked.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mapping.physical_host_addr,
                        host.ptr(),
                        mapping.physical_size,
                    );
                }
                let window = mapping
                    .ipa
                    .checked_sub(mapping.physical_ipa)
                    .ok_or_else(|| {
                        TrapError::Hypervisor(format!(
                            "HVPatch wiped alias IPA 0x{:x} precedes physical IPA 0x{:x}",
                            mapping.ipa, mapping.physical_ipa
                        ))
                    })?;
                for (offset, len) in &wiped_subranges {
                    let frame_offset = window.checked_add(*offset).and_then(|start| {
                        usize::try_from(start).ok().filter(|start| {
                            usize::try_from(*len)
                                .ok()
                                .and_then(|len| start.checked_add(len))
                                .is_some_and(|end| end <= mapping.physical_size)
                        })
                    });
                    let (Some(frame_offset), Ok(len)) = (frame_offset, usize::try_from(*len))
                    else {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch MADV_WIPEONFORK range +0x{offset:x}+0x{len:x} escapes the \
                             frame at VA 0x{:x} (physical size 0x{:x})",
                            mapping.start, mapping.physical_size
                        )));
                    };
                    // SAFETY: bounds-checked against `physical_size` above, and
                    // `host` is this child's freshly allocated frame.
                    unsafe {
                        std::ptr::write_bytes(host.ptr().add(frame_offset), 0, len);
                    }
                }
            }
            if disposition == ForkMappingDisposition::IndependentKernelState {
                // Preserve the fork boundary's coherent control-state image;
                // child identity/mailbox rebinding mutates this independent
                // frame before entry.  This is a bounded Carrick-kernel copy,
                // never a guest private whole-mapping snapshot.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mapping.physical_host_addr,
                        host.ptr(),
                        mapping.physical_size,
                    );
                }
            }
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias IPA 0x{:x} precedes physical IPA 0x{:x}",
                        mapping.ipa, mapping.physical_ipa
                    ))
                })?;
            let ipa = physical_ipa
                .checked_add(semantic_physical_offset)
                .ok_or_else(|| {
                    TrapError::Hypervisor("hvpatch child alias IPA overflow".to_owned())
                })?;
            let mapped = if (crate::memory::LINUX_KERNEL_REGION_BASE
                ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
                .contains(&mapping.start)
            {
                page_tables.map_kernel_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                    None,
                )
            } else {
                page_tables.map_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                    mapping.guest_writable,
                    None,
                )
            };
            mapped.map_err(|error| {
                // Name the pool's own numbers, exactly as `pt_edit_locked` does
                // for the syscall path. "OutOfTables" alone cannot distinguish a
                // legitimately huge address space from a pool the child clone was
                // refused permission to sweep.
                let (in_use, free, capacity, arenas) = page_tables.pool_stats();
                let (multi_vcpu, exclusive, reclaim_policy) = page_tables.coalesce_policy();
                let source = self.page_tables_authority().has_source();
                TrapError::Hypervisor(format!(
                    "map hvpatch child VA 0x{:x} to global/root-slot IPA 0x{ipa:x}: {error:?} \
                     (in_use={in_use} free={free} capacity={capacity} arenas={arenas} source={source} \
                     multi_vcpu={multi_vcpu} exclusive={exclusive} reclaim_pending={reclaim_policy})",
                    mapping.start
                ))
            })?;
            let physical_host_addr = host.ptr();
            let inventory_backing = HvfVmState::private_backing_identity();
            mappings.push(ProcessMappingDesc {
                start: mapping.start,
                ipa,
                end: mapping.end,
                host,
                size: mapping.size,
                physical_ipa,
                physical_host_addr,
                physical_size: mapping.physical_size,
                inventory_backing,
                perms: mapping.perms,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: GuestMappingSharing::Private,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                inherited_frame: None,
                stage2_lease,
                owner_generation: 0,
            });
            inventory_mappings.push(ProcessInventoryDesc {
                gpa: physical_ipa,
                length: mapping.physical_size as u64,
                permissions: {
                    let raw = u64::from(mapping.perms);
                    carrick_hal::MemPerms {
                        read: raw & 1 != 0,
                        write: raw & 2 != 0,
                        exec: raw & 4 != 0,
                    }
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: inventory_backing,
                stage2_lease: (physical_ipa, mapping.physical_size as u64),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: physical_host_addr as usize,
                    generation: 0,
                },
                fork_frame_receipt_kind: None,
            });
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::FramePlan,
            stage_started,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let mut child_pte_receipts = Vec::new();
        // Copied out so the memoizing closures below borrow neither `self`.
        let fork_mm_root_slot = self.mm_root_slot;
        let fork_container_root = self.container_root;
        // Built once for the whole fork; see `ForkTranslationOverlayIndex`.
        let overlay_index =
            ForkTranslationOverlayIndex::build(&mappings, fork_mm_root_slot, fork_container_root);
        for (index, mapping) in mappings.iter().enumerate() {
            let Some(translated) = page_tables
                .translate(mapping.start)
                .or_else(|| page_tables.translate_retained_output(mapping.start))
            else {
                // A live PROT_NONE reservation or post-munmap physical owner
                // intentionally has no valid stage-1 translation. It still
                // belongs in the child's physical/frame inventory and COW-arm
                // registry so a later mprotect/remap cannot expose the parent's
                // frame, but there is no live PTE to authenticate at fork.
                if self.protections.range_no_access(mapping.start, 1)
                    || mapping.is_dynamic_alias
                    || !fork_mapping_requires_base_translation(
                        mapping.start,
                        mapping.size,
                        mapping.is_dynamic_alias,
                    )
                {
                    continue;
                }
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 has no translation for VA 0x{:x}",
                    mapping.start
                )));
            };
            // A completed COW is an overlay on the original physical extent:
            // the old extent must remain in the child inventory for its
            // unaffected leaves, while the newer 16 KiB descriptor owns this
            // particular VA.  Validate against the last applicable overlay,
            // matching the reverse-order syscall-memory lookup authority.
            // Thread-local descriptor vectors and the process alias registry
            // can contribute COW overlays in different orders. The shared
            // stage-1 graph is authoritative, so authenticate its translation
            // against any other exact overlay owner rather than assuming the
            // winning overlay was appended after this descriptor.
            // Answer the overlay question at most ONCE per mapping, and only
            // when a cheaper condition has already failed.
            // `fork_translation_has_overlay_owner` walks every source mapping
            // AND the whole alias registry, so evaluating it eagerly for every
            // mapping made fork O(M * (M + R)) — 14.4% of carrier CPU under a
            // fork/exit storm. Both consumers below reach it only in the
            // uncommon case, so most mappings never pay for it at all.
            let mut overlay_matches: Option<bool> = None;
            if translated != mapping.ipa
                && !*overlay_matches.get_or_insert_with(|| {
                    fork_translation_has_overlay_owner(
                        &overlay_index,
                        &mappings,
                        index,
                        mapping.start,
                        translated,
                    )
                })
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 VA 0x{:x} resolves to IPA 0x{translated:x}, expected 0x{:x}",
                    mapping.start, mapping.ipa
                )));
            }
            if mapping.inherited_frame.is_some()
                && mapping.sharing == GuestMappingSharing::Private
                && !is_kernel_only_stage1_range(mapping.start, mapping.size)
                && !*overlay_matches.get_or_insert_with(|| {
                    fork_translation_has_overlay_owner(
                        &overlay_index,
                        &mappings,
                        index,
                        mapping.start,
                        translated,
                    )
                })
            {
                const VALID: u64 = 1;
                const NON_GLOBAL: u64 = 1 << 11;
                const AP_MASK: u64 = 0b11 << 6;
                const AP_USER_RW: u64 = 0b01 << 6;
                const AP_USER_RO: u64 = 0b11 << 6;
                let leaf = carrick_mem::page_table::terminal_descriptor(
                    page_tables.debug_walk(mapping.start),
                );
                if leaf & VALID != 0 {
                    let expected_ap = if request.shares_mm() {
                        // The descriptor can cover mixed ELF permissions; a
                        // shared-mm child keeps the exact cloned leaf rather
                        // than deriving AP from the coarse physical owner.
                        leaf & AP_MASK
                    } else if mapping.guest_writable && mapping.sharing.shares_across_fork() {
                        AP_USER_RW
                    } else {
                        AP_USER_RO
                    };
                    // CLONE_VM deliberately preserves the parent's exact
                    // user translation, including its global attribute: both
                    // ASIDs name the same frame until the child exits or execs.
                    let expected_non_global = !request.shares_mm();
                    if leaf & AP_MASK != expected_ap
                        || (expected_non_global && leaf & NON_GLOBAL == 0)
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child inherited stage-1 AP mismatch at VA 0x{:x}: leaf=0x{leaf:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}",
                            mapping.start,
                        )));
                    }
                    child_pte_receipts.push((
                        mapping.start,
                        mapping.ipa,
                        expected_ap,
                        expected_non_global,
                    ));
                }
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::Validation,
            stage_started,
            mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        // Borrow the table image; do NOT clone it. The region is
        // `LINUX_PAGE_TABLES_SIZE` = 1.75 MiB, and this runs once per fork, so
        // the clone was 1.75 MiB of allocation plus memcpy on top of the copy
        // into the child's backing below — roughly 238 MiB of pointless copying
        // across the 68 forks of a cold `go build`.
        const TWO_MIB: usize = 2 * 1024 * 1024;
        let child_extension_bases = page_tables.extension_arena_bases();
        for base in &child_extension_bases {
            let (host, physical_host_addr) =
                if let Some(pool) = carrier_foreign_mm_transport.custody.root_slot_pool() {
                    if let Some(handle) = pool.allocate_slot_at(*base) {
                        let ptr = handle.as_mut_ptr();
                        (ProcessMappingHost::PooledRootSlot { handle }, ptr)
                    } else {
                        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                            TWO_MIB,
                            crate::host_mapping::HostMappingKind::PerMmKernelState,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "allocate HVPatch child extension page-table backing: {error}"
                            ))
                        })?;
                        let ptr = owned.as_ptr();
                        (ProcessMappingHost::Owned(owned), ptr)
                    }
                } else {
                    let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        TWO_MIB,
                        crate::host_mapping::HostMappingKind::PerMmKernelState,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "allocate HVPatch child extension page-table backing: {error}"
                        ))
                    })?;
                    let ptr = owned.as_ptr();
                    (ProcessMappingHost::Owned(owned), ptr)
                };
            let inventory_backing = HvfVmState::private_backing_identity();
            let stage2_lease = Some(GlobalFrameStage2Lease::fixed(*base, TWO_MIB as u64));
            mappings.push(ProcessMappingDesc {
                start: *base,
                ipa: *base,
                end: *base + TWO_MIB as u64,
                host,
                size: TWO_MIB,
                physical_ipa: *base,
                physical_host_addr,
                physical_size: TWO_MIB,
                inventory_backing,
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                shared_key_base: 0,
                shared_key_offset: 0,
                inherited_frame: None,
                stage2_lease,
                owner_generation: 0,
            });
        }

        let table = mappings
            .iter_mut()
            .find(|mapping| mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child page-table mapping absent".to_owned())
            })?;
        if table.ipa != request.root_slot_base {
            return Err(TrapError::Hypervisor(
                "hvpatch child page-table root-slot layout mismatch".to_owned(),
            ));
        }

        let page_table_resolver = |base: u64| -> Option<*mut u8> {
            mappings
                .iter()
                .find(|m| m.ipa == base)
                .map(|m| m.physical_host_addr)
        };
        unsafe { page_tables.restore_quiesced_snapshot_to_host(page_table_resolver) };
        let copied_bytes = page_tables.copied_bytes();
        for mapping in &mappings {
            if let ProcessMappingHost::PooledRootSlot { ref handle } = mapping.host {
                handle.record_populated_prefix(copied_bytes as usize);
            }
        }

        for (va, expected_ipa, expected_ap, expected_non_global) in child_pte_receipts {
            let shadow = page_tables.debug_walk(va);
            let live =
                unsafe { page_tables.debug_walk_host(page_table_resolver, va) }.map_err(|e| {
                    TrapError::Hypervisor(format!(
                        "child live stage-1 debug_walk_host failed: {e:?}"
                    ))
                })?;
            let live_leaf = carrick_mem::page_table::terminal_descriptor(live);
            if shadow != live
                // An unmodified CLONE_VM graph may retain an L1/L2 block: its
                // descriptor carries the block base, while `expected_ipa`
                // includes the VA's offset inside that block. `shadow == live`
                // plus the earlier software translation receipt authenticates
                // the exact address without falsely applying an L3 mask.
                || (!request.shares_mm()
                    && live_leaf & 0x0000_FFFF_FFFF_F000
                        != expected_ipa & 0x0000_FFFF_FFFF_F000)
                || live_leaf & (0b11 << 6) != expected_ap
                || (expected_non_global && live_leaf & (1 << 11) == 0)
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child live stage-1 receipt mismatch at VA 0x{va:x}: shadow={shadow:x?} live={live:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}"
                )));
            }
            crate::probes::pt_alias_receipt(va, live_leaf, expected_ipa, expected_ap, 1);
        }
        let table_bytes_len = page_tables.copied_bytes();
        emit_stage(
            HvpatchForkProcessSpecStagePhase::TablePublish,
            stage_started,
            table_bytes_len,
        );

        let alias_revision_end = alias_registry().lock().revision();
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ForkSnapshotEnd,
            &carrier_foreign_mm_transport.custody,
            self.cow_identity,
            0,
            alias_revision_end,
        );
        crate::probes::hvpatch_fork_snapshot_end(
            request.child_tid.raw(),
            local_regions,
            candidate_regions,
            added_regions,
            added_bytes,
        );
        crate::probes::hvpatch_fork_snapshot_shape(
            request.child_tid.raw(),
            private_added_regions,
            shared_added_regions,
            largest_added_bytes,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let protections = std::sync::Arc::new(MemoryProtections::from_snapshot(
            self.protections.snapshot_all(),
        ));
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendProtections,
            stage_started,
            0,
        );

        let stage_started = std::time::Instant::now();
        let frame_inventory = {
            let mut parent_inventory = self.frame_inventory.lock();
            let reservation = parent_inventory.process_reservation.take();
            let mut child =
                HvpatchFrameInventory::with_frames(std::sync::Arc::clone(&parent_inventory.frames));
            child.process_reservation = reservation;
            std::sync::Arc::new(parking_lot::Mutex::new(child))
        };
        let mut child_cow_armed = self.cow_armed.lock().clone();
        child_cow_armed.arm(cow_ranges);
        if let Some(debug_va) = fork_debug_va() {
            let covered = child_cow_armed
                .ranges
                .iter()
                .any(|range| debug_va >= range.va && debug_va < range.va + range.len as u64);
            eprintln!(
                "[ARMDBG child-build parent_pid={:?} parent_mm={:?} child_slot={:x} \
                 ranges={} watch_covered={covered}]",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                request.root_slot_base,
                child_cow_armed.ranges.len(),
            );
        }
        let plan = ProcessSpecPlan::new(
            mappings,
            inventory_mappings,
            protections,
            mailbox_slots,
            syscall_transport,
            self.persistent_vm_lifecycle,
            (request.root_slot_base, request.root_slot_size),
            self.container_root,
            frame_inventory,
            std::sync::Arc::new(parking_lot::Mutex::new(child_cow_armed)),
            carrier_foreign_mm_transport,
        );
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendSpecFinalize,
            stage_started,
            0,
        );
        Ok(plan)
    }
}
