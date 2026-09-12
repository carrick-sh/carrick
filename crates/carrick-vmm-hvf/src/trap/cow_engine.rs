//! Copy-on-write (COW) engine and sparse backing materialization.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use carrick_fatal::carrick_fatal;

impl HvfVmState {
    /// Live private semantic mappings that a process fork must arm read-only in
    /// both stage-1 graphs. This includes a currently-read-only or PROT_NONE
    /// mapping: a later mprotect-to-write must still take frame COW rather than
    /// silently sharing the parent's frame. The alias registry supplies mappings
    /// installed by sibling vCPUs and filters retired lifetime-owner rows.
    pub(crate) fn fork_cow_ranges(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        let aliases = alias_registry()
            .lock()
            .process_visible_ordered(self.mm_root_slot, self.container_root);
        let alias_index = process_alias_index(&aliases, self.mm_root_slot, self.container_root);
        let mut ranges: Vec<_> = self
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.sharing == GuestMappingSharing::Private
                    && mapping.start != crate::memory::LINUX_PAGE_TABLES_BASE
                    && !is_kernel_only_stage1_range(
                        mapping.start,
                        semantic_extent_size(mapping.start, mapping.end),
                    )
                    && mapping_is_current_for_process_fork_indexed(mapping, &alias_index)
            })
            .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                va: mapping.start,
                len: semantic_extent_size(mapping.start, mapping.end),
                executable: u64::from(mapping.perms) & 4 != 0,
                kernel_only: is_kernel_only_stage1_range(
                    mapping.start,
                    semantic_extent_size(mapping.start, mapping.end),
                ),
                granule: carrick_aarch64::vmm::CowGranule::Compound,
            })
            .collect();
        let local_aliases = current_process_alias_keys(
            &self.mappings,
            &aliases,
            self.mm_root_slot,
            self.container_root,
        );
        ranges.extend(
            missing_process_aliases(
                &local_aliases,
                &aliases,
                self.mm_root_slot,
                self.container_root,
            )
            .into_iter()
            .filter(|mapping| {
                mapping.sharing == GuestMappingSharing::Private
                    && !is_kernel_only_stage1_range(mapping.start, mapping.size)
            })
            .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                va: mapping.start,
                len: mapping.size,
                executable: mapping.perms & 4 != 0,
                kernel_only: is_kernel_only_stage1_range(mapping.start, mapping.size),
                granule: carrick_aarch64::vmm::CowGranule::Compound,
            }),
        );
        ranges.sort_by_key(|range| (range.va, range.len));
        ranges.dedup_by_key(|range| (range.va, range.len));
        ranges
    }

    pub(crate) fn arm_frame_cow_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        if let Some(debug_va) = fork_debug_va()
            && let Some(range) = ranges
                .iter()
                .find(|range| debug_va >= range.va && debug_va < range.va + range.len as u64)
        {
            eprintln!(
                "[ARMDBG parent pid={:?} mm={:?} slot={:x?}] arm covers watch: va={:#x} len={:#x}",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                self.mm_root_slot,
                range.va,
                range.len,
            );
        }
        self.cow_armed.lock().arm(ranges);
    }

    pub(crate) fn frame_cow_arm_snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().snapshot()
    }

    pub(crate) fn restore_frame_cow_arm_snapshot(
        &mut self,
        snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>,
    ) {
        self.cow_armed.lock().restore(snapshot);
    }

    pub(crate) fn armed_frame_cow_ranges(
        &self,
        va: u64,
        len: usize,
    ) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().overlapping(va, len)
    }

    pub(crate) fn publish_private_repoint(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        let overlay_end = overlay_ipa.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("private repoint semantic IPA overflow".to_owned())
        })?;
        let (
            mapping_ipa,
            physical_ipa,
            mapping_host,
            physical_size,
            perms,
            mapping_owner_generation,
        ) = self
            .mappings
            .iter()
            .rev()
            .find(|mapping| {
                overlay_ipa >= mapping.ipa
                    && mapping
                        .ipa
                        .checked_add(mapping.size as u64)
                        .is_some_and(|end| overlay_end <= end)
            })
            .map(|mapping| {
                (
                    mapping.ipa,
                    mapping.physical_ipa,
                    mapping.host_addr as usize,
                    mapping.physical_size,
                    mapping.perms,
                    mapping
                        .structural_owner
                        .as_ref()
                        .map(|owner| owner.epoch().raw())
                        .unwrap_or(mapping.owner_generation),
                )
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint IPA 0x{overlay_ipa:x} size {len} has no physical owner"
                ))
            })?;
        let semantic_offset = overlay_ipa.checked_sub(physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("private repoint precedes its physical extent".to_owned())
        })?;
        let physical_host_addr = mapping_host
            .checked_sub(mapping_ipa.checked_sub(physical_ipa).ok_or_else(|| {
                TrapError::Hypervisor(
                    "private repoint mapping precedes its physical extent".to_owned(),
                )
            })? as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint physical host underflow".to_owned())
            })?;
        let host_addr = physical_host_addr
            .checked_add(semantic_offset as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint semantic host overflow".to_owned())
            })?;
        let inventory_backing = self
            .frame_inventory
            .lock()
            .extents
            .get(&(physical_ipa, physical_size as u64))
            .map(|extent| extent.backing)
            .or_else(|| (!self.persistent_vm_lifecycle).then(Self::private_backing_identity))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint physical IPA 0x{:x} size {} lacks frame inventory",
                    physical_ipa, physical_size
                ))
            })?;
        let owner_generation =
            if is_reusable_global_frame_extent(physical_ipa, physical_size as u64) {
                global_frame_host_owner_generation_in(
                    self.custody(),
                    physical_ipa,
                    physical_size as u64,
                )
            } else {
                mapping_owner_generation
            };
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: va,
            ipa: overlay_ipa,
            host_addr,
            size: len,
            physical_ipa,
            physical_host_addr,
            physical_size,
            perms: u64::from(perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        Ok(())
    }

    pub(crate) fn apply_exec_inventory(
        &mut self,
        replacement_mm: u64,
        apply: &mut dyn FnMut(
            carrick_hal::FrameInventoryCommit<()>,
        )
            -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<bool, TrapError> {
        let Some(ref mut reg) = self.registration else {
            return Ok(false);
        };
        let mm = std::num::NonZeroU64::new(replacement_mm).ok_or_else(|| {
            TrapError::Hypervisor("zero replacement MM for HVPatch exec".to_owned())
        })?;
        reg.bind_kernel_mm(mm)?;
        reg.apply_inventory(apply)?;
        Ok(true)
    }

    pub(crate) fn activate_exec_inventory(&mut self) -> Result<(), TrapError> {
        let Some(ref mut reg) = self.registration else {
            return Ok(());
        };
        reg.activate()
    }

    /// Whether the frame backing `ipa` is referenced by MORE than one extent in
    /// the shared backend registry — i.e., some other mm (a fork parent or
    /// child) still lives on it. The registry `Arc` is shared across every
    /// engine in the carrier and its counts drive retirement, so it is the
    /// authority for "shared", where the per-engine armed-set is only a
    /// derived (and known-omissive) approximation.
    /// Whether this mm may write DIRECTLY through the frame its retained
    /// stage-1 output names. Two ways to lose that right:
    ///
    /// - This mm's inventory holds NO extent covering the IPA at all: the leaf
    ///   is stale — it survived a retirement/replacement of the mapping it
    ///   belonged to — and whatever lives behind that IPA now belongs to
    ///   someone else. The forkserver worker's scrub had exactly this shape
    ///   (606 own extents, none covering the retained IPA) and its Direct
    ///   write zeroed the SERVER's live interned-dict granule.
    /// - An extent exists but the backend registry counts more than one
    ///   reference on its frame: a fork peer still lives on it, and a direct
    ///   write would be visible through the other mm.
    ///
    /// In both cases the maintenance write must MATERIALIZE a private zeroed
    /// replacement instead. The registry `Arc` is shared carrier-wide and its
    /// counts drive retirement, so it is the authority; the per-engine
    /// armed-set is a derived, known-omissive approximation
    /// (`mtforkcorrupt`).
    pub(crate) fn retained_output_lacks_exclusive_claim(&self, ipa: u64) -> bool {
        // Only REUSABLE global-frame IPAs carry claims at all. Boot and
        // identity regions (the heap, the low arena's fixed backing, page
        // tables) are per-mm by construction and never enter the extent map;
        // treating their absence as a lost claim routed every brk-heap scrub
        // into materialization and broke `ltp-brk02`/`ltp-tgkill01` outright.
        if !is_reusable_global_frame_extent(ipa, 1) {
            return false;
        }
        let inventory = self.frame_inventory.lock();
        let extent = inventory
            .extents
            .iter()
            .find(|(key, _)| key.0 <= ipa && ipa < key.0.saturating_add(key.1))
            .map(|(_, extent)| *extent);
        let Some(extent) = extent else {
            return true;
        };
        // DELIBERATE sharing is not a lost claim. A `SharedAnon`/`SharedFile`
        // backing is MAP_SHARED semantics: every mapper must keep seeing the
        // same bytes, and materializing a private replacement under it breaks
        // exactly what the guest asked for (measured: multiprocessing's
        // Barrier hung when a shared semaphore page was privatized here).
        // Only a PRIVATE backing observed by more than one mm is fork-COW
        // sharing that a maintenance write must not write through.
        //
        // A private FILE VIEW never carries an exclusive claim: its host
        // bytes are the file's page cache, so a direct maintenance write
        // would either fail (the view is `PROT_READ`) or, worse, be the file.
        // The maintenance write must materialize the page privately, exactly
        // like a guest write to a clean page.
        match extent.backing {
            InventoryBackingIdentity::PrivateFileView(_) => return true,
            InventoryBackingIdentity::Private(_) => {}
            InventoryBackingIdentity::SharedAnon(_)
            | InventoryBackingIdentity::SharedFile { .. } => return false,
        }
        inventory
            .frames
            .lock()
            .references
            .get(&extent.frame)
            .copied()
            .unwrap_or(0)
            > 1
    }

    pub(crate) const DEFAULT_FAULT_WINDOW_BYTES: u64 = 64 * 1024;

    pub(crate) fn fault_window_bytes() -> u64 {
        static WINDOW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *WINDOW.get_or_init(|| {
            std::env::var("CARRICK_FAULT_WINDOW_BYTES")
                .ok()
                .and_then(|val| val.parse::<u64>().ok())
                .filter(|&w| w >= 4096 && w.is_power_of_two())
                .unwrap_or(Self::DEFAULT_FAULT_WINDOW_BYTES)
        })
    }

    /// Materialize private zero backing for the exact accessible pieces of the
    /// sparse HVPatch mmap arena. One VMA hole becomes one host mapping, one
    /// stage-2 lease, and one inventory frame; there is no shared source frame
    /// and therefore no shared-zero COW authority.
    ///
    /// This is the first-touch fault service, so it is where the mapping-index
    /// census is taken: the row populations both lookup structures hold, the
    /// rows their walks visited for THIS fault, and the nanoseconds it cost.
    /// `docs/perf-results/2026-09-08-mapping-index-measurement.md` closed the
    /// full-table walk it could see by wall time alone and had to leave the
    /// residual super-linearity unnamed, because no probe reported a scan
    /// count. This is that probe.
    pub(crate) fn ensure_sparse_mmap_backing(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let Some(started) = carrick_observability::probes::hvpatch_mapping_index_begin(
            self.mappings.live_len() as u64,
            self.mappings.shadowed_len() as u64,
        ) else {
            return self.ensure_sparse_mmap_backing_censused(va, len, flush_stage1);
        };
        let mapping_rows_before = hot_path_rows_scanned_live(HotPathScan::TaskMappings);
        let alias_rows_before = hot_path_rows_scanned_live(HotPathScan::AliasState);
        let outcome = self.ensure_sparse_mmap_backing_censused(va, len, flush_stage1);
        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let (alias_rows, widest_va) = {
            let registry = alias_registry().lock();
            (registry.len() as u64, registry.widest_va_window())
        };
        carrick_observability::probes::hvpatch_mapping_index_fault(
            carrick_observability::probes::HvpatchMappingIndexCensus::new(
                va,
                self.mappings.live_len() as u64,
                self.mappings.shadowed_len() as u64,
                hot_path_rows_scanned_live(HotPathScan::TaskMappings)
                    .wrapping_sub(mapping_rows_before),
                alias_rows,
                hot_path_rows_scanned_live(HotPathScan::AliasState).wrapping_sub(alias_rows_before),
                widest_va,
                nanos,
            ),
        );
        outcome
    }

    pub(crate) fn ensure_sparse_mmap_backing_censused(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        if !self.persistent_vm_lifecycle || len == 0 {
            return Ok(());
        }
        let arena_start = crate::memory::LINUX_MMAP_BASE;
        let arena_end = arena_start
            .checked_add(crate::memory::mmap_arena_size())
            .ok_or_else(|| TrapError::Hypervisor("HVPatch mmap arena overflow".to_owned()))?;
        let requested_end = va
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap range overflow".to_owned()))?;
        let in_low_arena = va >= arena_start && requested_end <= arena_end;
        let in_high_va = crate::memory::is_high_va(va) && requested_end <= (1u64 << 48);
        if !in_low_arena && !in_high_va {
            return Ok(());
        }
        if let Some(state) = self.deferred_anonymous_state()
            && let Some(transition) =
                state.begin_private_file_materialization(carrick_guest_mem::GuestVa(va))
        {
            let start = transition.start().raw();
            let materialized = self.materialize_private_file_backing(
                start,
                transition.len(),
                transition.fd(),
                transition.file_offset(),
                transition.source(),
                flush_stage1,
            )?;
            if !materialized {
                return Err(TrapError::Hypervisor(format!(
                    "deferred private file view at VA 0x{start:x} refused first-touch publication"
                )));
            }
            transition.commit();
            return Ok(());
        }
        let mut current = align_down(va, PAGE_SIZE);
        let end = align_up(requested_end, PAGE_SIZE)?;

        // Zero-allocation fast path: if the requested range is already backed
        // by a live mapping, return immediately.
        if let Some(mapping) = self.mapping_for_range(current, 1) {
            if mapping.end >= end {
                return Ok(());
            }
        }

        // Anonymous private fault window (Step 1 + Step 2):
        // Widen the fault window up to W bytes (default 64 KiB) within the pristine hole:
        // window_end = min(hole_end, align_up(va + 1, W), vma_end, next_2mb_boundary)
        const COMPOUND: u64 = CowArmedRanges::COMPOUND_SIZE;
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        if len == PAGE_SIZE as usize && current < end {
            let pristine = self.deferred_anonymous_state().and_then(|state| {
                state
                    .snapshot()
                    .pristine
                    .into_iter()
                    .find(|r| r.start.raw() <= current && current < r.end.raw())
                    .map(|r| (r.start.raw(), r.end.raw()))
            });
            if let Some((p_start, p_end)) = pristine {
                let w = Self::fault_window_bytes();
                if w < COMPOUND {
                    // Hatch CARRICK_FAULT_WINDOW_BYTES=4096: single-page fallback.
                    let has_local = self
                        .mappings
                        .iter()
                        .any(|m| m.start < end && m.end > current);
                    let has_alias = alias_registry().lock().has_live_process_alias_overlapping(
                        current,
                        end,
                        self.mm_root_slot,
                        self.container_root,
                    );
                    if !has_local && !has_alias {
                        self.materialize_sparse_mmap_extent(
                            current,
                            end,
                            SparseExtentBacking::Anon,
                            flush_stage1,
                            Some(current..end),
                        )?;
                        return Ok(());
                    }
                } else {
                    let range_end_limit = if in_high_va { 1u64 << 48 } else { arena_end };
                    let range_start_limit = if in_high_va {
                        crate::memory::LINUX_HIGH_VA_THRESHOLD
                    } else {
                        arena_start
                    };
                    let w_end = align_up(current.saturating_add(1), w)?;
                    let next_2mb = align_down(current, TWO_MIB).saturating_add(TWO_MIB);
                    let vma_end = p_end;
                    let mut window_end = vma_end.min(next_2mb).min(w_end).min(range_end_limit);
                    window_end = window_end.max(end);

                    // Sorted by construction (`TaskMappingIndex`), so this
                    // neighbour question is an ordered range query. The
                    // earlier `partition_point` attempt was wrong because the
                    // VECTOR was unsorted and a binary search missed live
                    // mappings, letting a window materialize over them (Go
                    // heap corruption, 2026-09-07); the invariant now holds at
                    // every publication site, and displaced rows are searched
                    // too.
                    let next_local = self.mappings.first_start_between(
                        GuestVa(current),
                        GuestVa(window_end),
                        |_| true,
                    );
                    let next_alias = alias_registry()
                        .lock()
                        .first_matching_process_alias_start_between(
                            current,
                            window_end,
                            self.mm_root_slot,
                            self.container_root,
                            |alias| alias_backing_is_live(alias.physical_host_addr),
                        );
                    window_end = next_local
                        .into_iter()
                        .chain(next_alias)
                        .min()
                        .unwrap_or(window_end);

                    let compound_start = align_down(current, COMPOUND);
                    let window_start = if compound_start >= p_start
                        && compound_start >= range_start_limit
                        && !alias_registry().lock().has_live_process_alias_overlapping(
                            compound_start,
                            current,
                            self.mm_root_slot,
                            self.container_root,
                        ) {
                        let lower_has_local = self
                            .mappings
                            .any_lower_row_reaches(GuestVa(current), compound_start);
                        if !lower_has_local {
                            compound_start
                        } else {
                            current
                        }
                    } else {
                        current
                    };

                    if window_start < window_end && window_start <= current && end <= window_end {
                        let mut chunk_start = window_start;
                        while chunk_start < window_end {
                            let chunk_limit = if chunk_start.is_multiple_of(COMPOUND) {
                                chunk_start.saturating_add(COMPOUND).min(window_end)
                            } else {
                                align_up(chunk_start.saturating_add(1), COMPOUND)?.min(window_end)
                            };
                            let materialized_end = self.materialize_sparse_mmap_extent(
                                chunk_start,
                                chunk_limit,
                                SparseExtentBacking::Anon,
                                flush_stage1,
                                Some(current..end),
                            )?;
                            if materialized_end <= chunk_start {
                                break;
                            }
                            chunk_start = materialized_end;
                        }
                        return Ok(());
                    }
                }
            }
        }

        while current < end {
            if let Some(mapping) = self.mapping_for_range(current, 1) {
                let next = mapping.end.min(end);
                if next <= current {
                    return Err(TrapError::Hypervisor(format!(
                        "sparse mmap live mapping made no progress at VA 0x{current:x}: view VA 0x{:x}..0x{:x}, view IPA 0x{:x}, live IPA {:?}, mm root {:?}",
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        self.translate_va(current),
                        self.mm_root_slot,
                    )));
                }
                current = next;
                continue;
            }

            // Preserve already-materialized neighbours. The topology lock in
            // the materializer rechecks this shape before publication.
            let next_local =
                self.mappings
                    .first_start_between(GuestVa(current), GuestVa(end), |_| true);
            let next_alias = alias_registry()
                .lock()
                .first_matching_process_alias_start_between(
                    current,
                    end,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| alias_backing_is_live(alias.physical_host_addr),
                );
            let hole_end = next_local
                .into_iter()
                .chain(next_alias)
                .min()
                .unwrap_or(end);
            current = self.materialize_sparse_mmap_extent(
                current,
                hole_end,
                SparseExtentBacking::Anon,
                flush_stage1,
                None,
            )?;
        }
        Ok(())
    }

    /// Materialize a file view for a guest `MAP_PRIVATE` mapping in the sparse
    /// arena. Immutable lower artifacts use Darwin `MAP_PRIVATE`; mutable files
    /// require a writable `MAP_SHARED` host view so clean pages track later file
    /// writes. Carrick arms 4 KiB frame COW before guest access, keeping every
    /// guest and foreign store private to the exact MM.
    ///
    /// Returns `Ok(false)` when the request cannot take this shape and the
    /// dispatcher must fall back to its eager snapshot: ranges outside the
    /// sparse arena, a VA/offset pair that is not congruent modulo the 16 KiB
    /// host page, an offset at/after EOF, or a range that is not entirely a
    /// hole. A mutable read-only host fd is also refused by Darwin because the
    /// coherent host view needs write authority.
    pub(crate) fn materialize_private_file_backing(
        &mut self,
        va: u64,
        len: usize,
        fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        if !self.persistent_vm_lifecycle || len == 0 {
            return Ok(false);
        }
        let arena_start = crate::memory::LINUX_MMAP_BASE;
        let arena_end = arena_start
            .checked_add(crate::memory::mmap_arena_size())
            .ok_or_else(|| TrapError::Hypervisor("HVPatch mmap arena overflow".to_owned()))?;
        let end = va
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("private file view range overflow".to_owned()))?;
        let in_low_arena = va >= arena_start && end <= arena_end;
        let in_high_va = crate::memory::is_high_va(va) && end <= (1u64 << 48);
        // A private mapping may be moved into the shared aperture. Its VA
        // does not decide ownership: the live alias/mapping checks below still
        // refuse shared or non-dynamic backing before any retirement.
        let eligible_range =
            in_low_arena || in_high_va || crate::memory::va_in_shared_aperture(va, len as u64);
        if !eligible_range
            || !va.is_multiple_of(PAGE_SIZE)
            || !end.is_multiple_of(PAGE_SIZE)
            || !offset.is_multiple_of(PAGE_SIZE)
        {
            return Ok(false);
        }
        let file_len = {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `fstat` writes a `libc::stat` into the provided buffer.
            let rc = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
            if rc != 0 {
                return Ok(false);
            }
            // SAFETY: `fstat` succeeded and initialized the buffer.
            let stat = unsafe { stat.assume_init() };
            u64::try_from(stat.st_size).unwrap_or(0)
        };
        if offset >= file_len {
            return Ok(false);
        }
        let view_len = (file_len - offset).min(end - va);
        let view_end = va + view_len;
        let file_pages_end = align_up(view_end, PAGE_SIZE).unwrap_or(end).min(end);

        // Holes vs overlapping existing mappings:
        // A plain MAP_PRIVATE file mmap lands in a hole. A MAP_FIXED over an
        // existing private mapping (such as the ELF loader's PROT_NONE reservation)
        // retires the old backing for the range so it takes the lazy view too.
        // If any overlapping mapping or process-scoped alias is non-private or
        // non-dynamic (e.g. shared memory), refuse the lowering so dispatcher falls back.
        let overlapping_aliases = alias_registry().lock().overlapping_process_aliases(
            va,
            len,
            self.mm_root_slot,
            self.container_root,
        );
        let has_non_retirable_alias = overlapping_aliases.iter().any(|(_, alias)| {
            alias.sharing != GuestMappingSharing::Private
                || !alias_backing_is_live(alias.physical_host_addr)
        });
        if has_non_retirable_alias {
            return Ok(false);
        }

        let has_non_retirable_mapping = self.mappings.iter().any(|m| {
            m.start < end
                && m.end > va
                && global_frame_region_owner_matches_in(self.custody(), m)
                && (!m.is_dynamic_alias || m.sharing != GuestMappingSharing::Private)
        });
        if has_non_retirable_mapping {
            return Ok(false);
        }

        let mut current = va;
        while current < end {
            let hole_end = if current < file_pages_end {
                file_pages_end
            } else {
                end
            };
            let backing = if current < file_pages_end {
                SparseExtentBacking::FileView {
                    fd,
                    offset: offset + (current - va),
                    source,
                }
            } else {
                SparseExtentBacking::Anon
            };
            let next = self.materialize_sparse_mmap_extent_inner(
                current,
                hole_end,
                backing,
                flush_stage1,
                None,
                true,
            )?;
            if next <= current {
                return Err(TrapError::Hypervisor(format!(
                    "private file view materialization made no progress at VA 0x{current:x}"
                )));
            }
            current = next;
        }
        Ok(true)
    }

    pub(crate) fn materialize_sparse_mmap_extent(
        &mut self,
        start: u64,
        end: u64,
        backing: SparseExtentBacking<'_>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
        receipt_range: Option<std::ops::Range<u64>>,
    ) -> Result<u64, TrapError> {
        self.materialize_sparse_mmap_extent_inner(
            start,
            end,
            backing,
            flush_stage1,
            receipt_range,
            false,
        )
    }

    pub(crate) fn materialize_sparse_mmap_extent_inner(
        &mut self,
        start: u64,
        end: u64,
        backing: SparseExtentBacking<'_>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
        receipt_range: Option<std::ops::Range<u64>>,
        replacing: bool,
    ) -> Result<u64, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;

        if start >= end || !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
            return Err(TrapError::Hypervisor(format!(
                "invalid sparse mmap materialization 0x{start:x}..0x{end:x}"
            )));
        }
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch sparse mmap has no bound mm identity".to_owned())
        })?;
        let publication = sparse_materialization::PublicationContext::for_local(
            std::sync::Arc::clone(&self.mm_access),
            self.carrier_vm_custody(),
            identity,
        )?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );
        let end = if replacing {
            // Eligibility was screened before exact-MM quiescence. Recheck
            // under topology exclusion before bypassing the hole checks: a
            // sibling must not turn a private replacement into a shared unmap.
            let len = usize::try_from(end - start)
                .map_err(|_| TrapError::MappingTooLarge(end - start))?;
            let aliases = alias_registry().lock().overlapping_process_aliases(
                start,
                len,
                self.mm_root_slot,
                self.container_root,
            );
            let forbidden_alias = aliases.iter().any(|(_, alias)| {
                alias.sharing != GuestMappingSharing::Private
                    || !alias_backing_is_live(alias.physical_host_addr)
            });
            let forbidden_mapping = self.mappings.iter().any(|mapping| {
                mapping.start < end
                    && mapping.end > start
                    && global_frame_region_owner_matches_in(self.custody(), mapping)
                    && (!mapping.is_dynamic_alias
                        || mapping.sharing != GuestMappingSharing::Private)
            });
            if forbidden_alias || forbidden_mapping {
                return Err(TrapError::Hypervisor(
                    "private-file replacement eligibility changed before quiescence".to_owned(),
                ));
            }
            end
        } else {
            if let Some(mapping) = self.mapping_for_range(start, 1) {
                // An aperture identity row is a boot lookup fallback, not proof
                // that a private file view raced this publication. The caller has
                // already refused live shared aliases; process-scoped frame owners
                // below remain authoritative even after an old overlay is retired.
                let replaces_boot_identity =
                    matches!(backing, SparseExtentBacking::FileView { .. })
                        && crate::memory::va_in_shared_aperture(start, end - start)
                        && mapping.is_shared_aperture_identity();
                if !replaces_boot_identity {
                    return Ok(mapping.end.min(end));
                }
            }

            // Another vCPU in this mm can publish the physical alias while its
            // stage-1 receipt is deliberately still invalid.  Such an alias is
            // invisible to `mapping_for_range` on this sibling until the later
            // protection commit, so authenticate the process-shared physical owner
            // directly before allocating a second overlapping frame.
            let live_alias_end = alias_registry()
                .lock()
                .newest_process_alias_containing_va(
                    start,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        global_frame_host_owner_matches_in(
                            self.custody(),
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    },
                )
                .map(|alias| alias.start.saturating_add(alias.size as u64));
            if let Some(alias_end) = live_alias_end {
                return Ok(alias_end.min(end));
            }

            // The caller found this hole before quiescing. Recompute its upper
            // boundary under the topology lock so a sibling publication between
            // those two points cannot be overlapped.
            // Ordered range query (see the window arm above): this bound decides
            // whether the new extent overlaps a live mapping, so it must still see
            // every row -- including displaced ones -- that the exact live global
            // owner still backs.
            let custody = self.custody();
            let next_local =
                self.mappings
                    .first_start_between(GuestVa(start), GuestVa(end), |mapping| {
                        global_frame_region_owner_matches_in(custody, mapping)
                    });
            let next_alias = alias_registry()
                .lock()
                .first_matching_process_alias_start_between(
                    start,
                    end,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        global_frame_host_owner_matches_in(
                            self.custody(),
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    },
                );
            next_local
                .into_iter()
                .chain(next_alias)
                .min()
                .unwrap_or(end)
        };

        let semantic_len =
            usize::try_from(end - start).map_err(|_| TrapError::MappingTooLarge(end - start))?;
        let deferred_state = self.deferred_anonymous_state();
        let deferred_transition = deferred_state
            .as_ref()
            .map(|state| {
                state.begin_materialization(carrick_guest_mem::GuestVa(start), semantic_len)
            })
            .transpose()
            .map_err(|error| {
                TrapError::Hypervisor(format!("anonymous materialization range: {error}"))
            })?;

        let mut retirement = if replacing {
            Some(self.prepare_process_alias_retirement(start, semantic_len)?)
        } else {
            None
        };
        let published = sparse_materialization::publish_replacing(
            &publication,
            start,
            end,
            backing,
            flush_stage1,
            &mut || {
                if let Some(retirement) = retirement.take() {
                    // New descriptors and inventory are committed, but the new
                    // alias is not registered yet. Retire only the old rows.
                    // All ordinary allocation failures preceded this boundary.
                    self.commit_process_alias_retirement(start, semantic_len, retirement)
                        .unwrap_or_else(|error| {
                            carrick_fatal!(
                                "hvpatch::host_alias",
                                "committed private-file retirement failed: start=0x{start:x} len=0x{semantic_len:x} error={error}"
                            );
                        });
                }
            },
        )?;
        let page_granular_arm = published.page_granular_arm;
        let semantic_ipa = published.region.ipa;
        for ext in published.extension_regions {
            self.mappings.insert(ext);
        }
        self.mappings.insert(published.region);
        if page_granular_arm {
            // Every page of the view starts clean: the first guest (or host
            // syscall) write to a page must move THAT page, and only that
            // page, off the page-cache view. The anonymous beyond-EOF tail of
            // this extent is armed the same way so the extent is uniform.
            self.cow_armed
                .lock()
                .arm(&[carrick_aarch64::vmm::ForkCowRange {
                    va: start,
                    len: semantic_len,
                    executable: false,
                    kernel_only: false,
                    granule: carrick_aarch64::vmm::CowGranule::Page,
                }]);
        }
        let (receipt_va, receipt_len, receipt_ipa) = if let Some(range) = receipt_range {
            let r_start = start.max(range.start);
            let r_end = end.min(range.end);
            if r_start < r_end {
                let r_len = usize::try_from(r_end - r_start)
                    .map_err(|_| TrapError::MappingTooLarge(r_end - r_start))?;
                let r_ipa = semantic_ipa.checked_add(r_start - start).ok_or_else(|| {
                    TrapError::Hypervisor("sparse mmap receipt IPA overflow".to_owned())
                })?;
                (r_start, r_len, r_ipa)
            } else {
                (start, 0, semantic_ipa)
            }
        } else {
            (start, semantic_len, semantic_ipa)
        };
        if receipt_len > 0 {
            self.supersede_cow_receipts("sparse-mmap-extent", receipt_va, receipt_len as u64);
            self.cow_deferred_publications
                .lock()
                .push(PendingFrameCowPublication {
                    va: receipt_va,
                    len: receipt_len,
                    expected_ipa: receipt_ipa,
                });
        }
        if let Some(transition) = deferred_transition {
            transition.commit();
        }
        Ok(end)
    }

    /// Void every pending deferred-COW receipt naming `[va, va+len)`.
    ///
    /// A receipt is a promise about ONE `(VA -> IPA)` publication, redeemed by
    /// the `protect_range` that completes it. The moment a later transaction
    /// repoints those leaves the promise is void: authenticating it compares
    /// the live translation against an owner that has been DELIBERATELY
    /// replaced, and `observe_frame_cow_protection` then fails a publication
    /// that is in fact correct — which the dispatcher can only lower to a
    /// guest `ENOMEM`. That is how CPython's thread stacks came back
    /// MAP_FAILED ("Can't start 20 threads, only 4 threads started"): a
    /// sparse-mmap extent's receipt was falsified by a frame COW running
    /// between its publication and its protection commit.
    ///
    /// Every stage-1 repointer calls this before publishing its own receipt.
    /// No authentication coverage is lost: each repointer verifies its own
    /// leaves inline and leaves a receipt for the state that actually
    /// survives. A receipt only partly covered is split, never widened.
    pub(crate) fn supersede_cow_receipts(&self, site: &'static str, va: u64, len: u64) {
        let Some(end) = va.checked_add(len) else {
            return;
        };
        let mut receipts = self.cow_deferred_publications.lock();
        if receipts.is_empty() {
            return;
        }
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            if receipt_end <= va || receipt.va >= end {
                remaining.push(receipt);
                continue;
            }
            tracing::debug!(
                target: "carrick::cow",
                site,
                repoint = format_args!("{va:#x}+{len:#x}"),
                receipt = format_args!("{:#x}+{:#x}", receipt.va, receipt.len),
                expected_ipa = format_args!("{:#x}", receipt.expected_ipa),
                "superseding deferred COW receipt",
            );
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start
                && let Ok(prefix) = usize::try_from(overlap_start - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: prefix,
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end
                && let Ok(suffix) = usize::try_from(receipt_end - overlap_end)
                && let Some(expected_ipa) =
                    receipt.expected_ipa.checked_add(overlap_end - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: suffix,
                    expected_ipa,
                });
            }
        }
        *receipts = remaining;
    }

    /// Replace an invalid stage-1 output whose exact stage-2 lease was retired
    /// by `munmap` with a fresh zero frame before low-arena same-VA reuse.
    ///
    /// `munmap` deliberately preserves the descriptor output address while
    /// clearing VALID. That is useful while a partially unmapped compound still
    /// owns its physical lease, but a *full* semantic unmap now retires that
    /// lease exactly. A later anonymous mmap may reuse the same low VA without
    /// going through `add_alias`; merely setting VALID would resurrect an IPA
    /// that no longer exists in stage-2. Materialize a new global frame and
    /// repoint the still-invalid leaves transactionally. The later
    /// `protect_range` publication authenticates the deferred PTE receipts.
    pub(crate) fn materialize_retired_reuse(
        &mut self,
        va: u64,
        requested_end: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<Option<u64>, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const VALID: u64 = 1;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const NON_GLOBAL: u64 = 1 << 11;

        if !self.persistent_vm_lifecycle {
            return Ok(None);
        }
        let page_va = align_down(va, PAGE_SIZE);
        let retained_ipa = self
            .page_tables_authority()
            .with_manager(|manager| manager.translate_retained_output(page_va))
            .flatten();
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            return Ok(None);
        }
        if !self.protections.range_unmapped(page_va, 1) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch live VA 0x{page_va:x} names retired stage-2 IPA 0x{retained_ipa:x}"
            )));
        }

        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no inventory authority".to_owned())
        })?;
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch retained reuse: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another sibling may have repaired the leaf while this thread waited.
        let retained_ipa = self
            .page_tables_authority()
            .with_manager(|manager| manager.translate_retained_output(page_va))
            .flatten();
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            // A live PRIVATE source means a sibling repaired the leaf; nothing
            // to materialize. A live SHARED source is the case this exists
            // for: the mm must get its own zeroed replacement rather than
            // writing through (corruption) or reading through (disclosure)
            // the other mm's frame.
            return Ok(None);
        }

        let compound_va = align_down(page_va, CowArmedRanges::COMPOUND_SIZE);
        let compound_end = compound_va
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse compound overflow".to_owned())
            })?;
        // Extend past the trigger page only across pages in EXACTLY its state.
        //
        // The predicate above (a retained stage-1 output naming no live
        // physical source) selected `page_va` alone; the rest of the compound
        // was taken on trust. That is wrong, because a page whose backing was
        // published moments earlier by `materialize_sparse_mmap_extent` is
        // indistinguishable from a retired one AT THE LEAF: sparse
        // materialization deliberately leaves its stage-1 receipts invalid
        // until the protection commit. Repointing such a page replaces a live
        // physical owner and falsifies the `PendingFrameCowPublication` that
        // names it, so the `protect_range` that follows in the same guest
        // `mmap` fails to authenticate its own receipt and the guest gets
        // MAP_FAILED — with, before this, no explanation anywhere. That is the
        // shape that broke every CPython `dlopen` of a DSO whose PROT_NONE
        // reservation started one page into a 16 KiB compound.
        //
        // Authenticate each page against the live translation and the exact
        // current owner instead, and stop at the first page that already has
        // one. Splitting a compound across frames is already supported — the
        // repoint covers exactly `[page_va, span_end)`.
        let mut span_end = requested_end.min(compound_end);
        let mut probe = page_va.saturating_add(PAGE_SIZE);
        while probe < span_end {
            let retained = self
                .page_tables_authority()
                .with_manager(|manager| manager.translate_retained_output(probe))
                .flatten();
            let needs_materialization = retained.is_some_and(|ipa| {
                self.physical_cow_source(probe, ipa).is_none()
                    || self.retained_output_lacks_exclusive_claim(ipa)
            }) && self.protections.range_unmapped(probe, 1);
            if !needs_materialization {
                span_end = probe;
                break;
            }
            probe = probe.saturating_add(PAGE_SIZE);
        }
        let span_len = usize::try_from(span_end.checked_sub(page_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse span underflow".to_owned())
        })?)
        .map_err(|_| TrapError::MappingTooLarge(span_end.saturating_sub(page_va)))?;
        if span_len == 0 {
            return Ok(None);
        }
        let physical_offset = page_va.checked_sub(compound_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse offset underflow".to_owned())
        })?;
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse has no page-table backing".to_owned())
            })?;

        let mut reservation = authority.reserve(1, 1, 2).map_err(|error| {
            TrapError::Hypervisor(format!("reserve HVPatch retained reuse inventory: {error}"))
        })?;
        let backing = Self::private_backing_identity();
        let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            CowArmedRanges::COMPOUND_SIZE as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("allocate HVPatch retained reuse backing: {error}"))
        })?;
        let new_host_ptr = new_host.as_ptr();
        let mut new_lease = GlobalFrameStage2Lease::reserve(
            CowArmedRanges::COMPOUND_SIZE,
            CowArmedRanges::COMPOUND_SIZE,
        )?;
        let new_physical_ipa = new_lease.base;
        let new_ipa = new_physical_ipa
            .checked_add(physical_offset)
            .ok_or_else(|| TrapError::Hypervisor("retained reuse IPA overflow".to_owned()))?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_result = unsafe {
            inventory_hv_vm_map(
                new_host_ptr.cast(),
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map retained reuse IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        new_lease.mark_mapped();
        let custody = self.carrier_vm_custody();
        let owner_generation = register_global_frame_host_owner_in(
            &custody,
            new_lease,
            new_host,
            u64::from(stage2_perms),
        )?;
        let mut owner_rollback = GlobalFrameOwnerRollback::new(custody);
        owner_rollback.record((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE));

        let inventory_mapping = {
            let mut inventory = self.frame_inventory.lock();
            Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: new_physical_ipa,
                    length: CowArmedRanges::COMPOUND_SIZE,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing,
                    inherited_frame: None,
                    stage2_lease: Some((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE)),
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: new_host_ptr as usize,
                        generation: owner_generation,
                    },
                },
            )?
        };
        let inventory_entry = (
            (new_physical_ipa, CowArmedRanges::COMPOUND_SIZE),
            inventory_mapping,
        );

        // Journal this transaction's descriptor pre-images rather than
        // cloning the whole 1.75 MiB table region (see `begin_undo`).
        let publication = {
            let page_tables_authority = self.page_tables_authority();
            page_tables_authority
                .edit(
                    || {
                        Err(TrapError::Hypervisor(
                            "HVPatch retained reuse page tables are absent".to_owned(),
                        ))
                    },
                    |editor| -> Result<(), TrapError> {
                        editor.begin_undo();
                        Self::refresh_stage1_exclusivity(editor.manager);
                        editor
                            .repoint_preserving_attributes(page_va, new_ipa, span_len as u64)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "repoint HVPatch retained reuse leaves: {error:?}"
                                ))
                            })?;
                        // `PtOp::Invalidate` intentionally preserves AP. A retired overlay
                        // may therefore carry invalid+RW attributes, while the deferred
                        // PROT_NONE publication is required to authenticate invalid+RO.
                        // Normalize the unpublished leaves to fork-RO/nG now; a later RW
                        // protect changes AP while preserving the exact fresh IPA.
                        editor
                            .set_fork_readonly(page_va, span_len)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "restrict HVPatch retained reuse leaves: {error:?}"
                                ))
                            })?;
                        self.publish_stage1_extension_arenas(editor.manager)?;
                        let page_table_resolver =
                            self.page_table_resolver(editor.base(), Some(page_table_host));
                        unsafe { editor.sync_to_host(page_table_resolver) }.map_err(|e| {
                            TrapError::Hypervisor(format!("retained reuse sync_to_host failed: {e:?}"))
                        })?;
                        let mut current = page_va;
                        while current < span_end {
                            let expected_ipa = new_ipa.checked_add(current - page_va).ok_or_else(|| {
                                TrapError::Hypervisor("retained reuse leaf IPA overflow".to_owned())
                            })?;
                            let shadow = editor.debug_walk(current);
                            let live = unsafe { editor.debug_walk_host(page_table_resolver, current) }
                                .map_err(|e| {
                                    TrapError::Hypervisor(format!(
                                        "retained reuse debug_walk_host failed: {e:?}"
                                    ))
                                })?;
                            if shadow != live {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained reuse shadow/live mismatch at VA 0x{current:x}"
                                )));
                            }
                            let leaf = live[3];
                            if leaf & VALID != 0
                                || leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                                || leaf & AP_MASK != AP_USER_RO
                                || leaf & NON_GLOBAL == 0
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained reuse leaf authentication failed at VA 0x{current:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x}"
                                )));
                            }
                            current = current.saturating_add(PAGE_SIZE);
                        }
                        Ok::<(), TrapError>(())
                    },
                )
        };
        if let Err(error) = publication {
            let _ = self.page_tables_authority().edit(
                || Err(()),
                |editor| {
                    let manager_base = editor.base();
                    let page_table_resolver = |base: u64| {
                        (base == manager_base)
                            .then_some(page_table_host)
                            .or_else(|| {
                                self.host_ptr(
                                    base,
                                    carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
                                )
                            })
                    };
                    // SAFETY: the COW quiesce and topology guards remain held.
                    unsafe { editor.rollback_undo(page_table_resolver) };
                    Ok::<(), ()>(())
                },
            );
            if let Err(flush_error) = flush_stage1() {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "retained reuse rollback TLBI failed: {flush_error}"
                );
            }
            Self::rollback_unpublished_mappings(
                &mut self.frame_inventory.lock(),
                &[inventory_entry],
            )?;
            return Err(error);
        }
        // Publication succeeded: the journalled pre-images are no longer needed.
        let _ = self.page_tables_authority().edit(
            || Err(()),
            |editor| {
                editor.commit_undo();
                Ok::<(), ()>(())
            },
        );
        if let Err(error) = flush_stage1() {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "retained reuse stage-1 TLBI failed: {error}"
            );
        }
        if let Err(error) = authority.apply(reservation.commit(())) {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "retained reuse inventory commit failed: {error}"
            );
        }
        owner_rollback.commit();

        match authority.mapping_is_live(
            inventory_mapping.mapping,
            inventory_mapping.frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "retained reuse compound extent is zero"
                    );
                }),
            ),
        ) {
            Ok(true) => {}
            Ok(false) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "retained reuse mapping absent after commit"
                );
            }
            Err(error) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticate retained reuse mapping: {error}"
                );
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(physical_offset as usize) };
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: page_va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span_len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: page_va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span_end,
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        self.supersede_cow_receipts("retained-reuse", page_va, span_len as u64);
        let mut pending = self.cow_deferred_publications.lock();
        let mut current = page_va;
        while current < span_end {
            pending.push(PendingFrameCowPublication {
                va: current,
                len: PAGE_SIZE as usize,
                expected_ipa: new_ipa + (current - page_va),
            });
            current = current.saturating_add(PAGE_SIZE);
        }
        // This fresh frame is private to the reusing mm. A semantic arm can
        // outlive the retired physical lease (or be reintroduced by a later
        // fork from a broad arena descriptor), but carrying that arm into the
        // following `protect_range(PROT_WRITE)` would immediately force the
        // newly published leaves back to RO and fail their deferred receipt.
        if let Some(debug_va) = fork_debug_va()
            && debug_va >= page_va
            && debug_va < page_va.saturating_add(span_len as u64)
        {
            eprintln!(
                "[DISARMDBG retained-reuse pid={:?} mm={:?}] span=({page_va:#x},{span_len:#x})",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
            );
        }
        self.cow_armed.lock().disarm(CowArmedSpan {
            va: page_va,
            len: span_len,
            executable: false,
            kernel_only: false,
        });
        Ok(Some(span_end))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    pub(crate) fn publish_shared_repoint(
        &mut self,
        va: u64,
        target_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        let target_end = target_ipa.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("shared repoint target IPA overflow".to_owned())
        })?;

        let (
            physical_ipa,
            physical_size,
            physical_host_addr,
            perms,
            mapping_owner_generation,
            shared_key_base,
            shared_key_offset,
            alias_inventory_backing,
        ) = if let Some(mapping) = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            let phys_end = mapping
                .physical_ipa
                .checked_add(mapping.physical_size as u64);
            ((target_ipa >= mapping.ipa && mapping_end.is_some_and(|limit| target_end <= limit))
                || (target_ipa >= mapping.physical_ipa
                    && phys_end.is_some_and(|limit| target_end <= limit)))
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches_in(self.custody(), mapping))
        }) {
            let physical_ipa = mapping.physical_ipa;
            let physical_size = mapping.physical_size;
            let mapping_ipa = mapping.ipa;
            let mapping_host = mapping.host_addr as usize;
            let physical_offset = mapping_ipa.checked_sub(physical_ipa).ok_or_else(|| {
                TrapError::Hypervisor(
                    "shared repoint mapping precedes its physical extent".to_owned(),
                )
            })? as usize;
            let physical_host_addr =
                mapping_host.checked_sub(physical_offset).ok_or_else(|| {
                    TrapError::Hypervisor("shared repoint physical host underflow".to_owned())
                })?;
            let owner_gen = mapping
                .structural_owner
                .as_ref()
                .map(|owner| owner.epoch().raw())
                .unwrap_or(mapping.owner_generation);
            (
                physical_ipa,
                physical_size,
                physical_host_addr,
                mapping.perms,
                owner_gen,
                mapping.shared_key_base,
                mapping.shared_key_offset,
                None,
            )
        } else {
            let alias = alias_registry()
                .lock()
                .newest_matching_for_process(self.mm_root_slot, self.container_root, |alias| {
                    let alias_end = alias.ipa.checked_add(alias.size as u64);
                    let phys_end = alias.physical_ipa.checked_add(alias.physical_size as u64);
                    ((target_ipa >= alias.ipa
                        && alias_end.is_some_and(|limit| target_end <= limit))
                        || (target_ipa >= alias.physical_ipa
                            && phys_end.is_some_and(|limit| target_end <= limit)))
                        && alias_matches_process_scope(
                            alias.ownership_scope,
                            self.mm_root_slot,
                            self.container_root,
                        )
                        && (!self.persistent_vm_lifecycle
                            || !is_reusable_global_frame_extent(
                                alias.physical_ipa,
                                alias.physical_size as u64,
                            )
                            || global_frame_host_owner_matches_in(
                                self.custody(),
                                alias.physical_ipa,
                                alias.physical_size as u64,
                                alias.physical_host_addr,
                                alias.owner_generation,
                            ))
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "shared repoint IPA 0x{target_ipa:x} size {len} has no physical owner"
                    ))
                })?;
            let perms = match alias.perms {
                0 => applevisor::memory::MemPerms::None,
                1 => applevisor::memory::MemPerms::Read,
                2 => applevisor::memory::MemPerms::Write,
                3 => applevisor::memory::MemPerms::ReadWrite,
                4 => applevisor::memory::MemPerms::Exec,
                5 => applevisor::memory::MemPerms::ReadExec,
                6 => applevisor::memory::MemPerms::WriteExec,
                7 => applevisor::memory::MemPerms::ReadWriteExec,
                _ => applevisor::memory::MemPerms::ReadWrite,
            };
            (
                alias.physical_ipa,
                alias.physical_size,
                alias.physical_host_addr,
                perms,
                alias.owner_generation,
                alias.shared_key_base,
                alias.shared_key_offset,
                Some(alias.inventory_backing),
            )
        };

        let semantic_offset = target_ipa.checked_sub(physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("shared repoint precedes its physical extent".to_owned())
        })?;
        let host_addr = physical_host_addr
            .checked_add(semantic_offset as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("shared repoint semantic host overflow".to_owned())
            })?;

        let inventory_backing = alias_inventory_backing
            .or_else(|| {
                let registry = alias_registry().lock();
                registry
                    .physical_start_rows(physical_ipa)
                    .iter()
                    .find(|(_, alias)| alias.physical_size == physical_size)
                    .map(|(_, alias)| alias.inventory_backing)
                    .or_else(|| {
                        registry
                            .physical_start_rows(physical_ipa)
                            .first()
                            .map(|(_, alias)| alias.inventory_backing)
                    })
            })
            .or_else(|| {
                self.frame_inventory
                    .lock()
                    .extents
                    .get(&(physical_ipa, physical_size as u64))
                    .map(|extent| extent.backing)
            })
            .or_else(|| (!self.persistent_vm_lifecycle).then(HvfVmState::private_backing_identity))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "shared repoint physical IPA 0x{:x} size {} lacks frame inventory",
                    physical_ipa, physical_size
                ))
            })?;

        let owner_generation =
            if is_reusable_global_frame_extent(physical_ipa, physical_size as u64) {
                global_frame_host_owner_generation_in(
                    self.custody(),
                    physical_ipa,
                    physical_size as u64,
                )
            } else {
                mapping_owner_generation
            };

        self.page_tables_authority().edit(
            || {
                Err(TrapError::Hypervisor(
                    "repoint shared leaf stage-1 tables are absent".to_owned(),
                ))
            },
            |tables| {
                tables
                    .map_aliased(va, target_ipa, len as u64, true)
                    .map_err(|e| {
                        TrapError::Hypervisor(format!("repoint shared leaf pt edit: {e:?}"))
                    })
            },
        )?;

        let shared_key_offset = shared_key_offset.saturating_add(semantic_offset);
        let sharing = GuestMappingSharing::GlobalShared;
        register_shared_alias(AliasBacking {
            start: va,
            ipa: target_ipa,
            host_addr,
            size: len,
            physical_ipa,
            physical_host_addr,
            physical_size,
            perms: u64::from(perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: va,
            ipa: target_ipa,
            physical_ipa,
            end: va.saturating_add(len as u64),
            host_addr: host_addr as *mut u8,
            size: len,
            physical_size,
            perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        Ok(())
    }

    /// Walk the guest's live stage-1 page tables to resolve `va`→IPA (the output
    /// address carrick `hv_vm_map`'d). `None` if unmapped. Used to disambiguate
    /// overlapping high-VA alias regions in `mapping_for_range[_mut]`.
    pub(crate) fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables_authority()
            .with_manager(|manager| manager.translate(va))
            .flatten()
    }

    pub(crate) fn live_stage1_names_writable_private_mapping(
        &self,
        custody: &CarrierVmCustody,
        fault_va: u64,
        mapping: MappingView,
    ) -> Result<bool, TrapError> {
        const VALID_PAGE: u64 = 0b11;
        const NON_GLOBAL: u64 = 1 << 11;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RW: u64 = 0b01 << 6;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const PAGE_SIZE: u64 = 4 * 1024;

        let page_va = align_down(fault_va, PAGE_SIZE);
        let expected_ipa = mapping
            .ipa
            .checked_add(page_va.checked_sub(mapping.start).ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE precedes mapping start".to_owned())
            })?)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch winner PTE IPA overflow".to_owned()))?;
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE page-table backing is absent".to_owned())
            })?;
        let page_tables_authority = self.page_tables_authority();
        page_tables_authority
            .with_manager(|manager| -> Result<bool, TrapError> {
                let shadow = manager.debug_walk(page_va);
                let page_table_resolver =
                    self.page_table_resolver(manager.base(), Some(page_table_host));
                let live = unsafe { manager.debug_walk_host(page_table_resolver, page_va) }
                    .map_err(|e| {
                        TrapError::Hypervisor(format!(
                            "HVPatch winner PTE debug_walk_host failed: {e:?}"
                        ))
                    })?;
                if shadow != live {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch winner PTE shadow/live mismatch at VA 0x{page_va:x}: shadow={shadow:x?} live={live:x?}"
                    )));
                }
                let leaf = live[3];
                Ok(leaf & VALID_PAGE == VALID_PAGE
                    && leaf & NON_GLOBAL != 0
                    && leaf & AP_MASK == AP_USER_RW
                    && leaf & PA_MASK_4KIB == expected_ipa & PA_MASK_4KIB)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE manager is absent".to_owned())
            })?
    }

    /// Called only under the COW quiesce and topology guards. Use the complete
    /// physical alias bucket, not only live leaves: even a retained invalid
    /// projection or a foreign/stale alias conservatively prevents reuse.
    pub(crate) fn private_cow_lane_candidate(
        &self,
        custody: &CarrierVmCustody,
        authority: &dyn carrick_hal::FrameCowAuthority,
        span: CowArmedSpan,
        source_ipa: u64,
        offset: u64,
    ) -> Option<(PhysicalCowSource, InventoryExtent)> {
        if span.len != 0x1000 || span.kernel_only || span.va % 0x1000 != 0 {
            return None;
        }
        let scope = AliasRegistry::owned_scope(self.mm_root_slot, self.container_root);
        let base = align_down(span.va, CowArmedRanges::COMPOUND_SIZE);
        for lane in 0..4 {
            let neighbor = base + lane * 0x1000;
            if neighbor == span.va {
                continue;
            }
            let Some(ipa) = self.translate_va_for_cow(neighbor) else {
                continue;
            };
            let key = (
                align_down(ipa, CowArmedRanges::COMPOUND_SIZE),
                CowArmedRanges::COMPOUND_SIZE,
            );
            if key.0 == source_ipa {
                continue;
            }
            let extent = {
                let inventory = self.frame_inventory.lock();
                let Some(extent) = inventory.extents.get(&key).copied() else {
                    continue;
                };
                let frames = inventory.frames.lock();
                if frames.references.get(&extent.frame) != Some(&1)
                    || frames.extent_references.get(&(extent.frame, key.0, key.1)) != Some(&1)
                    || frames.stage2_references.get(&key) != Some(&1)
                {
                    continue;
                }
                extent
            };
            let aliases: Vec<_> = alias_registry()
                .lock()
                .by_physical_start
                .get(&key.0)
                .into_iter()
                .flatten()
                .map(|(_, alias)| *alias)
                .collect();
            if !cow_lane_is_unpublished(key, extent, scope, offset, &aliases) {
                continue;
            }
            let length =
                carrick_hal::FrameLength::from_mapping_extent(std::num::NonZeroU64::new(key.1)?);
            if authority.frame_mapping_count(extent.frame).ok() != Some(Some(1))
                || authority
                    .mapping_is_live(
                        extent.mapping,
                        extent.frame,
                        carrick_guest_mem::Gpa(key.0),
                        length,
                    )
                    .ok()
                    != Some(true)
            {
                continue;
            }
            let Some(pin) = pin_exact_live_global_frame_owner_in(
                custody,
                key.0,
                key.1,
                extent.stage2_owner.host_addr,
                extent.stage2_owner.generation,
            ) else {
                continue;
            };
            return Some((PhysicalCowSource::pinned(pin, 0, key.0), extent));
        }
        None
    }

    pub(crate) fn perform_frame_cow(
        &mut self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        fault_va: u64,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        trigger: FrameCowTrigger,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no inventory authority".to_owned())
        })?;
        // Lock order matches every runtime page-table editor: pause sibling
        // walkers first, then serialize shared HVF stage-2/alias topology.
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch frame COW: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another vCPU of this mm may have won while we waited for topology.
        // Take only what the fault path needs. This used to CLONE the whole
        // armed-range vector on EVERY COW fault — a heap allocation and copy
        // proportional to the mm's armed range count — to serve one boolean
        // and two diagnostics. A fork arms every private writable range, so
        // the clone grew with the very thing the faults are resolving.
        let (span, armed_is_empty, armed_len) = {
            let cow_armed = self.cow_armed.lock();
            (
                cow_armed.span_for(fault_va),
                cow_armed.ranges.is_empty(),
                cow_armed.ranges.len(),
            )
        };
        let Some(span) = span else {
            let mapping = self.mapping_for_range_in(custody, fault_va, 1);
            let write_denied = self.protections.range_write_denied(fault_va, 1);
            let private_writable_mapping = mapping.is_some_and(|mapping| {
                mapping.guest_writable && mapping.sharing == GuestMappingSharing::Private
            });
            let live_leaf_is_writable = match mapping {
                Some(mapping) if private_writable_mapping && !write_denied => {
                    self.live_stage1_names_writable_private_mapping(custody, fault_va, mapping)?
                }
                _ => false,
            };
            if let Some(debug_va) = fork_debug_va()
                && align_down(fault_va, 4 * 1024) == align_down(debug_va, 4 * 1024)
            {
                eprintln!(
                    "[COWDBG pid={} tid={}] UNARMED fault va={fault_va:#x} mm={:?} \
                     mapping={:?} write_denied={write_denied} \
                     private_writable={private_writable_mapping} \
                     live_leaf_writable={live_leaf_is_writable} armed_count={}",
                    identity.linux_pid,
                    identity.linux_tid,
                    identity.mm,
                    mapping.map(|m| (m.start, m.end, m.ipa, m.guest_writable, m.sharing)),
                    armed_len,
                );
            }
            match unarmed_permission_fault_route(
                private_writable_mapping,
                write_denied,
                !armed_is_empty,
                live_leaf_is_writable,
            ) {
                UnarmedPermissionFaultRoute::NotCow => return Ok(false),
                UnarmedPermissionFaultRoute::RetryCommittedWinner => {
                    // The exact live descriptor is already writable and names
                    // the current private mapping: a sibling won this COW while
                    // this vCPU was parking. Flush the losing vCPU's stale RO
                    // translation and retry the faulting instruction.
                    flush_stage1()?;
                    return Ok(true);
                }
                UnarmedPermissionFaultRoute::MissingArm => {
                    let mapping_shape = mapping.map(|mapping| {
                        (
                            mapping.start,
                            mapping.end,
                            mapping.ipa,
                            mapping.guest_writable,
                            mapping.sharing,
                        )
                    });
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch private writable permission fault at VA 0x{fault_va:x} has no COW arm; mapping={mapping_shape:?} write_denied={write_denied} armed={:?}",
                        // Only the fatal path pays to materialize the list.
                        self.cow_armed.lock().ranges
                    )));
                }
            }
        };
        // COW allocation is physical at the 16 KiB host compound, but guest
        // access authority is semantic at the exact fault byte. A compound can
        // cross the current `brk`, mprotect, or partial-unmap edge; rejecting
        // the whole span incorrectly SIGSEGVs a writable byte merely because an
        // adjacent page is denied. Internal backing maintenance is distinct:
        // mmap must zero a reclaimed, currently-unmapped page BEFORE publishing
        // its fresh VMA permission. It still splits/repoints the frame, while
        // the page-table publication below deliberately preserves the denied
        // descriptor until mmap's later `protect_range` commit.
        let source_guest_writable = self
            .mapping_for_range_in(custody, fault_va, 1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{fault_va:x} has no semantic mapping authority"
                ))
            })?
            .guest_writable;
        if frame_cow_write_is_denied(
            self.protections.range_write_denied(fault_va, 1),
            source_guest_writable,
            intent,
        ) {
            return Ok(false);
        }
        // `span.va` can name the host-granule prefix of a semantic fragment
        // whose first live Linux leaf begins at `fault_va` (Task 1 deliberately
        // keeps semantic and physical extents separate). A guest fault proves
        // that the exact byte translated; backing maintenance may intentionally
        // start from an invalid munmap descriptor, so the mapping-metadata
        // fallback is authoritative for that pre-publication transaction.
        let old_fault_ipa = self.translate_va_for_cow(fault_va).or_else(|| {
            let mapping = self.mapping_for_range_in(custody, fault_va, 1)?;
            mapping
                .ipa
                .checked_add(fault_va.checked_sub(mapping.start)?)
        });
        if let Some(debug_va) = fork_debug_va()
            && align_down(fault_va, 4 * 1024) == align_down(debug_va, 4 * 1024)
        {
            eprintln!(
                "[COWDBG pid={} tid={}] ARMED fault va={fault_va:#x} mm={:?} span=({:#x},{:#x}) old_fault_ipa={old_fault_ipa:?}",
                identity.linux_pid, identity.linux_tid, identity.mm, span.va, span.len,
            );
        }
        let semantic_offset = fault_va.checked_sub(span.va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW fault precedes its armed span".to_owned())
        })?;
        let old_ipa = old_fault_ipa
            .and_then(|ipa| ipa.checked_sub(semantic_offset))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{:x} (fault 0x{fault_va:x}) has no stage-1 or mapping translation",
                    span.va
                ))
            })?;
        let old_source = self
            .physical_cow_source_in(custody, span.va, old_ipa)
            .ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "HVPatch COW VA 0x{:x} IPA 0x{old_ipa:x} has no matching 16 KiB physical backing",
                span.va
            ))
        })?;
        let old_host = old_source.host_addr();
        let old_physical_ipa = old_source.physical_ipa();
        // The semantic span sits at `old_offset` WITHIN its 16 KiB compound.
        // The COW replacement must preserve that intra-compound offset: the
        // 2026-08-23 wedge2 change flattened `new_ipa`/`semantic_host` to the
        // compound base, which COWs the WRONG PAGE for every span whose
        // offset is nonzero — forkcow's child then reads unrelated bytes and
        // SIGSEGVs (bisect-convicted, red 3/3 at that commit, green 3/3 at
        // its parent).
        let old_offset = old_ipa.checked_sub(old_physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW physical offset underflow".to_owned())
        })?;
        let retention_aliases = authenticated_cow_retention_aliases_in(
            custody,
            self.mm_root_slot,
            self.container_root,
            old_physical_ipa,
        );
        let retain_old_compound = {
            let page_tables_authority = self.page_tables_authority();
            let retain = page_tables_authority.with_manager(|manager| {
                cow_source_has_retained_projection(
                    span,
                    old_ipa,
                    old_physical_ipa,
                    &retention_aliases,
                    |va| manager.translate_retained_output(va),
                )
            });
            match retain {
                Some(retain) => retain,
                None => {
                    page_tables_authority.emit_absent_probe(1);
                    return Err(TrapError::Hypervisor(
                        "HVPatch COW page-table manager is absent".to_owned(),
                    ));
                }
            }
        };
        let CowInventorySplitShape {
            old_key: old_inventory_key,
            old: old_inventory_extent,
            fragments: fragment_shapes,
            retirement,
        } = {
            let inventory = self.frame_inventory.lock();
            HvfVmState::cow_inventory_split_shape(
                &inventory,
                old_physical_ipa,
                retain_old_compound,
                |frame| {
                    authority.frame_mapping_count(frame).map_err(|error| {
                        TrapError::Hypervisor(format!("query COW frame mapping count: {error}"))
                    })
                },
            )?
        };
        let old_frame = old_inventory_extent.frame;
        // Resolve every authority needed for stage-1 publication before the
        // first physical/staged-inventory mutation.  A fork-time response can
        // run while the engine's mapping metadata is being rebuilt; failing
        // here must leave no staged MappingId for terminal retirement to see.
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW page-table backing is absent".to_owned())
            })?;

        let receipt_va = align_down(fault_va, 4 * 1024);
        let trigger_event = carrick_observability::probes::HvpatchFrameCowTrigger::new(
            trigger.class,
            identity.linux_pid,
            identity.linux_tid,
            identity.mm,
            u32::from(identity.asid),
            receipt_va,
            trigger.syndrome,
            trigger.far,
            trigger.ttbr0,
        )
        .unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "construct HVPatch frame-COW trigger: {error}"
            );
        });
        crate::probes::hvpatch_frame_cow_trigger(trigger_event);

        let reused_destination = if matches!(
            old_inventory_extent.backing,
            InventoryBackingIdentity::PrivateFileView(_)
        ) && intent
            == carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
        {
            self.private_cow_lane_candidate(
                custody,
                authority.as_ref(),
                span,
                old_physical_ipa,
                old_offset,
            )
        } else {
            None
        };
        let reused_extent = reused_destination.as_ref().map(|(_, extent)| *extent);
        let fresh_destination = reused_extent.is_none();
        // Reserve every kernel identity/event slot before physical mutation.
        let mapping_candidates = fragment_shapes
            .len()
            .saturating_add(usize::from(fresh_destination));
        let event_count = 1usize
            .saturating_add(mapping_candidates.saturating_mul(2))
            .saturating_add(usize::from(retirement.retire_old_frame));
        let mut reservation = authority
            .reserve(
                usize::from(fresh_destination),
                mapping_candidates,
                event_count,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!("reserve frame COW inventory: {error}"))
            })?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let pooled = if fresh_destination {
            custody.frame_pool().and_then(|p| p.allocate_compound())
        } else {
            None
        };
        let (new_host_ptr, new_physical_ipa, owner_generation) =
            if let Some((destination, extent)) = &reused_destination {
                // No published alias names this lane. Only the newly touched Linux
                // page is refreshed; previously written neighbors are never copied.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host.add(old_offset as usize),
                        destination.host_addr().add(old_offset as usize),
                        span.len,
                    );
                    crate::probes::hvpatch_frame_cow_copy(
                        old_frame.raw(),
                        old_ipa,
                        std::slice::from_raw_parts(old_host.add(old_offset as usize), span.len),
                        std::slice::from_raw_parts(
                            destination.host_addr().add(old_offset as usize),
                            span.len,
                        ),
                    );
                }
                drop(old_source);
                (
                    destination.host_addr(),
                    destination.physical_ipa(),
                    extent.stage2_owner.generation,
                )
            } else if let Some(handle) = pooled {
                let host_ptr = handle.as_mut_ptr();
                let physical_ipa = handle.ipa();
                carrick_observability::probes::hvpatch_frame_pool_hit(0, physical_ipa);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host,
                        host_ptr,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    );
                }
                let source = unsafe {
                    std::slice::from_raw_parts(
                        old_host.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                let destination = unsafe {
                    std::slice::from_raw_parts(
                        host_ptr.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                crate::probes::hvpatch_frame_cow_copy(
                    old_frame.raw(),
                    old_physical_ipa,
                    source,
                    destination,
                );
                drop(old_source);
                let owner_generation = register_pooled_global_frame_host_owner_in(
                    custody,
                    handle,
                    u64::from(stage2_perms),
                )?;
                (host_ptr, physical_ipa, owner_generation)
            } else {
                carrick_observability::probes::hvpatch_frame_pool_miss(0, 0);
                let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    CowArmedRanges::COMPOUND_SIZE as usize,
                    crate::host_mapping::HostMappingKind::FrameCow,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!("allocate frame COW backing: {error}"))
                })?;
                let new_host_ptr = new_host.as_ptr();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host,
                        new_host_ptr,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    );
                }
                let source = unsafe {
                    std::slice::from_raw_parts(
                        old_host.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                let destination = unsafe {
                    std::slice::from_raw_parts(
                        new_host_ptr.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                crate::probes::hvpatch_frame_cow_copy(
                    old_frame.raw(),
                    old_physical_ipa,
                    source,
                    destination,
                );
                drop(old_source);
                let mut new_lease = GlobalFrameStage2Lease::reserve(
                    CowArmedRanges::COMPOUND_SIZE,
                    CowArmedRanges::COMPOUND_SIZE,
                )?;
                let new_physical_ipa = new_lease.base;
                let map_result = unsafe {
                    inventory_hv_vm_map(
                        new_host_ptr.cast(),
                        new_physical_ipa,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                        u64::from(stage2_perms),
                    )
                };
                if map_result != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "map frame COW IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
                    )));
                }
                new_lease.mark_mapped();
                let owner_generation = register_global_frame_host_owner_in(
                    custody,
                    new_lease,
                    new_host,
                    u64::from(stage2_perms),
                )?;
                (new_host_ptr, new_physical_ipa, owner_generation)
            };
        let new_ipa = new_physical_ipa
            .checked_add(old_offset)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW semantic IPA overflow".to_owned()))?;

        let backing = reused_extent.map_or_else(HvfVmState::private_backing_identity, |extent| {
            extent.backing
        });
        let split = match HvfVmState::stage_cow_inventory_split(
            &mut reservation,
            old_inventory_key,
            old_inventory_extent,
            &fragment_shapes,
            retirement,
            CowInventoryReplacementStage {
                existing: reused_extent,
                gpa: new_physical_ipa,
                backing,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: new_host_ptr as usize,
                    generation: owner_generation,
                },
            },
        ) {
            Ok(split) => split,
            Err(error) => {
                if fresh_destination {
                    let _ = retire_global_frame_host_owner_in(
                        custody,
                        new_physical_ipa,
                        CowArmedRanges::COMPOUND_SIZE,
                    );
                }
                return Err(error);
            }
        };
        let new_frame = split.new_extent.frame;
        let new_mapping = split.new_extent.mapping;
        const PAGE_SIZE: u64 = 4 * 1024;
        let receipt_intent = match intent {
            carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                carrick_observability::probes::HvpatchFrameCowIntent::GuestVisible
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                carrick_observability::probes::HvpatchFrameCowIntent::BackingMaintenance
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                carrick_observability::probes::HvpatchFrameCowIntent::PrivilegedInternal
            }
        };
        let emit_cow = |phase| {
            let event = carrick_observability::probes::HvpatchFrameCow::new(
                phase,
                receipt_intent,
                identity.linux_pid,
                identity.linux_tid,
                identity.mm,
                u32::from(identity.asid),
                receipt_va,
                old_frame.raw(),
                new_frame.raw(),
                old_physical_ipa,
                new_physical_ipa,
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "construct HVPatch frame-COW receipt: {error}"
                );
            });
            crate::probes::hvpatch_frame_cow(event);
        };
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage2Mapped);
        // Journal this transaction's descriptor pre-images rather than
        // cloning the whole 1.75 MiB table region (see `begin_undo`).
        let mut preserved_protection_receipt = None;
        let page_table_result = {
            const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            const VALID: u64 = 1;
            const TYPE_TABLE_OR_PAGE: u64 = 0b11;
            const NON_GLOBAL: u64 = 1 << 11;
            let page_tables_authority = self.page_tables_authority();
            page_tables_authority
                .edit(
                    || {
                        page_tables_authority.emit_absent_probe(2);
                        Err(TrapError::Hypervisor(
                            "HVPatch COW page-table manager is absent".to_owned(),
                        ))
                    },
                    |manager| -> Result<(), TrapError> {
                        // The transaction can fail after one or more descriptors were
                        // written to both the manager shadow and live backing, so it needs
                        // a rollback log; the manager's `dirty` list is not one, because
                        // `sync_to_host` drains the NEW edits. `begin_undo` journals the
                        // pre-image of every descriptor this transaction writes.
                        manager.begin_undo();
                        // The leaf authentication below needs the AP bits each page held
                        // BEFORE this transaction, which it used to read by walking a full
                        // cloned pre-image. The span is a single 16 KiB compound, so
                        // capturing just those bits is exact and costs a handful of walks
                        // instead of a 1.75 MiB copy.
                        let mut pre_edit_ap: std::collections::BTreeMap<u64, u64> =
                            std::collections::BTreeMap::new();
                        {
                            let span_end = span.va.saturating_add(span.len as u64);
                            let mut probe_va = span.va & !(PAGE_SIZE - 1);
                            while probe_va < span_end {
                                pre_edit_ap.insert(probe_va, manager.debug_walk(probe_va)[3] & AP_MASK);
                                probe_va = probe_va.saturating_add(PAGE_SIZE);
                            }
                        }
                        HvfVmState::refresh_stage1_exclusivity(manager.manager);
                        if span.kernel_only {
                            manager
                                .map_kernel_aliased(span.va, new_ipa, span.len as u64)
                                .map_err(|error| {
                                    TrapError::Hypervisor(format!(
                                        "publish kernel-only HVPatch COW stage-1 leaf: {error:?}"
                                    ))
                                })?;
                        } else {
                            manager
                                .repoint_preserving_attributes(span.va, new_ipa, span.len as u64)
                                .map_err(|error| {
                                    TrapError::Hypervisor(format!(
                                        "repoint HVPatch COW stage-1 compound: {error:?}"
                                    ))
                                })?;
                            let span_end = span.va.saturating_add(span.len as u64);
                            let mut page_va = span.va & !(PAGE_SIZE - 1);
                            while page_va < span_end {
                                if source_guest_writable && !self.protections.range_write_denied(page_va, 1) {
                                    manager
                                        .set_writable_preserving_attributes(page_va, PAGE_SIZE as usize)
                                        .map_err(|error| {
                                            TrapError::Hypervisor(format!(
                                                "grant HVPatch COW semantic page write: {error:?}"
                                            ))
                                        })?;
                                }
                                page_va = page_va.saturating_add(PAGE_SIZE);
                            }
                        }
                        self.publish_stage1_extension_arenas(manager.manager)?;
                        let page_table_resolver =
                            self.page_table_resolver(manager.base(), Some(page_table_host));
                        unsafe { manager.sync_to_host(page_table_resolver) }.map_err(|e| {
                            TrapError::Hypervisor(format!("HVPatch COW sync_to_host failed: {e:?}"))
                        })?;

                        // A semantic fork result is not structural proof.  Before the
                        // stage-1 TLBI publishes this transaction, authenticate the exact
                        // descriptors the hardware walker will consume: the manager shadow
                        // and live backing must agree, every 4 KiB leaf in this 16 KiB COW
                        // compound must name the new global frame IPA, and its AP bits must
                        // match the EL1-only/user regime.  Fail closed while the old armed
                        // leaf is still live on any mismatch.
                        let span_end = span.va.saturating_add(span.len as u64);
                        let mut page_va = span.va & !(PAGE_SIZE - 1);
                        while page_va < span_end {
                            let expected_ipa = new_ipa.checked_add(page_va - span.va).ok_or_else(|| {
                                TrapError::Hypervisor("HVPatch COW leaf IPA overflow".to_owned())
                            })?;
                            let shadow = manager.debug_walk(page_va);
                            let live = unsafe {
                                manager.debug_walk_host(page_table_resolver, page_va)
                            }
                            .map_err(|e| {
                                TrapError::Hypervisor(format!(
                                    "HVPatch COW debug_walk_host failed: {e:?}"
                                ))
                            })?;
                            if shadow != live {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch COW shadow/live mismatch at VA 0x{page_va:x}"
                                )));
                            }
                            let leaf = live[3];
                            let page_is_valid = leaf & VALID != 0;
                            let expected_ap = if span.kernel_only {
                                0
                            } else if source_guest_writable
                                && !self.protections.range_write_denied(page_va, 1)
                            {
                                AP_USER_RW
                            } else {
                                pre_edit_ap.get(&page_va).copied().ok_or_else(|| {
                                    TrapError::Hypervisor(format!(
                                        "HVPatch COW pre-edit AP bits are absent for VA 0x{page_va:x}"
                                    ))
                                })?
                            };
                            if leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                                || (page_is_valid
                                    && (leaf & 0b11 != TYPE_TABLE_OR_PAGE
                                        || leaf & AP_MASK != expected_ap
                                        || (!span.kernel_only && leaf & NON_GLOBAL == 0)))
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch COW stage-1 leaf authentication failed at VA 0x{page_va:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x}"
                                )));
                            }
                            if page_va == receipt_va && frame_cow_preserves_guest_protection(intent) {
                                preserved_protection_receipt =
                                    Some((page_va, leaf, expected_ipa, leaf & AP_MASK));
                            } else if page_va == receipt_va {
                                crate::probes::pt_alias_receipt(page_va, leaf, expected_ipa, expected_ap, 2);
                            }
                            // Reuse the durable descriptor-walk probe so a signed live
                            // capture can bind the COW receipt to the exact published PTE.
                            crate::probes::pt_alias_walk(page_va, live, 1 << 3);
                            page_va = page_va.saturating_add(PAGE_SIZE);
                        }
                        Ok(())
                    },
                )
        };
        if let Err(error) = page_table_result {
            let _ = self.page_tables_authority().edit(
                || Err(()),
                |manager| {
                    let manager_base = manager.base();
                    let page_table_resolver = |base: u64| {
                        (base == manager_base)
                            .then_some(page_table_host)
                            .or_else(|| {
                                self.host_ptr_for_ipa(
                                    base,
                                    carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
                                )
                            })
                    };
                    // SAFETY: the COW quiesce and topology guards remain held;
                    // no vCPU can walk or edit this mm while the journalled
                    // pre-images are replayed into its live backing.
                    unsafe { manager.rollback_undo(page_table_resolver) };
                    Ok::<(), ()>(())
                },
            );
            if let Err(flush_error) = flush_stage1() {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "HVPatch COW rollback stage-1 TLBI failed: {flush_error}"
                );
            }
            if fresh_destination {
                let _ = retire_global_frame_host_owner_in(
                    custody,
                    new_physical_ipa,
                    CowArmedRanges::COMPOUND_SIZE,
                );
            }
            return Err(error);
        }
        // Publication succeeded: the journalled pre-images are no longer needed.
        let _ = self.page_tables_authority().edit(
            || Err(()),
            |manager| {
                manager.commit_undo();
                Ok::<(), ()>(())
            },
        );
        if let Err(error) = flush_stage1() {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "HVPatch COW stage-1 TLBI failed: {error}"
            );
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage1Published);
        if let Err(error) = authority.apply(reservation.commit(())) {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch COW inventory commit failed: {error}"
            );
        }
        let inventory_ledger = std::sync::Arc::clone(&self.frame_inventory.ledger);
        let retired_old_stage2 = {
            let mut inventory = inventory_ledger.lock();
            HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || {
                self.retire_stage2_extent_for_cow(
                    custody,
                    split.old.stage2_base,
                    split.old.stage2_length,
                )
            })
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "commit HVPatch backend COW inventory after kernel commit: {error}"
                );
            })
        };
        record_cow_inventory_lifecycle(
            CowDiagnosticLifecycleKind::InventoryRemoved,
            CowDiagnosticLifecycleSite::CowCommit,
            custody,
            self.cow_identity,
            self.mm_root_slot,
            span.va,
            span.len as u64,
            split.old_key,
            split.old,
        );
        for fragment in &split.fragments {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryPublished,
                CowDiagnosticLifecycleSite::CowCommit,
                custody,
                self.cow_identity,
                self.mm_root_slot,
                span.va,
                span.len as u64,
                (fragment.gpa, fragment.length),
                InventoryExtent {
                    frame: split.old.frame,
                    mapping: fragment.mapping,
                    backing: split.old.backing,
                    stage2_base: split.old.stage2_base,
                    stage2_length: split.old.stage2_length,
                    stage2_owner: split.old.stage2_owner,
                },
            );
        }
        if fresh_destination {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryPublished,
                CowDiagnosticLifecycleSite::CowCommit,
                custody,
                self.cow_identity,
                self.mm_root_slot,
                span.va,
                span.len as u64,
                split.new_key,
                split.new_extent,
            );
        }
        if retired_old_stage2 {
            {
                // Exact physical-owner selection plus a single rebuild of
                // each affected scope. This runs on every COW fault, so it
                // must not clone/diff or retain-scan carrier-global state.
                let retired = [RetiredStage2Projection::from(split.old)];
                let cleanup = mutate_known_external_alias_state(
                    |_, registry| retired_projection_mutation_keys(registry, &retired, &[]),
                    |replay, registry| {
                        remove_rows_for_retired_stage2_projections(replay, registry, &retired)
                    },
                );
                for alias in &cleanup.preserved_reused_aliases {
                    record_cow_alias_lifecycle(
                        CowDiagnosticLifecycleKind::AliasPreservedReused,
                        CowDiagnosticLifecycleSite::CowCommit,
                        Some(custody),
                        self.cow_identity,
                        self.mm_root_slot,
                        *alias,
                    );
                }
                for alias in &cleanup.removed_aliases {
                    record_cow_alias_lifecycle(
                        CowDiagnosticLifecycleKind::AliasRemoved,
                        CowDiagnosticLifecycleSite::CowCommit,
                        Some(custody),
                        self.cow_identity,
                        self.mm_root_slot,
                        *alias,
                    );
                }
            }
            self.mappings.remove_rows_matching_in_ranges(
                &[MappingExtent::Ipa(
                    split.old.stage2_base,
                    split.old.stage2_length,
                )],
                |mapping| mapped_region_matches_retired_inventory_extent(mapping, split.old.into()),
            );
        }
        let Some(cow_extent) = std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE) else {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch COW compound extent is zero"
            );
        };
        let cow_length = carrick_hal::FrameLength::from_mapping_extent(cow_extent);
        match authority.mapping_is_live(
            new_mapping,
            new_frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            cow_length,
        ) {
            Ok(true) => {}
            Ok(false) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticated HVPatch COW mapping {new_mapping:?} was absent immediately after commit"
                );
            }
            Err(error) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticate HVPatch COW mapping {new_mapping:?}: {error}"
                );
            }
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Committed);
        // The repoint above replaced this span's stage-1 output. Any receipt
        // still naming the PREVIOUS owner for these VAs — typically the
        // sparse-mmap extent published moments earlier in the very same guest
        // `mmap`, whose leaves are deliberately invalid until the protection
        // commit — is now a false promise, and would fail the authentication
        // that completes this mapping.
        self.supersede_cow_receipts_for_cow(span.va, span.len as u64);
        if let Some((va, leaf, expected_ipa, expected_ap)) = preserved_protection_receipt {
            crate::probes::pt_alias_receipt(va, leaf, expected_ipa, expected_ap, 3);
            if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance {
                self.cow_deferred_publications
                    .lock()
                    .push(PendingFrameCowPublication {
                        va,
                        len: PAGE_SIZE as usize,
                        expected_ipa,
                    });
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(old_offset as usize) };
        let alias = AliasBacking {
            start: span.va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span.len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: source_guest_writable,
            sharing: GuestMappingSharing::Private,
            ownership_scope: alias_ownership_scope(
                GuestMappingSharing::Private,
                self.mm_root_slot,
                self.container_root,
            ),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        };
        register_shared_alias(alias);
        record_cow_alias_lifecycle(
            CowDiagnosticLifecycleKind::AliasPublished,
            CowDiagnosticLifecycleSite::CowCommit,
            Some(custody),
            self.cow_identity,
            self.mm_root_slot,
            alias,
        );
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::CowPublication,
            custody,
            self.cow_identity,
            new_physical_ipa,
            alias_registry().lock().revision(),
        );
        self.mappings.insert(HvfMappedRegion {
            start: span.va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span.va.saturating_add(span.len as u64),
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: source_guest_writable,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        record_cow_diagnostic_event(CowDiagnosticEvent::ReplacementCommitted {
            custody: custody.as_ref() as *const CarrierVmCustody as usize,
            linux_pid: identity.linux_pid,
            mm: identity.mm,
            semantic_va: span.va,
            old_physical_ipa,
            new_physical_ipa,
            new_host_addr: new_host_ptr as usize,
            new_owner_generation: owner_generation,
            new_frame: new_frame.raw(),
            new_mapping: new_mapping.raw(),
            retired_old_stage2,
        });
        if let Some(debug_va) = fork_debug_va()
            && debug_va >= span.va
            && debug_va < span.va.saturating_add(span.len as u64)
        {
            eprintln!(
                "[DISARMDBG split pid={:?} mm={:?}] span=({:#x},{:#x}) new_ipa={new_ipa:#x}",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                span.va,
                span.len,
            );
        }
        self.cow_armed.lock().disarm(span);
        Ok(true)
    }

    pub(crate) fn refresh_fork_process_state_in(
        &mut self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let generation_address =
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64;
        if self.cow_armed.lock().span_for(generation_address).is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch child vvar generation has no COW arm".to_owned(),
            ));
        }
        if !self.perform_frame_cow(
            custody,
            generation_address,
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal,
            FrameCowTrigger {
                class:
                    carrick_observability::probes::HvpatchFrameCowTriggerClass::PrivilegedInternal,
                syndrome: 0,
                far: generation_address,
                ttbr0: 0,
            },
            flush_stage1,
        )? {
            return Err(TrapError::Hypervisor(
                "HVPatch child vvar generation COW was not resolved".to_owned(),
            ));
        }
        let mapping = self
            .mapping_for_range_in(custody, generation_address, core::mem::size_of::<u64>())
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch child vvar generation has no semantic mapping authority after COW"
                        .to_owned(),
                )
            })?;
        let offset = usize::try_from(generation_address - mapping.start).map_err(|_| {
            TrapError::Hypervisor("HVPatch child vvar generation offset overflow".to_owned())
        })?;
        let generation = next_vdso_rng_generation().to_le_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(
                generation.as_ptr(),
                mapping.host_addr.add(offset),
                generation.len(),
            );
        }
        Ok(())
    }
}

/// Does `zero_guest_backing` REPLACE an eligible reused private anonymous
/// range with fresh kernel zero pages (`mmap MAP_FIXED|MAP_ANON`) instead of
/// memsetting the old backing end to end?
///
/// **DEFAULT ON.** `CARRICK_DSR_ZERO_REMAP=0` is the exact escape hatch
/// (mirroring commit 52342762), preserving the immovable zeroed-anon guarantee
/// while touching nothing.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn zero_anonymous_remap_enabled() -> bool {
    #[cfg(not(test))]
    {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var_os("CARRICK_DSR_ZERO_REMAP").as_deref() != Some(std::ffi::OsStr::new("0"))
        })
    }
    #[cfg(test)]
    {
        std::env::var_os("CARRICK_DSR_ZERO_REMAP").as_deref() != Some(std::ffi::OsStr::new("0"))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ScrubRun {
    pub(crate) host_start: *mut u8,
    pub(crate) len: usize,
    pub(crate) eligible: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ScrubRun {
    pub(crate) fn flush(self) {
        const HOST_PAGE: usize = 16384;
        let ScrubRun {
            host_start,
            len,
            eligible,
        } = self;
        if len == 0 {
            return;
        }
        let aligned_len = if eligible && (host_start as usize) % HOST_PAGE == 0 {
            len & !(HOST_PAGE - 1)
        } else {
            0
        };
        let mut remapped = false;
        if aligned_len > 0 {
            let mapped = unsafe {
                libc::mmap(
                    host_start as *mut libc::c_void,
                    aligned_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if mapped == host_start as *mut libc::c_void {
                remapped = true;
                let tail_len = len - aligned_len;
                if tail_len > 0 {
                    unsafe {
                        core::ptr::write_bytes(host_start.add(aligned_len), 0u8, tail_len);
                    }
                }
            } else if mapped != libc::MAP_FAILED {
                unsafe {
                    libc::munmap(mapped, aligned_len);
                }
            }
        }
        if !remapped {
            unsafe {
                core::ptr::write_bytes(host_start, 0u8, len);
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn page_table_resolver<'a>(
        &'a self,
        manager_base: u64,
        primary_host: Option<*mut u8>,
    ) -> HvfPageTableResolver<'a> {
        self.task.page_table_resolver(manager_base, primary_host)
    }

    pub(crate) fn record_stage1_populated_prefix(&mut self, base: u64, prefix: usize) {
        self.task.record_stage1_populated_prefix(base, prefix);
    }

    pub(crate) fn publish_stage1_extension_arenas(
        &mut self,
        manager: &carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        self.task.publish_stage1_extension_arenas(manager)
    }

    pub(crate) fn retire_stage1_extension_arenas(
        &mut self,
        manager: &mut carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        self.task.retire_stage1_extension_arenas(manager)
    }

    pub(crate) fn resolve_frame_cow_fault(
        &mut self,
        syndrome: u64,
        far: u64,
        ttbr0: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<carrick_hal::CowFaultResolution, TrapError> {
        if is_stage1_cow_write_fault(syndrome) {
            let fault_va = strip_pointer_tag(far);
            let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
            let resolved = self.task.perform_frame_cow(
                &custody,
                fault_va,
                carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible,
                FrameCowTrigger {
                    class: carrick_observability::probes::HvpatchFrameCowTriggerClass::Stage1PermissionFault,
                    syndrome,
                    far: fault_va,
                    ttbr0,
                },
                flush_stage1,
            )?;
            if !resolved {
                return Ok(carrick_hal::CowFaultResolution::NotCow);
            }
            // The refault livelock detector keys on this live post-resolution
            // translation: a fork loop legitimately re-COWs the same VA to a
            // FRESH frame every iteration (fork re-arms the span, the wait loop
            // rewrites the same stack slot), so (FAR, ESR) alone cannot prove
            // the resolver made no progress.
            return Ok(carrick_hal::CowFaultResolution::Resolved {
                translation: self.translate_va(fault_va),
            });
        }

        // Anonymous first touch belongs to the runtime resident-fault plan,
        // which owns exact page permissions, residency and rollback authority.
        Ok(carrick_hal::CowFaultResolution::NotCow)
    }

    pub(crate) fn ensure_frame_cow_write(
        &mut self,
        va: u64,
        len: usize,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        if len == 0 {
            return Ok(());
        }
        let start = strip_pointer_tag(va);
        let end = start
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW write range overflow".to_owned()))?;
        let mut current = start;
        let mut stalled: Option<(u64, u32)> = None;
        while current < end {
            let (armed_span_end, next_armed_start) = {
                let cow_armed = self.cow_armed.lock();
                (
                    cow_armed
                        .span_for(current)
                        .map(|span| span.va.saturating_add(span.len as u64)),
                    cow_armed.next_armed_start_after(current),
                )
            };
            let armed = armed_span_end.is_some();
            let (retained_output_has_no_physical_source, retained_output_source_is_shared) =
                if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
                    && self.persistent_vm_lifecycle
                {
                    match self
                        .page_tables_authority()
                        .with_manager(|manager| manager.translate_retained_output(current))
                        .flatten()
                    {
                        Some(ipa) => {
                            // The retired-reuse materializer serves UNMAPPED
                            // VAs whose leaf retained a dead output. A LIVE VA
                            // in that state (a brk-heap page whose fork-COW
                            // lease retired underneath it) is not its case —
                            // the materializer refuses it by design, and
                            // routing it there turned every brk SHRINK over
                            // such a page into a refusal (ltp-brk02). A live
                            // VA's scrub resolves through its live backing.
                            let unmapped = self.protections.range_unmapped(current, 1);
                            let no_source =
                                unmapped && self.physical_cow_source(current, ipa).is_none();
                            let shared = unmapped
                                && !no_source
                                && self.retained_output_lacks_exclusive_claim(ipa);
                            (no_source, shared)
                        }
                        None => (false, false),
                    }
                } else {
                    (false, false)
                };
            let route = frame_cow_write_route(
                intent,
                armed,
                retained_output_has_no_physical_source,
                retained_output_source_is_shared,
            );
            if let Some(debug_va) = fork_debug_va()
                && current <= debug_va
                && debug_va < end.min(current.saturating_add(CowArmedRanges::COMPOUND_SIZE))
            {
                // Co-ownership audit for the watched VA: which physical frame
                // would a Direct write land in, and does any OTHER mm scope
                // still name that frame? A Direct GuestVisible write into a
                // frame another live mm reads is the fork-child stack-smash
                // corruption shape.
                let translation = self.translate_va(debug_va);
                let mapping = self.mapping_for_range(debug_va, 1).map(|mapping| {
                    (
                        mapping.start,
                        mapping.ipa,
                        mapping.host_addr as usize,
                        mapping.sharing,
                    )
                });
                let target_ipa =
                    mapping.map(|(start, ipa, _, _)| ipa.wrapping_add(debug_va - start));
                let co_owners: Vec<_> = target_ipa
                    .map(|ipa| {
                        alias_registry()
                            .lock()
                            .iter()
                            .filter(|alias| {
                                let base = alias.physical_ipa;
                                let end = base.saturating_add(alias.physical_size as u64);
                                ipa >= base
                                    && ipa < end
                                    && alias.ownership_scope
                                        != alias_ownership_scope(
                                            GuestMappingSharing::Private,
                                            self.mm_root_slot,
                                            self.container_root,
                                        )
                            })
                            .map(|alias| (alias.start, alias.physical_ipa, alias.ownership_scope))
                            .collect()
                    })
                    .unwrap_or_default();
                eprintln!(
                    "[ROUTEDBG pid={:?} mm={:?} slot={:x?}] va={current:#x} intent={intent:?} \
                     armed={armed} armed_len={} \
                     no_source={retained_output_has_no_physical_source} \
                     shared={retained_output_source_is_shared} route={route:?} \
                     translation={translation:x?} mapping={mapping:x?} co_owners={co_owners:x?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    self.cow_identity.map(|identity| identity.mm),
                    self.mm_root_slot,
                    self.cow_armed.lock().ranges.len(),
                );
            }
            match route {
                FrameCowWriteRoute::MaterializeRetired => {
                    if let Some(materialized_end) =
                        self.materialize_retired_reuse(current, end, flush_stage1)?
                    {
                        current = materialized_end;
                    }
                    // The materializer rechecks after acquiring quiesce. If a
                    // sibling repaired the leaf first, restart this chunk and
                    // route against the now-current stage-1/physical state.
                    // FAIL CLOSED if the restart makes no progress: a None
                    // return with UNCHANGED routing inputs re-enters this arm
                    // forever — a silent 100% CPU livelock that also starves
                    // this executor's InvalidateAsid servicing and parks every
                    // peer in consume_invalidation_acks (seen live on
                    // futexforkrequeue; core ffr-livelock-76407). Two repeats
                    // are already impossible if the recheck story holds; 16
                    // allows genuine sibling races to win first.
                    match &mut stalled {
                        Some((va, count)) if *va == current => {
                            *count += 1;
                            if *count >= 16 {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained-reuse materialization made no progress                                      at 0x{current:x} after {count} restarts                                      (intent={intent:?} armed={armed}                                      no_source={retained_output_has_no_physical_source}                                      shared={retained_output_source_is_shared}) —                                      COW routing livelock"
                                )));
                            }
                        }
                        _ => stalled = Some((current, 1)),
                    }
                    continue;
                }
                FrameCowWriteRoute::CopyOnWrite => {
                    let class = match intent {
                        carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::SyscallGuestWrite
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::BackingMaintenance
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::PrivilegedInternal
                        }
                    };
                    let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
                    if !self.task.perform_frame_cow(
                        &custody,
                        current,
                        intent,
                        FrameCowTrigger {
                            class,
                            syndrome: 0,
                            far: current,
                            ttbr0: 0,
                        },
                        flush_stage1,
                    )? {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch COW write at 0x{current:x} remained armed"
                        )));
                    }
                }
                FrameCowWriteRoute::Direct => {}
            }
            current =
                next_frame_cow_write_probe(intent, current, end, armed_span_end, next_armed_start);
        }
        Ok(())
    }

    pub(crate) fn observe_frame_cow_protection(
        &mut self,
        va: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const AP_USER_RW: u64 = 0b01 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;

        if len == 0 {
            return Ok(());
        }
        let end = va.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("deferred COW protection range overflow".to_owned())
        })?;
        let pending: Vec<_> = self
            .cow_deferred_publications
            .lock()
            .iter()
            .copied()
            .filter(|receipt| {
                receipt
                    .va
                    .checked_add(receipt.len as u64)
                    .is_some_and(|receipt_end| receipt.va < end && receipt_end > va)
            })
            .collect();
        if pending.is_empty() {
            return Ok(());
        }

        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "deferred COW protection has no page-table backing".to_owned(),
                )
            })?;
        let prot_flags = carrick_abi::LinuxProtFlags::from_bits_truncate(prot);
        let (expected_ap, phase, must_be_valid) =
            if prot_flags.contains(carrick_abi::LinuxProtFlags::WRITE) {
                (AP_USER_RW, 4, true)
            } else if prot_flags
                .intersects(carrick_abi::LinuxProtFlags::READ | carrick_abi::LinuxProtFlags::EXEC)
            {
                (AP_USER_RO, 5, true)
            } else {
                (AP_USER_RO, 6, false)
            };

        // `protect_range` re-downgrades every armed span to read-only after
        // granting PROT_WRITE (fork COW arms and the page-granular arms a
        // lowered MAP_PRIVATE file view carries), so a page inside an armed
        // range is authentic at `AP_USER_RO` even when the guest asked for
        // write access. Snapshot the arms before taking the page-table lock:
        // the two locks are never nested the other way round.
        let armed = if expected_ap == AP_USER_RW {
            self.cow_armed.lock().overlapping(va, len)
        } else {
            Vec::new()
        };
        let armed_covers = |page: u64| {
            armed.iter().any(|range| {
                range
                    .va
                    .checked_add(range.len as u64)
                    .is_some_and(|range_end| page >= range.va && page < range_end)
            })
        };

        let page_tables_authority = self.page_tables_authority();
        let authenticated = page_tables_authority
            .with_manager(|manager| -> Result<Vec<PendingFrameCowPublication>, TrapError> {
                let page_table_resolver =
                    self.page_table_resolver(manager.base(), Some(page_table_host));
                let mut authenticated = Vec::with_capacity(pending.len());
                for receipt in pending {
                    let receipt_end = receipt.va.checked_add(receipt.len as u64).ok_or_else(|| {
                        TrapError::Hypervisor("deferred COW receipt range overflow".to_owned())
                    })?;
                    let overlap_start = receipt.va.max(va);
                    let overlap_end = receipt_end.min(end);
                    if !overlap_start.is_multiple_of(PAGE_SIZE)
                        || !overlap_end.is_multiple_of(PAGE_SIZE)
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "deferred COW receipt/protection is not page aligned: receipt=0x{:x}..0x{receipt_end:x} protection=0x{va:x}..0x{end:x}",
                            receipt.va
                        )));
                    }
                    let mut page = overlap_start;
                    let mut first_leaf = None;
                    while page < overlap_end {
                        let expected_ipa = receipt
                            .expected_ipa
                            .checked_add(page - receipt.va)
                            .ok_or_else(|| {
                                TrapError::Hypervisor(
                                    "deferred COW receipt IPA range overflow".to_owned(),
                                )
                            })?;
                        let shadow = manager.debug_walk(page);
                        let live = unsafe { manager.debug_walk_host(page_table_resolver, page) }
                            .map_err(|e| {
                                TrapError::Hypervisor(format!(
                                    "deferred COW debug_walk_host failed: {e:?}"
                                ))
                            })?;
                        let leaf = carrick_mem::page_table::terminal_descriptor(live);
                        let translated = if must_be_valid {
                            manager.translate(page)
                        } else {
                            manager.translate_retained_output(page)
                        };
                        let expected_ap = if armed_covers(page) {
                            AP_USER_RO
                        } else {
                            expected_ap
                        };
                        if shadow != live
                            || !deferred_cow_leaf_authenticates(
                                leaf,
                                translated,
                                expected_ipa,
                                expected_ap,
                                must_be_valid,
                                prot_flags.contains(carrick_abi::LinuxProtFlags::EXEC),
                            )
                        {
                            return Err(TrapError::Hypervisor(format!(
                                "deferred COW protection authentication failed at VA 0x{page:x}: leaf=0x{leaf:x} translated={translated:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} valid={must_be_valid} receipt=0x{:x}+0x{:x}",
                                receipt.va, receipt.len
                            )));
                        }
                        first_leaf.get_or_insert((page, leaf, expected_ipa));
                        page = next_deferred_cow_authentication_page(live, page, overlap_end, &armed);
                    }
                    if let Some((page, leaf, expected_ipa)) = first_leaf {
                        crate::probes::pt_alias_receipt(page, leaf, expected_ipa, expected_ap, phase);
                    }
                    authenticated.push(receipt);
                }
                Ok(authenticated)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor("deferred COW protection has no page-table manager".to_owned())
            })??;

        let mut receipts = self.cow_deferred_publications.lock();
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            if !authenticated.contains(&receipt) {
                remaining.push(receipt);
                continue;
            }
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: usize::try_from(overlap_start - receipt.va).unwrap_or_else(|_| {
                        carrick_fatal!(
                            "hvpatch::cow_token",
                            "invalid leading span length in COW publication"
                        );
                    }),
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: usize::try_from(receipt_end - overlap_end).unwrap_or_else(|_| {
                        carrick_fatal!(
                            "hvpatch::cow_token",
                            "invalid trailing span length in COW publication"
                        );
                    }),
                    expected_ipa: receipt
                        .expected_ipa
                        .checked_add(overlap_end - receipt.va)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::cow_token",
                                "expected IPA overflow for trailing COW publication"
                            );
                        }),
                });
            }
        }
        *receipts = remaining;
        Ok(())
    }

    /// Create a fresh vCPU bound to this VM (the boot/clone/fork/reclaim
    /// vcpu_create; admission is the bounded scheduler's job, NOT this path).
    pub(crate) fn add_vcpu(
        &mut self,
    ) -> Result<(applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(vcpu.id());
        self.vcpu_id = vcpu.id();
        self.vcpu_handle = vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        let mailbox = self.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((vcpu, mailbox))
    }

    pub(crate) fn mailbox_host_pointer(
        &self,
        slot: MailboxSlotId,
    ) -> Result<std::ptr::NonNull<carrick_aarch64::mailbox::Aarch64SyscallMailbox>, TrapError> {
        let address = slot.guest_address();
        let size = carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize;
        let pointer = self
            .translate_va(address)
            .and_then(|ipa| {
                Self::mailbox_mapping_for_range(&self.mappings, address, ipa, size).map(|mapping| {
                    let offset =
                        usize::try_from(address.saturating_sub(mapping.start)).unwrap_or_default();
                    unsafe { mapping.host_addr.add(offset) }
                })
            })
            // A persistent-VM exec deliberately drops the software page-table
            // manager until the first real edit. The mailbox lives in a static
            // boot mapping whose guest-VA extent is unambiguous, so resolve that
            // mapping directly instead of paying a 1.8 MiB table clone solely to
            // recover the root-slot/global-frame IPA during publication.
            .or_else(|| {
                let mapping = self.mapping_for_range(address, size)?;
                let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
                Some(unsafe { mapping.host_addr.add(offset) })
            })
            .or_else(|| {
                self.carrier_mappings
                    .as_ref()?
                    .host_pointer(address, size)
                    .map(std::ptr::NonNull::as_ptr)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "AArch64 syscall mailbox slot {} at {address:#x} is not mapped",
                    slot.raw()
                ))
            })?;
        std::ptr::NonNull::new(pointer.cast()).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "AArch64 syscall mailbox slot {} resolved to a null host pointer",
                slot.raw()
            ))
        })
    }

    pub(crate) fn allocate_mailbox_for_vcpu(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: `mailbox_host_pointer` resolved the complete fixed slot from
        // this VM's process-lifetime mapping, and the lease uniquely owns it.
        let binding = unsafe { MailboxBinding::new(lease, pointer, self.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn relocate_mailbox_after_cow(
        &self,
        binding: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let pointer = self.mailbox_host_pointer(binding.slot())?;
        // SAFETY: the live stage-1 walk resolves the complete replacement
        // backing for this binding's uniquely leased slot. The COW copied the
        // prior header before the guest published its request into that backing,
        // so relocation must not reset or regenerate any protocol field.
        unsafe { binding.relocate_after_cow(pointer) };
        let diagnostics = binding.diagnostics();
        if diagnostics.generation != binding.generation() {
            return Err(TrapError::Hypervisor(format!(
                "AArch64 mailbox COW relocation changed generation: binding={} backing={}",
                binding.generation(),
                diagnostics.generation
            )));
        }
        Ok(())
    }

    pub(crate) fn enrich_mailbox_run_error(
        &self,
        binding: &MailboxBinding,
        error: TrapError,
    ) -> TrapError {
        let TrapError::Hypervisor(message) = error else {
            return error;
        };
        if !message.contains("without a published mailbox request") {
            return TrapError::Hypervisor(message);
        }
        let slot = binding.slot();
        let address = slot.guest_address();
        let translated_ipa = self.translate_va(address);
        let live = self.mailbox_host_pointer(slot).ok();
        let live_diagnostics = live.map(|pointer| {
            // SAFETY: `mailbox_host_pointer` authenticated a complete live slot,
            // and the vCPU is stopped at the HVC that produced `error`.
            unsafe { MailboxBinding::diagnostics_at(pointer) }
        });
        TrapError::Hypervisor(format!(
            "{message}; mailbox_route={{slot={}, va={address:#x}, translated_ipa={translated_ipa:?}, binding_host={:#x}, live_host={:?}, live={live_diagnostics:?}}}",
            slot.raw(),
            binding.host_address(),
            live.map(|pointer| pointer.as_ptr() as usize),
        ))
    }

    pub(crate) fn release_mailbox_for_reclaim(
        &self,
        binding: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        binding.release_for_reclaim().map_err(|error| {
            TrapError::Hypervisor(format!("park AArch64 syscall mailbox: {error}"))
        })
    }

    pub(crate) fn reacquire_mailbox_after_vcpu_create(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        binding: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: the allocator lease uniquely owns the complete fixed slot.
        unsafe { binding.reacquire_after_reclaim(lease, pointer, continuation) }.map_err(
            |error| TrapError::Hypervisor(format!("resume AArch64 syscall mailbox: {error}")),
        )?;
        vcpu.set_sys_reg(SysReg::SP_EL1, address).map_err(hvf_error)
    }

    /// Host pointer backing `[gpa, gpa+len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` copies through this; HVF resolves it via the same
    /// per-thread mapping walk (with the stage-1-IPA disambiguation) the
    /// syscall path uses.
    /// Map host memory at a stage-2 IPA (`hv_vm_map`). The STAGE-1 path stays in
    /// the engine; this is the backend stage-2 op only.
    pub(crate) fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: carrick_hal::MemPerms,
    ) -> Result<(), TrapError> {
        let perms_raw: u64 = u64::from(hvf_mem_perms(perms));
        let r = unsafe {
            inventory_hv_vm_map(host as *mut std::ffi::c_void, ipa, len as usize, perms_raw)
        };
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map(ipa=0x{ipa:x}, size={len}) failed: 0x{r:x}"
            )));
        }
        Ok(())
    }

    /// The HVF-only lazy high-VA alias re-map: a forked child rebuilt its VM
    /// from only the forking thread's mappings, dropping a global-shared alias a
    /// sibling thread mapped; re-`hv_vm_map` the registered host backing into
    /// THIS VM so the faulting instruction re-executes cleanly. Returns true iff
    /// it remapped. (The engine's `next_syscall` already runs the bounded in-loop
    /// remap; this is the `handle_memory_exit` hook surface — kept for the trait,
    /// driven on the rare path the in-loop remap doesn't cover.)
    pub(crate) fn try_lazy_alias_remap(&mut self, gpa: u64, va: u64) -> bool {
        let backing = if gpa != 0 {
            lookup_shared_alias(gpa)
        } else {
            lookup_shared_alias_by_va(va, 1, self.mm_root_slot, self.container_root)
        };
        let Some(b) = backing else {
            return false;
        };
        // SAFETY: `host_addr` is a live MAP_SHARED mmap registered by
        // `add_alias`. Replay succeeds only when HVF confirms the installation;
        // an arbitrary nonzero result is never evidence that a racing mapper won.
        let rc = unsafe { inventory_hv_vm_map_replay(b) };
        crate::probes::hv_vm_map_alias(
            va,
            b.physical_ipa,
            b.physical_size as u64,
            rc as i32,
            self.forked_no_exec as i32,
        );
        rc == 0
    }

    /// Back a dynamic `mmap` (`DispatchOutcome::MapHostAlias`) with host
    /// memory: `hv_vm_map` the host backing at the alias IPA, register the
    /// alias process-globally, and add the per-thread region — returning the
    /// `(gpa = ipa, writable)` the engine then threads into the SHARED stage-1
    /// `map_aliased`. RWX so a JIT (Rosetta) can write+execute it; the guest may
    /// `mprotect` afterwards.
    ///
    /// `backing` selects the host object, and the sharing it carries is the
    /// VMA's own: a deferred `mprotect` commit must preserve MAP_SHARED across
    /// host fork rather than silently substituting private COW backing. A
    /// `MAP_PRIVATE` file backing is refused outright: a Darwin `MAP_PRIVATE`
    /// file view is a map-time snapshot, so it cannot honour the Linux clause
    /// that clean private pages track later writes (`mmapprivatefiletrack`);
    /// that shape is served only by the sparse-arena page-cache view plus
    /// carrick-owned page COW (`materialize_private_file_backing`).
    pub(crate) fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(u64, bool), TrapError> {
        let sharing = match &backing {
            HostAliasBacking::File {
                sharing: HostAliasSharing::Shared,
                ..
            } => GuestMappingSharing::GlobalShared,
            HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Shared,
            } => GuestMappingSharing::ForkSharedAnonymous,
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Private,
            } => GuestMappingSharing::Private,
        };
        let inventory_backing = match &backing {
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Shared,
                ..
            } => {
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "identify HVPatch shared-file frame: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let offset = u64::try_from(*offset).map_err(|_| {
                    TrapError::Hypervisor(
                        "HVPatch shared-file frame has negative offset".to_owned(),
                    )
                })?;
                InventoryBackingIdentity::SharedFile {
                    device: stat.st_dev as u64,
                    inode: stat.st_ino as u64,
                    offset,
                    length: len,
                }
            }
            HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Shared,
            } => Self::shared_anon_backing_identity(),
            // A private file mapping is a private frame: its host object is a
            // per-mapping COW view of the file, never shared with another alias.
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Private,
            } => Self::private_backing_identity(),
        };
        // Mature VMM/root uses the IPA the dispatcher allocated from the global
        // alias arena. An in-process hvpatch mm relocates non-global aliases into
        // its mm scope; the returned GPA is authoritative for stage-1, while
        // dispatcher VMA metadata remains keyed by VA and needs no IPA.
        // hv_vm_map requires a 16 KiB-granular size; round the HOST mapping up
        // to the HVF granule. The stage-1 `map_aliased` (the engine, on the exact
        // `len`) below still maps only the guest's page-aligned request, so a
        // sub-16 KiB mmap never maps extra 4 KiB guest pages into a neighbouring
        // region's page-table entries (which would redirect that region's
        // fetches/reads to the wrong IPA — the amd64 Rosetta JIT undefined-
        // instruction bug).
        let hvf_len = align_up(len, HVF_PAGE_SIZE)?;
        let guest_size = usize::try_from(len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let requested_physical_size =
            usize::try_from(hvf_len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let guest_end = va.checked_add(len).ok_or(TrapError::MappingOverflow {
            guest_start: va,
            mapped_size: len,
        })?;
        // A shared file's host page is mapped at the guest's actual prot
        // (map_shared_file), so a PROT_READ file alias has a read-only host
        // backing. Track the guest-intended writability so the syscall
        // write-path returns EFAULT instead of SIGBUS-ing the host. Anon and
        // private-file aliases are RW-backed (a private file view is a COW
        // copy, so host PROT_WRITE never reaches the file).
        let alias_guest_writable = match &backing {
            HostAliasBacking::File {
                host_prot,
                sharing: HostAliasSharing::Shared,
                ..
            } => *host_prot & libc::PROT_WRITE != 0,
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous { .. } => true,
        };
        let (shared_key_base, shared_key_offset) = match &backing {
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Shared,
                ..
            } => (
                shared_file_key_base(fd.as_raw_fd()),
                u64::try_from(*offset).unwrap_or_default(),
            ),
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous { .. } => (0, 0),
        };
        let host_mapping = match &backing {
            // Live MAP_SHARED file: back the guest region with the file's page
            // cache directly, so writes are coherent with other openers and
            // survive fork. The dispatcher handed us a dup'd fd it owns; mmap
            // takes its own reference, so the dup closes with `backing`.
            HostAliasBacking::File {
                fd,
                offset,
                host_prot,
                sharing: HostAliasSharing::Shared,
            } => crate::host_mapping::OwnedHostMapping::map_shared_file(
                fd.as_raw_fd(),
                *offset,
                requested_physical_size,
                *host_prot,
            )
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "alias MAP_SHARED file (fd={} off={offset} size={requested_physical_size} prot={host_prot}) failed: {e}",
                    fd.as_raw_fd()
                ))
            })?,
            // MAP_PRIVATE file: refuse. A Darwin `MAP_PRIVATE` file view is a
            // snapshot of the file at mmap time (measured by
            // `overlay_shared_file_view_tracks_later_file_writes`), so it
            // cannot give Linux's clean-page-tracks-`write(2)` semantics; the
            // contract says a backend that cannot honour `Private` for a file
            // MUST refuse rather than silently map a snapshot. Arena-resident
            // MAP_PRIVATE file mappings take the page-granular
            // `materialize_private_file_backing` lane instead; no dispatcher
            // site produces this shape for a high-VA alias.
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Private,
                ..
            } => {
                return Err(TrapError::Hypervisor(format!(
                    "alias MAP_PRIVATE file (fd={} off={offset} size={requested_physical_size}) unsupported: a Darwin MAP_PRIVATE file view is a snapshot",
                    fd.as_raw_fd()
                )));
            }
            HostAliasBacking::Anonymous { .. } => {
                crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    requested_physical_size,
                    if sharing.shares_across_fork() {
                        crate::host_mapping::HostMappingKind::SharedAnon
                    } else {
                        crate::host_mapping::HostMappingKind::PrivateAnon
                    },
                )
                .map_err(|e| {
                    TrapError::Hypervisor(format!(
                        "alias mmap (size={requested_physical_size}) failed: {e}"
                    ))
                })?
            }
        };
        // The host mapping holds its own reference to the file; the
        // dispatcher's dup is closed here, on every path below, by drop.
        let seed_payload = !backing.is_file();
        drop(backing);
        let host = host_mapping.as_ptr();
        let physical_size = host_mapping.len();
        // Seed the anon content (a file mapping is already backed by the file's
        // pages; an anon mapping is zeroed and takes the dispatcher's payload).
        if seed_payload && !payload.is_empty() {
            let n = payload.len().min(guest_size);
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
        }
        // Alias mappings keep permissive stage-2 rights; guest-visible
        // protections are enforced in stage-1 and adjusted by mprotect.
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: true,
        });
        // Reserve the global-frame lease on a 2 MiB boundary, NOT the 16 KiB
        // COW compound granule. The dispatcher hands this path a 2 MiB-aligned
        // alias VA, so a 2 MiB-aligned output keeps VA and IPA congruent and
        // lets the stage-1 editor express the mapping as 1 GiB/2 MiB block
        // leaves. A 16 KiB-aligned base breaks that congruence, and since no
        // block leaf can then be expressed ANYWHERE the whole alias falls to
        // 4 KiB pages — one fresh L3 table per 2 MiB, which exhausts the
        // 440-page spare pool at ~850 MiB and fails the build (CPython's
        // `test_mmap` LargeMmapTests hung there). The sparse-arena sibling
        // reserves on `TWO_MIB` for exactly this reason.
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut global_lease = if self.persistent_vm_lifecycle {
            Some(GlobalFrameStage2Lease::reserve(hvf_len, TWO_MIB)?)
        } else {
            None
        };
        let ipa = global_lease.as_ref().map_or(ipa, |lease| lease.base);
        let r = unsafe { inventory_hv_vm_map(host.cast(), ipa, physical_size, u64::from(perms)) };
        crate::probes::hv_vm_map_alias(
            va,
            ipa,
            physical_size as u64,
            r as i32,
            self.forked_no_exec as i32,
        );
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map alias va=0x{va:x} ipa=0x{ipa:x} size={physical_size} failed: 0x{r:x}"
            )));
        }
        if let Some(lease) = global_lease.as_mut() {
            lease.mark_mapped();
        }
        let (host_mapping, owner_generation) = if self.persistent_vm_lifecycle {
            let custody = self.carrier_vm_custody();
            let owner_generation = register_global_frame_host_owner_in(
                &custody,
                global_lease.take().ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch alias lost its global IPA lease".to_owned())
                })?,
                host_mapping,
                u64::from(perms),
            )?;
            (None, owner_generation)
        } else {
            (Some(host_mapping), 0)
        };
        // Register EVERY alias (MAP_SHARED file AND private anon — Go's high-VA
        // heap arenas) process-globally in `alias_registry`. Two consumers: the
        // stage-2 lazy on-fault re-map (a forked VM that lost the alias), and the
        // SYSCALL-PATH cross-thread fallback in `mapping_for_range` (a sibling
        // thread whose per-thread `mappings` never saw this alias — the
        // "read/wait: bad address" EFAULT). The index is non-owning (raw
        // host_addr) and removed on munmap. guest_writable is carried so a
        // PROT_READ file alias still EFAULTs a syscall write via the fallback
        // instead of SIGBUS-ing the host.
        register_shared_alias(AliasBacking {
            start: va,
            ipa,
            host_addr: host as usize,
            size: guest_size,
            physical_ipa: ipa,
            physical_host_addr: host as usize,
            physical_size,
            perms: u64::from(perms),
            guest_writable: alias_guest_writable,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: guest_end,
            host_addr: host,
            size: physical_size,
            physical_size,
            perms,
            memory: None,
            host_mapping,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: alias_guest_writable,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            let mut reservation = inventory.alias_reservation.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "HVPatch alias mapped without frame inventory reservation"
                );
            });
            match Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: ipa,
                    length: physical_size as u64,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing: inventory_backing,
                    inherited_frame: None,
                    stage2_lease: None,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: host as usize,
                        generation: owner_generation,
                    },
                },
            ) {
                Ok(extent) => {
                    tracing::trace!(
                        mapping = ?extent.mapping,
                        frame = ?extent.frame,
                        gpa = format_args!("{ipa:#x}"),
                        "hvpatch alias stage"
                    );
                    inventory
                        .alias_staged
                        .push(((ipa, physical_size as u64), extent));
                }
                Err(error) => {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "stage inventory after HVPatch alias map: {error}"
                    );
                }
            }
            inventory.alias_commit = Some(reservation.commit(()));
        }
        Ok((ipa, alias_guest_writable))
    }

    pub(crate) fn emulate_el0_sys64_read_inner(
        vcpu: &mut applevisor::vcpu::Vcpu,
        esr: u64,
    ) -> Result<bool, TrapError> {
        use applevisor::prelude::*;

        // EL0 read of a feature-ID register (the CRn==0, Op0==3, Op1==0 space).
        // The Linux kernel emulates these for userspace; Apple Rosetta reads
        // ID_AA64MMFR1_EL1 (and friends) at startup, and without this the MRS
        // takes a fatal undef. Return the real vCPU value. (The Op1==3 timer /
        // CTR_EL0 / DCZID_EL0 reads handled below are a separate space.)
        let op0 = (esr >> 20) & 0x3;
        let op1 = (esr >> 14) & 0x7;
        let crn = (esr >> 10) & 0xf;
        let crm = (esr >> 1) & 0xf;
        let op2 = (esr >> 17) & 0x7;
        let direction_read = esr & 1 == 1;
        if direction_read && op0 == 3 && op1 == 0 && crn == 0 {
            let rt_id = ((esr >> 5) & 0x1f) as usize;
            let enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
            let id_reg = match enc {
                0xc000 => Some(SysReg::MIDR_EL1),
                0xc020 => Some(SysReg::ID_AA64PFR0_EL1),
                0xc021 => Some(SysReg::ID_AA64PFR1_EL1),
                0xc028 => Some(SysReg::ID_AA64DFR0_EL1),
                0xc029 => Some(SysReg::ID_AA64DFR1_EL1),
                0xc030 => Some(SysReg::ID_AA64ISAR0_EL1),
                0xc031 => Some(SysReg::ID_AA64ISAR1_EL1),
                0xc038 => Some(SysReg::ID_AA64MMFR0_EL1),
                0xc039 => Some(SysReg::ID_AA64MMFR1_EL1),
                0xc03a => Some(SysReg::ID_AA64MMFR2_EL1),
                // Any other CRn==0/Op0==3/Op1==0 slot reads-as-zero (RES0),
                // matching the architectural default for unallocated ID regs.
                _ => None,
            };
            let value = match id_reg {
                Some(reg) => vcpu.get_sys_reg(reg).map_err(hvf_error)?,
                None => 0,
            };
            if let Some(target) = GPR_TABLE.get(rt_id) {
                vcpu.set_reg(*target, value).map_err(hvf_error)?;
            }
            let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
                .map_err(hvf_error)?;
            return Ok(true);
        }

        let Some((rt, reg)) = decode_el0_sys64_read(esr) else {
            return Ok(false);
        };
        let value = match reg {
            El0SysRegRead::CntfrqEl0 => AARCH64_GUEST_COUNTER_HZ,
            El0SysRegRead::CntvctEl0 => guest_counter_ticks(),
            // Fallback if a guest's CTR_EL0/DCZID_EL0 read still traps despite
            // SCTLR_EL1.UCT/DZE (e.g. a forked child before its sysregs are
            // re-applied). Return the real host cache geometry.
            El0SysRegRead::CtrEl0 => host_ctr_dczid().0,
            El0SysRegRead::DczidEl0 => host_ctr_dczid().1,
        };
        if let Some(target) = GPR_TABLE.get(rt as usize) {
            vcpu.set_reg(*target, value).map_err(hvf_error)?;
        }
        let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
            .map_err(hvf_error)?;
        Ok(true)
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range. Used
    /// to fault syscall-path accesses to a guest PROT_NONE buffer (EFAULT).
    pub(crate) fn range_no_access(&self, address: u64, length: usize) -> bool {
        self.protections.range_no_access(address, length)
    }

    /// Write the vDSO vvar data page: the counter frequency and the
    /// monotonic→realtime offset, so `__kernel_clock_gettime` can convert
    /// CNTVCT_EL0 to a timespec entirely in userspace. The guest reads the same
    /// counter we calibrate against (CNTKCTL_EL1.EL0VCTEN), so the rate is exact;
    /// monotonic durations depend only on the frequency. Best-effort: silently
    /// skips if the vvar page isn't mapped.
    ///
    /// Stamp a fresh process-local epoch into the vvar RNG generation (P2).
    /// Re-stamping each forked child ensures the generation never matches the
    /// state snapshot inherited from its parent, forcing the userspace
    /// getrandom blob to reseed rather than reuse the parent's keystream.
    pub(crate) fn stamp_rng_generation(&mut self) -> Result<(), MemoryError> {
        let generation = next_vdso_rng_generation();
        self.write_guest_bytes(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64,
            &generation.to_le_bytes(),
        )
    }

    pub(crate) fn populate_vdso_data_page(&mut self) {
        // Independent of the clock data (getrandom needs no calibrated counter),
        // so stamp it first and unconditionally.
        let _ = self.stamp_rng_generation();
        let freq = host_counter_frequency();
        if freq == 0 {
            return;
        }
        // The vDSO computes the guest's CLOCK_REALTIME as
        //   realtime_ns = guest_CNTVCT/freq + realtime_off.
        // So `realtime_off` MUST be `unix_ns - guest_CNTVCT/freq` measured on
        // the SAME clock the guest's CNTVCT_EL0 actually exposes.
        //
        // Crucially, the guest's CNTVCT does NOT equal the raw `cntvct_el0` MRS
        // that carrick reads in `host_counter()`: the bare hardware counter
        // keeps ticking across system SUSPEND (it is BOOTTIME-like), whereas
        // HVF gives the guest a virtual counter aligned to macOS
        // CLOCK_UPTIME_RAW (which EXCLUDES suspend) — empirically the guest's
        // CNTVCT/freq matches CLOCK_UPTIME_RAW to the millisecond, while the
        // raw MRS runs HOURS ahead after a laptop has slept (hv_vcpu's
        // vtimer_offset reports 0, so the gap is invisible through that API).
        // Calibrating `mono_ns` off the raw MRS therefore skewed guest
        // CLOCK_REALTIME by the accumulated suspend time → every absolute
        // FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME deadline (glibc sem_timedwait /
        // pthread condvar timeouts, i.e. multiprocessing SemLock/Condition)
        // computed as already-past → instant spurious ETIMEDOUT.
        //
        // Reading CLOCK_UPTIME_RAW here matches the guest's counter base, so
        // realtime_off is exact. CLOCK_MONOTONIC is unaffected (durations
        // cancel any constant base), but its absolute value now also agrees
        // with carrick's syscall-path monotonic (`monotonic_duration`, also
        // CLOCK_UPTIME_RAW) — the vDSO and syscall fast/slow paths are coherent.
        let mono_ns = host_clock_uptime_ns();
        let unix_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let realtime_off = unix_ns.wrapping_sub(mono_ns);
        // Publish the SAME offset to the shared store so the trapping
        // clock_gettime(CLOCK_REALTIME) syscall computes uptime + realtime_off
        // identically to the vDSO fast path (which adds VVAR_OFF_REALTIME_OFF_NS
        // to the guest CNTVCT) — keeping the two paths coherent (clock_gettime04).
        crate::vdso::set_realtime_off_ns(realtime_off);

        let base = crate::vdso::LINUX_VVAR_BASE;
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_FREQ as u64,
            &freq.to_le_bytes(),
        );
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &realtime_off.to_le_bytes(),
        );
        // seq stays 0 (even = stable); these aren't updated after boot.
    }

    /// Mark `[address, address+len)` PROT_NONE (`no_access=true`) or clear it.
    /// Clearing performs interval subtraction so an mprotect/mmap that re-enables
    /// part of a PROT_NONE region leaves only the still-protected remainder.
    pub(crate) fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    /// Mirror a partial `munmap`'s registry split onto this engine's LOCAL
    /// mapping rows.
    ///
    /// `unregister_alias_entries` splits an overlapped registry entry into its
    /// surviving head/tail fragments, but the engine's own row kept the
    /// ORIGINAL extent. `mapping_is_current_for_process_fork_indexed` then
    /// matched that row against the registry index by exact identity
    /// `(start, ipa, host_addr, semantic size)` — and a fragment never equals
    /// the whole — so fork DROPPED the row from its COW ranges. The child's
    /// cloned stage-1 kept a WRITABLE leaf onto the parent's frame, no COW
    /// fault ever fired, and the child's frees scribbled pymalloc free-list
    /// links over the parent's live objects (`cpython-threading`'s
    /// `free(): invalid pointer`, reducer
    /// `docs/perf-results/2026-08-17-closure-post-libuv/reducers/cpython-fork-shutdown-parent-segv.py`).
    /// An identity test was standing in for a liveness question; keeping the
    /// two representations in step restores the invariant at its source
    /// instead of teaching the consumer to guess.
    ///
    /// Ownership: `HvfMappedRegion` owns its backing handles and is not
    /// `Clone`, so the surviving HEAD keeps them and a tail fragment carries
    /// `None`. Both fragments retain the same `physical_ipa`/`physical_size`,
    /// which is what stage-2 retirement keys on, so they are still retired
    /// together. A row the unmap covers ENTIRELY is left untouched: the
    /// registry drops such an entry outright, and excluding a dead row from
    /// fork is correct.
    pub(crate) fn split_local_rows_for_unmap(&mut self, va: u64, len: usize) {
        self.mappings.split_local_rows_for_unmap(va, len);
    }

    pub(crate) fn unregister_process_alias(
        &mut self,
        va: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        // An unmap is a stage-1 repointer that publishes NO receipt of its own,
        // so it has to void the promises naming the range it is tearing down —
        // the contract `supersede_cow_receipts` states for every repointer.
        // Without this a receipt outlives the leaves it describes, and the next
        // mapping over that VA authenticates it against an absent translation:
        // `deferred COW protection authentication failed ... leaf=0x0
        // translated=None`, which the dispatcher can only lower to a guest
        // `ENOMEM`. Seen as `go-net` dying with "fatal error: runtime: cannot
        // allocate memory" on a 256 KiB arena mmap whose fifth page still held
        // a one-page receipt from a freed mapping.
        if !self.persistent_vm_lifecycle {
            self.supersede_cow_receipts("process-alias-unmap", va, len as u64);
            if let Some(debug_va) = fork_debug_va()
                && debug_va >= va
                && debug_va < va.saturating_add(len as u64)
            {
                eprintln!(
                    "[DISARMDBG alias-unmap-legacy pid={:?}] va={va:#x} len={len:#x}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                );
            }
            self.cow_armed.lock().disarm(CowArmedSpan {
                va,
                len,
                executable: false,
                kernel_only: false,
            });
            let _ = unregister_alias(va, len, self.mm_root_slot, self.container_root);
            self.split_local_rows_for_unmap(va, len);
            return Ok(());
        }
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no mm identity".to_owned())
        })?;
        // `GuestMemory::unmap_range` is reached only from the mmap-family
        // syscall set, whose runtime dispatch already owns the process-wide
        // page-table pause across invalidate + TLBI + this backend retirement.
        // Acquiring the same non-reentrant pause here deadlocks the coordinator
        // against itself as soon as the mm has a sibling vCPU.
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasUnmap,
            identity.linux_pid,
            identity.linux_tid,
        );

        let prepared = self.prepare_process_alias_retirement(va, len)?;
        self.commit_process_alias_retirement(va, len, prepared)
    }

    /// Prepare while the caller holds topology exclusion. Dropping this value
    /// leaves aliases, COW state, receipts and inventory unchanged.
    pub(crate) fn prepare_process_alias_retirement(
        &self,
        va: u64,
        len: usize,
    ) -> Result<PreparedProcessAliasRetirement, TrapError> {
        let authority = self.cow_authority.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no inventory authority".to_owned())
        })?;
        let (planned_leases, registry_before, diagnostic_before) = {
            let registry = alias_registry().lock();
            let (planned_leases, registry_before) = registry.plan_unregister_process_alias(
                va,
                len,
                self.mm_root_slot,
                self.container_root,
            );
            let diagnostic_before = if cow_refusal_diagnostics_enabled() {
                registry.process_visible_ordered(self.mm_root_slot, self.container_root)
            } else {
                Vec::new()
            };
            (planned_leases, registry_before, diagnostic_before)
        };
        let disarm_spans = retired_alias_disarm_spans(
            &registry_before,
            va,
            len,
            self.mm_root_slot,
            self.container_root,
            &planned_leases,
        );
        let inventory = if planned_leases.is_empty() {
            None
        } else {
            let retirement = {
                let inventory = self.frame_inventory.lock();
                Self::inventory_lease_retirement_shape(&inventory, &planned_leases, &|frame| {
                    authority.frame_mapping_count(frame).map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "query alias-retirement frame mapping count: {error}"
                        ))
                    })
                })?
            };
            if retirement.mappings.is_empty() {
                None
            } else {
                let event_count = retirement
                    .mappings
                    .len()
                    .saturating_add(retirement.frames.len());
                let mut reservation = authority.reserve(0, 0, event_count).map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "reserve HVPatch alias retirement inventory: {error}"
                    ))
                })?;
                Self::stage_inventory_lease_retirement(&mut reservation, &retirement)?;
                Some((retirement, reservation))
            }
        };
        Ok(PreparedProcessAliasRetirement {
            planned_leases,
            diagnostic_before,
            disarm_spans,
            inventory,
        })
    }

    /// Consume a retirement under the same topology exclusion as preparation.
    pub(crate) fn commit_process_alias_retirement(
        &mut self,
        va: u64,
        len: usize,
        prepared: PreparedProcessAliasRetirement,
    ) -> Result<(), TrapError> {
        let authority = self.cow_authority.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no inventory authority".to_owned())
        })?;
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no mm identity".to_owned())
        })?;
        let custody = self.carrier_vm_custody();
        let PreparedProcessAliasRetirement {
            planned_leases,
            diagnostic_before,
            disarm_spans,
            inventory,
        } = prepared;
        self.supersede_cow_receipts("process-alias-unmap", va, len as u64);
        let actual_leases = unregister_alias(va, len, self.mm_root_slot, self.container_root);
        if actual_leases != planned_leases {
            carrick_fatal!(
                "hvpatch::host_alias",
                "HVPatch alias registry changed under topology lock: planned={planned_leases:?} actual={actual_leases:?}"
            );
        }
        record_alias_unmap_lifecycle(
            CowDiagnosticLifecycleSite::AliasUnmap,
            &custody,
            Some(identity),
            self.mm_root_slot,
            self.container_root,
            &diagnostic_before,
        );
        let Some((retirement, reservation)) = inventory else {
            self.split_local_rows_for_unmap(va, len);
            // A surviving fragment of a compound still needs its COW arm.
            // The planner emits spans only for leases it actually retires.
            let mut armed = self.cow_armed.lock();
            for span in disarm_spans {
                armed.disarm(span);
            }
            return Ok(());
        };
        if let Err(error) = authority.apply(reservation.commit(())) {
            // Name the retirement, not just the id that failed. This abort used
            // to print one MappingId and nothing else, which cannot distinguish
            // a double-retire from a mapping the authority never saw, and gives
            // no way to tell WHICH extent named it — `inventory.extents` is
            // keyed by `(gpa, length)`, so an extent has no lifetime tie to the
            // mapping it names and an orphan is invisible from the id alone.
            let inventory = self.frame_inventory.lock();
            let retiring: std::collections::BTreeSet<_> = retirement
                .mappings
                .iter()
                .map(|(_, extent)| extent.mapping)
                .collect();
            let naming: Vec<_> = inventory
                .extents
                .iter()
                .filter(|(_, extent)| retiring.contains(&extent.mapping))
                .map(|(&key, extent)| (key, extent.mapping, extent.frame, extent.backing))
                .collect();
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "apply HVPatch alias retirement inventory: {error}\n  \
                 va={va:#x} len={len:#x} retiring={:?}\n  frames={:?} leases={:?}\n  \
                 every extent naming those mappings: {naming:?}\n  \
                 live extents={} planned_leases={planned_leases:?}",
                retirement.mappings,
                retirement.frames,
                retirement.stage2_leases,
                inventory.extents.len(),
            );
        }
        {
            let mut inventory = self.frame_inventory.lock();
            Self::commit_inventory_lease_retirement(&mut inventory, &retirement).unwrap_or_else(
                |error| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "commit HVPatch alias retirement backend ledger: {error}"
                    )
                },
            );
        }
        for &(logical_key, extent) in &retirement.mappings {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryRemoved,
                CowDiagnosticLifecycleSite::AliasUnmap,
                &custody,
                Some(identity),
                self.mm_root_slot,
                va,
                len as u64,
                logical_key,
                extent,
            );
        }
        for &(ipa, length) in &retirement.stage2_leases {
            let retired = retirement
                .mappings
                .iter()
                .filter_map(|(_, extent)| {
                    ((extent.stage2_base, extent.stage2_length) == (ipa, length))
                        .then_some(RetiredStage2Projection::from(*extent))
                })
                .try_fold(None, |selected, candidate| match selected {
                    Some(selected) if selected != candidate => Err(TrapError::Hypervisor(format!(
                        "HVPatch alias retirement IPA 0x{ipa:x} size {length} has conflicting owner identities"
                    ))),
                    Some(selected) => Ok(Some(selected)),
                    None => Ok(Some(candidate)),
                })?
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias retirement IPA 0x{ipa:x} size {length} has no exact inventory owner"
                    ))
            })?;
            self.retire_stage2_extent(ipa, length)?;
            let retired = [retired];
            let cleanup = mutate_known_external_alias_state(
                |_, registry| retired_projection_mutation_keys(registry, &retired, &[]),
                |replay, registry| {
                    remove_rows_for_retired_stage2_projections(replay, registry, &retired)
                },
            );
            for alias in cleanup.removed_aliases {
                record_cow_alias_lifecycle(
                    CowDiagnosticLifecycleKind::AliasRemoved,
                    CowDiagnosticLifecycleSite::AliasUnmap,
                    Some(&custody),
                    Some(identity),
                    self.mm_root_slot,
                    alias,
                );
            }
            for alias in cleanup.preserved_reused_aliases {
                record_cow_alias_lifecycle(
                    CowDiagnosticLifecycleKind::AliasPreservedReused,
                    CowDiagnosticLifecycleSite::AliasUnmap,
                    Some(&custody),
                    Some(identity),
                    self.mm_root_slot,
                    alias,
                );
            }
            self.mappings
                .remove_rows_matching_in_ranges(&[MappingExtent::Ipa(ipa, length)], |mapping| {
                    mapped_region_matches_retired_inventory_extent(mapping, retired[0])
                });
        }
        self.split_local_rows_for_unmap(va, len);
        let mut armed = self.cow_armed.lock();
        for span in disarm_spans {
            armed.disarm(span);
        }
        Ok(())
    }

    /// Resolve a guest VA range to a [`MappingView`] (host pointer + bounds +
    /// writability). THE single chokepoint every syscall-path memory accessor
    /// (read/write_guest_bytes, host_ptr_for_read/write, validate_guest_write_range,
    /// zero_guest_backing) routes through.
    ///
    /// Fast path: THIS thread's per-thread `mappings`. Cross-thread FALLBACK: when
    /// that misses for a high-VA address, the VA→IPA half is already process-shared
    /// (`translate_va` walks the Arc-shared page tables, which `map_aliased` edits
    /// for EVERY thread's alias), so resolve IPA→host from the process-shared
    /// `alias_registry` — fixing a syscall buffer that lives in a high-VA alias
    /// (Go heap arena) ANOTHER goroutine mmap'd, invisible to this thread's list
    /// (the "read/wait: bad address" EFAULT). Both `_range` and `_range_mut`
    /// resolve identically — no accessor mutates the region itself.
    pub(crate) fn mapping_for_range(&self, address: u64, length: usize) -> Option<MappingView> {
        let custody = self.carrier_vm_custody();
        self.task.mapping_for_range_in(&custody, address, length)
    }

    pub(crate) fn mapping_for_range_mut(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<MappingView> {
        self.mapping_for_range(address, length)
    }

    /// The address the per-chunk region lookup + offset should use for a syscall
    /// buffer at guest VA `chunk_va`. Identity for everything but a
    /// `repoint_private` overlay: a MAP_FIXED|MAP_PRIVATE carved over a
    /// shared-aperture VA repoints the stage-1 leaf to a per-process overlay IPA
    /// (608 GiB), but registers NO region keyed at the original VA — the only
    /// region with the overlay backing is keyed at the overlay IPA. So a syscall
    /// copy must look up (and offset) by that translated IPA, or it resolves to
    /// the STALE shared-aperture region the VA still covers (the repoint_private
    /// syscall-buffer bug). High-VA aliases are NOT redirected here: their region
    /// is keyed at the VA and `mapping_for_range` already disambiguates
    /// overlapping aliases via `translate_va` internally (VA-relative offset). For
    /// every other (identity) VA this returns `chunk_va` unchanged — no walk.
    pub(crate) fn syscall_buffer_lookup_addr(&self, chunk_va: u64, chunk_len: usize) -> u64 {
        if !crate::memory::needs_stage1_translation(chunk_va, chunk_len as u64) {
            return chunk_va;
        }
        self.translate_va(chunk_va).unwrap_or(chunk_va)
    }

    /// True if `ipa` falls in `region`'s `hv_vm_map`'d IPA window.
    pub(crate) fn region_owns_ipa(region: &HvfMappedRegion, ipa: u64) -> bool {
        ipa >= region.ipa && ipa < region.ipa + region.size as u64
    }

    #[cfg(test)]
    pub(crate) fn mapping_index_for_range(
        mappings: &[HvfMappedRegion],
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
    ) -> Option<usize> {
        // Prefer the region selected by the authoritative stage-1 output when
        // overlapping semantic descriptors exist, then fall back newest-first
        // for test fixtures without a live page-table walk.
        if let Some(ipa) = stage1_ipa
            && let Some((idx, _)) = mappings.iter().enumerate().rev().find(|(_, mapping)| {
                Self::region_owns_ipa(mapping, ipa) && mapping.contains_range(address, length)
            })
        {
            return Some(idx);
        }
        mappings
            .iter()
            .enumerate()
            .rev()
            .find(|(_, mapping)| mapping.contains_range(address, length))
            .map(|(idx, _)| idx)
    }

    /// Resolve a raw stage-2 IPA without treating it as a guest virtual
    /// address. Global-frame aliases deliberately have `start != ipa`; using
    /// the VA lookup here could select no mapping (or an unrelated mapping at
    /// the same VA) when editing a non-identity backing.
    pub(crate) fn mapping_for_ipa_range(
        mappings: &TaskMappingIndex,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        ipa.checked_add(length)?;
        mappings
            .candidates_for_ipa_range(ipa, length)
            .next()
            .map(HvfMappedRegion::view)
    }

    /// Resolve one mailbox route without losing its semantic VA identity.
    ///
    /// A raw IPA is not a sufficient key in the persistent VM: the reusable
    /// allocator can give a retired dynamic row's physical IPA to a later
    /// process-local kernel-state mapping while that stale row remains in one
    /// vCPU's metadata solely to retain its host owner. Require the same row to
    /// cover the mailbox VA *and* express the live VA-to-IPA translation.
    pub(crate) fn mailbox_mapping_for_range(
        mappings: &TaskMappingIndex,
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let semantic_end = semantic_va.checked_add(u64::try_from(length).ok()?)?;
        mappings
            .candidates_for_range(GuestVa(semantic_va), length as u64)
            .find(|mapping| {
                semantic_va >= mapping.start
                    && semantic_end <= mapping.end
                    && mapping
                        .ipa
                        .checked_add(semantic_va.saturating_sub(mapping.start))
                        == Some(ipa)
            })
            .map(HvfMappedRegion::view)
    }

    /// Resolve a raw IPA only through the exact currently-owned generation.
    /// A retired dynamic row can keep the same IPA and raw host pointer after
    /// the reusable allocator hands that IPA to another frame; mapped-address
    /// liveness or IPA equality alone would then select stale memory.
    pub(crate) fn mapping_for_live_ipa_range(
        &self,
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        let end = ipa.checked_add(length)?;
        let semantic_end = semantic_va.checked_add(length)?;
        if let Some(mapping) = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            semantic_va >= mapping.start
                && semantic_end <= mapping.end
                && mapping
                    .ipa
                    .checked_add(semantic_va.saturating_sub(mapping.start))
                    == Some(ipa)
                && ipa >= mapping.ipa
                && mapping_end.is_some_and(|limit| end <= limit)
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches_in(self.custody(), mapping))
        }) {
            return Some(mapping.view());
        }
        alias_registry()
            .lock()
            .newest_process_alias_containing_va(
                semantic_va,
                self.mm_root_slot,
                self.container_root,
                |alias| {
                    let alias_end = alias.ipa.checked_add(alias.size as u64);
                    semantic_end <= alias.start.saturating_add(alias.size as u64)
                        && alias
                            .ipa
                            .checked_add(semantic_va.saturating_sub(alias.start))
                            == Some(ipa)
                        && ipa >= alias.ipa
                        && alias_end.is_some_and(|limit| end <= limit)
                        && (!self.persistent_vm_lifecycle
                            || !is_reusable_global_frame_extent(
                                alias.physical_ipa,
                                alias.physical_size as u64,
                            )
                            || global_frame_host_owner_matches_in(
                                self.custody(),
                                alias.physical_ipa,
                                alias.physical_size as u64,
                                alias.physical_host_addr,
                                alias.owner_generation,
                            ))
                },
            )
            .map(|alias| MappingView::from_alias(&alias))
    }

    pub(crate) fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !self.range_no_access(address, length)
            && self
                .validate_guest_write_range_with_pristine(address, length, true, true)
                .is_ok()
    }
}

impl HvfTaskState {
    pub(crate) fn physical_cow_source(
        &self,
        semantic_va: u64,
        ipa: u64,
    ) -> Option<PhysicalCowSource> {
        self.physical_cow_source_in(self.custody(), semantic_va, ipa)
    }

    pub(crate) fn report_physical_cow_source_refusal(
        &self,
        custody: &CarrierVmCustody,
        semantic_va: u64,
        ipa: u64,
    ) {
        if !cow_refusal_diagnostics_enabled() {
            return;
        }
        const PAGE_SIZE: u64 = 4 * 1024;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const REPORT_ROW_LIMIT: usize = 16;

        let physical_ipa = align_down(ipa, CowArmedRanges::COMPOUND_SIZE);
        let physical_offset = ipa.saturating_sub(physical_ipa);
        let compound_va = semantic_va
            .checked_sub(physical_offset)
            .unwrap_or_else(|| align_down(semantic_va, CowArmedRanges::COMPOUND_SIZE));
        let compound_end = compound_va.saturating_add(CowArmedRanges::COMPOUND_SIZE);
        let custody_identity = custody as *const CarrierVmCustody as usize;
        let mm_access_identity = std::sync::Arc::as_ptr(&self.mm_access) as usize;
        let page_tables_authority = self.page_tables_authority();
        let page_tables_identity = page_tables_authority.authority_id() as usize;
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr);
        let (page_table_root, stage1_rows) = page_tables_authority
            .with_manager(|manager| {
                let mut rows = Vec::with_capacity(4);
                let mut va = compound_va;
                while va < compound_end {
                    let shadow = manager.debug_walk(va);
                    let live = page_table_host.and_then(|host| unsafe {
                        manager
                            .debug_walk_host(
                                self.page_table_resolver(manager.base(), Some(host)),
                                va,
                            )
                            .ok()
                    });
                    rows.push((
                        va,
                        manager.translate(va),
                        manager.translate_retained_output(va),
                        shadow,
                        live,
                    ));
                    va = va.saturating_add(PAGE_SIZE);
                }
                (Some(manager.base()), rows)
            })
            .unwrap_or((None, Vec::new()));
        eprintln!(
            "[COW-REFUSAL] input_va={semantic_va:#x} input_ipa={ipa:#x} compound_va={compound_va:#x} physical={physical_ipa:#x}+{:#x} custody={custody_identity:#x} mm_access={mm_access_identity:#x} page_tables={page_tables_identity:#x} root={page_table_root:#x?} mm_root_slot={:?} cow_identity={:?}",
            CowArmedRanges::COMPOUND_SIZE,
            self.mm_root_slot,
            self.cow_identity,
        );
        for (va, translated, retained, shadow, live) in stage1_rows {
            let live_leaf = live.map(|walk| walk[3]);
            let live_ipa = live_leaf.map(|leaf| leaf & PA_MASK_4KIB);
            eprintln!(
                "[COW-REFUSAL stage1] va={va:#x} translated={translated:#x?} retained={retained:#x?} shadow={shadow:x?} live={live:x?} live_leaf_ipa={live_ipa:#x?}",
            );
        }

        let owner_entry = custody
            .global_frame_host_owners
            .lock()
            .get(&(physical_ipa, CowArmedRanges::COMPOUND_SIZE))
            .cloned();
        match &owner_entry {
            Some(GlobalFrameOwnerEntry::Live(owner)) => eprintln!(
                "[COW-REFUSAL owner] state=live host={:#x} generation={} mapping_pins={} record={:?} stage2={:?}",
                owner.host_addr(),
                owner.generation(),
                owner.mapping.pin_count(),
                owner.record_identity,
                owner.snapshot(),
            ),
            Some(GlobalFrameOwnerEntry::RetirementPending {
                owner,
                error,
                in_flight,
            }) => eprintln!(
                "[COW-REFUSAL owner] state=retirement-pending host={:#x} generation={} mapping_pins={} in_flight={} error={:?} record={:?} stage2={:?}",
                owner.host_addr(),
                owner.generation(),
                owner.mapping.pin_count(),
                in_flight,
                error,
                owner.record_identity,
                owner.snapshot(),
            ),
            None => eprintln!(
                "[COW-REFUSAL owner] state=absent physical={physical_ipa:#x}+{:#x}",
                CowArmedRanges::COMPOUND_SIZE,
            ),
        }

        let (inventory_total, inventory_rows, inventory_identity, inventory_consistent) = {
            let inventory = self.frame_inventory.lock();
            let mut total = 0usize;
            let mut rows = Vec::new();
            let mut identity = None;
            let mut consistent = true;
            for (&logical_key, &extent) in inventory.extents.iter().filter(|(_, extent)| {
                (extent.stage2_base, extent.stage2_length)
                    == (physical_ipa, CowArmedRanges::COMPOUND_SIZE)
            }) {
                total = total.saturating_add(1);
                if extent.stage2_owner.generation == 0
                    || identity.is_some_and(|current| current != extent.stage2_owner)
                {
                    consistent = false;
                }
                identity.get_or_insert(extent.stage2_owner);
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push((logical_key, extent));
                }
            }
            (total, rows, identity, consistent)
        };
        let inventory_authorized = inventory_consistent
            && inventory_identity.is_some_and(|identity| {
                identity.generation != 0
                    && matches!(
                        &owner_entry,
                        Some(GlobalFrameOwnerEntry::Live(owner))
                            if owner.host_addr() == identity.host_addr
                                && owner.generation() == identity.generation
                    )
            });
        eprintln!(
            "[COW-REFUSAL inventory] exact_stage2_candidates={inventory_total} shown={} identity={inventory_identity:?} consistent={inventory_consistent} authorized={inventory_authorized}",
            inventory_rows.len(),
        );
        for (logical_key, extent) in inventory_rows {
            eprintln!(
                "[COW-REFUSAL inventory-row] logical={logical_key:#x?} frame={:?} mapping={:?} backing={:?} stage2=({:#x},{:#x}) owner={:?}",
                extent.frame,
                extent.mapping,
                extent.backing,
                extent.stage2_base,
                extent.stage2_length,
                extent.stage2_owner,
            );
        }

        let affine_translation_matches = |mapping_start: u64, mapping_ipa: u64| {
            if semantic_va < mapping_start {
                ipa.checked_add(mapping_start - semantic_va) == Some(mapping_ipa)
            } else {
                mapping_ipa.checked_add(semantic_va - mapping_start) == Some(ipa)
            }
        };
        let (mapping_total, mapping_rows) = {
            let mut total = 0usize;
            let mut rows = Vec::new();
            for mapping in self
                .mappings
                .iter()
                .rev()
                .filter(|mapping| mapping.start < compound_end && compound_va < mapping.end)
            {
                total = total.saturating_add(1);
                let physical_host_addr = mapped_region_physical_host_addr(mapping);
                let owner_matches = physical_host_addr.is_some_and(|host| {
                    mapping.owner_generation != 0
                        && global_frame_host_owner_identity_in(
                            custody,
                            mapping.physical_ipa,
                            mapping.physical_size as u64,
                        ) == Some((host as usize, mapping.owner_generation))
                });
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push((
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.physical_ipa,
                        mapping.physical_size,
                        physical_host_addr.map_or(0, |host| host as usize),
                        mapping.owner_generation,
                        owner_matches,
                        mapping.guest_writable,
                        mapping.sharing,
                    ));
                }
            }
            (total, rows)
        };
        eprintln!(
            "[COW-REFUSAL semantic-mappings] total={mapping_total} shown={}",
            mapping_rows.len()
        );
        for (
            start,
            end,
            mapping_ipa,
            mapping_physical_ipa,
            physical_size,
            physical_host_addr,
            owner_generation,
            owner_matches,
            guest_writable,
            sharing,
        ) in mapping_rows
        {
            eprintln!(
                "[COW-REFUSAL semantic-mapping] va=({:#x},{:#x}) ipa={:#x} affine={} physical=({:#x},{:#x}) host={:#x} owner_generation={} owner_matches={} writable={} sharing={:?}",
                start,
                end,
                mapping_ipa,
                affine_translation_matches(start, mapping_ipa),
                mapping_physical_ipa,
                physical_size,
                physical_host_addr,
                owner_generation,
                owner_matches,
                guest_writable,
                sharing,
            );
        }
        let (alias_total, alias_rows) = {
            let mut total = 0usize;
            let mut rows = Vec::new();
            for alias in alias_registry()
                .lock()
                .process_visible_ordered(self.mm_root_slot, self.container_root)
                .into_iter()
                .rev()
                .filter(|alias| {
                    alias.start < compound_end
                        && compound_va < alias.start.saturating_add(alias.size as u64)
                })
            {
                total = total.saturating_add(1);
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push(alias);
                }
            }
            (total, rows)
        };
        eprintln!(
            "[COW-REFUSAL semantic-aliases] total={alias_total} shown={}",
            alias_rows.len()
        );
        for alias in alias_rows {
            let owner_matches = alias.owner_generation != 0
                && global_frame_host_owner_identity_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                ) == Some((alias.physical_host_addr, alias.owner_generation));
            eprintln!(
                "[COW-REFUSAL semantic-alias] va=({:#x},{:#x}) ipa={:#x} affine={} physical=({:#x},{:#x}) host={:#x} owner_generation={} owner_matches={} writable={} sharing={:?} scope={:?}",
                alias.start,
                alias.start.saturating_add(alias.size as u64),
                alias.ipa,
                affine_translation_matches(alias.start, alias.ipa),
                alias.physical_ipa,
                alias.physical_size,
                alias.physical_host_addr,
                alias.owner_generation,
                owner_matches,
                alias.guest_writable,
                alias.sharing,
                alias.ownership_scope,
            );
        }

        let history = cow_diagnostic_history().lock().relevant(
            custody_identity,
            physical_ipa,
            Some(mm_access_identity),
            REPORT_ROW_LIMIT,
        );
        eprintln!("[COW-REFUSAL history] shown={}", history.len());
        for event in history {
            eprintln!("[COW-REFUSAL history-row] {event:?}");
        }
    }

    pub(crate) fn physical_cow_source_in(
        &self,
        custody: &CarrierVmCustody,
        semantic_va: u64,
        ipa: u64,
    ) -> Option<PhysicalCowSource> {
        let physical_ipa = align_down(ipa, CowArmedRanges::COMPOUND_SIZE);
        let physical_end = physical_ipa.checked_add(CowArmedRanges::COMPOUND_SIZE)?;
        let semantic_end = semantic_va.checked_add(CowArmedRanges::COMPOUND_SIZE)?;
        let affine_translation_matches = |mapping_start: u64, mapping_ipa: u64| {
            if semantic_va < mapping_start {
                ipa.checked_add(mapping_start - semantic_va) == Some(mapping_ipa)
            } else {
                mapping_ipa.checked_add(semantic_va - mapping_start) == Some(ipa)
            }
        };
        if let Some(alias) = alias_registry().lock().newest_matching_for_process(
            self.mm_root_slot,
            self.container_root,
            |alias| {
                alias_matches_process_scope(
                    alias.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) && alias.start < semantic_end
                    && alias
                        .start
                        .checked_add(alias.size as u64)
                        .is_some_and(|alias_end| semantic_va < alias_end)
                    && affine_translation_matches(alias.start, alias.ipa)
                    && physical_ipa >= alias.physical_ipa
                    && physical_end
                        <= alias
                            .physical_ipa
                            .saturating_add(alias.physical_size as u64)
                    && if self.persistent_vm_lifecycle
                        && is_reusable_global_frame_extent(
                            alias.physical_ipa,
                            alias.physical_size as u64,
                        )
                    {
                        global_frame_host_owner_matches_in(
                            custody,
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    } else {
                        alias_backing_is_live(alias.physical_host_addr)
                    }
            },
        ) {
            let offset = usize::try_from(physical_ipa - alias.physical_ipa).ok()?;
            if self.persistent_vm_lifecycle
                && is_reusable_global_frame_extent(alias.physical_ipa, alias.physical_size as u64)
            {
                if let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                    alias.physical_host_addr,
                    alias.owner_generation,
                ) {
                    return Some(PhysicalCowSource::pinned(pin, offset, physical_ipa));
                }
            } else {
                return Some(PhysicalCowSource::unpinned(
                    unsafe { (alias.physical_host_addr as *mut u8).add(offset) },
                    physical_ipa,
                ));
            }
        }
        let mapping = self
            .mappings
            .candidates_for_range(GuestVa(semantic_va), CowArmedRanges::COMPOUND_SIZE)
            .find(|mapping| {
                let physical_mapping_end = mapping
                    .physical_ipa
                    .checked_add(mapping.physical_size as u64);
                mapping.start < semantic_end
                    && semantic_va < mapping.end
                    && affine_translation_matches(mapping.start, mapping.ipa)
                    && physical_ipa >= mapping.physical_ipa
                    && physical_mapping_end.is_some_and(|limit| physical_end <= limit)
                    && (!self.persistent_vm_lifecycle
                        || !is_reusable_global_frame_extent(
                            mapping.physical_ipa,
                            mapping.physical_size as u64,
                        )
                        || global_frame_region_owner_matches_in(custody, mapping))
            });
        if let Some(mapping) = mapping
            && let Some(physical_host_addr) = mapped_region_physical_host_addr(mapping)
            && let Ok(offset) = usize::try_from(physical_ipa - mapping.physical_ipa)
        {
            if self.persistent_vm_lifecycle
                && is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                )
            {
                if let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                    physical_host_addr as usize,
                    mapping.owner_generation,
                ) {
                    return Some(PhysicalCowSource::pinned(pin, offset, physical_ipa));
                }
            } else {
                return Some(PhysicalCowSource::unpinned(
                    unsafe { physical_host_addr.add(offset) },
                    physical_ipa,
                ));
            }
        }
        // A newly activated sibling can have stale worker-local semantic rows
        // even though its live stage-1 tree and shared inventory already name
        // the current COW overlay. Authenticate that physical fact directly:
        // the extent, host address, and owner generation must all match exactly,
        // and the returned source retains both mapping and stage-2 pins.
        if self.persistent_vm_lifecycle
            && is_reusable_global_frame_extent(physical_ipa, CowArmedRanges::COMPOUND_SIZE)
        {
            let inventory_owner = {
                let inventory = self.frame_inventory.lock();
                let mut owner = None;
                let mut consistent = true;
                for extent in inventory.extents.values().filter(|extent| {
                    (extent.stage2_base, extent.stage2_length)
                        == (physical_ipa, CowArmedRanges::COMPOUND_SIZE)
                }) {
                    let candidate = extent.stage2_owner;
                    if candidate.generation == 0
                        || owner.is_some_and(|current| current != candidate)
                    {
                        consistent = false;
                        break;
                    }
                    owner = Some(candidate);
                }
                consistent.then_some(owner).flatten()
            };
            if let Some(owner) = inventory_owner
                && let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    physical_ipa,
                    CowArmedRanges::COMPOUND_SIZE,
                    owner.host_addr,
                    owner.generation,
                )
            {
                return Some(PhysicalCowSource::pinned(pin, 0, physical_ipa));
            }
        }
        self.report_physical_cow_source_refusal(custody, semantic_va, ipa);
        None
    }

    pub(crate) fn host_ptr_for_ipa(&self, ipa: u64, len: usize) -> Option<*mut u8> {
        let mapping = HvfVmState::mapping_for_ipa_range(&self.mappings, ipa, len.max(1))?;
        let offset = usize::try_from(ipa.saturating_sub(mapping.ipa)).ok()?;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    pub(crate) fn record_stage1_populated_prefix(&self, base: u64, prefix: usize) {
        if let Some(owner) = self
            .mm_access
            .structural_owners
            .read()
            .get(&(base, carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize))
        {
            owner.record_populated_prefix(prefix);
        }
        if let Some(ref auth) = *self.mm_access.mm_root_stage2.lock() {
            if auth.root_slot.0 == base {
                auth.owner.record_populated_prefix(prefix);
            }
        }
    }

    pub(crate) fn page_table_resolver<'a>(
        &'a self,
        manager_base: u64,
        primary_host: Option<*mut u8>,
    ) -> HvfPageTableResolver<'a> {
        HvfPageTableResolver {
            task: self,
            manager_base,
            primary_host,
        }
    }

    pub(crate) fn publish_stage1_extension_arenas(
        &mut self,
        manager: &carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        let root_perms = self
            .mm_root_slot
            .and_then(|(root_base, _)| {
                self.mappings
                    .iter()
                    .find(|m| m.ipa == root_base)
                    .map(|m| m.perms)
            })
            .unwrap_or(applevisor::memory::MemPerms::ReadWrite);

        let published = self.mm_access.publish_stage1_extension_arenas(
            &self.custody_arc(),
            manager,
            root_perms,
        )?;
        self.mappings.extend(published);
        Ok(())
    }

    pub(crate) fn retire_stage1_extension_arenas(
        &mut self,
        manager: &mut carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let custody = self.custody_arc();
        let retired_bases = manager.retire_extension_arenas();
        for base in retired_bases {
            HvfVmState::retire_stage2_extent_from_mappings_in(
                &custody,
                &mut self.mappings,
                base,
                TWO_MIB,
            )?;
            self.mappings.retain(|m| m.ipa != base);
        }
        Ok(())
    }

    pub(crate) fn translate_va_for_cow(&self, va: u64) -> Option<u64> {
        self.page_tables_authority()
            .with_manager(|m| m.translate(va))
            .flatten()
    }

    pub(crate) fn mapping_for_range_in(
        &self,
        custody: &CarrierVmCustody,
        address: u64,
        length: usize,
    ) -> Option<MappingView> {
        let address = strip_pointer_tag(address);
        let stage1_ipa = self.translate_va_for_cow(address);
        let region_is_live = |mapping: &HvfMappedRegion| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                )
                || global_frame_region_owner_matches_in(custody, mapping)
        };
        let alias_is_live = |alias: &AliasBacking| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(alias.physical_ipa, alias.physical_size as u64)
                || global_frame_host_owner_matches_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                    alias.physical_host_addr,
                    alias.owner_generation,
                )
        };
        if let Some(ipa) = stage1_ipa {
            if let Some(mapping) = self
                .mappings
                .candidates_for_range(GuestVa(address), length as u64)
                .find(|mapping| {
                    ipa >= mapping.ipa
                        && ipa < mapping.ipa.saturating_add(mapping.size as u64)
                        && mapping.contains_range(address, length)
                        && mapping.ipa.checked_add(address - mapping.start) == Some(ipa)
                        && region_is_live(mapping)
                })
            {
                return Some(mapping.view());
            }
            if let Some(alias) = alias_registry().lock().newest_containing_ipa(ipa, |alias| {
                // A fork peer can retain the same physical frame at a
                // different VA. Its live IPA is not a semantic mapping for
                // this MM: copy offsets and sparse-materialization bounds
                // must come from the requested VA's exact translation.
                alias_matches_process_scope(
                    alias.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) && address >= alias.start
                    && address.checked_add(length as u64).is_some_and(|end| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                    })
                    && alias.ipa.checked_add(address - alias.start) == Some(ipa)
                    && ipa >= alias.ipa
                    && ipa < alias.ipa.saturating_add(alias.size as u64)
                    && alias_is_live(alias)
            }) {
                return Some(MappingView::from_alias(&alias));
            }
            return None;
        }
        // A dynamic-alias row is this task's CACHE of a process-wide registry
        // projection, and only the registry is edited by a sibling task's
        // partial `munmap`/`MAP_FIXED`: `unregister_alias_entries` splits the
        // registry entry and `split_local_rows_for_unmap` mirrors that onto the
        // unmapping task's own rows, so every OTHER task keeps a row that still
        // spans the retired page. Frame liveness cannot see that: the compound
        // stays owned as long as one neighbouring page still uses it, so the
        // stale row authenticated a PAGE the process had already unmapped. The
        // page's next incarnation then took the zero-allocation fast path of
        // `ensure_sparse_mmap_backing` and revalidated the retired leaf output
        // (a frame handed to someone else, or the page's previous bytes) —
        // the wide fault window makes multi-page rows, and with them this
        // shape, routine (go_types `s.allocCount != s.nelems`, the
        // `windowcoherence` cross-thread stress). Authenticate the row against
        // the registry at the page: the projection it caches must still exist
        // for this process scope with the same physical incarnation.
        let row_projection_is_current = |mapping: &HvfMappedRegion| {
            // Only the persistent (HVPatch) lifecycle publishes multi-page
            // rows into a process-scoped registry; the mature lane stamps no
            // owner generation and clears the registry at exec, so its rows
            // keep the frame-liveness contract above.
            if !mapping.is_dynamic_alias || !self.persistent_vm_lifecycle {
                return true;
            }
            let Some(end) = address.checked_add(length as u64) else {
                return false;
            };
            alias_registry()
                .lock()
                .newest_process_alias_containing_va(
                    address,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                            && alias.physical_ipa == mapping.physical_ipa
                            && alias.physical_size == mapping.physical_size
                            && alias.owner_generation == mapping.owner_generation
                            && alias.ipa.checked_add(address - alias.start)
                                == mapping.ipa.checked_add(address - mapping.start)
                    },
                )
                .is_some()
        };
        if let Some(mapping) = self
            .mappings
            .candidates_for_range(GuestVa(address), length as u64)
            .find(|mapping| {
                mapping.contains_range(address, length)
                    && region_is_live(mapping)
                    && row_projection_is_current(mapping)
            })
        {
            return Some(mapping.view());
        }
        if !self.protections.range_no_access(address, length) {
            if let Some(alias) = alias_registry().lock().newest_process_alias_containing_va(
                address,
                self.mm_root_slot,
                self.container_root,
                |alias| {
                    address.checked_add(length as u64).is_some_and(|end| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                    }) && alias_is_live(alias)
                },
            ) {
                return Some(MappingView::from_alias(&alias));
            }
        }
        None
    }

    pub(crate) fn supersede_cow_receipts_for_cow(&self, va: u64, len: u64) {
        let Some(end) = va.checked_add(len) else {
            return;
        };
        let mut receipts = self.cow_deferred_publications.lock();
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            if receipt_end <= va || receipt.va >= end {
                remaining.push(receipt);
                continue;
            }
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start
                && let Ok(prefix) = usize::try_from(overlap_start - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: prefix,
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end
                && let Ok(suffix) = usize::try_from(receipt_end - overlap_end)
                && let Some(expected_ipa) =
                    receipt.expected_ipa.checked_add(overlap_end - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: suffix,
                    expected_ipa,
                });
            }
        }
        *receipts = remaining;
    }

    pub(crate) fn retire_stage2_extent_for_cow(
        &mut self,
        custody: &CarrierVmCustody,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        HvfVmState::retire_stage2_extent_from_mappings_in(custody, &mut self.mappings, ipa, length)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForkMappingDisposition {
    /// Parent and child keep the same frame and the same writable permissions.
    SharedFrameWritable,
    /// Parent and child name the same private frame, with both stage-1 leaves
    /// armed read-only until one mm takes the write-permission COW fault.
    SharedFrameReadOnly,
    /// Carrick-owned stage-1 tables are per-mm mutable kernel state, so the
    /// child receives an independent table frame before publication.
    IndependentPageTables,
    /// Carrick-owned EL1 identity/mailbox state is never guest-accessible and
    /// must be writable before the exception vector can run.  Give the child a
    /// fresh per-mm frame before entry rather than depending on recovery from a
    /// current-EL write-permission fault.
    IndependentKernelState,
    /// `MADV_WIPEONFORK`: the child must see this guest mapping as fresh zero
    /// pages while the parent keeps its contents, so it cannot share the
    /// parent's frame even read-only. The child gets its own frame, seeded with
    /// the parent's bytes and then zeroed across exactly the wiped sub-ranges
    /// -- the frame can be wider than the semantic window and can carry other
    /// aliases' bytes, which must survive.
    IndependentGuestZeroed,
}

/// What the dispatcher's fork projection says about ONE VMM mapping's span.
///
/// `derive_fork_projection` turns the `madvise` fork policies into per-VMA
/// `ForkLeafDisposition`s and `ProcessForkRequest` carries them all the way
/// here, but the VMM used to derive every disposition from the mapping's own
/// properties and never read the plan -- so `MADV_DONTFORK`/`MADV_WIPEONFORK`
/// changed carrick's metadata while the child still inherited the pages.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProjectedForkSpan {
    /// No omitted or zeroed range touches this mapping.
    Preserve,
    /// `MADV_DONTFORK` covers the WHOLE span: the child gets no mapping here.
    Omit,
    /// `MADV_WIPEONFORK` covers part or all of the span. Byte ranges are
    /// relative to the mapping's semantic start.
    Zero { wiped: Vec<(u64, u64)> },
    /// `MADV_DONTFORK` covers only PART of the span. A hole inside one physical
    /// mapping is not representable in a single descriptor, and silently
    /// preserving the range would hand the child memory the guest asked it not
    /// to inherit, so this fails closed instead.
    PartialOmit,
}

/// Intersect one VMM mapping's semantic span with the fork projection.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn projected_fork_span(
    ranges: &[carrick_hal::ForkProjectionRange],
    start: u64,
    end: u64,
) -> ProjectedForkSpan {
    if end <= start {
        return ProjectedForkSpan::Preserve;
    }
    let mut omitted: u64 = 0;
    let mut wiped: Vec<(u64, u64)> = Vec::new();
    for range in ranges {
        let range_end = range.va.saturating_add(range.len);
        let lo = range.va.max(start);
        let hi = range_end.min(end);
        if hi <= lo {
            continue;
        }
        match range.disposition {
            carrick_hal::ForkLeafDisposition::Omit => omitted = omitted.saturating_add(hi - lo),
            carrick_hal::ForkLeafDisposition::Zero => wiped.push((lo - start, hi - lo)),
            carrick_hal::ForkLeafDisposition::Preserve => {}
        }
    }
    if omitted > 0 {
        return if omitted == end - start {
            ProjectedForkSpan::Omit
        } else {
            ProjectedForkSpan::PartialOmit
        };
    }
    if wiped.is_empty() {
        ProjectedForkSpan::Preserve
    } else {
        ProjectedForkSpan::Zero { wiped }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_mapping_disposition(
    mapping: &ThreadMappingDesc,
    shares_mm: bool,
) -> ForkMappingDisposition {
    if mapping.sharing.shares_across_fork() {
        ForkMappingDisposition::SharedFrameWritable
    } else if mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE {
        ForkMappingDisposition::IndependentPageTables
    } else if mapping.guest_writable && is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::IndependentKernelState
    } else if shares_mm && !is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::SharedFrameWritable
    } else {
        ForkMappingDisposition::SharedFrameReadOnly
    }
}

/// Apply the dispatcher's fork projection on top of the mapping's own
/// disposition.
///
/// The projection describes GUEST VMAs, so it may only redirect a mapping that
/// would otherwise be shared with the child. Carrick's own per-mm state (the
/// stage-1 tables and the EL1 control frame) keeps its disposition: those
/// ranges have no semantic VMA and must exist in every child.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn projected_fork_mapping_disposition(
    mapping: &ThreadMappingDesc,
    shares_mm: bool,
    ranges: &[carrick_hal::ForkProjectionRange],
) -> ForkMappingPlan {
    let base = fork_mapping_disposition(mapping, shares_mm);
    if !matches!(
        base,
        ForkMappingDisposition::SharedFrameWritable | ForkMappingDisposition::SharedFrameReadOnly
    ) {
        return ForkMappingPlan::preserved(base);
    }
    match projected_fork_span(ranges, mapping.start, mapping.end) {
        ProjectedForkSpan::Preserve => ForkMappingPlan::preserved(base),
        ProjectedForkSpan::Omit => ForkMappingPlan::Omit,
        ProjectedForkSpan::Zero { wiped } => ForkMappingPlan::Map {
            disposition: ForkMappingDisposition::IndependentGuestZeroed,
            wiped,
        },
        ProjectedForkSpan::PartialOmit => ForkMappingPlan::PartialOmit,
    }
}

/// What one VMM mapping becomes in the child once the fork projection has been
/// applied on top of the mapping's own disposition.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ForkMappingPlan {
    /// The child gets the mapping. `wiped` names the sub-ranges, relative to
    /// the mapping's semantic start, whose bytes must read as zero there.
    Map {
        disposition: ForkMappingDisposition,
        wiped: Vec<(u64, u64)>,
    },
    /// `MADV_DONTFORK` over the whole span: the child gets nothing here.
    Omit,
    /// `MADV_DONTFORK` over only part of the span, which one descriptor cannot
    /// express. See `ProjectedForkSpan::PartialOmit`.
    PartialOmit,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkMappingPlan {
    pub(crate) fn preserved(disposition: ForkMappingDisposition) -> Self {
        Self::Map {
            disposition,
            wiped: Vec::new(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_frame_receipt_kind(
    disposition: ForkMappingDisposition,
    start: u64,
    size: usize,
) -> Option<carrick_observability::probes::HvpatchForkFrameKind> {
    use carrick_observability::probes::HvpatchForkFrameKind;

    match disposition {
        ForkMappingDisposition::SharedFrameWritable => Some(HvpatchForkFrameKind::Shared),
        ForkMappingDisposition::SharedFrameReadOnly
            if !is_kernel_only_stage1_range(start, size) =>
        {
            Some(HvpatchForkFrameKind::PrivateCow)
        }
        ForkMappingDisposition::SharedFrameReadOnly
        | ForkMappingDisposition::IndependentPageTables
        | ForkMappingDisposition::IndependentKernelState
        // A wiped mapping shares no frame with the parent, so there is no
        // fork-frame receipt to publish for it.
        | ForkMappingDisposition::IndependentGuestZeroed => None,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_stage1_cow_write_fault(syndrome: u64) -> bool {
    const EXCEPTION_CLASS_MASK: u64 = 0x3f;
    const DATA_ABORT_LOWER_EL: u64 = 0x24;
    const WRITE_NOT_READ: u64 = 1 << 6;
    const FAULT_STATUS_MASK: u64 = 0x3f;
    let exception_class = (syndrome >> 26) & EXCEPTION_CLASS_MASK;
    let fault_status = syndrome & FAULT_STATUS_MASK;
    matches!(exception_class, DATA_ABORT_LOWER_EL | 0x25)
        && syndrome & WRITE_NOT_READ != 0
        && matches!(fault_status, 0x0d..=0x0f)
}

pub(crate) fn frame_cow_write_is_denied(
    protection_denied: bool,
    guest_writable: bool,
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
) -> bool {
    intent == carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
        && (protection_denied || !guest_writable)
}

pub(crate) fn frame_cow_preserves_guest_protection(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
) -> bool {
    intent != carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameCowWriteRoute {
    Direct,
    CopyOnWrite,
    MaterializeRetired,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnarmedPermissionFaultRoute {
    NotCow,
    RetryCommittedWinner,
    MissingArm,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unarmed_permission_fault_route(
    private_writable_mapping: bool,
    write_denied: bool,
    any_arms: bool,
    live_leaf_is_writable: bool,
) -> UnarmedPermissionFaultRoute {
    if !private_writable_mapping || write_denied {
        UnarmedPermissionFaultRoute::NotCow
    } else if live_leaf_is_writable {
        UnarmedPermissionFaultRoute::RetryCommittedWinner
    } else if !any_arms {
        UnarmedPermissionFaultRoute::NotCow
    } else {
        UnarmedPermissionFaultRoute::MissingArm
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn frame_cow_write_route(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
    armed: bool,
    retained_output_has_no_physical_source: bool,
    retained_output_source_is_shared: bool,
) -> FrameCowWriteRoute {
    // A maintenance write whose retained output names a frame OTHER mms still
    // reference must MATERIALIZE a private replacement, exactly like the
    // no-source case — never write through. The armed-set cannot make this
    // call: it is derived at fork from alias rows and is known-omissive
    // (`mtforkcorrupt`), and an unarmed Direct write through a shared frame
    // zeroed one process's live memory during another's mmap reuse (the
    // CPython forkserver interned-dict corruption). The frame inventory's
    // reference count is the authority that actually knows who shares.
    if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
        && (retained_output_has_no_physical_source || retained_output_source_is_shared)
    {
        FrameCowWriteRoute::MaterializeRetired
    } else if armed {
        FrameCowWriteRoute::CopyOnWrite
    } else {
        FrameCowWriteRoute::Direct
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn next_frame_cow_write_probe(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
    current: u64,
    end: u64,
    armed_span_end: Option<u64>,
    next_armed_start: Option<u64>,
) -> u64 {
    // A 16 KiB physical frame may carry four independently mapped Linux 4 KiB
    // pages. Backing maintenance runs while reused leaves are invalid, and
    // those four outputs can therefore name a mixture of live, shared, and
    // retired owners. Classify each Linux page.
    if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance {
        return align_down(current, 0x1000).saturating_add(0x1000).min(end);
    }
    // A guest-visible write advances by exactly what the armed COW
    // transaction resolved: the span itself (one 16 KiB compound for a fork
    // arm, one 4 KiB page for a private file view whose clean siblings must
    // keep tracking the file). An unarmed page advances to the end of its
    // compound, but never past the next armed range: a page privatized out
    // of a compound leaves its siblings armed, and stepping over them would
    // write straight into a shared frame or a file view.
    let next = match armed_span_end {
        Some(span_end) if span_end > current => span_end,
        _ => {
            let compound_end = align_down(current, CowArmedRanges::COMPOUND_SIZE)
                .saturating_add(CowArmedRanges::COMPOUND_SIZE);
            match next_armed_start {
                Some(start) if start > current => compound_end.min(start),
                _ => compound_end,
            }
        }
    };
    next.max(current.saturating_add(1)).min(end)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameCowTrigger {
    class: carrick_observability::probes::HvpatchFrameCowTriggerClass,
    syndrome: u64,
    far: u64,
    ttbr0: u64,
}

#[cfg(test)]
pub(crate) mod tests;
