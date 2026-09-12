//! # Frame Inventory
//!
//! Monotonic tracking and publication of stage-2 physical frame allocations,
//! COW extents, and alias inventory transactions.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum InventoryBackingIdentity {
    Private(u64),
    /// One unique anonymous object whose host mapping is inherited through an
    /// explicit fork-child descriptor. Unlike `SharedFile`, this identity is
    /// never looked up globally or deduplicated across independently-created
    /// mappings.
    SharedAnon(u64),
    /// One guest `MAP_PRIVATE` file mapping. Mutable files use a writable host
    /// `MAP_SHARED` page-cache view; immutable lowers use host `MAP_PRIVATE`.
    /// A maintenance write must still materialize a private replacement rather
    /// than write through either view, and every guest page starts fork-COW
    /// armed at 4 KiB granularity. Like `SharedAnon` it is never deduplicated.
    PrivateFileView(u64),
    SharedFile {
        device: u64,
        inode: u64,
        offset: u64,
        length: u64,
    },
}

/// What backs a freshly materialized sparse-arena extent.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
pub(crate) enum SparseExtentBacking<'a> {
    /// Fresh zero-filled private anonymous frames.
    Anon,
    /// Fresh private anonymous frames initialized from an exact byte slice.
    /// Foreign copyout uses this to privatize one page from the retained
    /// immutable file recipe without publishing the whole mapping first.
    SeededAnon { bytes: &'a [u8] },
    /// A file view that supplies a guest `MAP_PRIVATE` mapping. Immutable lower
    /// files use host `MAP_PRIVATE`; mutable writable files use host
    /// `MAP_SHARED` so clean guest pages follow later file writes. Stage-1 COW
    /// keeps guest stores private in both cases.
    FileView {
        fd: std::os::fd::BorrowedFd<'a>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryStage2OwnerIdentity {
    /// Base host pointer for the complete `stage2_base/stage2_length` lease.
    pub(crate) host_addr: usize,
    /// Exact global-owner incarnation, or zero for a local/carrier lease.
    pub(crate) generation: u64,
}

#[cfg(test)]
impl InventoryStage2OwnerIdentity {
    pub(crate) const TEST_UNOWNED: Self = Self {
        host_addr: 0,
        generation: 0,
    };
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryExtent {
    pub(crate) frame: carrick_hal::FrameId,
    pub(crate) mapping: carrick_hal::MappingId,
    pub(crate) backing: InventoryBackingIdentity,
    /// Physical stage-2 lease that contains this exact logical mapping. COW
    /// can split one large per-mm mapping into 16 KiB coverage fragments while
    /// the original host/HVF extent remains installed exactly once.
    pub(crate) stage2_base: u64,
    pub(crate) stage2_length: u64,
    /// Physical owner authenticated when this inventory mapping was published.
    /// Retirement consumes this identity instead of reconstructing authority
    /// from historical per-executor mapping rows.
    pub(crate) stage2_owner: InventoryStage2OwnerIdentity,
}

/// Metadata half of lane reuse eligibility. Callers must additionally hold
/// quiescence/topology, authenticate the owner and kernel mapping, and prove
/// exclusive frame/stage-2 references before writing any byte.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cow_lane_is_unpublished(
    key: (u64, u64),
    extent: InventoryExtent,
    scope: AliasOwnershipScope,
    offset: u64,
    aliases: &[AliasBacking],
) -> bool {
    const PAGE: u64 = 0x1000;
    if key.1 != 4 * PAGE
        || key.0 % (4 * PAGE) != 0
        || extent.stage2_base != key.0
        || extent.stage2_length != key.1
        || !matches!(extent.backing, InventoryBackingIdentity::Private(_))
        || extent.stage2_owner.generation == 0
        || offset >= key.1
        || offset % PAGE != 0
        || aliases.is_empty()
    {
        return false;
    }
    let Some(lane) = key.0.checked_add(offset) else {
        return false;
    };
    let Some(lane_end) = lane.checked_add(PAGE) else {
        return false;
    };
    aliases.iter().all(|alias| {
        let Some(start) = alias.ipa.checked_sub(key.0) else {
            return false;
        };
        let Some(end) = start.checked_add(alias.size as u64) else {
            return false;
        };
        alias.sharing == GuestMappingSharing::Private
            && alias.ownership_scope == scope
            && alias.inventory_backing == extent.backing
            && alias.physical_ipa == key.0
            && alias.physical_size as u64 == key.1
            && alias.physical_host_addr == extent.stage2_owner.host_addr
            && alias.owner_generation == extent.stage2_owner.generation
            && extent.stage2_owner.host_addr.checked_add(start as usize) == Some(alias.host_addr)
            && start % PAGE == 0
            && alias.size > 0
            && alias.size as u64 % PAGE == 0
            && end <= key.1
            && (alias.ipa >= lane_end || end <= offset)
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CowInventorySplitShape {
    pub(crate) old_key: (u64, u64),
    pub(crate) old: InventoryExtent,
    pub(crate) fragments: Vec<(u64, u64)>,
    pub(crate) retirement: CowInventoryRetirementDecision,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CowInventoryReplacementStage {
    pub(crate) gpa: u64,
    pub(crate) backing: InventoryBackingIdentity,
    pub(crate) stage2_owner: InventoryStage2OwnerIdentity,
    pub(crate) existing: Option<InventoryExtent>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CowInventoryRetirementDecision {
    pub(crate) retire_old_frame: bool,
    pub(crate) backend_frame_references_complete: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct InventoryMappingStage {
    pub(crate) gpa: u64,
    pub(crate) length: u64,
    pub(crate) permissions: carrick_hal::MemPerms,
    pub(crate) backing: InventoryBackingIdentity,
    pub(crate) inherited_frame: Option<carrick_hal::FrameId>,
    pub(crate) stage2_lease: Option<(u64, u64)>,
    pub(crate) stage2_owner: InventoryStage2OwnerIdentity,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CowInventoryFragment {
    pub(crate) gpa: u64,
    pub(crate) length: u64,
    pub(crate) mapping: carrick_hal::MappingId,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CowInventorySplit {
    pub(crate) replacement_is_existing: bool,
    pub(crate) old_key: (u64, u64),
    pub(crate) old: InventoryExtent,
    pub(crate) fragments: Vec<CowInventoryFragment>,
    pub(crate) new_key: (u64, u64),
    pub(crate) new_extent: InventoryExtent,
    pub(crate) retirement: CowInventoryRetirementDecision,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct InventoryLeaseRetirement {
    pub(crate) mappings: Vec<((u64, u64), InventoryExtent)>,
    pub(crate) frames: std::collections::BTreeSet<carrick_hal::FrameId>,
    pub(crate) stage2_leases: std::collections::BTreeSet<(u64, u64)>,
    pub(crate) stage2_population_complete: std::collections::BTreeMap<(u64, u64), bool>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PreparedProcessAliasRetirement {
    pub(crate) planned_leases: std::collections::BTreeSet<(u64, u64)>,
    pub(crate) diagnostic_before: Vec<AliasBacking>,
    pub(crate) disarm_spans: Vec<CowArmedSpan>,
    pub(crate) inventory: Option<(
        InventoryLeaseRetirement,
        carrick_hal::FrameInventoryReservation,
    )>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn decrement_inventory_reference<K: Ord + Copy + std::fmt::Debug>(
    map: &mut std::collections::BTreeMap<K, usize>,
    key: K,
) -> Result<(), TrapError> {
    let count = map.get_mut(&key).ok_or_else(|| {
        TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} disappeared"))
    })?;
    *count = count.checked_sub(1).ok_or_else(|| {
        TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} underflow"))
    })?;
    if *count == 0 {
        map.remove(&key);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn increment_inventory_reference<K: Ord + Copy + std::fmt::Debug>(
    map: &mut std::collections::BTreeMap<K, usize>,
    key: K,
) -> Result<(), TrapError> {
    let next = map
        .get(&key)
        .copied()
        .unwrap_or_default()
        .checked_add(1)
        .ok_or_else(|| {
            TrapError::Hypervisor(format!("HVPatch COW backend reference {key:?} exhausted"))
        })?;
    map.insert(key, next);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct InventoryFrameRegistry {
    pub(crate) shared: std::collections::BTreeMap<InventoryBackingIdentity, carrick_hal::FrameId>,
    pub(crate) references: std::collections::BTreeMap<carrick_hal::FrameId, usize>,
    pub(crate) extent_references:
        std::collections::BTreeMap<(carrick_hal::FrameId, u64, u64), usize>,
    pub(crate) stage2_references: std::collections::BTreeMap<(u64, u64), usize>,
    /// One-shot handoffs for physical leases whose backend population reached
    /// zero while the Kernel still reported mappings outside that population.
    /// The carrier destructor consumes a token and leaves the lease parked; a
    /// later exact retirement may then take that parked lease normally.
    pub(crate) authority_retained_stage2: std::collections::BTreeSet<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Reconcile the conservative carrier handoff after the caller has applied its
/// complete stage-2 reference-count mutation while holding `frames`.
///
/// Numeric references protect a live lease directly. A zero count needs the
/// one-shot token only when Kernel authority reports mappings outside that
/// backend population, and only for a lease actually owned by the carrier
/// registry; global host-owner leases retain their independent generation-bound
/// retirement path.
pub(crate) fn reconcile_carrier_stage2_authority_retention(
    frames: &mut InventoryFrameRegistry,
    lease: (u64, u64),
    authority_population_complete: bool,
) {
    if authority_population_complete {
        frames.authority_retained_stage2.remove(&lease);
    } else if !frames.stage2_references.contains_key(&lease) {
        frames.authority_retained_stage2.insert(lease);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct HvpatchFrameInventory {
    pub(crate) initialized: bool,
    pub(crate) extents: std::collections::BTreeMap<(u64, u64), InventoryExtent>,
    pub(crate) frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    pub(crate) alias_reservation: Option<carrick_hal::FrameInventoryReservation>,
    pub(crate) alias_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
    /// Extents `stage_mapping` inserted for the alias transaction currently in
    /// flight. They name MappingIds the authority does not learn about until the
    /// commit is applied, so a CANCELLED transaction has to take them back out —
    /// see `cancel_alias_inventory`.
    pub(crate) alias_staged: Vec<((u64, u64), InventoryExtent)>,
    pub(crate) process_reservation: Option<carrick_hal::FrameInventoryReservation>,
    pub(crate) process_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
    pub(crate) retired_reservation: Option<carrick_hal::FrameInventoryReservation>,
    pub(crate) replacement_reservation: Option<carrick_hal::FrameInventoryReservation>,
    pub(crate) exec_commits: Option<carrick_hal::ExecInventoryCommits>,
    pub(crate) retirement_reservation: Option<carrick_hal::FrameInventoryReservation>,
    pub(crate) retirement_commit: Option<carrick_hal::FrameInventoryCommit<()>>,
    /// The mappings this mm owned at the instant its retirement was staged.
    ///
    /// `stage_retirement` pushes one `UnmapMapping` per extent and then CLEARS
    /// `extents`, so by the time the MM authority authenticates the commit the
    /// ledger it would compare against is already empty. Capturing the
    /// expectation here — in the same critical section that drains it — is what
    /// lets `HvpatchTaskInventoryAuthority::prepare_retirement` still check
    /// exactness instead of reading a ledger the commit construction emptied.
    pub(crate) retirement_expected: Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchFrameInventory {
    pub(crate) fn with_frames(
        frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    ) -> Self {
        Self {
            frames,
            ..Self::default()
        }
    }
}

/// One engine state's handle onto the process-shared frame ledger.
///
/// The diagnostic arm is deliberately local to this handle. Sibling engines
/// share the authoritative mapping ledger but cannot consume one another's
/// selected-target failure injection.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchFrameInventoryState {
    pub(crate) ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CowArmedSpan {
    pub(crate) va: u64,
    pub(crate) len: usize,
    pub(crate) executable: bool,
    pub(crate) kernel_only: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct CowArmedRanges {
    pub(crate) ranges: Vec<carrick_aarch64::vmm::ForkCowRange>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CowArmedRanges {
    pub(crate) const COMPOUND_SIZE: u64 = 16 * 1024;
    pub(crate) const PAGE_SIZE: u64 = 4 * 1024;

    pub(crate) fn arm(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        self.ranges.extend_from_slice(ranges);
        self.ranges.sort_by_key(|range| (range.va, range.len));
        self.ranges.dedup();
    }

    pub(crate) fn snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.ranges.clone()
    }

    pub(crate) fn restore(&mut self, snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>) {
        self.ranges = snapshot;
    }

    pub(crate) fn span_for(&self, va: u64) -> Option<CowArmedSpan> {
        // A boot arena row can remain as a broad structural mapping while
        // exact post-COW/post-unmap alias fragments overlap it. The live
        // stage-1 leaf belongs to the most-specific fragment: greatest start,
        // then shortest length for equal starts. Choosing the broad row here
        // repointed an adjacent frame across the fragment boundary (a write in
        // a8-aa replaced aa-ac and corrupted musl's allocation header).
        let range = self
            .ranges
            .iter()
            .filter(|range| {
                range
                    .va
                    .checked_add(range.len as u64)
                    .is_some_and(|range_end| va >= range.va && va < range_end)
            })
            .max_by(|left, right| {
                left.va
                    .cmp(&right.va)
                    .then_with(|| right.len.cmp(&left.len))
                    // A page-granular arm (private file view) over the same
                    // range as a fork's compound arm must win: privatizing one
                    // 4 KiB page keeps its clean siblings on the page-cache
                    // view AND still armed for the fork peer, which is exact
                    // for both; privatizing the compound stops the siblings
                    // tracking the file.
                    .then_with(|| {
                        let page = |range: &carrick_aarch64::vmm::ForkCowRange| {
                            range.granule == carrick_aarch64::vmm::CowGranule::Page
                        };
                        page(left).cmp(&page(right))
                    })
            })?;
        let range_end = range.va.checked_add(range.len as u64)?;
        let granule = match range.granule {
            carrick_aarch64::vmm::CowGranule::Compound => Self::COMPOUND_SIZE,
            carrick_aarch64::vmm::CowGranule::Page => Self::PAGE_SIZE,
        };
        let granule_start = va & !(granule - 1);
        let granule_end = granule_start.checked_add(granule)?;
        let start = range.va.max(granule_start);
        let end = range_end.min(granule_end);
        Some(CowArmedSpan {
            va: start,
            len: usize::try_from(end.checked_sub(start)?).ok()?,
            executable: range.executable,
            kernel_only: range.kernel_only,
        })
    }

    /// The lowest armed range start strictly above `va`, so an unarmed write
    /// can advance to exactly where the next armed page begins.
    pub(crate) fn next_armed_start_after(&self, va: u64) -> Option<u64> {
        self.ranges
            .iter()
            .map(|range| range.va)
            .filter(|start| *start > va)
            .min()
    }

    pub(crate) fn disarm(&mut self, span: CowArmedSpan) {
        let span_end = span.va.saturating_add(span.len as u64);
        let mut replacement = Vec::with_capacity(self.ranges.len().saturating_add(1));
        for range in self.ranges.drain(..) {
            let range_end = range.va.saturating_add(range.len as u64);
            if range_end <= span.va || range.va >= span_end {
                replacement.push(range);
                continue;
            }
            if range.va < span.va {
                replacement.push(carrick_aarch64::vmm::ForkCowRange {
                    va: range.va,
                    len: usize::try_from(span.va - range.va).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                    granule: range.granule,
                });
            }
            if range_end > span_end {
                replacement.push(carrick_aarch64::vmm::ForkCowRange {
                    va: span_end,
                    len: usize::try_from(range_end - span_end).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                    granule: range.granule,
                });
            }
        }
        self.ranges = replacement;
    }

    pub(crate) fn overlapping(
        &self,
        va: u64,
        len: usize,
    ) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        let end = va.saturating_add(len as u64);
        self.ranges
            .iter()
            .filter_map(|range| {
                let range_end = range.va.saturating_add(range.len as u64);
                let start = range.va.max(va);
                let overlap_end = range_end.min(end);
                (start < overlap_end).then(|| carrick_aarch64::vmm::ForkCowRange {
                    va: start,
                    len: usize::try_from(overlap_end - start).unwrap_or_default(),
                    executable: range.executable,
                    kernel_only: range.kernel_only,
                    granule: range.granule,
                })
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn disarm_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        for range in ranges {
            self.disarm(CowArmedSpan {
                va: range.va,
                len: range.len,
                executable: range.executable,
                kernel_only: range.kernel_only,
            });
        }
    }
}

/// Whether repointing one semantic COW span leaves another Linux leaf in this
/// address space naming the same 16 KiB physical source frame.
///
/// The frame inventory is physical while Linux permissions and mappings are
/// 4 KiB-semantic. A `brk`, `mprotect`, or partial-unmap boundary can therefore
/// make one COW transaction repoint only part of a host compound. The old
/// physical frame must remain inventoried until every sibling leaf has moved;
/// otherwise the last child reference can retire stage-2 while the parent PTE
/// still names that frame.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cow_source_has_retained_sibling(
    span: CowArmedSpan,
    old_ipa: u64,
    old_physical_ipa: u64,
    mut retained_translation: impl FnMut(u64) -> Option<u64>,
) -> bool {
    const PAGE_SIZE: u64 = 4 * 1024;
    let Some(source_offset) = old_ipa.checked_sub(old_physical_ipa) else {
        return false;
    };
    let Some(source_va) = span.va.checked_sub(source_offset) else {
        return false;
    };
    let repoint_start = span.va & !(PAGE_SIZE - 1);
    let Some(span_end) = span.va.checked_add(span.len as u64) else {
        return false;
    };
    let Some(repoint_end) = span_end
        .checked_add(PAGE_SIZE - 1)
        .map(|end| end & !(PAGE_SIZE - 1))
    else {
        return false;
    };

    (0..CowArmedRanges::COMPOUND_SIZE)
        .step_by(PAGE_SIZE as usize)
        .any(|offset| {
            let Some(page_va) = source_va.checked_add(offset) else {
                return false;
            };
            if page_va >= repoint_start && page_va < repoint_end {
                return false;
            }
            let Some(expected_ipa) = old_physical_ipa.checked_add(offset) else {
                return false;
            };
            retained_translation(page_va)
                .is_some_and(|translated| align_down(translated, PAGE_SIZE) == expected_ipa)
        })
}

/// Extend the local-compound sibling check to semantic aliases elsewhere in
/// the same address space.
///
/// `aliases` must already have been authenticated against their current
/// stage-2 owner generation. This function independently requires the live
/// stage-1 leaf to preserve the exact affine IPA relation, so an old registry
/// row cannot retain inventory after its PTE was repointed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cow_source_has_retained_projection(
    span: CowArmedSpan,
    old_ipa: u64,
    old_physical_ipa: u64,
    aliases: &[AliasBacking],
    mut retained_translation: impl FnMut(u64) -> Option<u64>,
) -> bool {
    const PAGE_SIZE: u64 = 4 * 1024;
    if cow_source_has_retained_sibling(span, old_ipa, old_physical_ipa, |va| {
        retained_translation(va)
    }) {
        return true;
    }
    let repoint_start = span.va & !(PAGE_SIZE - 1);
    let Some(span_end) = span.va.checked_add(span.len as u64) else {
        return false;
    };
    let Some(repoint_end) = span_end
        .checked_add(PAGE_SIZE - 1)
        .map(|end| end & !(PAGE_SIZE - 1))
    else {
        return false;
    };

    aliases.iter().any(|alias| {
        let Some(alias_ipa_end) = alias.ipa.checked_add(alias.size as u64) else {
            return false;
        };
        (0..CowArmedRanges::COMPOUND_SIZE)
            .step_by(PAGE_SIZE as usize)
            .any(|offset| {
                let Some(expected_ipa) = old_physical_ipa.checked_add(offset) else {
                    return false;
                };
                if expected_ipa < alias.ipa || expected_ipa >= alias_ipa_end {
                    return false;
                }
                let Some(candidate_va) = alias
                    .start
                    .checked_add(expected_ipa.saturating_sub(alias.ipa))
                else {
                    return false;
                };
                if candidate_va >= repoint_start && candidate_va < repoint_end {
                    return false;
                }
                retained_translation(candidate_va)
                    .is_some_and(|translated| align_down(translated, PAGE_SIZE) == expected_ipa)
            })
    })
}

/// Resolve only current, process-visible semantic rows that may prove another
/// live stage-1 projection of this physical COW compound.
///
/// The physical index bounds the lookup. Exact current-owner generation and
/// host-pointer affinity make the returned rows lifetime authority rather than
/// stale semantic hints.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn authenticated_cow_retention_aliases_in(
    custody: &CarrierVmCustody,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    old_physical_ipa: u64,
) -> Vec<AliasBacking> {
    // Do not hold the alias lock while consulting the owner directory. Both
    // are carrier-global authorities, and keeping the lock graph acyclic is
    // more important than retaining a stale candidate snapshot: exact owner
    // generation plus the later live stage-1 read reject any intervening
    // retirement or repoint.
    let candidates = {
        let registry = alias_registry().lock();
        registry.private_owned_containing_physical(
            mm_root_slot,
            container_root,
            old_physical_ipa,
            CowArmedRanges::COMPOUND_SIZE,
        )
    };
    authenticate_cow_retention_aliases(candidates, |alias| {
        global_frame_host_owner_matches_in(
            custody,
            alias.physical_ipa,
            alias.physical_size as u64,
            alias.physical_host_addr,
            alias.owner_generation,
        )
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn authenticate_cow_retention_aliases(
    candidates: impl IntoIterator<Item = AliasBacking>,
    mut owner_matches: impl FnMut(&AliasBacking) -> bool,
) -> Vec<AliasBacking> {
    candidates
        .into_iter()
        .filter(|alias| {
            if alias.sharing != GuestMappingSharing::Private || alias.owner_generation == 0 {
                return false;
            }
            let Some(semantic_physical_offset) = alias.ipa.checked_sub(alias.physical_ipa) else {
                return false;
            };
            let Ok(semantic_physical_offset) = usize::try_from(semantic_physical_offset) else {
                return false;
            };
            if alias
                .physical_host_addr
                .checked_add(semantic_physical_offset)
                != Some(alias.host_addr)
            {
                return false;
            }
            owner_matches(alias)
        })
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchFrameInventoryState {
    pub(crate) fn new(ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>) -> Self {
        Self { ledger }
    }

    pub(crate) fn lock(&self) -> parking_lot::MutexGuard<'_, HvpatchFrameInventory> {
        self.ledger.lock()
    }

    pub(crate) fn shared_ledger(
        &self,
    ) -> std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>> {
        std::sync::Arc::clone(&self.ledger)
    }

    pub(crate) fn begin_process_inventory(
        &self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.ledger.lock();
        if inventory.process_reservation.is_some() || inventory.process_commit.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch child inventory transaction".to_owned(),
            ));
        }
        inventory.process_reservation = Some(reservation);
        Ok(())
    }

    pub(crate) fn cancel_process_inventory(&self) -> bool {
        self.ledger.lock().process_reservation.take().is_some()
    }

    pub(crate) fn begin_alias_inventory(
        &self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.ledger.lock();
        if inventory.alias_reservation.is_some() || inventory.alias_commit.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch alias inventory transaction".to_owned(),
            ));
        }
        inventory.alias_reservation = Some(reservation);
        Ok(())
    }

    /// Discard whatever alias staging a FAILED install left armed, so the next
    /// guest `mmap` can arm its own transaction instead of being rejected as
    /// overlapping.
    ///
    /// Both slots are cleared because the failure can land on either side of the
    /// hand-off: `add_alias_with_sharing` returning early leaves the
    /// `alias_reservation` it never consumed, while a stage-1 `map_aliased`
    /// failure after a successful stage-2 install leaves the `alias_commit` it
    /// already staged.
    ///
    /// Dropping the reservation really is free — reservations are pointer-free
    /// data whose only cost is burning candidate IDs the monotonic registry
    /// never reissues. Dropping the COMMIT is NOT. By the time one exists,
    /// `stage_mapping` has already inserted an `InventoryExtent` into
    /// `extents`, and that extent names a MappingId the authority only learns
    /// about when the commit is applied. Discarding the commit alone therefore
    /// left the backend ledger holding an extent for a mapping the authority
    /// had never seen, and the next `munmap` of that VA staged an
    /// `UnmapMapping` for it and aborted the carrier with
    /// `mapping MappingId(N) is not live`. So the staged extents are rolled
    /// back here too, which is what makes this discard leave no residue.
    pub(crate) fn cancel_alias_inventory(&self) -> bool {
        let mut inventory = self.ledger.lock();
        let reservation = inventory.alias_reservation.take();
        let commit = inventory.alias_commit.take();
        let staged = std::mem::take(&mut inventory.alias_staged);
        tracing::trace!(
            staged = staged.len(),
            reservation = reservation.is_some(),
            commit = commit.is_some(),
            "hvpatch alias cancel"
        );
        if !staged.is_empty()
            && let Err(error) = HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)
        {
            // The ledger and the authority have already diverged; continuing
            // would hand a later retirement an extent naming a mapping that
            // does not exist, which aborts anyway but much further from the
            // cause.
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "rollback of unpublished alias mappings failed: error={error} staged_count={}",
                staged.len()
            );
        }
        reservation.is_some() || commit.is_some()
    }

    pub(crate) fn begin_exec_inventory(
        &self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.ledger.lock();
        if inventory.retired_reservation.is_some()
            || inventory.replacement_reservation.is_some()
            || inventory.exec_commits.is_some()
        {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch exec inventory transaction".to_owned(),
            ));
        }
        inventory.retired_reservation = retired;
        inventory.replacement_reservation = Some(replacement);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn final_exec_physical_extents(
    inventory: &HvpatchFrameInventory,
    authority: &dyn carrick_hal::FrameCowAuthority,
) -> Result<std::collections::BTreeSet<(u64, usize)>, TrapError> {
    let frames = inventory.frames.lock();
    let mut physical = std::collections::BTreeSet::new();
    let mut local_stage2_references = std::collections::BTreeMap::new();
    let mut candidate_frames_set = std::collections::BTreeSet::new();
    for extent in inventory.extents.values() {
        *local_stage2_references
            .entry((extent.stage2_base, extent.stage2_length))
            .or_insert(0usize) += 1;
        candidate_frames_set.insert(extent.frame);
    }
    let candidate_frames: Vec<carrick_hal::FrameId> = candidate_frames_set.into_iter().collect();
    let (_, frame_counts) = authority
        .retirement_batch_query(&[], &candidate_frames)
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "query exec-retirement frame inventory batch: {error}"
            ))
        })?;
    let authoritative_counts: std::collections::BTreeMap<carrick_hal::FrameId, Option<usize>> =
        candidate_frames.into_iter().zip(frame_counts).collect();

    let mut complete_frames = std::collections::BTreeSet::new();
    for (&frame, authoritative) in &authoritative_counts {
        let backend = frames.references.get(&frame).copied().ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "HVPatch exec frame {frame:?} has no backend reference"
            ))
        })?;
        if *authoritative == Some(backend) {
            complete_frames.insert(frame);
        }
    }
    for (lease, local) in local_stage2_references {
        let references = frames
            .stage2_references
            .get(&lease)
            .copied()
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {lease:?} has no backend reference"
                ))
            })?;
        let all_frame_populations_complete = inventory
            .extents
            .values()
            .filter(|extent| (extent.stage2_base, extent.stage2_length) == lease)
            .all(|extent| complete_frames.contains(&extent.frame));
        if references == local && all_frame_populations_complete {
            physical.insert((
                lease.0,
                usize::try_from(lease.1).map_err(|_| TrapError::MappingTooLarge(lease.1))?,
            ));
        }
    }
    Ok(physical)
}

#[cfg(test)]
pub(crate) mod tests;

impl HvfVmState {
    pub(crate) fn retire_stage2_extent(&mut self, ipa: u64, length: u64) -> Result<(), TrapError> {
        #[cfg(not(test))]
        {
            let custody = std::sync::Arc::clone(&self.custody);
            Self::retire_stage2_extent_from_mappings_in(&custody, &mut self.mappings, ipa, length)
        }
        #[cfg(test)]
        {
            Self::retire_stage2_extent_from_mappings_in(
                legacy_test_carrier_vm_custody(),
                &mut self.mappings,
                ipa,
                length,
            )
        }
    }

    pub(crate) fn retire_stage2_extent_from_mappings_in(
        custody: &CarrierVmCustody,
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        let outcome = retire_global_frame_host_owner_in(custody, ipa, length);
        if outcome.is_retired()
            || matches!(
                outcome,
                GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                    | GlobalFrameRetirementOutcome::RetryPending { .. }
            )
        {
            return Ok(());
        }
        if let Some((row, owner)) = mappings.take_structural_owner(ipa, length) {
            let Some(mapping) = mappings.row(row) else {
                unreachable!("structural claim named a row that is not in the index")
            };
            let identity = authenticated_structural_owner_record_in(
                custody,
                &owner,
                mapped_region_physical_host_addr(mapping).unwrap_or(std::ptr::null_mut()),
                mapping.physical_ipa,
                mapping.physical_size,
                mapping.perms,
                mapping.owner_generation,
            );
            let Some(identity) = identity
                .filter(|_| mapping.physical_ipa == ipa && mapping.physical_size as u64 == length)
            else {
                mappings.restore_structural_owner(row, owner);
                return Err(TrapError::Hypervisor(format!(
                    "structural retirement owner for IPA 0x{ipa:x} size {length} is not the exact current custody owner"
                )));
            };
            // Process retirement is the authoritative lifetime boundary for
            // this structural stage-2 extent.  MM-access projections retain
            // owner Arcs so foreign reads can authenticate live semantic
            // mappings, but those metadata references must not postpone the
            // root-slot unmap after the Kernel has retired the MM and returned
            // its fixed slot for reuse.
            owner
                .retained
                .owner_retired
                .store(true, std::sync::atomic::Ordering::Release);
            let retirement = retry_structural_backing_identities_in_using(
                custody,
                &[identity],
                &mut unmap_global_frame_stage2_record,
                &mut release_retired_stage2_ipa,
            );
            if let Err(error) = retirement {
                mappings.restore_structural_owner(row, owner);
                return Err(error);
            }
            if custody.stage2_record_snapshot(identity.record_id).is_some() {
                mappings.restore_structural_owner(row, owner);
                return Err(TrapError::Hypervisor(format!(
                    "structural retirement owner for IPA 0x{ipa:x} size {length} did not reach terminal retirement"
                )));
            }
            drop(owner);
            return Ok(());
        }
        if let Some(lease) = mappings.take_stage2_lease(ipa, length) {
            drop(lease);
            return Ok(());
        }
        // A forked process parks its fresh kernel-state leases on the carrier,
        // not on a mapping row. Without this the fallback below released an IPA
        // whose lease was still live, and the lease's `Drop` then released it
        // again.
        if let Some(identity) = take_carrier_stage2_record(custody, ipa, length) {
            retire_carrier_stage2_record_at_safe_point(custody, identity)?;
            return Ok(());
        }
        if is_reusable_global_frame_extent(ipa, length)
            && !global_frame_ipa_allocator().lock().is_live(ipa, length)
        {
            return Ok(());
        }
        if custody.is_pooled_ipa(ipa) {
            return Ok(());
        }
        let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
        let rc = unsafe { inventory_hv_vm_unmap(ipa, size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "retire HVPatch stage-2 extent IPA 0x{ipa:x} size {size} failed: 0x{rc:x}"
            )));
        }
        release_retired_stage2_ipa(ipa, length)?;
        Ok(())
    }

    pub(crate) fn retire_unowned_stage2_extent_from_mappings_in(
        custody: &CarrierVmCustody,
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
        host_addr: usize,
    ) -> Result<(), TrapError> {
        if let Some(live) = global_frame_host_owner_identity_in(custody, ipa, length) {
            return Err(TrapError::Hypervisor(format!(
                "unowned stage-2 retirement {ipa:#x}/{length:#x} found live global owner {live:?}"
            )));
        }
        if let Some(lease) = mappings.take_exact_unowned_stage2_lease(ipa, length, host_addr) {
            drop(lease);
            return Ok(());
        }
        if let Some(identity) = take_carrier_stage2_record_if_owner(custody, ipa, length, host_addr)
        {
            retire_carrier_stage2_record_at_safe_point(custody, identity)?;
            return Ok(());
        }
        if is_reusable_global_frame_extent(ipa, length) {
            return Err(TrapError::Hypervisor(format!(
                "unowned reusable stage-2 retirement {ipa:#x}/{length:#x} lost exact mapped local/carrier owner 0x{host_addr:x}"
            )));
        }
        let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
        let rc = unsafe { inventory_hv_vm_unmap(ipa, size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "retire unowned HVPatch stage-2 extent IPA 0x{ipa:x} size {size} failed: 0x{rc:x}"
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retire_stage2_extent_from_mappings(
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        Self::retire_stage2_extent_from_mappings_in(
            legacy_test_carrier_vm_custody(),
            mappings,
            ipa,
            length,
        )
    }

    #[cfg(test)]
    pub(crate) fn retire_unowned_stage2_extent_from_mappings(
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
        host_addr: usize,
    ) -> Result<(), TrapError> {
        Self::retire_unowned_stage2_extent_from_mappings_in(
            legacy_test_carrier_vm_custody(),
            mappings,
            ipa,
            length,
            host_addr,
        )
    }

    pub(crate) fn inventory_generation(raw: u64) -> carrick_hal::MappingGeneration {
        let Some(raw) = std::num::NonZeroU64::new(raw) else {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "attempted to construct MappingGeneration from zero raw counter"
            );
        };
        carrick_hal::MappingGeneration::from_backend_counter(raw)
    }

    pub(crate) fn private_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch private backing identity exhausted"
            );
        }
        InventoryBackingIdentity::Private(serial)
    }

    pub(crate) fn private_file_view_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch private file-view backing identity exhausted"
            );
        }
        InventoryBackingIdentity::PrivateFileView(serial)
    }

    pub(crate) fn shared_anon_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch shared-anonymous backing identity exhausted"
            );
        }
        InventoryBackingIdentity::SharedAnon(serial)
    }

    pub(crate) fn region_permissions(region: &HvfMappedRegion) -> carrick_hal::MemPerms {
        let raw = u64::from(region.perms);
        carrick_hal::MemPerms {
            read: raw & 1 != 0,
            write: raw & 2 != 0,
            exec: raw & 4 != 0,
        }
    }

    pub(crate) fn reservation_error(
        error: carrick_hal::FrameInventoryReservationError,
    ) -> TrapError {
        TrapError::Hypervisor(format!("HVPatch frame inventory staging failed: {error}"))
    }

    pub(crate) fn push_exact_mapping_events(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        frame: carrick_hal::FrameId,
        gpa: u64,
        length: u64,
        permissions: carrick_hal::MemPerms,
    ) -> Result<carrick_hal::MappingId, TrapError> {
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let length = std::num::NonZeroU64::new(length).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch inventory received an empty mapping extent".to_owned())
        })?;
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: carrick_hal::FrameLength::from_mapping_extent(length),
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        Ok(mapping)
    }

    pub(crate) fn cow_inventory_split_shape(
        inventory: &HvpatchFrameInventory,
        compound_gpa: u64,
        retain_compound: bool,
        authority_mapping_count: impl Fn(carrick_hal::FrameId) -> Result<Option<usize>, TrapError>,
    ) -> Result<CowInventorySplitShape, TrapError> {
        let compound_end = compound_gpa
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW compound overflow".to_owned()))?;
        let (&old_key, &old) = inventory
            .extents
            .iter()
            .find(|((base, length), _)| {
                compound_gpa >= *base && compound_end <= base.saturating_add(*length)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW compound IPA 0x{compound_gpa:x} has no exact inventory coverage"
                ))
            })?;
        let old_end = old_key.0.checked_add(old_key.1).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch old inventory extent overflow".to_owned())
        })?;
        let mut fragments = Vec::with_capacity(2);
        if old_key.0 < compound_gpa {
            fragments.push((old_key.0, compound_gpa - old_key.0));
        }
        if retain_compound {
            fragments.push((compound_gpa, CowArmedRanges::COMPOUND_SIZE));
        }
        if compound_end < old_end {
            fragments.push((compound_end, old_end - compound_end));
        }
        let global_references = inventory
            .frames
            .lock()
            .references
            .get(&old.frame)
            .copied()
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW frame {:?} lacks backend references",
                    old.frame
                ))
            })?;
        let authoritative_references = authority_mapping_count(old.frame)?;
        let backend_frame_references_complete = authoritative_references == Some(global_references);
        let retire_old_frame =
            global_references == 1 && fragments.is_empty() && authoritative_references == Some(1);
        Ok(CowInventorySplitShape {
            old_key,
            old,
            fragments,
            retirement: CowInventoryRetirementDecision {
                retire_old_frame,
                backend_frame_references_complete,
            },
        })
    }

    /// Plan which mappings, frames and stage-2 leases a munmap retires.
    ///
    /// `authority_mapping_count` reports the authority's VM-WIDE live-mapping
    /// count for a frame. It is not redundant with the backend reference
    /// counts consulted below: `inventory.extents` is per-mm, the authority's
    /// count spans every mm, and `RetireFrame` is rejected unless the frame
    /// reaches zero mappings there. Retiring on the per-mm population alone
    /// aborts the carrier the moment a second Linux process maps the same
    /// frame, which is precisely what a forking guest does.
    pub(crate) fn inventory_lease_retirement_shape(
        inventory: &HvpatchFrameInventory,
        leases: &std::collections::BTreeSet<(u64, u64)>,
        authority_mapping_count: &dyn Fn(carrick_hal::FrameId) -> Result<Option<usize>, TrapError>,
    ) -> Result<InventoryLeaseRetirement, TrapError> {
        let mappings: Vec<_> = inventory
            .extents
            .iter()
            .filter(|(_, extent)| leases.contains(&(extent.stage2_base, extent.stage2_length)))
            .map(|(&key, &extent)| (key, extent))
            .collect();
        let mut removed_frames = std::collections::BTreeMap::new();
        let mut removed_leases = std::collections::BTreeMap::new();
        for (_, extent) in &mappings {
            *removed_frames.entry(extent.frame).or_insert(0usize) += 1;
            *removed_leases
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }
        let registry = inventory.frames.lock();
        let mut frames = std::collections::BTreeSet::new();
        let mut complete_frames = std::collections::BTreeSet::new();
        for (&frame, &removed) in &removed_frames {
            let live = registry.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} has no backend reference"
                ))
            })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} reference underflow"
                )));
            }
            let authoritative = authority_mapping_count(frame)?;
            if authoritative == Some(live) {
                complete_frames.insert(frame);
            }
            // Both populations must agree. `removed == live` says this mm
            // dropped the last backend reference it knows about; the authority
            // count says no OTHER mm still maps the frame. Requiring both can
            // only decline a retirement, never invent one, and a frame left
            // live is reclaimed by a later unmap where a wrong retirement
            // aborts the whole carrier.
            if removed == live && authoritative == Some(removed) {
                frames.insert(frame);
            }
        }
        let mut stage2_leases = std::collections::BTreeSet::new();
        let mut stage2_population_complete = std::collections::BTreeMap::new();
        for (&lease, &removed) in &removed_leases {
            let live = registry
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias retirement stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement stage-2 lease {lease:?} reference underflow"
                )));
            }
            let all_frame_populations_complete = mappings
                .iter()
                .filter(|(_, extent)| (extent.stage2_base, extent.stage2_length) == lease)
                .all(|(_, extent)| complete_frames.contains(&extent.frame));
            stage2_population_complete.insert(lease, all_frame_populations_complete);
            if removed == live && all_frame_populations_complete {
                stage2_leases.insert(lease);
            }
        }
        Ok(InventoryLeaseRetirement {
            mappings,
            frames,
            stage2_leases,
            stage2_population_complete,
        })
    }

    pub(crate) fn stage_inventory_lease_retirement(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let transaction = reservation.transaction();
        for (_, extent) in &retirement.mappings {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        for &frame in &retirement.frames {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(())
    }

    pub(crate) fn commit_inventory_lease_retirement(
        inventory: &mut HvpatchFrameInventory,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let mut removed = Vec::with_capacity(retirement.mappings.len());
        for &(key, expected) in &retirement.mappings {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} disappeared"
                ))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} identity drifted"
                )));
            }
            removed.push((key, actual));
        }
        let mut registry = inventory.frames.lock();
        for (key, extent) in removed {
            decrement_inventory_reference(&mut registry.references, extent.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (extent.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (extent.stage2_base, extent.stage2_length),
            )?;
            if retirement.frames.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                registry.shared.remove(&extent.backing);
            }
        }
        for frame in &retirement.frames {
            if registry.references.contains_key(frame) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired alias frame {frame:?} retains backend references"
                )));
            }
        }
        for lease in &retirement.stage2_leases {
            if registry.stage2_references.contains_key(lease) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired stage-2 lease {lease:?} retains backend references"
                )));
            }
        }
        for (&lease, &population_complete) in &retirement.stage2_population_complete {
            reconcile_carrier_stage2_authority_retention(&mut registry, lease, population_complete);
        }
        Ok(())
    }

    pub(crate) fn stage_cow_inventory_split(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        old_key: (u64, u64),
        old: InventoryExtent,
        fragment_shapes: &[(u64, u64)],
        retirement: CowInventoryRetirementDecision,
        replacement: CowInventoryReplacementStage,
    ) -> Result<CowInventorySplit, TrapError> {
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                transaction,
                mapping: old.mapping,
                generation: Self::inventory_generation(2),
            })
            .map_err(Self::reservation_error)?;
        let permissions = carrick_hal::MemPerms {
            read: true,
            write: true,
            exec: true,
        };
        let mut fragments = Vec::with_capacity(fragment_shapes.len());
        for &(gpa, length) in fragment_shapes {
            let mapping =
                Self::push_exact_mapping_events(reservation, old.frame, gpa, length, permissions)?;
            fragments.push(CowInventoryFragment {
                gpa,
                length,
                mapping,
            });
        }
        let (new_frame, new_mapping) = if let Some(existing) = replacement.existing {
            if existing.frame == old.frame
                || existing.stage2_base != replacement.gpa
                || existing.stage2_length != CowArmedRanges::COMPOUND_SIZE
                || existing.stage2_owner != replacement.stage2_owner
                || existing.backing != replacement.backing
            {
                return Err(TrapError::Hypervisor(
                    "HVPatch COW reuse identity mismatch".to_owned(),
                ));
            }
            (existing.frame, existing.mapping)
        } else {
            let frame = reservation.claim_frame().map_err(Self::reservation_error)?;
            let mapping = Self::push_exact_mapping_events(
                reservation,
                frame,
                replacement.gpa,
                CowArmedRanges::COMPOUND_SIZE,
                permissions,
            )?;
            (frame, mapping)
        };
        if retirement.retire_old_frame {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame: old.frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(CowInventorySplit {
            replacement_is_existing: replacement.existing.is_some(),
            old_key,
            old,
            fragments,
            new_key: (replacement.gpa, CowArmedRanges::COMPOUND_SIZE),
            new_extent: InventoryExtent {
                frame: new_frame,
                mapping: new_mapping,
                backing: replacement.backing,
                stage2_base: replacement.gpa,
                stage2_length: CowArmedRanges::COMPOUND_SIZE,
                stage2_owner: replacement.stage2_owner,
            },
            retirement,
        })
    }

    pub(crate) fn commit_cow_inventory_split(
        inventory: &mut HvpatchFrameInventory,
        split: &CowInventorySplit,
        retire_stage2: impl FnOnce() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        if split.replacement_is_existing {
            if split.new_extent.frame == split.old.frame
                || inventory.extents.get(&split.new_key) != Some(&split.new_extent)
            {
                return Err(TrapError::Hypervisor(
                    "HVPatch COW reuse destination drifted".to_owned(),
                ));
            }
        } else if let Some(existing) = inventory.extents.get(&split.new_key) {
            let stage2_references = inventory
                .frames
                .lock()
                .stage2_references
                .get(&(existing.stage2_base, existing.stage2_length))
                .copied();
            return Err(TrapError::Hypervisor(format!(
                "HVPatch COW new inventory extent collided before backend mutation: \
                 new_key={:?} existing={existing:?} existing_stage2_references={stage2_references:?} \
                 old_key={:?} fragments={:?}",
                split.new_key, split.old_key, split.fragments,
            )));
        }
        let removed = inventory.extents.remove(&split.old_key).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW old inventory mapping disappeared".to_owned())
        })?;
        if removed.mapping != split.old.mapping || removed.frame != split.old.frame {
            return Err(TrapError::Hypervisor(
                "HVPatch COW old inventory identity drifted".to_owned(),
            ));
        }
        let mut frames = inventory.frames.lock();
        decrement_inventory_reference(&mut frames.references, split.old.frame)?;
        decrement_inventory_reference(
            &mut frames.extent_references,
            (split.old.frame, split.old_key.0, split.old_key.1),
        )?;
        decrement_inventory_reference(
            &mut frames.stage2_references,
            (split.old.stage2_base, split.old.stage2_length),
        )?;
        for fragment in &split.fragments {
            increment_inventory_reference(&mut frames.references, split.old.frame)?;
            increment_inventory_reference(
                &mut frames.extent_references,
                (split.old.frame, fragment.gpa, fragment.length),
            )?;
            increment_inventory_reference(
                &mut frames.stage2_references,
                (split.old.stage2_base, split.old.stage2_length),
            )?;
            inventory.extents.insert(
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
        if !split.replacement_is_existing {
            increment_inventory_reference(&mut frames.references, split.new_extent.frame)?;
            increment_inventory_reference(
                &mut frames.extent_references,
                (split.new_extent.frame, split.new_key.0, split.new_key.1),
            )?;
            increment_inventory_reference(
                &mut frames.stage2_references,
                (split.new_extent.stage2_base, split.new_extent.stage2_length),
            )?;
        }
        if split.retirement.retire_old_frame && frames.references.contains_key(&split.old.frame) {
            return Err(TrapError::Hypervisor(
                "HVPatch COW retired old frame retains backend mappings".to_owned(),
            ));
        }
        reconcile_carrier_stage2_authority_retention(
            &mut frames,
            (split.old.stage2_base, split.old.stage2_length),
            split.retirement.backend_frame_references_complete,
        );
        let retire_old_stage2 = split.retirement.backend_frame_references_complete
            && !frames
                .stage2_references
                .contains_key(&(split.old.stage2_base, split.old.stage2_length));
        if retire_old_stage2 {
            // `stage_mapping` publishes a sibling reference while holding this
            // same registry lock. Keep it through physical-owner removal and
            // allocator release so the old zero-reference decision cannot go
            // stale before another COW reserves the recycled IPA.
            retire_stage2()?;
        }
        drop(frames);
        if !split.replacement_is_existing
            && inventory
                .extents
                .insert(split.new_key, split.new_extent)
                .is_some()
        {
            return Err(TrapError::Hypervisor(
                "HVPatch COW new inventory extent collided".to_owned(),
            ));
        }
        Ok(retire_old_stage2)
    }

    pub(crate) fn retire_stage2_candidate_if_unreferenced(
        frames: &std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
        candidate: (u64, u64),
        retire: impl FnOnce() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        let registry = frames.lock();
        if registry.stage2_references.contains_key(&candidate) {
            return Ok(false);
        }
        retire()?;
        drop(registry);
        Ok(true)
    }

    pub(crate) fn stage_mapping_in(
        custody: &CarrierVmCustody,
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        stage: InventoryMappingStage,
    ) -> Result<InventoryExtent, TrapError> {
        #[cfg(test)]
        if STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            let count = state.stage_mapping_count;
            state.stage_mapping_count += 1;
            if state.fail_stage_mapping {
                state.fail_stage_mapping = false;
                true
            } else if state.fail_stage_mapping_on_row == Some(count) {
                state.fail_stage_mapping_on_row = None;
                true
            } else {
                false
            }
        }) {
            return Err(TrapError::Hypervisor(
                "injected stage_mapping failure".to_owned(),
            ));
        }
        let InventoryMappingStage {
            gpa,
            length,
            permissions,
            backing,
            inherited_frame,
            stage2_lease,
            stage2_owner,
        } = stage;
        if inventory.extents.contains_key(&(gpa, length)) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch inventory extent IPA 0x{gpa:x} size {length} is duplicated"
            )));
        }
        let transaction = reservation.transaction();
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let frame = if let Some(frame) = inherited_frame {
            frame
        } else if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            let existing = inventory.frames.lock().shared.get(&backing).copied();
            match existing {
                Some(frame) => frame,
                None => reservation.claim_frame().map_err(Self::reservation_error)?,
            }
        } else {
            reservation.claim_frame().map_err(Self::reservation_error)?
        };
        let Some(length_value) = std::num::NonZeroU64::new(length) else {
            return Err(TrapError::Hypervisor(
                "HVPatch inventory received an empty mapping extent".to_owned(),
            ));
        };
        let length_typed = carrick_hal::FrameLength::from_mapping_extent(length_value);
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: length_typed,
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        let mut frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .get(&frame)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count exhausted"
                ))
            })?;
        let extent_key = (frame, gpa, length);
        let extent_references = frames
            .extent_references
            .get(&extent_key)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {extent_key:?} reference count exhausted"
                ))
            })?;
        let stage2_lease = stage2_lease.unwrap_or((gpa, length));
        if is_reusable_global_frame_extent(stage2_lease.0, stage2_lease.1) {
            match global_frame_host_owner_identity_in(custody, stage2_lease.0, stage2_lease.1) {
                Some(live)
                    if stage2_owner.generation != 0
                        && live == (stage2_owner.host_addr, stage2_owner.generation) => {}
                Some(live) => {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch inventory stage-2 owner is not live: lease={stage2_lease:?} owner={stage2_owner:?} live={live:?}"
                    )));
                }
                None if stage2_owner.generation == 0 => {}
                None => {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch inventory stage-2 owner is not live: lease={stage2_lease:?} owner={stage2_owner:?} live=None"
                    )));
                }
            }
        }
        let stage2_references = frames
            .stage2_references
            .get(&stage2_lease)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {stage2_lease:?} reference count exhausted"
                ))
            })?;
        // Owner authentication and every fallible count calculation complete
        // before the shared registry is mutated. A rejected publication has no
        // InventoryExtent for rollback to discover, so partial insertion here
        // would manufacture phantom frame authority permanently.
        frames.references.insert(frame, frame_references);
        frames
            .extent_references
            .insert(extent_key, extent_references);
        frames
            .stage2_references
            .insert(stage2_lease, stage2_references);
        if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            // From this point the frame is REUSABLE by the next installer of
            // the same file (the `existing` lookup above), and a reuser's batch
            // names it without reserving it. The authority accepts that only
            // once this frame is published, so whoever stages a fresh shared
            // frame must publish it before releasing the frame registry guard
            // (`FrameRegistryGuard` / `frame_registry_lock()`) the staging ran
            // under (`vcpu_loop` alias-install arm). Publishing after the release
            // let a reuser publish first and aborted the carrier with
            // `UnreservedFrame` (2026-09-08).
            frames.shared.entry(backing).or_insert(frame);
        }
        drop(frames);
        let extent = InventoryExtent {
            frame,
            mapping,
            backing,
            stage2_base: stage2_lease.0,
            stage2_length: stage2_lease.1,
            stage2_owner,
        };
        inventory.extents.insert((gpa, length), extent);
        Ok(extent)
    }

    #[cfg(test)]
    pub(crate) fn stage_mapping(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        stage: InventoryMappingStage,
    ) -> Result<InventoryExtent, TrapError> {
        Self::stage_mapping_in(
            legacy_test_carrier_vm_custody(),
            inventory,
            reservation,
            stage,
        )
    }

    pub(crate) fn rollback_unpublished_mappings(
        inventory: &mut HvpatchFrameInventory,
        mappings: &[((u64, u64), InventoryExtent)],
    ) -> Result<(), TrapError> {
        let mut registry = inventory.frames.lock();
        for &(key, expected) in mappings.iter().rev() {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch unpublished mapping rollback lost {key:?}"))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch unpublished mapping rollback identity drifted at {key:?}"
                )));
            }
            decrement_inventory_reference(&mut registry.references, actual.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (actual.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (actual.stage2_base, actual.stage2_length),
            )?;
            if matches!(actual.backing, InventoryBackingIdentity::SharedFile { .. })
                && !registry.references.contains_key(&actual.frame)
            {
                registry.shared.remove(&actual.backing);
            }
        }
        Ok(())
    }

    pub(crate) fn stage_retirement(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        authority: &dyn carrick_hal::FrameCowAuthority,
    ) -> Result<std::collections::BTreeSet<(u64, u64)>, TrapError> {
        let mut candidate_extents = Vec::with_capacity(inventory.extents.len());
        for (&(gpa, mapping_length), extent) in &inventory.extents {
            let non_zero_len = std::num::NonZeroU64::new(mapping_length).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch retirement contains empty extent at IPA 0x{gpa:x}"
                ))
            })?;
            candidate_extents.push((
                extent.mapping,
                extent.frame,
                carrick_guest_mem::Gpa(gpa),
                carrick_hal::FrameLength::from_mapping_extent(non_zero_len),
            ));
        }

        let mut local_frame_references =
            std::collections::BTreeMap::<carrick_hal::FrameId, usize>::new();
        for extent in inventory.extents.values() {
            let local = local_frame_references.entry(extent.frame).or_default();
            *local = local.checked_add(1).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {:?} local retirement count exhausted",
                    extent.frame
                ))
            })?;
        }
        let candidate_frames: Vec<carrick_hal::FrameId> =
            local_frame_references.keys().copied().collect();

        let (extent_liveness, frame_counts) = authority
            .retirement_batch_query(&candidate_extents, &candidate_frames)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "query process-terminal frame inventory retirement batch: {error}"
                ))
            })?;

        for (i, &exact_live) in extent_liveness.iter().enumerate() {
            if !exact_live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch process retirement mapping {:?} is not exact-live for retiring mm",
                    candidate_extents[i].0
                )));
            }
        }

        let authoritative_counts: std::collections::BTreeMap<carrick_hal::FrameId, Option<usize>> =
            candidate_frames.into_iter().zip(frame_counts).collect();

        let transaction = reservation.transaction();
        for extent in inventory.extents.values() {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        let mut local_stage2_references = std::collections::BTreeMap::new();
        for extent in inventory.extents.values() {
            *local_stage2_references
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }

        let mut frames = inventory.frames.lock();
        let mut retired = std::collections::BTreeSet::new();
        let mut complete_frames = std::collections::BTreeSet::new();
        for (&frame, &local) in &local_frame_references {
            let global = frames.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch frame {frame:?} has no backend reference"))
            })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count underflow"
                )));
            }
            let authoritative = authoritative_counts.get(&frame).copied().flatten();
            if authoritative == Some(global) {
                complete_frames.insert(frame);
            }
            // `frames.references` is backend bookkeeping; `RetireFrame` is a
            // claim about the kernel authority's VM-wide mapping population.
            // A sibling mm can therefore keep the frame live even when this
            // retirement removes every backend reference visible here. Require
            // exact agreement before emitting the irreversible frame event.
            if global == local && authoritative == Some(local) {
                retired.insert(frame);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let references = frames.extent_references.get(&key).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} has no backend reference"
                ))
            })?;
            if references == 0 {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} reference count underflow"
                )));
            }
        }
        let mut incomplete_stage2_leases = std::collections::BTreeSet::new();
        for extent in inventory.extents.values() {
            if !complete_frames.contains(&extent.frame) {
                incomplete_stage2_leases.insert((extent.stage2_base, extent.stage2_length));
            }
        }
        let mut retired_stage2 = std::collections::BTreeSet::new();
        let mut stage2_population_complete = std::collections::BTreeMap::new();
        for (&lease, &local) in &local_stage2_references {
            let global = frames
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {lease:?} reference count underflow"
                )));
            }
            let all_frame_populations_complete = !incomplete_stage2_leases.contains(&lease);
            stage2_population_complete.insert(lease, all_frame_populations_complete);
            if global == local && all_frame_populations_complete {
                retired_stage2.insert(lease);
            }
        }
        for &frame in &retired {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }

        for (&frame, &local) in &local_frame_references {
            let remaining = frames.references[&frame] - local;
            if remaining == 0 {
                frames.references.remove(&frame);
            } else {
                frames.references.insert(frame, remaining);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let remaining = frames.extent_references[&key] - 1;
            if remaining == 0 {
                frames.extent_references.remove(&key);
            } else {
                frames.extent_references.insert(key, remaining);
            }
            if retired.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                frames.shared.remove(&extent.backing);
            }
        }
        for (&lease, &local) in &local_stage2_references {
            let remaining = frames.stage2_references[&lease] - local;
            if remaining == 0 {
                frames.stage2_references.remove(&lease);
            } else {
                frames.stage2_references.insert(lease, remaining);
            }
        }
        for (&lease, &population_complete) in &stage2_population_complete {
            reconcile_carrier_stage2_authority_retention(&mut frames, lease, population_complete);
        }
        drop(frames);
        // Record what this mm owned BEFORE dropping it, so the authority can
        // still authenticate the commit against the exact set it retires.
        let mut expected: Vec<_> = inventory
            .extents
            .values()
            .map(|extent| (extent.mapping, extent.frame))
            .collect();
        expected.sort_unstable();
        expected.dedup();
        inventory.retirement_expected = expected;
        inventory.extents.clear();
        Ok(retired_stage2)
    }

    pub(crate) fn frame_inventory_extent_count(&self) -> usize {
        let inventory = self.frame_inventory.lock();
        if inventory.initialized {
            inventory.extents.len()
        } else {
            self.mappings
                .iter()
                .filter(|mapping| {
                    mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, mapping)
                })
                .count()
        }
    }

    pub(crate) fn inventory_initial_mappings(
        &mut self,
        mut reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if !inventory.extents.is_empty() {
            return Ok(reservation.commit(()));
        }
        for region in &self.mappings {
            if !mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, region) {
                continue;
            }
            let stage2_owner = mapped_region_stage2_owner_identity(region).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch initial inventory region IPA 0x{:x} has invalid physical owner offset",
                    region.physical_ipa
                ))
            })?;
            Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: region.physical_ipa,
                    length: region.physical_size as u64,
                    permissions: Self::region_permissions(region),
                    backing: Self::private_backing_identity(),
                    inherited_frame: None,
                    stage2_lease: None,
                    stage2_owner,
                },
            )?;
        }
        inventory.initialized = true;
        Ok(reservation.commit(()))
    }

    pub(crate) fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_alias_inventory(reservation)
    }

    pub(crate) fn take_alias_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        let mut inventory = self.frame_inventory.lock();
        // Handing the commit off makes the staged extents the authority's
        // business, so they are no longer this transaction's to roll back.
        tracing::trace!(
            staged = inventory.alias_staged.len(),
            commit = inventory.alias_commit.is_some(),
            "hvpatch alias take"
        );
        inventory.alias_staged.clear();
        inventory.alias_commit.take()
    }

    pub(crate) fn abandon_alias_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_alias_inventory()
    }

    pub(crate) fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.task.begin_exec_inventory(retired, replacement)
    }

    pub(crate) fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.task.fail_next_begin_exec_inventory = true;
    }

    pub(crate) fn frame_inventory_exec_extent_counts(
        &self,
        new_image: &crate::memory::AddressSpace,
    ) -> (usize, usize) {
        let replacement = GuestMappingPlan::from_address_space(new_image)
            .map(|plan| {
                plan.mappings
                    .iter()
                    .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
                    .count()
            })
            .unwrap_or(0);
        (self.exec_retired_extent_count(), replacement)
    }

    pub(crate) fn take_exec_inventory(&mut self) -> Option<carrick_hal::ExecInventoryCommits> {
        self.frame_inventory.lock().exec_commits.take()
    }

    pub(crate) fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_process_inventory(reservation)
    }

    pub(crate) fn cancel_process_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_process_inventory()
    }

    pub(crate) fn take_process_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().process_commit.take()
    }

    pub(crate) fn commit_process_materialization(&mut self) -> Result<(), TrapError> {
        if self.frame_inventory.lock().process_commit.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch process materialization has no inventory commit".to_owned(),
            ));
        }
        // Register only after the fresh vCPU register restore succeeds. Until
        // this point the aliases remain an owned, unpublished vector.
        for alias in std::mem::take(&mut self.pending_process_aliases) {
            register_shared_alias(alias);
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasPublished,
                CowDiagnosticLifecycleSite::ProcessMaterialization,
                Some(self.custody()),
                self.cow_identity,
                self.mm_root_slot,
                alias,
            );
        }
        Ok(())
    }

    pub(crate) fn refresh_fork_process_state(
        &mut self,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
        self.task
            .refresh_fork_process_state_in(&custody, flush_stage1)
    }

    pub(crate) fn abort_process_materialization(&mut self) -> Result<(), TrapError> {
        self.pending_process_aliases.clear();
        self.pending_fork_frame_receipts.clear();
        {
            let mut inventory = self.frame_inventory.lock();
            let staged: Vec<_> = inventory
                .extents
                .iter()
                .map(|(&key, &extent)| (key, extent))
                .collect();
            Self::rollback_unpublished_mappings(&mut inventory, &staged)?;
            drop(inventory.process_commit.take());
        }
        // Fresh per-mm mappings own their stage-2 leases; inherited mappings
        // are non-owning. Dropping this vector therefore unmaps/releases only
        // unpublished child-local extents.
        drop(std::mem::take(&mut self.mappings));
        self.mm_root_slot = None;
        Ok(())
    }

    pub(crate) fn begin_retirement_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if inventory.retirement_reservation.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch retirement inventory transaction".to_owned(),
            ));
        }
        inventory.retirement_reservation = Some(reservation);
        Ok(())
    }

    pub(crate) fn take_retirement_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn page_tables_snapshot(&self) -> Option<crate::page_table::PageTableManager> {
        self.page_tables_authority().snapshot_image()
    }

    pub(crate) fn bind_stage1_page_tables(
        &mut self,
        page_tables: carrick_aarch64::Stage1Authority,
    ) {
        page_tables.emit_bind_probe();
        tracing::debug!(
            target: "carrick::stage1_arena",
            authority = page_tables.authority_id() as usize,
            present = page_tables.is_present(),
            has_source = page_tables.has_source(),
            arenas = page_tables.pool_stats().map_or(0, |s| s.3),
            "bind stage-1 page tables"
        );
        self.mm_access.bind_page_tables_authority(page_tables);
    }

    pub(crate) fn task_runtime_authorities_match(
        &self,
        mm_access: &std::sync::Arc<MmAccessState>,
        page_tables: &carrick_aarch64::Stage1Authority,
        protections: &std::sync::Arc<MemoryProtections>,
    ) -> bool {
        self.task
            .runtime_authorities_match(mm_access, page_tables, protections)
    }

    pub(crate) fn task_mm_access_authority(&self) -> std::sync::Arc<MmAccessState> {
        self.task.mm_access_authority()
    }

    pub(crate) fn task_protections_authority(&self) -> std::sync::Arc<MemoryProtections> {
        std::sync::Arc::clone(&self.protections)
    }

    /// Tell `manager` whether THIS thread's edit is exclusive, before an
    /// HVPatch mapping publication that locks `self.page_tables` directly.
    ///
    /// `Aarch64EngineCore::pt_edit_locked` pushes the same answer for every
    /// edit that goes through the engine, but the HVPatch publications below
    /// take the lock themselves and would otherwise allocate spare sub-tables
    /// under whatever marker the PREVIOUS editor happened to leave behind.
    /// The marker gates `alloc_table`'s last-resort reclaim sweep, so a stale
    /// `false` turns a recoverable pool into `OutOfTables` -> guest `ENOMEM`:
    /// cpython `concurrent_futures` raised `MemoryError` out of a 16 KiB
    /// anonymous `mmap` whose own syscall dispatch DID hold exclusivity.
    ///
    /// Only exclusivity is refreshed. `multi_vcpu` gates the EAGER coalescing
    /// scan, which is a throughput decision this path must not silently flip
    /// (enabling it cost `go-net_http` 50 s -> over 200 s).
    pub(crate) fn refresh_stage1_exclusivity(manager: &mut crate::page_table::PageTableManager) {
        manager.set_stage1_exclusive(
            carrick_hal::stage1_exclusive::current_thread_edits_exclusively(),
        );
    }

    /// Complete pre-transaction image of `manager`, taken into the recycled
    /// buffer when one is available.
    ///
    /// This is byte-for-byte what `manager.clone()` produced before; the only
    /// change is that a returned buffer is refilled in place instead of asking
    /// the allocator for another 1.75 MiB region. See `cow_rollback_scratch`.
    pub(crate) fn rollback_pre_image(
        scratch: &mut Option<crate::page_table::PageTableManager>,
        manager: &crate::page_table::PageTableManager,
    ) -> crate::page_table::PageTableManager {
        match scratch.take() {
            Some(mut reused) => {
                reused.clone_from(manager);
                reused
            }
            None => manager.clone(),
        }
    }

    pub(crate) fn retire_process_mappings(&mut self) -> Result<(), TrapError> {
        Self::retire_task_state_process_mappings(&mut self.task)
    }

    pub(crate) fn retire_task_state_process_mappings(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        Self::retire_task_state_process_mappings_inner(task, None).map(|_| ())
    }

    pub(crate) fn retire_task_state_process_mappings_with_root_proof(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        Self::retire_task_state_process_mappings_inner(task, Some(expected_root_slot))?.ok_or_else(
            || {
                TrapError::Hypervisor(
                    "HVPatch process retirement produced no stage-1 root proof".to_owned(),
                )
            },
        )
    }

    pub(crate) fn retire_task_state_process_mappings_inner(
        task: &mut HvfTaskState,
        expected_root_slot: Option<(u64, u64)>,
    ) -> Result<Option<HvpatchMmRootRetirementProof>, TrapError> {
        /// Answer "which mapping rows contain `[ipa, ipa + length)`" for terminal
        /// retirement without re-walking every row per inventory extent.
        ///
        /// Process-terminal retirement asks that question once per inventory
        /// extent. Written directly as `task.mappings.iter().filter(..)` it is
        /// O(extents x rows): a CPython `test_compile` guest retires with 33,471
        /// inventory extents against 33,478 mapping rows, so one executor spins
        /// through ~1.1e9 row visits inside
        /// [`HvfVmState::retire_task_state_process_mappings_inner`] while its
        /// Linux task is already a zombie. That is the shape the always-on
        /// process-graph liveness sink reports as "1 container job(s) unpublished
        /// with 0 live task(s), 1 live thread(s) and 0 runnable row(s) for
        /// 2000ms" (`carrick run` rc 125): nothing is deadlocked, the settlement
        /// that publishes the container job is simply still queued behind a
        /// quadratic sweep.
        ///
        /// [`TaskMappingIndex::by_ipa`] cannot serve this query. It orders the
        /// SEMANTIC `ipa`/`size` projection, while every lifetime decision here
        /// must use the exact `physical_ipa`/`physical_size` tuple — a partial
        /// 4 KiB Linux mapping can retain a 16 KiB physical owner whose base
        /// precedes its semantic view. This index is therefore built once per
        /// retirement, from a single pass over the rows, and covers displaced
        /// rows as well as live ones because the scan it replaces did.
        struct PhysicalExtentIndex<'rows> {
            /// Rows ascending by `physical_ipa`.
            rows: Vec<&'rows HvfMappedRegion>,
            /// `rows[i].physical_ipa`, kept apart for the binary search.
            starts: Vec<u64>,
            /// `max(physical end of rows[0..=i])`. Non-decreasing, so a descending
            /// walk stops at the first index whose prefix maximum can no longer
            /// reach the query end: no earlier row reaches further either.
            prefix_max_end: Vec<u64>,
        }

        impl<'rows> PhysicalExtentIndex<'rows> {
            fn build(rows: impl Iterator<Item = &'rows HvfMappedRegion>) -> Self {
                let mut rows: Vec<&'rows HvfMappedRegion> = rows.collect();
                rows.sort_unstable_by_key(|row| row.physical_ipa);
                let starts = rows.iter().map(|row| row.physical_ipa).collect::<Vec<_>>();
                let mut prefix_max_end = Vec::with_capacity(rows.len());
                let mut running = 0u64;
                for row in &rows {
                    running = running.max(Self::physical_end(row));
                    prefix_max_end.push(running);
                }
                Self {
                    rows,
                    starts,
                    prefix_max_end,
                }
            }

            fn physical_end(row: &HvfMappedRegion) -> u64 {
                row.physical_ipa.saturating_add(row.physical_size as u64)
            }

            /// Every row whose exact stage-2 physical extent contains
            /// `[ipa, ipa + length)`, in no particular order — both consumers ask
            /// `any`/`iter().any`, so order carries no meaning here.
            fn containing(
                &self,
                ipa: u64,
                length: u64,
            ) -> impl Iterator<Item = &'rows HvfMappedRegion> {
                let end = ipa.checked_add(length);
                let upper = self.starts.partition_point(|start| *start <= ipa);
                let prefix_max_end = &self.prefix_max_end;
                let rows = &self.rows;
                (0..upper)
                    .rev()
                    .take_while(move |&position| {
                        end.is_some_and(|end| prefix_max_end[position] >= end)
                    })
                    .map(move |position| rows[position])
                    .filter(move |row| end.is_some_and(|end| end <= Self::physical_end(row)))
            }
        }

        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&task.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        // Mature VMM processes own a private VM and retain the historical
        // teardown path; only the persistent single-VM HVPatch lane publishes
        // per-process frame-inventory retirement.
        if !task.persistent_vm_lifecycle {
            return Ok(None);
        }
        let authority = task.cow_authority.as_ref().cloned().ok_or_else(|| {
            TrapError::Hypervisor(
                "HVPatch process retirement has no frame inventory authority".to_owned(),
            )
        })?;
        // The runtime holds the process-wide HVPatch topology lock across this
        // method. Stage the backend inventory retirement BEFORE recycling any
        // physical extent. The old order sampled `stage2_references`, dropped
        // that lock, recycled the IPA, and only later removed this mm's
        // references. A sibling publication in that window could retain the
        // old extent after its global owner was gone; the allocator then handed
        // the IPA to a COW transaction whose per-mm inventory still contained
        // that key (`HVPatch COW new inventory extent collided`).
        let ledger = std::sync::Arc::clone(&task.frame_inventory.ledger);
        let (candidates, frames, retirement_commit, stage2_owners) = {
            let mut inventory = ledger.lock();
            if inventory.extents.is_empty() {
                if task.mappings.is_empty() {
                    return Ok(None);
                }
                return Err(TrapError::Hypervisor(
                    "HVPatch process retirement has mappings without frame inventory authority"
                        .to_owned(),
                ));
            }
            if inventory.retirement_reservation.is_none() {
                return Err(TrapError::Hypervisor(
                    "HVPatch retirement began without frame inventory reservation".to_owned(),
                ));
            }

            // Validate every physical candidate extent in inventory before
            // performing any logical mutation. The inventory records the
            // owner identity that was live at publication; `task.mappings`
            // deliberately retains historical rows and therefore cannot be
            // used to reconstruct one generation at terminal retirement.
            //
            // One pass builds the physical-extent index the per-extent
            // containment queries below read; see `PhysicalExtentIndex` for
            // why the direct per-extent scan is the exit residual.
            let mapping_extents = PhysicalExtentIndex::build(task.mappings.iter());
            let mut stage2_owners = std::collections::BTreeMap::new();
            for (&(_gpa, mapping_length), extent) in &inventory.extents {
                if mapping_length == 0 {
                    return Err(TrapError::Hypervisor(
                        "HVPatch process retirement inventory has zero-length mapping".to_owned(),
                    ));
                }
                let ipa = extent.stage2_base;
                let length = extent.stage2_length;
                let _size =
                    usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
                let lease = (ipa, length);
                if let Some(previous) = stage2_owners.insert(lease, extent.stage2_owner)
                    && previous != extent.stage2_owner
                {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch process retirement lease {lease:?} has conflicting inventory owner identities {previous:?} and {:?}",
                        extent.stage2_owner
                    )));
                }
                let matching_rows: Vec<_> = mapping_extents
                    .containing(ipa, length)
                    .filter_map(|mapping| {
                        mapped_region_stage2_owner_identity(mapping).map(|identity| {
                            (
                                identity,
                                mapping
                                    .stage2_lease
                                    .as_ref()
                                    .map(|lease| (lease.key(), lease.active, lease.mapped)),
                                mapping.is_dynamic_alias,
                            )
                        })
                    })
                    .collect();
                if is_reusable_global_frame_extent(ipa, length) {
                    let live_owner = global_frame_host_owner_identity_in(custody, ipa, length);
                    if extent.stage2_owner.generation == 0 {
                        if live_owner.is_some() {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement unowned lease {lease:?} unexpectedly has live global owner {live_owner:?}"
                            )));
                        }
                        let local_lease = matching_rows.iter().any(|(identity, local, _)| {
                            *identity == extent.stage2_owner
                                && local.is_some_and(|((key_base, key_len), active, mapped)| {
                                    key_base <= ipa
                                        && ipa
                                            .checked_add(length)
                                            .is_some_and(|end| end <= key_base + key_len)
                                        && active
                                        && mapped
                                })
                        });
                        let carrier_lease = carrier_stage2_lease_owner_matches(
                            custody,
                            ipa,
                            length,
                            extent.stage2_owner.host_addr,
                        );
                        // Generation-zero extents have no global owner identity to
                        // authenticate. They therefore still require an exact
                        // live task or carrier lease. Nonzero extents are different:
                        // the inventory captured their complete host/generation
                        // identity at publication and the global-owner comparison
                        // below authenticates it directly. A detached task-only
                        // reload may legitimately omit a duplicate runtime-created
                        // mapping row while retaining that inventory authority.
                        if !local_lease && !carrier_lease {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement reusable unowned lease {lease:?} has no exact local or carrier lease"
                            )));
                        }
                    } else {
                        match live_owner {
                            Some(live)
                                if live
                                    == (
                                        extent.stage2_owner.host_addr,
                                        extent.stage2_owner.generation,
                                    ) => {}
                            Some((live_host, live_generation))
                                if live_generation == extent.stage2_owner.generation =>
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch process retirement owner pointer drifted for lease {lease:?}: inventory={:?} live=({live_host}, {live_generation})",
                                    extent.stage2_owner
                                )));
                            }
                            // A different live generation is a successor owner.
                            // This stale mm may retire its logical inventory but
                            // must leave the successor's physical lease untouched.
                            Some(_) => {}
                            None => {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch process retirement owned lease {lease:?} expected inventory owner {:?} but the owner is absent",
                                    extent.stage2_owner
                                )));
                            }
                        }
                    }
                } else {
                    let local_lease = matching_rows.iter().any(|(identity, local, _)| {
                        *identity == extent.stage2_owner
                            && local.is_some_and(|((key_base, key_len), active, mapped)| {
                                key_base <= ipa
                                    && ipa
                                        .checked_add(length)
                                        .is_some_and(|end| end <= key_base + key_len)
                                    && active
                                    && mapped
                            })
                    }) || mapping_extents.containing(ipa, length).any(|m| {
                        extent.stage2_owner.generation == 0
                            || m.owner_generation == extent.stage2_owner.generation
                            || m.structural_owner.as_ref().is_some_and(|owner| {
                                owner.epoch().raw() == extent.stage2_owner.generation
                            })
                    });
                    let carrier_lease = carrier_stage2_lease_owner_matches(
                        custody,
                        ipa,
                        length,
                        extent.stage2_owner.host_addr,
                    );
                    if !local_lease
                        && !carrier_lease
                        && take_carrier_stage2_record(custody, ipa, length).is_none()
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement structural lease {lease:?} has no exact local, structural, or carrier lease"
                        )));
                    }
                }
            }

            let frames = std::sync::Arc::clone(&inventory.frames);
            let mut reservation = inventory.retirement_reservation.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "validated HVPatch retirement reservation disappeared before candidate staging"
                );
            });
            let diagnostic_extents = if cow_refusal_diagnostics_enabled() {
                inventory
                    .extents
                    .iter()
                    .map(|(&key, &extent)| (key, extent))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let candidates =
                Self::stage_retirement(&mut inventory, &mut reservation, authority.as_ref())?;
            let scope = CowInventoryLifecycleScope {
                custody,
                identity: task.cow_identity,
                mm_root_slot: task.mm_root_slot,
                semantic_va: 0,
                semantic_length: 0,
            };
            for (key, extent) in diagnostic_extents {
                record_cow_inventory_lifecycle(
                    CowDiagnosticLifecycleKind::InventoryRemoved,
                    CowDiagnosticLifecycleSite::ProcessRetirement,
                    &scope,
                    key,
                    extent,
                );
            }
            (candidates, frames, reservation.commit(()), stage2_owners)
        };

        // `stage_mapping` increments the same registry while holding this exact
        // lock. Recheck each stale candidate and keep the lock through owner
        // removal/allocator release: publication either wins first and keeps
        // the extent live, or retirement wins first and no later publication
        // can inherit the recycled owner.
        let mut extents = std::collections::BTreeSet::new();
        let mut superseded_owners = std::collections::BTreeMap::new();
        for &(ipa, length) in &candidates {
            let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
            let lease = (ipa, length);
            let owner = stage2_owners.get(&lease).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch process retirement candidate {lease:?} lost inventory owner identity"
                ))
            })?;
            if is_reusable_global_frame_extent(ipa, length) {
                let live_owner = global_frame_host_owner_identity_in(custody, ipa, length);
                if owner.generation == 0 {
                    if live_owner.is_some() {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement unowned candidate {lease:?} unexpectedly has live global owner {live_owner:?}"
                        )));
                    }
                    if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                        Self::retire_unowned_stage2_extent_from_mappings_in(
                            custody,
                            &mut task.mappings,
                            ipa,
                            length,
                            owner.host_addr,
                        )
                    })? {
                        extents.insert((ipa, size));
                    }
                } else if live_owner == Some((owner.host_addr, owner.generation)) {
                    if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                        let outcome = retire_global_frame_host_owner_if_generation_in(
                            custody,
                            ipa,
                            length,
                            owner.generation,
                        );
                        match outcome {
                            GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
                            | GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. }
                            | GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                            | GlobalFrameRetirementOutcome::RetryPending { .. } => Ok(()),
                            outcome => Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement owner identity drifted for lease {lease:?}: {outcome:?}"
                            ))),
                        }
                    })? {
                        extents.insert((ipa, size));
                    }
                } else if let Some((live_host, live_generation)) = live_owner {
                    if live_generation == owner.generation {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement candidate owner pointer drifted for lease {lease:?}: inventory={owner:?} live=({live_host}, {live_generation})"
                        )));
                    }
                    // Stale cleanup: a successor owner is live; leave it untouched.
                    superseded_owners.insert(lease, owner);
                } else {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch process retirement owned candidate {lease:?} expected inventory owner {owner:?} but the owner is absent"
                    )));
                }
            } else {
                if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                    Self::retire_stage2_extent_from_mappings_in(
                        custody,
                        &mut task.mappings,
                        ipa,
                        length,
                    )
                })? {
                    extents.insert((ipa, size));
                }
            }
        }
        let retired_root = expected_root_slot
            .map(|root_slot| task.mm_access.retire_mm_root_stage2_in(custody, root_slot))
            .transpose()?;
        if let Some(root) = &retired_root {
            extents.insert(root.physical_extent);
        }
        let retiring_aliases = if cow_refusal_diagnostics_enabled() {
            alias_registry()
                .lock()
                .process_visible_ordered(task.mm_root_slot, task.container_root)
        } else {
            Vec::new()
        };
        retire_process_aliases(task.mm_root_slot, task.container_root, |alias| {
            let key = (alias.physical_ipa, alias.physical_size as u64);
            let retired_exact_owner = superseded_owners.get(&key).is_some_and(|owner| {
                owner.host_addr == alias.physical_host_addr
                    && owner.generation == alias.owner_generation
            });
            !extents.contains(&(alias.physical_ipa, alias.physical_size)) && !retired_exact_owner
        });
        record_alias_unmap_lifecycle(
            CowDiagnosticLifecycleSite::ProcessRetirement,
            custody,
            task.cow_identity,
            task.mm_root_slot,
            task.container_root,
            &retiring_aliases,
        );

        // A retained shared extent still points at its original host allocation.
        // Reclaim only exact extents removed above and preserve the remaining
        // backing until the single VM is finally destroyed.
        let mut retained_backings = Vec::new();
        for mapping in std::mem::take(&mut task.mappings) {
            if extents.contains(&(mapping.physical_ipa, mapping.physical_size)) {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        task.mm_root_slot = None;

        ledger.lock().retirement_commit = Some(retirement_commit);
        Ok(retired_root.map(|root| root.proof))
    }

    pub(crate) fn retire_task_state_mm_root_only(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&task.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        if !task.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "stage-1 root-only retirement requires persistent HVPatch lifecycle".to_owned(),
            ));
        }
        let retired = task
            .mm_access
            .retire_mm_root_stage2_in(custody, expected_root_slot)?;
        task.mm_root_slot = None;
        Ok(retired.proof)
    }

    pub(crate) fn take_task_state_retirement_inventory(
        task: &mut HvfTaskState,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        task.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn retire_task_state_exec_predecessor(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        let mut cleanup = task.pending_exec_stage2_cleanup.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached exec successor lost predecessor stage-2 cleanup authority".to_owned(),
            )
        })?;
        cleanup.retire()
    }

    pub(crate) fn retire_task_state_exec_predecessor_with_root_proof(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        let mut cleanup = task.pending_exec_stage2_cleanup.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached exec successor lost predecessor stage-2 cleanup authority".to_owned(),
            )
        })?;
        cleanup.retire_with_root_proof(expected_root_slot)
    }

    pub(crate) fn retire_task_state_dormant_authority(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        if let Some(reg) = &mut task.registration {
            reg.retire_dormant_authority();
        }
        Ok(())
    }
}
