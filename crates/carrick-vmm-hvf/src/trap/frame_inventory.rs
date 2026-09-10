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
