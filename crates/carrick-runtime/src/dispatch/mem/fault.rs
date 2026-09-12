//! Anonymous first-touch fault arming, residency tracking, and grow-down stack fault resolution.

use super::*;
use carrick_fatal::carrick_fatal;

#[derive(Clone, Copy)]
pub(crate) struct ResidentFaultRange {
    pub(crate) range: crate::vfs::GuestMemoryRange,
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
pub(crate) struct FirstTouchArming {
    /// `start -> (end, prot)`, non-overlapping, ordered by `start`.
    extents: std::collections::BTreeMap<u64, FirstTouchArm>,
}

#[derive(Clone, Copy)]
struct FirstTouchArm {
    end: u64,
    prot: LinuxProtFlags,
}

impl FirstTouchArming {
    /// Arm `range` for first-touch observation at `prot`, replacing whatever
    /// armed the pages it covers.
    pub(crate) fn arm(&mut self, range: crate::vfs::GuestMemoryRange, prot: LinuxProtFlags) {
        self.disarm(range);
        self.extents.insert(
            range.start().raw(),
            FirstTouchArm {
                end: range.end().raw(),
                prot,
            },
        );
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

    /// Drop `range` from the set, keeping the parts of any extent that lie
    /// outside it. This is the commit path for one page, so it must not touch
    /// entries the range does not overlap.
    pub(crate) fn disarm(&mut self, range: crate::vfs::GuestMemoryRange) {
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
        range: crate::vfs::GuestMemoryRange,
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
                crate::vfs::GuestMemoryRange::new(
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
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(arm.end)).map(|range| {
                ResidentFaultRange {
                    range,
                    prot: arm.prot,
                }
            })
        })
    }
}

/// The pages of `range` that lie inside a first-touch tracked extent and have
/// not been committed resident: exactly the pages whose leaf must stay
/// invalid so their first touch is still observed.
pub(crate) fn tracked_nonresident_subranges(
    mem: &MemState,
    range: crate::vfs::GuestMemoryRange,
) -> Vec<crate::vfs::GuestMemoryRange> {
    let mut out = Vec::new();
    for tracked in &mem.resident_tracked_ranges {
        let start = tracked.start().raw().max(range.start().raw());
        let end = tracked.end().raw().min(range.end().raw());
        if let Some(sub) = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) {
            out.push(sub);
        }
    }
    for resident in &mem.resident_ranges {
        locked_ranges_remove(&mut out, *resident);
    }
    out.sort_by_key(|sub| sub.start().raw());
    out
}

/// Owns alias exclusion from grow-down fault lookup through backend protection
/// and dispatcher metadata publication.
pub(crate) struct MmapGrowdownFaultPlan<'permit> {
    pub(crate) start: u64,
    pub(crate) len: usize,
    pub(crate) exclusion: super::HostAliasDispatchGuard<'permit>,
}

impl MmapGrowdownFaultPlan<'_> {
    pub(crate) fn start(&self) -> u64 {
        self.start
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Owns alias exclusion from resident-fault lookup through backend protection
/// and residency publication.
pub(crate) struct ResidentFaultPlan<'permit> {
    pub(crate) page: u64,
    pub(crate) prot: u64,
    pub(crate) exclusion: super::HostAliasDispatchGuard<'permit>,
}

impl ResidentFaultPlan<'_> {
    pub(crate) fn page(&self) -> u64 {
        self.page
    }

    pub(crate) fn prot(&self) -> u64 {
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
        self.mem()
            .lock()
            .bus_fault_ranges
            .iter()
            .any(|&(start, len)| {
                start
                    .checked_add(len)
                    .is_some_and(|end| addr >= start && addr < end)
            })
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
        let tracked = ranges_contain_page(&mem.resident_tracked_ranges, page)
            || mem
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
                let obstacle = mem
                    .dynamic_maps
                    .iter()
                    .any(|map| map.start < current && map.end > low && map.start != current);
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
        let Some(range) = crate::vfs::GuestMemoryRange::new(
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
        let Some(range) = crate::vfs::GuestMemoryRange::new(
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
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem().lock().resident_ranges, range);
        }
    }

    pub(in crate::dispatch::mem) fn mark_range_nonresident(&self, start: u64, len: u64) {
        let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        else {
            return;
        };
        let authority = self.mem();
        let mut mem = authority.lock();
        locked_ranges_remove(&mut mem.resident_ranges, range);
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
        let prot = mem.resident_fault_ranges.prot_for_page(page)?.bits();
        Some(ResidentFaultPlan {
            page,
            prot,
            exclusion,
        })
    }

    #[cfg(test)]
    pub(crate) fn seed_resident_fault_for_test(&self, page: u64, prot: u64) {
        self.track_resident_fault_range(
            page,
            self.linux_page_size(),
            LinuxProtFlags::from_bits_truncate(prot),
        );
    }

    #[cfg(test)]
    pub(crate) fn with_resident_fault_plan_for_test<T>(
        &self,
        addr: u64,
        use_plan: impl FnOnce(ResidentFaultPlan<'_>) -> T,
    ) -> Option<T> {
        super::mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.resident_fault_plan(permit, addr).map(use_plan)
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
        let Some(range) = crate::vfs::GuestMemoryRange::new(GuestVa(plan.page), GuestVa(end))
        else {
            return;
        };
        let mem_authority_33 = self.mem();
        let mut mem = mem_authority_33.lock();
        locked_ranges_insert(&mut mem.resident_ranges, range);
        mem.resident_fault_ranges.disarm(range);
    }

    pub(in crate::dispatch::mem) fn populate_resident_range(
        &self,
        memory: &mut impl CurrentMmMemory,
        range: crate::vfs::GuestMemoryRange,
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
        locked_ranges_insert(&mut mem.resident_ranges, range);
        mem.resident_fault_ranges.disarm(range);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
