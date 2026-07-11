//! Process-wide guest-VMA protection bookkeeping, shared by every backend.
//!
//! When the guest `mprotect(PROT_NONE)`s (or `munmap`s) a range, a later
//! syscall whose buffer overlaps that range must fault with `EFAULT` exactly as
//! Linux would — even though the host backing is still physically accessible
//! (the host-side check; making the GUEST's own EL0 access fault needs stage-1
//! edits + signal injection, which the page-table managers handle separately).
//!
//! These sets are the single source of truth for that host-side check and keep
//! mapped `PROT_NONE` distinct from post-`munmap` holes for Linux `si_code`.
//! They are
//! **process-wide**: sibling vCPU threads (a `clone(CLONE_VM)` thread group run
//! on one VM) MUST share ONE instance — wrapped in [`std::sync::Arc`] — so a
//! `mprotect` made by any guest thread is observed by every other thread's
//! syscall-path access checks. A thread-local copy silently diverges: one
//! thread reserves a region `PROT_NONE`, another commits it `PROT_READ|WRITE`,
//! and the first thread then wrongly faults a perfectly valid buffer there (the
//! Go-runtime-on-KVM `futexwakeup … EFAULT` / `netpollBreak write failed`
//! crashes were exactly this divergence before the set was shared).
//!
//! This type lives in `carrick-guest-mem` (the leaf crate the [`GuestMemory`]
//! trait lives in) so the trait's default `read_bytes`/`write_bytes` can run the
//! gate directly — one shared host-side EFAULT check every backend inherits.
//! `carrick-mem::protections` re-exports it for back-compat.
//!
//! One interior [`parking_lot::RwLock`] covers all VMA-classification sets, so
//! transitions are coherent and the shared `Arc` needs no outer lock. The HVF
//! and KVM backends both hold an `Arc<MemoryProtections>` and clone it into each
//! sibling; a `fork(2)` child gets an INDEPENDENT copy (the Linux COW of the
//! whole process duplicates the underlying `Vec`, or `MemoryProtections::snapshot`
//! plus `MemoryProtections::from_snapshot`); `execve` starts fresh
//! (`MemoryProtections::default`).
//!
//! [`GuestMemory`]: crate::GuestMemory

/// Sorted, merged, non-overlapping `[start, end)` guest-address ranges with an
/// O(log n) overlap query. The shared building block for the PROT_NONE,
/// unmapped, and read-only sets in [`MemoryProtections`].
#[derive(Default)]
struct RangeSet {
    ranges: Vec<(u64, u64)>,
}

impl RangeSet {
    fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self { ranges }
    }

    fn snapshot(&self) -> Vec<(u64, u64)> {
        self.ranges.clone()
    }

    /// True if `[address, address+length)` overlaps any range in the set.
    fn contains(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let idx = self.ranges.partition_point(|&(_, e)| e <= address);
        self.ranges
            .get(idx)
            .is_some_and(|&(s, e)| address < e && s < end)
    }

    /// Add (`present=true`, merging adjacent/overlapping) or remove
    /// (`present=false`, splitting a partially-cleared range into the surviving
    /// ends) the range `[address, address+len)`, keeping the set sorted + merged.
    fn set(&mut self, address: u64, len: usize, present: bool) {
        let end = address.saturating_add(len as u64);
        if end <= address {
            return;
        }
        if present {
            let mut start = address;
            let mut merged_end = end;
            let idx = self
                .ranges
                .partition_point(|&(_, range_end)| range_end < start);
            let mut remove_end = idx;
            while let Some(&(range_start, range_end)) = self.ranges.get(remove_end) {
                if range_start > merged_end {
                    break;
                }
                start = start.min(range_start);
                merged_end = merged_end.max(range_end);
                remove_end += 1;
            }
            self.ranges.splice(idx..remove_end, [(start, merged_end)]);
            return;
        }

        let idx = self
            .ranges
            .partition_point(|&(_, range_end)| range_end <= address);
        let mut remove_end = idx;
        let mut replacement = Vec::new();
        while let Some(&(s, e)) = self.ranges.get(remove_end) {
            if s >= end {
                break;
            }
            if s < address {
                replacement.push((s, address));
            }
            if end < e {
                replacement.push((end, e));
            }
            remove_end += 1;
        }
        if idx != remove_end {
            self.ranges.splice(idx..remove_end, replacement);
        }
    }
}

#[derive(Default)]
struct ProtectionState {
    no_access: RangeSet,
    unmapped: RangeSet,
    no_write: RangeSet,
}

/// The process-wide host-side protection sets a backend enforces on the syscall
/// path: live PROT_NONE, unmapped holes, and read-only mappings. See the module
/// docs for the sharing contract.
#[derive(Default)]
pub struct MemoryProtections {
    /// One lock covers every VMA classification so readers see coherent state
    /// and the hot path pays one lock acquisition, not one per range set.
    state: parking_lot::RwLock<ProtectionState>,
}

impl MemoryProtections {
    /// Seed the PROT_NONE set from an existing range list. The no-write set starts
    /// empty; use [`Self::from_snapshot`] when cloning full syscall-path protection
    /// state across fork.
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            state: parking_lot::RwLock::new(ProtectionState {
                no_access: RangeSet::from_ranges(ranges),
                ..ProtectionState::default()
            }),
        }
    }

    /// A point-in-time copy of the PROT_NONE ranges.
    pub fn snapshot(&self) -> Vec<(u64, u64)> {
        self.state.read().no_access.snapshot()
    }

    /// A point-in-time copy of both syscall-path protection sets.
    pub fn snapshot_all(&self) -> ProtectionSnapshot {
        let state = self.state.read();
        ProtectionSnapshot {
            no_access: state.no_access.snapshot(),
            unmapped: state.unmapped.snapshot(),
            no_write: state.no_write.snapshot(),
        }
    }

    /// Seed both syscall-path protection sets from a fork-time snapshot.
    pub fn from_snapshot(snapshot: ProtectionSnapshot) -> Self {
        Self {
            state: parking_lot::RwLock::new(ProtectionState {
                no_access: RangeSet::from_ranges(snapshot.no_access),
                unmapped: RangeSet::from_ranges(snapshot.unmapped),
                no_write: RangeSet::from_ranges(snapshot.no_write),
            }),
        }
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range — a syscall
    /// buffer there must fault `EFAULT` (read OR write).
    pub fn range_no_access(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length) || state.unmapped.contains(address, length)
    }

    /// True only for a live `PROT_NONE` mapping. Unlike
    /// [`Self::range_no_access`], this excludes post-`munmap` holes so fault
    /// delivery can distinguish Linux `SEGV_ACCERR` from `SEGV_MAPERR`.
    pub fn range_prot_none(&self, address: u64, length: usize) -> bool {
        self.state.read().no_access.contains(address, length)
    }

    /// True when the range was removed from the guest VMA set.
    pub fn range_unmapped(&self, address: u64, length: usize) -> bool {
        self.state.read().unmapped.contains(address, length)
    }

    /// True when a syscall write must fail: PROT_NONE, post-unmap, or a live
    /// read-only mapping. All three sets are sampled under one read lock.
    pub fn range_write_denied(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length)
            || state.unmapped.contains(address, length)
            || state.no_write.contains(address, length)
    }

    /// True when a hardware `MAPERR` must be upgraded to Linux `ACCERR`: the
    /// VMA is live but denies the access. Post-unmap holes are excluded.
    pub fn range_fault_is_access_error(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length) || state.no_write.contains(address, length)
    }

    /// Record (`no_access=true`) or clear (`false`) a live PROT_NONE range.
    /// Any protection update establishes a live mapping, so it also clears
    /// stale post-unmap state for the same range.
    pub fn set_no_access(&self, address: u64, len: usize, no_access: bool) {
        let mut state = self.state.write();
        state.unmapped.set(address, len, false);
        state.no_access.set(address, len, no_access);
    }

    /// Record or clear a post-unmap hole. Removing a VMA also clears its prior
    /// PROT_NONE/read-only attributes so a later reuse cannot inherit them.
    pub fn set_unmapped(&self, address: u64, len: usize, unmapped: bool) {
        let mut state = self.state.write();
        if unmapped {
            state.no_access.set(address, len, false);
            state.no_write.set(address, len, false);
        }
        state.unmapped.set(address, len, unmapped);
    }

    /// True if `[address, address+length)` overlaps any READ-ONLY range — a syscall
    /// WRITE there must fault `EFAULT` (a READ is allowed).
    pub fn range_no_write(&self, address: u64, length: usize) -> bool {
        self.state.read().no_write.contains(address, length)
    }

    /// Record (`no_write=true`, a `PROT_READ`-only range) or clear (`false`, the
    /// range became writable / unmapped) a read-only range.
    pub fn set_no_write(&self, address: u64, len: usize, no_write: bool) {
        let mut state = self.state.write();
        if no_write {
            state.unmapped.set(address, len, false);
        }
        state.no_write.set(address, len, no_write);
    }

    /// Publish the complete protection state of a live mapping atomically.
    /// This prevents sibling vCPUs from observing a transient accessible gap
    /// while an unmapped range becomes PROT_NONE/read-only or vice versa.
    pub fn set_mapping_protection(
        &self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        let mut state = self.state.write();
        state.unmapped.set(address, len, false);
        state.no_access.set(address, len, no_access);
        state.no_write.set(address, len, no_write);
    }
}

/// Fork-time copy of syscall-path protection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionSnapshot {
    pub no_access: Vec<(u64, u64)>,
    pub unmapped: Vec<(u64, u64)>,
    pub no_write: Vec<(u64, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_merge_split_and_query() {
        let p = MemoryProtections::default();
        assert!(!p.range_no_access(0x1000, 0x1000));
        // Two adjacent sets merge.
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_access(0x2000, 0x1000, true);
        assert_eq!(p.snapshot(), vec![(0x1000, 0x3000)]);
        assert!(p.range_no_access(0x1500, 0x100));
        assert!(p.range_no_access(0x2fff, 0x1)); // last byte protected
        assert!(!p.range_no_access(0x3000, 0x1)); // one past the end is clear
        // Clearing the middle splits into two ends.
        p.set_no_access(0x1800, 0x1000, false);
        assert_eq!(p.snapshot(), vec![(0x1000, 0x1800), (0x2800, 0x3000)]);
        assert!(!p.range_no_access(0x1800, 0x1000));
        assert!(p.range_no_access(0x1700, 0x100));
    }

    #[test]
    fn zero_length_and_overflow_are_noops() {
        let p = MemoryProtections::from_ranges(vec![(0x1000, 0x2000)]);
        p.set_no_access(0x4000, 0, true); // zero length: no-op
        assert_eq!(p.snapshot(), vec![(0x1000, 0x2000)]);
        assert!(!p.range_no_access(0x4000, 0)); // zero length never faults
        assert!(!p.range_no_access(u64::MAX, 16)); // saturating end: no overlap
    }

    /// The no_write (read-only) set is INDEPENDENT of no_access and shares the same
    /// merge/split RangeSet logic. A PROT_READ range is no_write but NOT no_access
    /// (reads are fine, writes EFAULT); clearing (became writable) removes it.
    #[test]
    fn no_write_set_is_independent_of_no_access() {
        let p = MemoryProtections::default();
        p.set_no_write(0x5000, 0x1000, true);
        assert!(p.range_no_write(0x5500, 0x10), "read-only range recorded");
        assert!(
            !p.range_no_access(0x5500, 0x10),
            "no_write != no_access (reads ok)"
        );
        // Independent sets: marking no_access elsewhere doesn't touch no_write.
        p.set_no_access(0x8000, 0x1000, true);
        assert!(p.range_no_write(0x5500, 0x10));
        assert!(p.range_no_access(0x8000, 0x10));
        assert!(!p.range_no_write(0x8000, 0x10));
        // Became writable: cleared.
        p.set_no_write(0x5000, 0x1000, false);
        assert!(
            !p.range_no_write(0x5500, 0x10),
            "writable again clears no_write"
        );
    }

    #[test]
    fn full_snapshot_preserves_no_write() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_write(0x4000, 0x1000, true);
        p.set_unmapped(0x8000, 0x1000, true);

        let cloned = MemoryProtections::from_snapshot(p.snapshot_all());

        assert!(cloned.range_no_access(0x1800, 0x10));
        assert!(cloned.range_prot_none(0x1800, 0x10));
        assert!(cloned.range_no_write(0x4800, 0x10));
        assert!(!cloned.range_no_access(0x4800, 0x10));
        assert!(cloned.range_no_access(0x8800, 0x10));
        assert!(cloned.range_unmapped(0x8800, 0x10));
        assert!(!cloned.range_prot_none(0x8800, 0x10));
    }

    #[test]
    fn mapped_prot_none_is_distinct_from_unmapped_and_reuse_clears_hole() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        assert!(p.range_no_access(0x1800, 1));
        assert!(p.range_prot_none(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));

        p.set_unmapped(0x1000, 0x1000, true);
        assert!(p.range_no_access(0x1800, 1));
        assert!(!p.range_prot_none(0x1800, 1));
        assert!(p.range_unmapped(0x1800, 1));

        p.set_mapping_protection(0x1000, 0x1000, true, false);
        assert!(p.range_prot_none(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));

        p.set_mapping_protection(0x1000, 0x1000, false, true);
        assert!(!p.range_no_access(0x1800, 1));
        assert!(p.range_no_write(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));
    }
}
