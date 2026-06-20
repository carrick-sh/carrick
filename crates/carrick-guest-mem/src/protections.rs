//! Process-wide PROT_NONE range bookkeeping, shared by every hypervisor backend.
//!
//! When the guest `mprotect(PROT_NONE)`s (or `munmap`s) a range, a later
//! syscall whose buffer overlaps that range must fault with `EFAULT` exactly as
//! Linux would — even though the host backing is still physically accessible
//! (the host-side check; making the GUEST's own EL0 access fault needs stage-1
//! edits + signal injection, which the page-table managers handle separately).
//!
//! This set is the single source of truth for that host-side check. It is
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
//! Interior mutability ([`parking_lot::RwLock`]) so the shared `Arc` needs no
//! outer lock and `set_no_access`/`range_no_access` both take `&self`. The HVF
//! and KVM backends both hold an `Arc<MemoryProtections>` and clone it into each
//! sibling; a `fork(2)` child gets an INDEPENDENT copy (the Linux COW of the
//! whole process duplicates the underlying `Vec`, or `MemoryProtections::from_ranges`
//! over a `MemoryProtections::snapshot`); `execve` starts fresh
//! (`MemoryProtections::default`).
//!
//! [`GuestMemory`]: crate::GuestMemory

/// Sorted, merged, non-overlapping `[start, end)` guest-address ranges that are
/// currently `PROT_NONE`. See the module docs for the sharing contract.
#[derive(Default)]
pub struct MemoryProtections {
    no_access: parking_lot::RwLock<Vec<(u64, u64)>>,
}

impl MemoryProtections {
    /// Seed from an existing range list (e.g. a `fork(2)` child taking an
    /// independent copy of the parent's [`snapshot`](Self::snapshot)).
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            no_access: parking_lot::RwLock::new(ranges),
        }
    }

    /// A point-in-time copy of the protected ranges (for an independent fork).
    pub fn snapshot(&self) -> Vec<(u64, u64)> {
        self.no_access.read().clone()
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range — i.e. a
    /// syscall buffer there must fault `EFAULT`.
    pub fn range_no_access(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let ranges = self.no_access.read();
        let idx = ranges.partition_point(|&(_, e)| e <= address);
        ranges
            .get(idx)
            .is_some_and(|&(s, e)| address < e && s < end)
    }

    /// Record (`no_access=true`) or clear (`false`) a PROT_NONE range, keeping
    /// the set sorted and merged. Setting merges adjacent/overlapping ranges;
    /// clearing splits a partially-cleared range into the still-protected ends.
    pub fn set_no_access(&self, address: u64, len: usize, no_access: bool) {
        let end = address.saturating_add(len as u64);
        if end <= address {
            return;
        }
        let mut ranges = self.no_access.write();
        if no_access {
            ranges.push((address, end));
            ranges.sort_by_key(|&(start, _)| start);
            let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
            for (start, end) in std::mem::take(&mut *ranges) {
                if let Some((_, last_end)) = merged.last_mut()
                    && start <= *last_end
                {
                    *last_end = (*last_end).max(end);
                    continue;
                }
                merged.push((start, end));
            }
            *ranges = merged;
            return;
        }
        let mut next = Vec::with_capacity(ranges.len());
        for (s, e) in std::mem::take(&mut *ranges) {
            if address <= s && end >= e {
                continue;
            }
            if end <= s || address >= e {
                next.push((s, e));
                continue;
            }
            if s < address {
                next.push((s, address));
            }
            if end < e {
                next.push((end, e));
            }
        }
        next.sort_by_key(|&(start, _)| start);
        *ranges = next;
    }
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
}
