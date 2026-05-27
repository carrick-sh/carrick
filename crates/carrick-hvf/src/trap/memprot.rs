//! Process-wide PROT_NONE range bookkeeping split out of trap.rs (WS-F3).
//! Sibling vCPU threads share this so syscall-path access checks observe
//! mprotect(PROT_NONE) made by any guest thread. macOS/aarch64 only.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[derive(Default)]
pub(super) struct MemoryProtections {
    no_access: parking_lot::RwLock<Vec<(u64, u64)>>,
}

impl MemoryProtections {
    pub(super) fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            no_access: parking_lot::RwLock::new(ranges),
        }
    }

    pub(super) fn snapshot(&self) -> Vec<(u64, u64)> {
        self.no_access.read().clone()
    }

    pub(super) fn range_no_access(&self, address: u64, length: usize) -> bool {
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

    pub(super) fn set_no_access(&self, address: u64, len: usize, no_access: bool) {
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
