//! Sub-allocator and backing-object model for the fixed, boot-mapped shared
//! aperture (`LINUX_SHARED_FILE_BASE`, `LINUX_SHARED_FILE_SIZE`).
//!
//! The aperture itself is a single host `MAP_ANON | MAP_SHARED | MAP_NORESERVE`
//! region `hv_vm_map`'d once before vCPU threads exist (see
//! `linux_runtime_regions` in `memory.rs`). Guest `MAP_SHARED` mmaps then carve
//! sub-ranges out of it here, so NO `hv_vm_map`/`hv_vm_unmap` runs after vCPUs
//! exist. This is the spec's "stable stage-2 aperture topology" rule.

use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};

/// What backs a live shared-aperture allocation. This is the skeleton of the
/// spec's backing-object model; later plans add `PrivateAnon`, `PrivateFile`,
/// and `CarrickKernel`. The shared aperture only ever holds shared backings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackingObject {
    /// Guest `MAP_SHARED | MAP_ANON`: lives entirely in the aperture's host
    /// backing, shared across `fork(2)`, never copied. No writeback.
    SharedAnon,
    /// Guest `MAP_SHARED` of a file. Bytes are copied into the aperture on map;
    /// dirty bytes are written back to `host_fd` at `offset` on
    /// `msync(MS_SYNC)`/`munmap`. `host_fd` is a dup the allocator owns until
    /// the allocation is freed.
    SharedFile { host_fd: i32, offset: u64 },
}

/// One live allocation within the shared aperture.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedAlloc {
    pub guest_addr: u64,
    pub len: u64,
    pub backing: BackingObject,
}

/// Bump-plus-free-list sub-allocator over the fixed shared aperture window
/// `[LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE)`.
/// All sizes/addresses are HVF-granule (`0x4000`) aligned. No HVF calls happen
/// here — the window is `hv_vm_map`'d once at boot.
#[derive(Debug, Clone)]
pub(crate) struct SharedAperture {
    next: u64,
    /// Freed `(start, len)` ranges, sorted by start, coalesced. Reused before
    /// the bump cursor advances.
    free: Vec<(u64, u64)>,
    live: Vec<SharedAlloc>,
}

const GRANULE: u64 = 0x4000; // HVF_PAGE_SIZE; kept local to avoid a trap.rs dep.

fn align_up(value: u64, align: u64) -> Option<u64> {
    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
    }
}

impl SharedAperture {
    pub(crate) fn new() -> Self {
        Self {
            next: LINUX_SHARED_FILE_BASE,
            free: Vec::new(),
            live: Vec::new(),
        }
    }

    fn window_end() -> u64 {
        LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE
    }

    /// Reserve `len` bytes (rounded up to the granule). Returns the guest IPA,
    /// or `None` if the window is exhausted. Records the backing.
    pub(crate) fn alloc(&mut self, len: u64, backing: BackingObject) -> Option<u64> {
        if len == 0 {
            return None;
        }
        let len = align_up(len, GRANULE)?;
        // Reuse a freed range first.
        if let Some(pos) = self.free.iter().position(|&(_, l)| l >= len) {
            let (s, l) = self.free[pos];
            if l == len {
                self.free.remove(pos);
            } else {
                self.free[pos] = (s + len, l - len);
            }
            self.live.push(SharedAlloc {
                guest_addr: s,
                len,
                backing,
            });
            return Some(s);
        }
        let addr = align_up(self.next, GRANULE)?;
        let end = addr.checked_add(len)?;
        if end > Self::window_end() {
            return None;
        }
        self.next = end;
        self.live.push(SharedAlloc {
            guest_addr: addr,
            len,
            backing,
        });
        Some(addr)
    }

    /// Free the allocation starting at `guest_addr`. Returns the removed
    /// allocation (so the caller can write back / close the fd), or `None` if
    /// no live allocation starts there.
    pub(crate) fn free(&mut self, guest_addr: u64) -> Option<SharedAlloc> {
        let pos = self.live.iter().position(|a| a.guest_addr == guest_addr)?;
        let alloc = self.live.remove(pos);
        free_insert(&mut self.free, alloc.guest_addr, alloc.len);
        Some(alloc)
    }

    /// The backing for the live allocation starting at `guest_addr`, if any.
    pub(crate) fn backing(&self, guest_addr: u64) -> Option<BackingObject> {
        self.live
            .iter()
            .find(|a| a.guest_addr == guest_addr)
            .map(|a| a.backing)
    }

    /// All live allocations (used by `msync`-all and fork bookkeeping).
    pub(crate) fn live(&self) -> &[SharedAlloc] {
        &self.live
    }
}

/// Insert `[addr, addr+len)` into `regions`, coalescing adjacent/overlapping.
fn free_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let mut start = addr;
    let mut end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < start || s > end {
            if !inserted && s > end {
                out.push((start, end - start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            start = start.min(s);
            end = end.max(e);
        }
    }
    if !inserted {
        out.push((start, end - start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> u64 {
        LINUX_SHARED_FILE_BASE
    }

    #[test]
    fn bump_allocates_aligned_within_window() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x4000, BackingObject::SharedAnon).expect("alloc");
        let b = ap.alloc(0x1000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(a, base());
        // Second allocation is rounded up to the HVF granule (0x4000).
        assert_eq!(b, base() + 0x4000);
    }

    #[test]
    fn rejects_allocation_past_window_end() {
        let mut ap = SharedAperture::new();
        assert!(
            ap.alloc(LINUX_SHARED_FILE_SIZE + 0x4000, BackingObject::SharedAnon)
                .is_none()
        );
    }

    #[test]
    fn free_then_realloc_reuses_space() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        let freed = ap.free(a).expect("freed backing");
        assert!(matches!(freed.backing, BackingObject::SharedAnon));
        // The freed range is reused before the bump cursor advances.
        let b = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(b, a);
    }

    #[test]
    fn free_unknown_address_returns_none() {
        let mut ap = SharedAperture::new();
        assert!(ap.free(base() + 0x123).is_none());
    }

    #[test]
    fn lookup_returns_backing_for_live_alloc() {
        let mut ap = SharedAperture::new();
        let fd = 7;
        let a = ap
            .alloc(
                0x4000,
                BackingObject::SharedFile {
                    host_fd: fd,
                    offset: 0x1000,
                },
            )
            .expect("alloc");
        let got = ap.backing(a).expect("live");
        assert!(matches!(
            got,
            BackingObject::SharedFile {
                host_fd: 7,
                offset: 0x1000
            }
        ));
    }
}
