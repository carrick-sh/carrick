//! Pending terminal open-reference handoffs in the EL1 open-table extent.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use carrick_core_abi::OpenReferenceKey;

/// Indexed terminal handoffs occupy unused space in the open-table extent.
#[repr(C)]
pub struct OpenReferencePending {
    ready: AtomicBool,
    words: [AtomicU64; super::MAX_ZONE_OPEN_FILES / 64],
}
impl OpenReferencePending {
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            words: [const { AtomicU64::new(0) }; super::MAX_ZONE_OPEN_FILES / 64],
        }
    }
    pub fn mark(&self, key: OpenReferenceKey) {
        if let Some(index) = key.handle.checked_sub(1).map(|h| h as usize)
            && index < super::MAX_ZONE_OPEN_FILES
        {
            self.words[index / 64].fetch_or(1 << (index % 64), Ordering::Release);
            self.ready.store(true, Ordering::Release);
        }
    }
    pub fn clear(&self, handle: u32) {
        if let Some(index) = handle.checked_sub(1).map(|h| h as usize)
            && index < super::MAX_ZONE_OPEN_FILES
        {
            self.words[index / 64].fetch_and(!(1 << (index % 64)), Ordering::AcqRel);
        }
    }
    pub fn take(&self) -> impl Iterator<Item = u32> + '_ {
        let ready = self.ready.swap(false, Ordering::AcqRel);
        self.words
            .iter()
            .enumerate()
            .take_while(move |_| ready)
            .flat_map(|(word, bits)| {
                let mut bits = bits.swap(0, Ordering::AcqRel);
                core::iter::from_fn(move || {
                    if bits == 0 {
                        return None;
                    }
                    let bit = bits.trailing_zeros();
                    bits &= bits - 1;
                    Some((word * 64 + bit as usize + 1) as u32)
                })
            })
    }
}
impl Default for OpenReferencePending {
    fn default() -> Self {
        Self::new()
    }
}

pub const OPEN_REFERENCE_PENDING_OFFSET: u64 = super::EL1_OPEN_FILE_TABLE_OFFSET
    + (super::MAX_ZONE_OPEN_FILES * core::mem::size_of::<super::DelegatedOpenFile>()) as u64;
const _: () = assert!(
    OPEN_REFERENCE_PENDING_OFFSET + core::mem::size_of::<OpenReferencePending>() as u64
        <= super::EL1_OPEN_FILE_TABLE_OFFSET + super::EL1_OPEN_FILE_TABLE_SIZE
);

/// # Safety
/// `region` retains the aligned supervisor aperture through the returned borrow.
pub unsafe fn pending_at<'a>(region: usize) -> &'a OpenReferencePending {
    unsafe { &*((region + OPEN_REFERENCE_PENDING_OFFSET as usize) as *const OpenReferencePending) }
}

/// Publish only a terminal key. Slot reuse clears its owed edge before allocation.
pub fn queue_open_release(key: OpenReferenceKey) {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    let region = super::EL1_REGION_BASE as usize;
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    // F3 (#384) must wire region-indexed terminal retirement and its host drain.
    // F2 handles name carrier-local records, but the x86 host only consumes
    // explicit stdio release crossings, not exit-time pending release keys.
    let region = 0;
    #[cfg(not(target_os = "none"))]
    let region = super::get_el1_region_host_ptr();
    if region != 0 {
        // SAFETY: entry/host aperture admission retains this region.
        unsafe { pending_at(region) }.mark(key);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use carrick_core_abi::OpenReferenceKey;
    #[test]
    fn terminal_index_is_exact_and_coalesces_owed_edges() {
        let pending = OpenReferencePending::new();
        for handle in [1, 16, 512] {
            let key = OpenReferenceKey {
                handle,
                incarnation: 7,
            };
            pending.mark(key);
            pending.mark(key);
        }
        assert_eq!(pending.take().collect::<std::vec::Vec<_>>(), [1, 16, 512]);
        assert!(pending.take().next().is_none());
        pending.mark(OpenReferenceKey {
            handle: 1,
            incarnation: 7,
        });
        pending.clear(1);
        assert!(pending.take().next().is_none());
    }
}
