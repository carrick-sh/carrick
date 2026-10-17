//! Pending terminal open-reference handoffs in the EL1 open-table extent.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use carrick_core_abi::OpenReferenceKey;

/// Admission-issued witness that one open record was initialized in the
/// region's `DelegatedOpenFile` table, deriving its 1-based handle from the
/// record's index in `DelegatedOpenFile[]`.
///
/// Callers cannot construct this type outside [`admit_open_file_in_region`],
/// even after a glob import:
///
/// ```compile_fail
/// use carrick_el1_abi::*;
/// let key = OpenReferenceKey { handle: 5, incarnation: 7 };
/// let _ = AdmittedOpenReference(key);
/// ```
///
/// ```compile_fail
/// use carrick_el1_abi::*;
/// let key = OpenReferenceKey { handle: 5, incarnation: 7 };
/// let _ = AdmittedOpenReference { 0: key };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedOpenReference(OpenReferenceKey);
impl AdmittedOpenReference {
    pub const fn key(self) -> OpenReferenceKey {
        self.0
    }
    pub const fn handle(self) -> u32 {
        self.0.handle
    }
    pub const fn incarnation(self) -> u64 {
        self.0.incarnation
    }
}

/// Initialize the open record at `index` in `region`'s `DelegatedOpenFile`
/// table and mint its [`AdmittedOpenReference`], deriving the 1-based handle
/// from `index`.
///
/// # Safety
/// `region` is the aligned base of a retained supervisor region.
pub unsafe fn admit_open_file_in_region(
    region: usize,
    index: usize,
    incarnation: u64,
    host: bool,
) -> Option<AdmittedOpenReference> {
    if region == 0 || index >= super::MAX_ZONE_OPEN_FILES {
        return None;
    }
    let table_ptr = (region + super::EL1_OPEN_FILE_TABLE_OFFSET as usize)
        as *const [super::DelegatedOpenFile; super::MAX_ZONE_OPEN_FILES];
    // SAFETY: caller retains the aligned supervisor region.
    let record = &unsafe { &*table_ptr }[index];
    let handle = (index + 1) as u32;
    record
        .lifetime
        .initialize(incarnation, host)
        .then_some(AdmittedOpenReference(OpenReferenceKey {
            handle,
            incarnation,
        }))
}

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
    pub fn is_marked(&self, handle: u32) -> bool {
        let Some(index) = handle.checked_sub(1).map(|h| h as usize) else {
            return false;
        };
        index < super::MAX_ZONE_OPEN_FILES
            && self.ready.load(Ordering::Acquire)
            && (self.words[index / 64].load(Ordering::Acquire) & (1 << (index % 64))) != 0
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

/// Publish only a terminal key in `region`. Slot reuse clears its owed edge
/// before allocation.
pub fn queue_open_release(region: usize, key: OpenReferenceKey) {
    if region != 0 {
        // SAFETY: entry/host aperture admission retains this region.
        unsafe { pending_at(region) }.mark(key);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use carrick_core_abi::{OpenReferenceKey, OpenRelease};
    #[test]
    fn admit_open_file_in_region_mints_handle_and_refuses_live_record() {
        let len = (super::super::EL1_OPEN_FILE_TABLE_OFFSET
            + super::super::EL1_OPEN_FILE_TABLE_SIZE) as usize;
        let layout = std::alloc::Layout::from_size_align(len, 64).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        let base = ptr as usize;
        assert_eq!(unsafe { admit_open_file_in_region(0, 0, 1, true) }, None);
        assert_eq!(
            unsafe { admit_open_file_in_region(base, super::super::MAX_ZONE_OPEN_FILES, 1, true) },
            None
        );
        assert_eq!(unsafe { admit_open_file_in_region(base, 4, 0, true) }, None);
        let admitted = unsafe { admit_open_file_in_region(base, 4, 7, true) }.unwrap();
        assert_eq!(admitted.handle(), 5);
        assert_eq!(admitted.incarnation(), 7);
        // Re-admitting the same index while the record is still live is refused.
        assert_eq!(unsafe { admit_open_file_in_region(base, 4, 8, true) }, None);
        let table_ptr = (base + super::super::EL1_OPEN_FILE_TABLE_OFFSET as usize)
            as *const [super::super::DelegatedOpenFile; super::super::MAX_ZONE_OPEN_FILES];
        let record = &unsafe { &*table_ptr }[4];
        assert_eq!(record.lifetime.release_host(7), OpenRelease::Terminal);
        assert_eq!(unsafe { admit_open_file_in_region(base, 4, 7, true) }, None);
        let next = unsafe { admit_open_file_in_region(base, 4, 8, false) }.unwrap();
        assert_eq!(next.handle(), 5);
        assert_eq!(next.incarnation(), 8);
        unsafe { std::alloc::dealloc(ptr, layout) };
    }
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
            assert!(pending.is_marked(handle));
        }
        assert_eq!(pending.take().collect::<std::vec::Vec<_>>(), [1, 16, 512]);
        assert!(!pending.is_marked(1));
        assert!(pending.take().next().is_none());
        pending.mark(OpenReferenceKey {
            handle: 1,
            incarnation: 7,
        });
        assert!(pending.is_marked(1));
        pending.clear(1);
        assert!(!pending.is_marked(1));
        assert!(pending.take().next().is_none());
    }
}
