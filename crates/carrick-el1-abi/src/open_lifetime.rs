//! One terminal decision for a host reference group and owned ring references.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const HOST: u64 = 1 << 31;
const COUNT: u64 = HOST - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenReferenceKey {
    pub handle: u32,
    pub incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenRelease {
    Live,
    Terminal,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenReferenceWork {
    pub cas_attempts: u64,
}

/// Generation and population change in one CAS, including terminal admission.
/// A zero population cannot be resurrected. Generation exhaustion refuses.
#[repr(transparent)]
#[derive(Debug)]
pub struct OpenLifetime(AtomicU64);
impl OpenLifetime {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    /// Caller exclusively owns an unpublished or retired record.
    pub fn initialize(&self, incarnation: u64, host: bool) -> bool {
        let Ok(generation) = u32::try_from(incarnation) else {
            return false;
        };
        if generation == 0 {
            return false;
        }
        let old = self.0.load(Ordering::Acquire);
        if old & (HOST | COUNT) != 0 || incarnation <= old >> 32 {
            return false;
        }
        self.0
            .compare_exchange(
                old,
                (u64::from(generation) << 32) | if host { HOST } else { 1 },
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    /// # Safety
    /// Admission has published no root, fd view, or owned ring reference.
    pub unsafe fn abort_admission(&self, incarnation: u64) {
        let terminal = incarnation << 32;
        assert!(
            self.0
                .compare_exchange(
                    terminal | HOST,
                    terminal,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_ok()
                || self.0.load(Ordering::Acquire) == terminal
        );
    }
    fn update(&self, incarnation: u64, f: impl Fn(u64) -> Option<u64>) -> OpenRelease {
        self.update_observed(incarnation, f, |_| {})
    }
    fn update_observed(
        &self,
        incarnation: u64,
        f: impl Fn(u64) -> Option<u64>,
        mut observe: impl FnMut(OpenReferenceWork),
    ) -> OpenRelease {
        let mut work = OpenReferenceWork { cas_attempts: 0 };
        let mut old = self.0.load(Ordering::Acquire);
        loop {
            if old >> 32 != incarnation || old & (HOST | COUNT) == 0 {
                observe(work);
                return OpenRelease::Stale;
            }
            let Some(low) = f(old & (HOST | COUNT)) else {
                observe(work);
                return OpenRelease::Stale;
            };
            work.cas_attempts += 1;
            let new = (old & !(HOST | COUNT)) | low;
            match self
                .0
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    observe(work);
                    return if low == 0 {
                        OpenRelease::Terminal
                    } else {
                        OpenRelease::Live
                    };
                }
                Err(actual) => old = actual,
            }
        }
    }
    pub fn retain(&self, incarnation: u64) -> bool {
        self.update(incarnation, |low| (low & COUNT < COUNT).then_some(low + 1))
            == OpenRelease::Live
    }
    pub fn release(&self, incarnation: u64) -> OpenRelease {
        self.release_observed(incarnation, |_| {})
    }
    pub fn release_observed(
        &self,
        incarnation: u64,
        observe: impl FnMut(OpenReferenceWork),
    ) -> OpenRelease {
        self.update_observed(
            incarnation,
            |low| (low & COUNT != 0).then_some(low - 1),
            observe,
        )
    }
    pub fn release_host(&self, incarnation: u64) -> OpenRelease {
        self.update(incarnation, |low| (low & HOST != 0).then_some(low & !HOST))
    }
    pub fn is_terminal(&self, incarnation: u64) -> bool {
        self.0.load(Ordering::Acquire) == incarnation.checked_shl(32).unwrap_or(0)
            && incarnation != 0
            && incarnation <= u64::from(u32::MAX)
    }
    pub fn ring_references(&self, incarnation: u64) -> Option<u32> {
        let state = self.0.load(Ordering::Acquire);
        (state >> 32 == incarnation).then_some((state & COUNT) as u32)
    }
}
impl Default for OpenLifetime {
    fn default() -> Self {
        Self::new()
    }
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
    // F2/F3 must wire region-indexed open retirement before x86 emits edges.
    // Its current static handle namespace has no matching host drain.
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
    #[test]
    fn shared_open_lifetime_rejects_replay_and_generation_reuse() {
        let lifetime = OpenLifetime::new();
        assert!(!lifetime.initialize(0, true));
        assert!(!lifetime.initialize(u64::from(u32::MAX) + 1, true));
        assert!(lifetime.initialize(7, true));
        assert!(lifetime.retain(7));
        assert!(!lifetime.initialize(8, true));
        assert!(!lifetime.retain(8));
        assert_eq!(lifetime.release_host(7), OpenRelease::Live);
        assert_eq!(lifetime.release_host(7), OpenRelease::Stale);
        assert_eq!(lifetime.release(8), OpenRelease::Stale);
        assert_eq!(lifetime.release(7), OpenRelease::Terminal);
        assert_eq!(lifetime.release(7), OpenRelease::Stale);
        assert!(!lifetime.retain(7));
        assert!(!lifetime.initialize(7, false));
        assert!(lifetime.initialize(8, false));
        assert_eq!(lifetime.release(7), OpenRelease::Stale);
        assert_eq!(lifetime.release(8), OpenRelease::Terminal);
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
